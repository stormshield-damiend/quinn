use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use quinn::TokioRuntime;
use tracing::{debug, error, info, warn};

use perf::bind_socket;

#[derive(Parser)]
#[clap(name = "server datagram")]
struct Opt {
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:4433")]
    listen: SocketAddr,
    /// TLS private key in PEM format
    #[clap(parse(from_os_str), short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(parse(from_os_str), short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Send buffer size in bytes
    #[clap(long, default_value = "2097152")]
    send_buffer_size: usize,
    /// Receive buffer size in bytes
    #[clap(long, default_value = "2097152")]
    recv_buffer_size: usize,
    /// Whether to print connection statistics
    #[clap(long)]
    conn_stats: bool,
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,
    /// UDP payload size that the network must be capable of carrying
    #[clap(long, default_value = "1200")]
    initial_max_udp_payload_size: u16,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt::init();

    if let Err(e) = run(opt).await {
        error!("{:#}", e);
    }
}

async fn run(opt: Opt) -> Result<()> {
    let (key, cert) = match (&opt.key, &opt.cert) {
        (&Some(ref key), &Some(ref cert)) => {
            let key = fs::read(key).context("reading key")?;
            let cert = fs::read(cert).expect("reading cert");

            let mut certs = Vec::new();
            for cert in rustls_pemfile::certs(&mut cert.as_ref()).context("parsing cert")? {
                certs.push(rustls::Certificate(cert));
            }

            (rustls::PrivateKey(key), certs)
        }
        _ => {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (
                rustls::PrivateKey(cert.serialize_private_key_der()),
                vec![rustls::Certificate(cert.serialize_der().unwrap())],
            )
        }
    };

    let mut crypto = rustls::ServerConfig::builder()
        .with_cipher_suites(perf::PERF_CIPHER_SUITES)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .unwrap();
    crypto.alpn_protocols = vec![b"perf".to_vec()];

    if opt.keylog {
        crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut transport = quinn::TransportConfig::default();
    transport.initial_max_udp_payload_size(opt.initial_max_udp_payload_size);
    // FIXME add command line option
    transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    transport.datagram_send_buffer_size(16 * 1024 * 1024);

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport_config(Arc::new(transport));

    let socket = bind_socket(opt.listen, opt.send_buffer_size, opt.recv_buffer_size)?;

    let endpoint = quinn::Endpoint::new(
        Default::default(),
        Some(server_config),
        socket,
        TokioRuntime,
    )
    .context("creating endpoint")?;

    info!("listening on {}", endpoint.local_addr().unwrap());

    let opt = Arc::new(opt);

    while let Some(handshake) = endpoint.accept().await {
        let opt = opt.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(handshake, opt).await {
                error!("connection lost: {:#}", e);
            }
        });
    }

    Ok(())
}

async fn handle(handshake: quinn::Connecting, opt: Arc<Opt>) -> Result<()> {
    let connection = handshake.await.context("handshake failed")?;
    debug!("{} connected", connection.remote_address());
    tokio::try_join!(drive_dgram(connection.clone()), conn_stats(connection, opt))?;
    Ok(())
}

async fn conn_stats(connection: quinn::Connection, opt: Arc<Opt>) -> Result<()> {
    if opt.conn_stats {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("{:?}\n", connection.stats());
        }
    }

    Ok(())
}

async fn drive_dgram(connection: quinn::Connection) -> Result<()> {
    loop {
        while let Ok((send, recv)) = connection.accept_bi().await {
            let connection2 = connection.clone();
            if let Err(e) = handle_dgram(connection2, send, recv).await {
                error!("request failed: {:#}", e);
            }
        }
    }
}

async fn handle_dgram(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    // read upload amound as start frame
    debug!("receiving expected upload size");
    let mut buf = [0; 8];
    recv.read_exact(&mut buf)
        .await
        .context("reading expected upload size")?;
    let expected_upload = u64::from_be_bytes(buf);
    debug!("will receive {} bytes on {}", expected_upload, recv.id());

    // FIXME: stats

    let mut received: u64 = 0;
    let mut buf = [0; 8];
    let start = Instant::now();
    loop {
        tokio::select! {
            dgram = connection.read_datagram() => {
                let dgram = dgram.context("reading datagram")?;
                received += dgram.len() as u64;
                // debug!("received datagram {}", received);
            },
            // read upload amount as stop frame
            _ = recv.read_exact(&mut buf) => {
                let stop = u64::from_be_bytes(buf);
                assert_eq!(stop, expected_upload);
                debug!("received stop message {} upload {}", stop, expected_upload);
                break;
            }
        };
    }

    // add few extra second to allow receiving some more datagram based on received amount and time
    let missing = expected_upload - received;
    if received != 0 && missing != 0 {
        let elapsed = start.elapsed();
        let needed_time = missing * elapsed.as_micros() as u64 / received;
        let extra_time = 2 * needed_time;
        debug!("stop message received too early, expected {}, received {}, missing {}, elapsed {:?}, needed time {}us, extra_time {}us",
              expected_upload, received, missing, elapsed, needed_time, extra_time);
        loop {
            tokio::select! {
                dgram = connection.read_datagram() => {
                    let dgram = dgram.context("reading datagram")?;
                    received += dgram.len() as u64;
                    // debug!("received datagram {}", received);
                },
                _ = tokio::time::sleep(Duration::from_micros(extra_time)) => {
                    let missing = expected_upload - received;
                    debug!("grace time expired, upload {}, received {}, missing {}", expected_upload, received, missing);
                    break;
                },
            }
        }
    }

    // write received amount as stop message
    debug!("sending stop message, received {}", received);
    send.write_all(&received.to_be_bytes())
        .await
        .context("writting stop message")?;

    let dropped = expected_upload - received;
    debug!(
        "expected {} received {} dropped {}",
        expected_upload, received, dropped
    );
    if dropped > 0 {
        warn!("dropped {} out of {} datagrams", dropped, expected_upload);
    }

    Ok(())
}
