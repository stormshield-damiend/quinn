use std::any::Any;
use std::cmp;
use std::sync::Arc;

use super::{BASE_DATAGRAM_SIZE, Controller, ControllerFactory};
use crate::connection::RttEstimator;
use crate::{Duration, Instant};

/// CUBIC Constants.
///
/// These are recommended value in RFC9438.
const BETA_CUBIC: f64 = 0.7;

const C: f64 = 0.4;

/// CUBIC State Variables.
///
/// We need to keep those variables across the connection.
/// k, w_max are described in the RFC.
#[derive(Debug, Default, Clone)]
struct State {
    /// Time period that the cubic function takes to increase the window size to W_max.
    k: f64,

    /// Congestion window size when the last congestion event occurred.
    w_max: f64,

    /// Congestion window increment stored during congestion avoidance.
    cwnd_inc: u64,

    /// Maximum number of bytes in flight that may be sent.
    window: u64,

    /// Slow start threshold in bytes.
    ///
    /// When the congestion window is below ssthresh, the mode is slow start
    /// and the window grows by the number of bytes acknowledged.
    ssthresh: u64,

    /// The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent
    /// after this time is acknowledged, QUIC exits recovery.
    recovery_start_time: Option<Instant>,
}

/// CUBIC Functions.
///
/// Note that these calculations are based on a count of cwnd as bytes,
/// not packets.
/// Unit of t (duration) and RTT are based on seconds (f64).
impl State {
    // K = cbrt(w_max * (1 - beta_cubic) / C) (Eq. 2)
    fn cubic_k(&self, max_datagram_size: u64) -> f64 {
        unimplemented!()
    }

    // W_cubic(t) = C * (t - K)^3 + w_max (Eq. 1)
    fn w_cubic(&self, t: Duration, max_datagram_size: u64) -> f64 {
        unimplemented!()
    }

    // W_est(t) = w_max * beta_cubic + 3 * (1 - beta_cubic) / (1 + beta_cubic) *
    // (t / RTT) (Eq. 4)
    fn w_est(&self, t: Duration, rtt: Duration, max_datagram_size: u64) -> f64 {
        unimplemented!()
    }
}

/// The RFC9438 congestion controller, as widely used for TCP
#[derive(Debug, Clone)]
pub struct Cubic {
    config: Arc<CubicConfig>,
    current_mtu: u64,
    state: State,
    /// Copy of the controller state to restore when a spurious congestion event is detected.
    pre_congestion_state: Option<State>,
}

impl Cubic {
    /// Construct a state using the given `config` and current time `now`
    pub fn new(config: Arc<CubicConfig>, _now: Instant, current_mtu: u16) -> Self {
        unimplemented!()
    }
}

impl Controller for Cubic {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        unimplemented!();
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        is_ecn: bool,
        _lost_bytes: u64,
    ) {
        unimplemented!();
    }

    fn on_spurious_congestion_event(&mut self) {
        if let Some(prior_state) = self.pre_congestion_state.take() {
            if self.state.window < prior_state.window {
                self.state = prior_state;
            }
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        unimplemented!();
    }

    fn window(&self) -> u64 {
        self.state.window
    }

    fn metrics(&self) -> super::ControllerMetrics {
        super::ControllerMetrics {
            congestion_window: self.window(),
            ssthresh: Some(self.state.ssthresh),
            pacing_rate: None,
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.config.initial_window
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Configuration for the `Cubic` congestion controller
#[derive(Debug, Clone)]
pub struct CubicConfig {
    initial_window: u64,
}

impl CubicConfig {
    /// Default limit on the amount of outstanding data in bytes.
    ///
    /// Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
    pub fn initial_window(&mut self, value: u64) -> &mut Self {
        self.initial_window = value;
        self
    }
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            initial_window: 14720.clamp(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE),
        }
    }
}

impl ControllerFactory for CubicConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Cubic::new(self, now, current_mtu))
    }
}
