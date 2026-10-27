//! Connection event hooks.
//!
//! Every async client and server in this crate is generic over an
//! [`EventHandler`]. The handler is invoked at well-defined points in the
//! connection lifecycle (association up, state changed, service received,
//! bytes sent, disconnect, protocol error) with default no-op implementations,
//! so users only need to override the events they care about.
//!
//! The library ships [`DefaultLoggingHandler`] which routes everything to the
//! `tracing` crate at appropriate levels.

use mms_proto::assoc::{DisconnectReason, State};
use mms_proto::mms::MmsPdu;

/// Trait implemented by types that want to observe connection events.
///
/// All methods have empty defaults; implement only what you need. The trait
/// requires `Send + Sync + 'static` so handlers can be shared across the
/// driver task and the user-facing API.
pub trait EventHandler: Send + Sync + 'static {
    /// Called when the association reaches the data phase.
    fn on_association_up(&self) {}

    /// Called when the association state machine changes state.
    fn on_state_changed(&self, _state: State) {}

    /// Called when an inbound MMS PDU is delivered by the state machine.
    fn on_service_received(&self, _pdu: &MmsPdu) {}

    /// Called after a block of framed bytes is written to the wire.
    fn on_bytes_sent(&self, _len: usize) {}

    /// Called when the association is torn down, with the reason.
    fn on_disconnect(&self, _reason: &DisconnectReason) {}

    /// Called when a protocol-level error caused or will cause a disconnect.
    fn on_protocol_error(&self, _message: &str) {}
}

/// A handler that swallows every event. Useful as a generic default when the
/// caller hasn't supplied one.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopHandler;

impl EventHandler for NoopHandler {}

/// A handler that emits structured `tracing` events at appropriate levels:
///
/// * `debug` — service deliveries and byte writes
/// * `info`  — association up and state transitions
/// * `warn`  — disconnects and protocol errors
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultLoggingHandler;

impl EventHandler for DefaultLoggingHandler {
    fn on_association_up(&self) {
        tracing::info!(target: "tase2::assoc", "association up");
    }
    fn on_state_changed(&self, state: State) {
        tracing::info!(target: "tase2::state", ?state, "association state changed");
    }
    fn on_service_received(&self, pdu: &MmsPdu) {
        tracing::debug!(target: "tase2::rx", ?pdu, "service received");
    }
    fn on_bytes_sent(&self, len: usize) {
        tracing::debug!(target: "tase2::tx", len, "bytes sent");
    }
    fn on_disconnect(&self, reason: &DisconnectReason) {
        tracing::warn!(target: "tase2::assoc", ?reason, "association disconnected");
    }
    fn on_protocol_error(&self, message: &str) {
        tracing::warn!(target: "tase2::error", "protocol error: {message}");
    }
}
