//! Deadline bookkeeping for the association state machine.
//!
//! The store holds at most two deadlines — the handshake setup deadline and
//! the graceful-release deadline — each expressed as an absolute
//! [`Instant`]. Time never flows from `Instant::now()`; deadlines are armed
//! relative to the caller-supplied `now` and evaluated against it.

use std::time::Instant;

/// Absolute deadlines for the association state machine.
#[derive(Debug, Default)]
pub(super) struct Deadlines {
    /// When the Associate → Associated handshake must complete.
    pub(super) setup: Option<Instant>,
    /// When the Release → Closed exchange must complete.
    pub(super) release: Option<Instant>,
}

impl Deadlines {
    /// Returns `true` if the setup deadline is set and has passed at `now`.
    pub(super) fn setup_expired(&self, now: Instant) -> bool {
        self.setup.is_some_and(|d| now >= d)
    }

    /// Returns `true` if the release deadline is set and has passed at `now`.
    pub(super) fn release_expired(&self, now: Instant) -> bool {
        self.release.is_some_and(|d| now >= d)
    }

    /// Clear all deadlines.
    pub(super) fn clear(&mut self) {
        self.setup = None;
        self.release = None;
    }
}
