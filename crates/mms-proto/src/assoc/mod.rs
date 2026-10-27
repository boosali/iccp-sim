//! The MMS association state machine (sans-I/O).
//!
//! [`MmsConnection`] is the orchestration layer that drives the COTP →
//! Session/Presentation/ACSE → MMS handshake and data phase as a pure
//! input → action machine. It holds no sockets and never reads the clock:
//! callers pass the current [`std::time::Instant`] into every
//! [`MmsConnection::handle`] call so the machine is fully deterministic.
//!
//! | Module      | Contents                                              |
//! |-------------|-------------------------------------------------------|
//! | [`config`]  | [`AssocConfig`] — addresses, timeouts, Initiate PDU   |
//! | [`state`]   | [`MmsConnection`], [`MmsInput`], [`MmsAction`], states |
//! | `timers`    | internal deadline bookkeeping                         |

pub mod config;
pub mod state;
mod timers;

pub use config::AssocConfig;
pub use state::{AssocStage, DisconnectReason, MmsAction, MmsConnection, MmsInput, Role, State};
