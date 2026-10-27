//! COTP (Connection-Oriented Transport Protocol) — ISO 8073 class 0.
//!
//! This module implements the COTP framing layer that sits immediately above
//! TPKT in the MMS protocol stack.  Only transport class 0 is
//! supported, which is what RFC 1006 mandates for ISO over TCP.
//!
//! # Module layout
//!
//! | Module          | Contents                                                  |
//! |-----------------|-----------------------------------------------------------|
//! | [`pdu`]         | `CotpPdu` enum and `ConnectionPdu` struct                 |
//! | [`params`]      | `CotpParams`, `TpduSize`                                  |
//! | [`codec`]       | `CotpCodec` — stateless TPDU encoder/decoder              |
//! | [`reassembly`]  | `CotpReassembler` — DT-fragment reassembly buffer         |

pub mod codec;
pub mod params;
pub mod pdu;
pub mod reassembly;

#[cfg(test)]
mod proptests;

pub use codec::CotpCodec;
pub use params::{CotpParams, TpduSize};
pub use pdu::{ConnectionPdu, CotpPdu};
pub use reassembly::CotpReassembler;
