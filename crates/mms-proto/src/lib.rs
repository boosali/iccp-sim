//! Sans-I/O implementation of the MMS (ISO 9506) protocol stack.
//!
//! This crate contains no `async`, no sockets and no clocks. It will expose:
//!
//! * ASN.1 BER primitives and codecs
//! * TPKT and COTP framing
//! * ISO Session, Presentation, and ACSE layers
//! * MMS services
//!
//! Downstream crates tie these layers into async clients and servers.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod assoc;
pub mod ber;
pub mod cotp;
pub mod error;
pub mod mms;
pub mod osi;
pub mod tpkt;

pub use error::{Error, Result};
