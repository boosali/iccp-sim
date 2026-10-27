//! TPKT framing — RFC 1006 transport layer for OSI over TCP/IP.
//!
//! TPKT wraps each ISO transport TSDU (Transport Service Data Unit) in a
//! simple 4-byte header so it can be carried over a TCP byte-stream that
//! provides no record boundaries of its own.
//!
//! # Wire format
//!
//! ```text
//! Offset  Size  Field
//! ------  ----  -----
//! 0       1     Version  — must be 0x03
//! 1       1     Reserved — 0x00 on write; ignored on read
//! 2–3     2     Length   — total packet length *including* this 4-byte header,
//!                          big-endian u16; RFC 1006 minimum is 7 (4-byte header
//!                          + 3-byte minimum COTP header)
//! 4+      n     Payload  — the COTP TPDU or other ISO transport PDU
//! ```

pub mod codec;

#[cfg(test)]
mod proptests;

pub use codec::Tpkt;

/// Byte length of the TPKT header.
pub const TPKT_HEADER_LEN: usize = 4;

/// Maximum total TPKT packet length (header included) as a u16.
pub const TPKT_MAX_LEN: usize = 65_535;

/// Maximum payload length that can be encoded in a single TPKT packet.
pub const TPKT_MAX_PAYLOAD: usize = TPKT_MAX_LEN - TPKT_HEADER_LEN;

/// TPKT protocol version.
pub const TPKT_VERSION: u8 = 3;
