//! COTP TPDU model types.
//!
//! This module defines the in-memory representation of each COTP TPDU (Transport
//! Protocol Data Unit) that this implementation handles. Only the TPDU types
//! relevant to ISO 8073 **transport class 0** over RFC 1006 are modelled:
//!
//! | Code | Type                  | Acronym |
//! |------|-----------------------|---------|
//! | 0xE0 | Connection Request    | CR      |
//! | 0xD0 | Connection Confirm    | CC      |
//! | 0x80 | Disconnect Request    | DR      |
//! | 0xF0 | Data                  | DT      |
//! | 0x70 | Error                 | ER      |

use crate::cotp::params::CotpParams;

// ---------------------------------------------------------------------------
// TPDU codes
// ---------------------------------------------------------------------------

/// TPDU code for Connection Request.
pub const CODE_CR: u8 = 0xE0;
/// TPDU code for Connection Confirm.
pub const CODE_CC: u8 = 0xD0;
/// TPDU code for Disconnect Request.
pub const CODE_DR: u8 = 0x80;
/// TPDU code for Data.
pub const CODE_DT: u8 = 0xF0;
/// TPDU code for Error.
pub const CODE_ER: u8 = 0x70;

// ---------------------------------------------------------------------------
// ConnectionPdu
// ---------------------------------------------------------------------------

/// Shared fields for CR (Connection Request) and CC (Connection Confirm) TPDUs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPdu {
    /// Destination reference (2 bytes, big-endian on the wire).
    pub dst_ref: u16,
    /// Source reference (2 bytes, big-endian on the wire).
    pub src_ref: u16,
    /// Class/options octet.  For class 0 this is `0x00`.
    pub class: u8,
    /// Optional variable-part parameters.
    pub params: CotpParams,
}

// ---------------------------------------------------------------------------
// CotpPdu
// ---------------------------------------------------------------------------

/// A decoded COTP TPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CotpPdu {
    /// Connection Request (code 0xE0).
    ConnectionRequest(ConnectionPdu),
    /// Connection Confirm (code 0xD0).
    ConnectionConfirm(ConnectionPdu),
    /// Disconnect Request (code 0x80).
    DisconnectRequest {
        dst_ref: u16,
        src_ref: u16,
        reason: u8,
    },
    /// Data TPDU (code 0xF0).
    Data {
        /// End-of-TSDU: set on the last (or only) DT in a sequence.
        eot: bool,
        /// User data carried in this DT TPDU.
        payload: Vec<u8>,
    },
    /// Error (ER) TPDU (code 0x70).
    ///
    /// Named `ErrorTpdu` rather than `Error` to avoid collision with
    /// [`crate::Error`] in shared scopes.
    ErrorTpdu { dst_ref: u16, reject_cause: u8 },
}
