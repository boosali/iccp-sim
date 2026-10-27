use thiserror::Error;

use crate::ber::tag::Tag;

/// Result type used throughout the mms-proto crate.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Errors produced by BER codecs and upper-layer state machines in this crate.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Buffer ended before the TLV was complete.
    #[error("BER truncated: needed {needed} bytes, had {have}")]
    BerTruncated { needed: usize, have: usize },

    /// An oversized BER length field.
    ///
    /// `len` carries the *number of length octets* when the long form declares
    /// more than 4 octets (a >32-bit length), otherwise it carries the
    /// oversized length *value* that does not fit in `usize`.
    #[error("BER length overflow: {len}")]
    BerLengthOverflow { len: u64 },

    /// The tag encoding is malformed (e.g. indefinite length on a primitive,
    /// reserved 0xFF length octet, or a tag number that overflows u32).
    #[error("BER invalid tag encoding")]
    BerInvalidTag,

    /// An INTEGER content span is longer than 8 octets (won't fit in i64).
    #[error("BER integer overflow: content is {len} octets")]
    BerIntegerOverflow { len: usize },

    /// A BOOLEAN value has the wrong content length.
    #[error("BER invalid BOOLEAN: content length {len} (expected 1)")]
    BerInvalidBool { len: usize },

    /// A VisibleString contains bytes outside the 0x20..=0x7E ASCII range.
    #[error("BER invalid VisibleString: non-printable ASCII byte")]
    BerInvalidString,

    /// An OBJECT IDENTIFIER encoding is malformed (empty, or base-128 decode
    /// overflows, or trailing continuation octet).
    #[error("BER invalid OID encoding")]
    BerInvalidOid,

    /// The decoder expected a specific tag but found a different one.
    #[error("BER unexpected tag: expected {expected}, got {got}")]
    BerUnexpectedTag { expected: Tag, got: Tag },

    /// Bytes remain in the buffer after the expected structure was fully
    /// parsed.
    #[error("BER trailing bytes: {count} octets left")]
    BerTrailingBytes { count: usize },

    /// Indefinite-length nesting exceeded the depth cap while scanning for
    /// end-of-contents.
    #[error("BER nesting depth exceeded maximum of {max}")]
    BerDepthExceeded { max: usize },

    // ---- TPKT (RFC 1006) errors --------------------------------------------
    /// The TPKT version field is not 0x03.
    #[error("TPKT invalid version: got {got}, expected 3")]
    TpktInvalidVersion { got: u8 },

    /// The TPKT length field is less than 7 (RFC 1006 minimum).
    #[error("TPKT invalid length: {len} (minimum is 7)")]
    TpktInvalidLength { len: u16 },

    /// The payload to encode is too large to fit in a single TPKT packet.
    #[error("TPKT payload too long: {len} bytes (maximum is 65531)")]
    TpktPayloadTooLong { len: usize },

    // ---- COTP (ISO 8073 class 0) errors ------------------------------------
    /// The buffer ended before a complete COTP TPDU could be read.
    #[error("COTP truncated")]
    CotpTruncated,

    /// The LI (length indicator) octet is inconsistent with the TPDU type.
    #[error("COTP invalid length indicator: {li}")]
    CotpInvalidLengthIndicator { li: u8 },

    /// The TPDU code byte is not one of the recognised COTP TPDU types.
    #[error("COTP unknown TPDU code: 0x{code:02X}")]
    CotpUnknownTpduCode { code: u8 },

    /// A parameter in the COTP variable part is malformed.
    #[error("COTP invalid parameter: code 0x{code:02X}")]
    CotpInvalidParameter { code: u8 },

    /// The transport-class nibble in a CR/CC indicates a class other than 0.
    #[error("COTP unsupported class: {class}")]
    CotpUnsupportedClass { class: u8 },

    /// The TPDU-size exponent in a TPDU-size parameter is outside the valid
    /// range 7..=13.
    #[error("COTP invalid TPDU size exponent: {exponent}")]
    CotpInvalidTpduSize { exponent: u8 },

    /// Accumulating DT-TPDU payload would exceed the reassembly buffer limit.
    #[error("COTP reassembly overflow: maximum is {max} bytes")]
    CotpReassemblyOverflow { max: usize },

    // ---- ISO Session (ISO 8327-1) errors -----------------------------------
    /// The buffer ended before a complete session SPDU could be read.
    #[error("session SPDU truncated")]
    SessionTruncated,

    /// The SPDU identifier (SI) byte is not one of the recognised SPDU types.
    #[error("session unknown SPDU: SI {si}")]
    SessionUnknownSpdu { si: u8 },

    /// A parameter (PI/PGI) in the session header is malformed (e.g. a fixed
    /// parameter with the wrong declared length, or a length that runs past the
    /// end of the SPDU).
    #[error("session invalid parameter: code {code}")]
    SessionInvalidParameter { code: u8 },

    /// A CONNECT was answered with a REFUSE SPDU.
    #[error("session refused")]
    SessionRefused,

    // ---- ISO Presentation (ISO 8823) errors --------------------------------
    /// A presentation PPDU is structurally invalid (missing mandatory fields,
    /// wrong outer tag, or a context-definition that cannot be parsed).
    #[error("presentation PPDU invalid")]
    PresentationInvalid,

    /// A data PPDU referenced a presentation-context-identifier we never
    /// learned.
    #[error("presentation context unknown: PCI {pci}")]
    PresentationContextUnknown { pci: u32 },

    /// The peer's presentation-context-definition-list did not advertise a
    /// context for an abstract syntax the MMS profile requires. `which` is
    /// `"acse"` or `"mms"`.
    #[error("presentation abstract syntax not offered: {which}")]
    PresentationAbstractSyntaxUnoffered { which: &'static str },

    // ---- ISO ACSE (ISO 8650) errors ----------------------------------------
    /// An ACSE APDU is structurally invalid.
    #[error("ACSE APDU invalid")]
    AcseInvalid,

    /// The ACSE APDU carried an APPLICATION tag we do not handle.
    #[error("ACSE unexpected PDU: tag 0x{tag:02X}")]
    AcseUnexpectedPdu { tag: u8 },

    /// An AARE carried a non-zero association result. The codec itself decodes
    /// a rejecting AARE successfully and never returns this; it is constructed
    /// by the association state machine (Phase 6) when it acts on the result.
    #[error("ACSE association rejected: result {result}")]
    AcseRejected { result: i64 },

    // ---- MMS (ISO 9506) errors ---------------------------------------------
    /// An MMS PDU is structurally invalid (missing mandatory field, malformed
    /// nested structure, or a CHOICE with no recognised alternative).
    #[error("MMS PDU invalid")]
    MmsInvalidPdu,

    /// The top-level MMSpdu CHOICE carried a context tag we do not recognise.
    #[error("MMS unknown PDU tag: {tag}")]
    MmsUnknownPduTag { tag: u32 },

    /// A ConfirmedServiceRequest/Response CHOICE carried a service tag we do
    /// not handle. Carried through decode as an `Unsupported`/`Unknown`
    /// variant rather than an error; this error exists for the cases where a
    /// service tag is genuinely undecodable.
    #[error("MMS unknown service tag: {tag}")]
    MmsUnknownServiceTag { tag: u32 },

    /// An MMS `Identifier` (VisibleString) violated the length or character
    /// rules (1..=32 chars, `[A-Za-z_$][A-Za-z0-9_$]*`).
    #[error("MMS invalid identifier")]
    MmsInvalidIdentifier,

    /// A recursive `Data` value nested deeper than the decode depth cap.
    #[error("MMS Data nesting depth exceeded maximum of {max}")]
    MmsDataDepthExceeded { max: usize },

    /// A floating-point `Data` value had an OCTET STRING length that does not
    /// match a supported IEEE layout (5 octets for single, 9 for double).
    #[error("MMS invalid floating-point: content is {len} octets")]
    MmsInvalidFloat { len: usize },
}
