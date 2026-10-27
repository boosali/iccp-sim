//! The MMS `Data` CHOICE: the recursive value model carried by Read, Write and
//! InformationReport.
//!
//! # Context tags (ISO 9506-2)
//!
//! | Tag  | Alternative      | Wire type                                  |
//! |------|------------------|--------------------------------------------|
//! | `[1]`| array            | IMPLICIT SEQUENCE OF Data                  |
//! | `[2]`| structure        | IMPLICIT SEQUENCE OF Data                  |
//! | `[3]`| boolean          | IMPLICIT BOOLEAN                           |
//! | `[4]`| bit-string       | IMPLICIT BIT STRING                        |
//! | `[5]`| integer          | IMPLICIT INTEGER                           |
//! | `[6]`| unsigned         | IMPLICIT INTEGER (non-negative)            |
//! | `[7]`| floating-point   | IMPLICIT OCTET STRING (FloatingPoint)      |
//! | `[9]`| octet-string     | IMPLICIT OCTET STRING                      |
//! | `[10]`| visible-string  | IMPLICIT VisibleString                     |
//! | `[12]`| binary-time     | IMPLICIT OCTET STRING (TimeOfDay, 4 or 6)  |
//! | `[16]`| mMSString       | IMPLICIT UTF8String (VisibleString in std) |
//! | `[17]`| utc-time        | IMPLICIT OCTET STRING (SIZE 8)             |
//!
//! # FloatingPoint encoding
//! `FloatingPoint ::= OCTET STRING` whose first octet is the *exponent width
//! in bits* and the remaining octets are the IEEE 754 mantissa+exponent in
//! big-endian order:
//! * single precision: first octet `8`, then 4 bytes  → 5 octets total
//! * double precision: first octet `11`, then 8 bytes → 9 octets total
//!
//! # Depth cap
//! `array`/`structure` recurse. Decoding caps nesting at [`MAX_DATA_DEPTH`] so
//! a maliciously deep "Data bomb" yields [`Error::MmsDataDepthExceeded`] rather
//! than exhausting the stack.

use crate::ber::primitives::BitString;
use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, TagClass};
use crate::ber::writer::BerWriter;
use crate::ber::{
    decode_bit_string, decode_bool, decode_integer_i64, decode_unsigned_u64, decode_visible_string,
};
use crate::{Error, Result};

/// Maximum `Data` recursion depth accepted on decode. Shares the spirit of the
/// BER reader's `MAX_DEPTH = 32`.
pub const MAX_DATA_DEPTH: usize = 32;

// --- Data context tags ------------------------------------------------------

const TAG_ARRAY: Tag = Tag::context_constructed(1);
const TAG_STRUCTURE: Tag = Tag::context_constructed(2);
const TAG_BOOLEAN: Tag = Tag::context(3);
const TAG_BIT_STRING: Tag = Tag::context(4);
const TAG_INTEGER: Tag = Tag::context(5);
const TAG_UNSIGNED: Tag = Tag::context(6);
const TAG_FLOAT: Tag = Tag::context(7);
const TAG_OCTET_STRING: Tag = Tag::context(9);
const TAG_VISIBLE_STRING: Tag = Tag::context(10);
const TAG_BINARY_TIME: Tag = Tag::context(12);
const TAG_MMS_STRING: Tag = Tag::context(16);
const TAG_UTC_TIME: Tag = Tag::context(17);

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

/// An MMS `Data` value (recursive CHOICE).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Data {
    /// `array [1]` — ordered list of same-typed elements.
    Array(Vec<Data>),
    /// `structure [2]` — ordered list of (possibly heterogeneous) elements.
    Structure(Vec<Data>),
    /// `boolean [3]`.
    Boolean(bool),
    /// `bit-string [4]`.
    BitString(BitString),
    /// `integer [5]`.
    Integer(i64),
    /// `unsigned [6]`.
    Unsigned(u64),
    /// `floating-point [7]` single precision (exponent width 8).
    Float(f32),
    /// `floating-point [7]` double precision (exponent width 11).
    Double(f64),
    /// `octet-string [9]`.
    OctetString(Vec<u8>),
    /// `visible-string [10]`.
    VisibleString(String),
    /// `binary-time [12]` — raw 4- or 6-octet TimeOfDay.
    BinaryTime(Vec<u8>),
    /// `mMSString [16]` — UTF-8 string.
    Utf8String(String),
    /// `utc-time [17]` — 8 octets (4 secs + 3 fraction + 1 quality).
    UtcTime([u8; 8]),
    /// Any other / unhandled CHOICE alternative, preserved verbatim so the
    /// value re-encodes identically (tolerant decode of e.g. `bcd [13]`,
    /// `objId [15]`).
    Unknown {
        /// The context tag number of the unhandled alternative.
        tag: u32,
        /// Whether the alternative was constructed.
        constructed: bool,
        /// The raw content bytes.
        bytes: Vec<u8>,
    },
}

impl Data {
    /// Encode this `Data` value into `w`.
    pub fn encode(&self, w: &mut BerWriter) {
        match self {
            Data::Array(elems) => w.write_tlv(TAG_ARRAY, |seq| {
                for e in elems {
                    e.encode(seq);
                }
            }),
            Data::Structure(elems) => w.write_tlv(TAG_STRUCTURE, |seq| {
                for e in elems {
                    e.encode(seq);
                }
            }),
            Data::Boolean(b) => w.write_bool(TAG_BOOLEAN, *b),
            Data::BitString(bs) => w.write_bit_string(TAG_BIT_STRING, bs),
            Data::Integer(v) => w.write_integer(TAG_INTEGER, *v),
            Data::Unsigned(v) => w.write_unsigned(TAG_UNSIGNED, *v),
            Data::Float(f) => {
                let mut content = Vec::with_capacity(5);
                content.push(8); // exponent width in bits for IEEE single
                content.extend_from_slice(&f.to_be_bytes());
                w.write_octet_string(TAG_FLOAT, &content);
            }
            Data::Double(d) => {
                let mut content = Vec::with_capacity(9);
                content.push(11); // exponent width in bits for IEEE double
                content.extend_from_slice(&d.to_be_bytes());
                w.write_octet_string(TAG_FLOAT, &content);
            }
            Data::OctetString(b) => w.write_octet_string(TAG_OCTET_STRING, b),
            Data::VisibleString(s) => w.write_visible_string(TAG_VISIBLE_STRING, s),
            Data::BinaryTime(b) => w.write_octet_string(TAG_BINARY_TIME, b),
            Data::Utf8String(s) => w.write_octet_string(TAG_MMS_STRING, s.as_bytes()),
            Data::UtcTime(b) => w.write_octet_string(TAG_UTC_TIME, b),
            Data::Unknown {
                tag,
                constructed,
                bytes,
            } => {
                let t = Tag {
                    class: TagClass::ContextSpecific,
                    constructed: *constructed,
                    number: *tag,
                };
                w.write_primitive(t, bytes);
            }
        }
    }

    /// Decode one `Data` TLV from `r`, bounding recursion at [`MAX_DATA_DEPTH`].
    pub fn decode(r: &mut BerReader<'_>) -> Result<Self> {
        Self::decode_depth(r, 0)
    }

    /// Decode a `Data` value from a `(tag, content)` pair already read off the
    /// stream (used where the caller had to peek the tag, e.g. `AccessResult`).
    pub(crate) fn decode_tlv(tag: Tag, content: &[u8]) -> Result<Self> {
        Self::decode_from(tag, content, 0)
    }

    fn decode_depth(r: &mut BerReader<'_>, depth: usize) -> Result<Self> {
        if depth >= MAX_DATA_DEPTH {
            return Err(Error::MmsDataDepthExceeded {
                max: MAX_DATA_DEPTH,
            });
        }
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        Self::decode_from(tag, content, depth)
    }

    fn decode_from(tag: Tag, content: &[u8], depth: usize) -> Result<Self> {
        if tag == TAG_ARRAY || tag == TAG_STRUCTURE {
            let mut inner = BerReader::new(content);
            let mut elems = Vec::new();
            while !inner.done() {
                elems.push(Self::decode_depth(&mut inner, depth + 1)?);
            }
            return Ok(if tag == TAG_ARRAY {
                Data::Array(elems)
            } else {
                Data::Structure(elems)
            });
        }
        if tag == TAG_BOOLEAN {
            return Ok(Data::Boolean(
                decode_bool(content).map_err(|_| Error::MmsInvalidPdu)?,
            ));
        }
        if tag == TAG_BIT_STRING {
            return Ok(Data::BitString(
                decode_bit_string(content).map_err(|_| Error::MmsInvalidPdu)?,
            ));
        }
        if tag == TAG_INTEGER {
            return Ok(Data::Integer(
                decode_integer_i64(content).map_err(|_| Error::MmsInvalidPdu)?,
            ));
        }
        if tag == TAG_UNSIGNED {
            return Ok(Data::Unsigned(
                decode_unsigned_u64(content).map_err(|_| Error::MmsInvalidPdu)?,
            ));
        }
        if tag == TAG_FLOAT {
            return decode_float(content);
        }
        if tag == TAG_OCTET_STRING {
            return Ok(Data::OctetString(content.to_vec()));
        }
        if tag == TAG_VISIBLE_STRING {
            let s = decode_visible_string(content).map_err(|_| Error::MmsInvalidPdu)?;
            return Ok(Data::VisibleString(s.to_string()));
        }
        if tag == TAG_BINARY_TIME {
            return Ok(Data::BinaryTime(content.to_vec()));
        }
        if tag == TAG_MMS_STRING {
            let s = core::str::from_utf8(content).map_err(|_| Error::MmsInvalidPdu)?;
            return Ok(Data::Utf8String(s.to_string()));
        }
        if tag == TAG_UTC_TIME {
            let arr: [u8; 8] = content.try_into().map_err(|_| Error::MmsInvalidPdu)?;
            return Ok(Data::UtcTime(arr));
        }
        // Tolerant catch-all (bcd [13], objId [15], unknown alternatives).
        Ok(Data::Unknown {
            tag: tag.number,
            constructed: tag.constructed,
            bytes: content.to_vec(),
        })
    }
}

/// Decode a `FloatingPoint` OCTET STRING into [`Data::Float`] or
/// [`Data::Double`].
///
/// The first content octet is the exponent width; we key on the *total length*
/// (5 = single, 9 = double), which is unambiguous and matches every MMS peer.
fn decode_float(content: &[u8]) -> Result<Data> {
    match content.len() {
        5 => {
            // content[0] is the exponent width (8); content[1..5] is the f32.
            let bytes: [u8; 4] = content[1..5]
                .try_into()
                .map_err(|_| Error::MmsInvalidFloat { len: content.len() })?;
            Ok(Data::Float(f32::from_be_bytes(bytes)))
        }
        9 => {
            let bytes: [u8; 8] = content[1..9]
                .try_into()
                .map_err(|_| Error::MmsInvalidFloat { len: content.len() })?;
            Ok(Data::Double(f64::from_be_bytes(bytes)))
        }
        len => Err(Error::MmsInvalidFloat { len }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(d: &Data) -> Data {
        let mut w = BerWriter::new();
        d.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let out = Data::decode(&mut r).unwrap();
        assert!(r.done(), "trailing bytes after decoding {d:?}");
        out
    }

    #[test]
    fn scalar_variants_roundtrip() {
        let cases = vec![
            Data::Boolean(true),
            Data::Boolean(false),
            Data::BitString(BitString::from_bits(&[true, false, true])),
            Data::Integer(-42),
            Data::Integer(i64::MIN),
            Data::Unsigned(0),
            Data::Unsigned(u64::MAX),
            Data::OctetString(vec![0, 1, 2, 255]),
            Data::VisibleString("hello".to_string()),
            Data::BinaryTime(vec![1, 2, 3, 4]),
            Data::BinaryTime(vec![1, 2, 3, 4, 5, 6]),
            Data::Utf8String("héllo".to_string()),
            Data::UtcTime([1, 2, 3, 4, 5, 6, 7, 8]),
        ];
        for c in cases {
            assert_eq!(roundtrip(&c), c, "roundtrip {c:?}");
        }
    }

    #[test]
    fn float_f32_byte_layout() {
        let d = Data::Float(1.5f32);
        let mut w = BerWriter::new();
        d.encode(&mut w);
        let bytes = w.into_bytes();
        // [7] primitive (0x87), len 5, then 08 + IEEE754 1.5 = 3F C0 00 00.
        assert_eq!(bytes[0], 0x87);
        assert_eq!(bytes[1], 0x05);
        assert_eq!(bytes[2], 0x08, "exponent-width octet");
        assert_eq!(&bytes[3..7], &1.5f32.to_be_bytes());
        assert_eq!(roundtrip(&d), d);
    }

    #[test]
    fn float_f64_byte_layout() {
        let d = Data::Double(-2.0f64);
        let mut w = BerWriter::new();
        d.encode(&mut w);
        let bytes = w.into_bytes();
        assert_eq!(bytes[0], 0x87);
        assert_eq!(bytes[1], 0x09);
        assert_eq!(bytes[2], 11, "exponent-width octet");
        assert_eq!(&bytes[3..11], &(-2.0f64).to_be_bytes());
        assert_eq!(roundtrip(&d), d);
    }

    #[test]
    fn float_invalid_length() {
        // [7] with 3 content octets is not a valid FloatingPoint.
        let mut w = BerWriter::new();
        w.write_octet_string(TAG_FLOAT, &[8, 0, 0]);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        assert!(matches!(
            Data::decode(&mut r),
            Err(Error::MmsInvalidFloat { len: 3 })
        ));
    }

    #[test]
    fn nested_structure_and_array() {
        let d = Data::Structure(vec![
            Data::Integer(1),
            Data::Array(vec![Data::Boolean(true), Data::Boolean(false)]),
            Data::VisibleString("x".to_string()),
        ]);
        assert_eq!(roundtrip(&d), d);
    }

    #[test]
    fn unknown_passthrough_reencodes_identically() {
        // bcd [13] primitive with arbitrary content.
        let mut w = BerWriter::new();
        w.write_primitive(Tag::context(13), &[0x12, 0x34]);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let d = Data::decode(&mut r).unwrap();
        assert_eq!(
            d,
            Data::Unknown {
                tag: 13,
                constructed: false,
                bytes: vec![0x12, 0x34]
            }
        );
        let mut w2 = BerWriter::new();
        d.encode(&mut w2);
        assert_eq!(w2.into_bytes(), bytes);
    }

    #[test]
    fn depth_bomb_rejected() {
        // Build 33 nested array [1] TLVs ending in an integer.
        const N: usize = 33;
        let mut innermost = Data::Integer(7);
        for _ in 0..N {
            innermost = Data::Array(vec![innermost]);
        }
        let mut w = BerWriter::new();
        innermost.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        assert!(matches!(
            Data::decode(&mut r),
            Err(Error::MmsDataDepthExceeded {
                max: MAX_DATA_DEPTH
            })
        ));
    }

    #[test]
    fn depth_at_limit_ok() {
        // Exactly MAX_DATA_DEPTH-1 nested arrays around a scalar decode fine.
        let mut innermost = Data::Integer(7);
        for _ in 0..(MAX_DATA_DEPTH - 1) {
            innermost = Data::Array(vec![innermost]);
        }
        assert_eq!(roundtrip(&innermost), innermost);
    }
}
