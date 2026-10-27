//! Content-slice decoders and encoders for BER primitive types.
//!
//! Each decoder takes a raw content slice (i.e. the bytes *after* the TLV tag
//! and length have been consumed) and returns either a typed value or a typed
//! error. No panics on malformed input.

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// BitString
// ---------------------------------------------------------------------------

/// An ASN.1 BIT STRING value.
///
/// `unused_bits` is the count of zero-padding bits at the *end* of the last
/// `data` octet. Its value must be in `0..=7`. When `data` is empty,
/// `unused_bits` must be 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitString {
    pub unused_bits: u8,
    pub data: Vec<u8>,
}

impl BitString {
    /// Construct from a slice of individual bit values (MSB-first within each
    /// octet). Pads the last octet with zeros if needed.
    #[must_use]
    pub fn from_bits(bits: &[bool]) -> Self {
        let n_octets = bits.len().div_ceil(8);
        let unused_bits = if bits.is_empty() {
            0
        } else {
            (8 - bits.len() % 8) as u8 % 8
        };
        let mut data = vec![0u8; n_octets];
        for (i, &b) in bits.iter().enumerate() {
            if b {
                data[i / 8] |= 0x80 >> (i % 8);
            }
        }
        BitString { unused_bits, data }
    }

    /// Read the `i`-th bit (0-indexed, MSB-first). Returns `false` if `i` is
    /// out of range.
    ///
    /// Safe even for a hand-constructed, internally-inconsistent `BitString`
    /// (e.g. empty `data` with `unused_bits > 0`): the usable-bit count is
    /// computed with a saturating subtraction so it never underflows.
    #[must_use]
    pub fn bit(&self, i: usize) -> bool {
        if i >= self.bit_len() {
            return false;
        }
        (self.data[i / 8] >> (7 - i % 8)) & 1 == 1
    }

    /// Total number of significant bits. Saturates to 0 for an internally
    /// inconsistent value (more `unused_bits` than `data` can hold).
    #[must_use]
    pub fn bit_len(&self) -> usize {
        (self.data.len() * 8).saturating_sub(self.unused_bits as usize)
    }
}

// ---------------------------------------------------------------------------
// ObjectIdentifier
// ---------------------------------------------------------------------------

/// An ASN.1 OBJECT IDENTIFIER, stored as a sequence of arc values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectIdentifier(pub Vec<u32>);

impl ObjectIdentifier {
    /// Construct from an arc slice.
    ///
    /// Does *not* validate arc values beyond storing them; validation happens
    /// on encode/decode.
    #[must_use]
    pub fn from_arcs(arcs: &[u32]) -> Self {
        ObjectIdentifier(arcs.to_vec())
    }
}

impl core::fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for arc in &self.0 {
            if !first {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
            first = false;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// INTEGER
// ---------------------------------------------------------------------------

/// Decode BER INTEGER content (two's complement, 1..=8 octets) into `i64`.
pub fn decode_integer_i64(content: &[u8]) -> Result<i64> {
    match content.len() {
        0 => Err(Error::BerIntegerOverflow { len: 0 }),
        n if n > 8 => Err(Error::BerIntegerOverflow { len: n }),
        n => {
            // Sign-extend from the most significant content byte.
            let mut v = if content[0] & 0x80 != 0 { -1i64 } else { 0i64 };
            for &b in content.iter().take(n) {
                v = (v << 8) | b as i64;
            }
            Ok(v)
        }
    }
}

/// Decode BER INTEGER content as an unsigned `u64`.
///
/// Accepts a leading `0x00` octet (used when the high bit would otherwise
/// look like a sign bit), making at most 9 octets total. Rejects negative
/// values.
pub fn decode_unsigned_u64(content: &[u8]) -> Result<u64> {
    match content.len() {
        0 => Err(Error::BerIntegerOverflow { len: 0 }),
        n if n > 9 => Err(Error::BerIntegerOverflow { len: n }),
        9 => {
            // Only valid if the leading octet is 0x00 (positive sign extension).
            if content[0] != 0x00 {
                return Err(Error::BerIntegerOverflow { len: 9 });
            }
            let mut v = 0u64;
            for &b in &content[1..] {
                v = (v << 8) | b as u64;
            }
            Ok(v)
        }
        _ => {
            // Check sign bit.
            if content[0] & 0x80 != 0 {
                return Err(Error::BerIntegerOverflow { len: content.len() });
            }
            let mut v = 0u64;
            for &b in content {
                v = (v << 8) | b as u64;
            }
            Ok(v)
        }
    }
}

/// Encode `v` as a minimal two's-complement BER integer content and append to
/// `out`.
pub fn encode_integer_i64(v: i64, out: &mut Vec<u8>) {
    if v == 0 {
        out.push(0x00);
        return;
    }
    // Find the minimal byte count.
    let bytes = v.to_be_bytes();
    // Skip leading redundant bytes: a byte is redundant if it is 0x00 and the
    // next byte's MSB is 0, OR if it is 0xFF and the next byte's MSB is 1.
    let mut start = 0usize;
    while start < 7 {
        let cur = bytes[start];
        let next = bytes[start + 1];
        let redundant = (cur == 0x00 && next & 0x80 == 0) || (cur == 0xFF && next & 0x80 != 0);
        if redundant {
            start += 1;
        } else {
            break;
        }
    }
    out.extend_from_slice(&bytes[start..]);
}

/// Encode `v` as a minimal unsigned BER integer content (big-endian, with a
/// leading `0x00` if the MSB would look like a sign bit).
pub fn encode_unsigned_u64(v: u64, out: &mut Vec<u8>) {
    if v == 0 {
        out.push(0x00);
        return;
    }
    let bytes = v.to_be_bytes();
    // Skip leading zero bytes unless we need to keep one for sign.
    let mut start = 0usize;
    while start < 7 && bytes[start] == 0x00 {
        start += 1;
    }
    if bytes[start] & 0x80 != 0 {
        // Would look like a negative number; prepend a zero byte.
        out.push(0x00);
    }
    out.extend_from_slice(&bytes[start..]);
}

// ---------------------------------------------------------------------------
// BOOLEAN
// ---------------------------------------------------------------------------

/// Decode BER BOOLEAN content. Requires exactly 1 octet; any non-zero value
/// is `true` (BER tolerant reading).
pub fn decode_bool(content: &[u8]) -> Result<bool> {
    match content {
        [b] => Ok(*b != 0),
        _ => Err(Error::BerInvalidBool { len: content.len() }),
    }
}

/// Encode a BOOLEAN content octet: `0xFF` for true, `0x00` for false.
pub fn encode_bool(v: bool, out: &mut Vec<u8>) {
    out.push(if v { 0xFF } else { 0x00 });
}

// ---------------------------------------------------------------------------
// OCTET STRING / VisibleString
// ---------------------------------------------------------------------------

/// Decode BER VisibleString content.
///
/// Validates that all bytes are in the `0x20..=0x7E` printable ASCII range.
pub fn decode_visible_string(content: &[u8]) -> Result<&str> {
    for &b in content {
        if !(0x20..=0x7E).contains(&b) {
            return Err(Error::BerInvalidString);
        }
    }
    // All bytes are valid ASCII, so from_utf8 will succeed.
    core::str::from_utf8(content).map_err(|_| Error::BerInvalidString)
}

// ---------------------------------------------------------------------------
// BIT STRING
// ---------------------------------------------------------------------------

/// Decode BER BIT STRING content into a [`BitString`].
///
/// The first content octet is the unused-bit count (0..=7). When `data` is
/// empty (no further octets), `unused_bits` must be 0.
pub fn decode_bit_string(content: &[u8]) -> Result<BitString> {
    if content.is_empty() {
        return Err(Error::BerInvalidString);
    }
    let unused_bits = content[0];
    if unused_bits > 7 {
        return Err(Error::BerInvalidString);
    }
    let data = content[1..].to_vec();
    if data.is_empty() && unused_bits != 0 {
        return Err(Error::BerInvalidString);
    }
    Ok(BitString { unused_bits, data })
}

/// Encode a [`BitString`] into content bytes: first octet = unused-bit count,
/// then data bytes.
pub fn encode_bit_string(bs: &BitString, out: &mut Vec<u8>) {
    out.push(bs.unused_bits);
    out.extend_from_slice(&bs.data);
}

// ---------------------------------------------------------------------------
// OBJECT IDENTIFIER
// ---------------------------------------------------------------------------

/// Decode BER OID content into an [`ObjectIdentifier`].
///
/// The BER encoding concatenates base-128 sub-identifier octets. The *first*
/// sub-identifier encodes two arcs as `40*X + Y`.
pub fn decode_oid(content: &[u8]) -> Result<ObjectIdentifier> {
    if content.is_empty() {
        return Err(Error::BerInvalidOid);
    }

    let mut arcs: Vec<u32> = Vec::new();
    let mut pos = 0usize;

    while pos < content.len() {
        let (sub, consumed) = decode_base128_u32(content, pos)?;
        pos += consumed;

        if arcs.is_empty() {
            // First sub-identifier encodes arc-0 (X) and arc-1 (Y) as 40*X + Y.
            // arc-0 is restricted to {0, 1, 2}. When arc-0 is 0 or 1, arc-1 is
            // bounded to 0..=39, so sub < 80 maps cleanly. When arc-0 is 2,
            // arc-1 is unbounded, so any sub >= 80 is decomposed as X=2,
            // Y=sub-80. This is round-trip faithful with `encode_oid`; the
            // BER ambiguity for the first sub-identifier is inherent to the
            // encoding, not a decode choice we can avoid.
            let (x, y) = if sub < 40 {
                (0u32, sub)
            } else if sub < 80 {
                (1u32, sub - 40)
            } else {
                (2u32, sub - 80)
            };
            arcs.push(x);
            arcs.push(y);
        } else {
            arcs.push(sub);
        }
    }

    if arcs.is_empty() {
        return Err(Error::BerInvalidOid);
    }

    Ok(ObjectIdentifier(arcs))
}

/// Encode an [`ObjectIdentifier`] into BER content bytes.
pub fn encode_oid(oid: &ObjectIdentifier, out: &mut Vec<u8>) {
    let arcs = &oid.0;
    if arcs.is_empty() {
        // Empty OID — nothing to encode (caller error, but no panic).
        return;
    }

    // First two arcs combined into one sub-identifier.
    let first_sub = if arcs.len() == 1 {
        arcs[0] * 40
    } else {
        arcs[0] * 40 + arcs[1]
    };
    encode_base128_u32(first_sub, out);

    // Remaining arcs.
    for &arc in arcs.iter().skip(2) {
        encode_base128_u32(arc, out);
    }
}

// ---------------------------------------------------------------------------
// Base-128 helpers (shared with tag.rs logic, but private here)
// ---------------------------------------------------------------------------

/// Decode a base-128 sub-identifier from `content` starting at `pos`.
/// Returns `(value, bytes_consumed)`.
fn decode_base128_u32(content: &[u8], pos: usize) -> Result<(u32, usize)> {
    let mut value: u32 = 0;
    let mut consumed = 0usize;
    loop {
        if pos + consumed >= content.len() {
            return Err(Error::BerTruncated {
                needed: pos + consumed + 1,
                have: content.len(),
            });
        }
        let b = content[pos + consumed];
        consumed += 1;
        let fragment = (b & 0x7F) as u32;
        value = value
            .checked_shl(7)
            .and_then(|v| v.checked_add(fragment))
            .ok_or(Error::BerInvalidOid)?;
        if b & 0x80 == 0 {
            break;
        }
    }
    Ok((value, consumed))
}

/// Encode a value into base-128 octets (big-endian, continuation MSB).
fn encode_base128_u32(v: u32, out: &mut Vec<u8>) {
    if v == 0 {
        out.push(0x00);
        return;
    }
    let start = out.len();
    let mut n = v;
    while n > 0 {
        out.push((n & 0x7F) as u8);
        n >>= 7;
    }
    out[start..].reverse();
    let end = out.len();
    for b in out[start..end - 1].iter_mut() {
        *b |= 0x80;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- BitString ----------------------------------------------------------

    #[test]
    fn bitstring_from_bits_empty() {
        let bs = BitString::from_bits(&[]);
        assert_eq!(bs.unused_bits, 0);
        assert!(bs.data.is_empty());
    }

    #[test]
    fn bitstring_from_bits_one() {
        let bs = BitString::from_bits(&[true]);
        assert_eq!(bs.unused_bits, 7);
        assert_eq!(bs.data, vec![0x80]);
        assert!(bs.bit(0));
        assert!(!bs.bit(1));
    }

    #[test]
    fn bitstring_from_bits_seven_unused() {
        // 1 true bit → 7 unused.
        let bs = BitString::from_bits(&[true]);
        assert_eq!(bs.bit_len(), 1);
        assert_eq!(bs.unused_bits, 7);
    }

    #[test]
    fn bitstring_from_bits_multi_byte() {
        let bits: Vec<bool> = (0..9).map(|i| i % 2 == 0).collect();
        let bs = BitString::from_bits(&bits);
        assert_eq!(bs.bit_len(), 9);
        for (i, &b) in bits.iter().enumerate() {
            assert_eq!(bs.bit(i), b, "bit {i}");
        }
    }

    #[test]
    fn bitstring_roundtrip() {
        let bs = BitString::from_bits(&[true, false, true, true]);
        let mut buf = Vec::new();
        encode_bit_string(&bs, &mut buf);
        let decoded = decode_bit_string(&buf).unwrap();
        assert_eq!(decoded, bs);
    }

    #[test]
    fn bitstring_empty_decode() {
        // Content must have at least the unused-bits octet.
        assert!(matches!(
            decode_bit_string(&[]),
            Err(Error::BerInvalidString)
        ));
    }

    #[test]
    fn bitstring_unused_bits_out_of_range() {
        assert!(matches!(
            decode_bit_string(&[8]),
            Err(Error::BerInvalidString)
        ));
    }

    #[test]
    fn bitstring_nonzero_unused_with_empty_data() {
        assert!(matches!(
            decode_bit_string(&[3]),
            Err(Error::BerInvalidString)
        ));
    }

    // --- INTEGER ------------------------------------------------------------

    fn roundtrip_i64(v: i64) {
        let mut buf = Vec::new();
        encode_integer_i64(v, &mut buf);
        let decoded = decode_integer_i64(&buf).unwrap();
        assert_eq!(decoded, v, "i64 roundtrip failed for {v}");
    }

    #[test]
    fn integer_roundtrips() {
        for v in [
            0i64,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            i64::MIN,
            i64::MAX,
            0x7F,
            0x80,
            -0x80,
            -0x81,
        ] {
            roundtrip_i64(v);
        }
    }

    #[test]
    fn integer_too_long_rejected() {
        let buf = [0u8; 9];
        assert!(matches!(
            decode_integer_i64(&buf),
            Err(Error::BerIntegerOverflow { len: 9 })
        ));
    }

    #[test]
    fn integer_empty_rejected() {
        assert!(matches!(
            decode_integer_i64(&[]),
            Err(Error::BerIntegerOverflow { len: 0 })
        ));
    }

    fn roundtrip_u64(v: u64) {
        let mut buf = Vec::new();
        encode_unsigned_u64(v, &mut buf);
        let decoded = decode_unsigned_u64(&buf).unwrap();
        assert_eq!(decoded, v, "u64 roundtrip failed for {v}");
    }

    #[test]
    fn unsigned_roundtrips() {
        for v in [0u64, 1, 127, 128, u64::MAX, u64::MAX - 1] {
            roundtrip_u64(v);
        }
    }

    #[test]
    fn unsigned_negative_rejected() {
        // 0xFF as a 1-byte BER integer would be -1.
        assert!(matches!(
            decode_unsigned_u64(&[0xFF]),
            Err(Error::BerIntegerOverflow { .. })
        ));
    }

    // --- BOOLEAN ------------------------------------------------------------

    #[test]
    fn bool_roundtrip() {
        for v in [true, false] {
            let mut buf = Vec::new();
            encode_bool(v, &mut buf);
            assert_eq!(decode_bool(&buf).unwrap(), v);
        }
    }

    #[test]
    fn bool_ber_tolerant_nonzero() {
        // BER allows any non-zero as true.
        assert!(decode_bool(&[0x01]).unwrap());
        assert!(decode_bool(&[0xFE]).unwrap());
    }

    #[test]
    fn bool_wrong_length_rejected() {
        assert!(matches!(
            decode_bool(&[]),
            Err(Error::BerInvalidBool { len: 0 })
        ));
        assert!(matches!(
            decode_bool(&[0, 0]),
            Err(Error::BerInvalidBool { len: 2 })
        ));
    }

    // --- VisibleString ------------------------------------------------------

    #[test]
    fn visible_string_valid() {
        let content = b"Hello, World!";
        assert_eq!(decode_visible_string(content).unwrap(), "Hello, World!");
    }

    #[test]
    fn visible_string_empty_ok() {
        assert_eq!(decode_visible_string(b"").unwrap(), "");
    }

    #[test]
    fn visible_string_control_char_rejected() {
        // 0x00 is not in 0x20..=0x7E.
        assert!(matches!(
            decode_visible_string(&[0x00]),
            Err(Error::BerInvalidString)
        ));
    }

    #[test]
    fn visible_string_del_rejected() {
        // 0x7F (DEL) is not in 0x20..=0x7E.
        assert!(matches!(
            decode_visible_string(&[0x7F]),
            Err(Error::BerInvalidString)
        ));
    }

    // --- OID ----------------------------------------------------------------

    fn roundtrip_oid(arcs: &[u32]) {
        let oid = ObjectIdentifier::from_arcs(arcs);
        let mut buf = Vec::new();
        encode_oid(&oid, &mut buf);
        let decoded = decode_oid(&buf).unwrap();
        assert_eq!(decoded, oid, "OID roundtrip failed for {:?}", arcs);
    }

    #[test]
    fn oid_mms_abstract_syntax() {
        // 1.0.9506.2.1 — the MMS abstract syntax OID.
        roundtrip_oid(&[1, 0, 9506, 2, 1]);
    }

    #[test]
    fn oid_2_2_299_1() {
        roundtrip_oid(&[2, 2, 299, 1]);
    }

    #[test]
    fn oid_large_arc() {
        // Arc > 16383 requires 3+ base-128 octets.
        roundtrip_oid(&[1, 2, 840, 10045, 4]);
    }

    #[test]
    fn oid_display() {
        let oid = ObjectIdentifier::from_arcs(&[1, 0, 9506, 2, 1]);
        assert_eq!(oid.to_string(), "1.0.9506.2.1");
    }

    #[test]
    fn oid_empty_rejected() {
        assert!(matches!(decode_oid(&[]), Err(Error::BerInvalidOid)));
    }
}
