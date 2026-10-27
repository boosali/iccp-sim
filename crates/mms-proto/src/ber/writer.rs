//! BER encoder. Produces definite-length encodings only; never emits
//! indefinite lengths.
//!
//! # `write_tlv` implementation note
//! The closure writes content directly into the *same* `Vec<u8>` (it is handed
//! `&mut self`), so there is no per-level scratch allocation and no per-level
//! copy. After the closure returns the encoded length is spliced in between the
//! tag octets and the content with a single `Vec::splice`, giving overall
//! `O(total size)` work regardless of nesting depth.

use super::length::encode_length;
use super::primitives::{
    encode_bit_string, encode_bool, encode_integer_i64, encode_oid, encode_unsigned_u64, BitString,
    ObjectIdentifier,
};
use super::tag::Tag;

/// BER encoder that appends encoded TLVs to an internal `Vec<u8>`.
#[derive(Debug, Default)]
pub struct BerWriter {
    buf: Vec<u8>,
}

impl BerWriter {
    /// Create an empty writer.
    pub fn new() -> Self {
        BerWriter { buf: Vec::new() }
    }

    // --- Core encoding ------------------------------------------------------

    /// Encode a TLV whose content is produced by `f`.
    ///
    /// Writes the tag, runs `f` to append the content directly into this
    /// writer's buffer, then splices the encoded length in front of that
    /// content. No scratch buffer is allocated per nesting level, so nesting
    /// `f` calls cost `O(total size)` overall rather than quadratic.
    pub fn write_tlv(&mut self, tag: Tag, f: impl FnOnce(&mut BerWriter)) {
        // Write the tag, then record where the content begins.
        tag.encode(&mut self.buf);
        let content_start = self.buf.len();

        // Append the content in place.
        f(self);
        let content_len = self.buf.len() - content_start;

        // Encode the length into a tiny scratch buffer (at most 5 bytes) and
        // splice it in front of the content with a single shift.
        let mut length_bytes = Vec::new();
        encode_length(content_len, &mut length_bytes);
        self.buf.splice(content_start..content_start, length_bytes);
    }

    /// Append raw bytes directly to the output buffer (no tag/length wrapper).
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Encode a TLV with the given tag and literal content bytes.
    pub fn write_primitive(&mut self, tag: Tag, content: &[u8]) {
        tag.encode(&mut self.buf);
        encode_length(content.len(), &mut self.buf);
        self.buf.extend_from_slice(content);
    }

    // --- Typed helpers ------------------------------------------------------

    /// Encode a signed 64-bit integer using minimal two's-complement octets.
    pub fn write_integer(&mut self, tag: Tag, v: i64) {
        let mut content = Vec::with_capacity(8);
        encode_integer_i64(v, &mut content);
        self.write_primitive(tag, &content);
    }

    /// Encode an unsigned 64-bit integer, prepending a zero byte if the high
    /// bit would be set.
    pub fn write_unsigned(&mut self, tag: Tag, v: u64) {
        let mut content = Vec::with_capacity(9);
        encode_unsigned_u64(v, &mut content);
        self.write_primitive(tag, &content);
    }

    /// Encode a BOOLEAN: `0xFF` for `true`, `0x00` for `false`.
    pub fn write_bool(&mut self, tag: Tag, v: bool) {
        let mut content = Vec::with_capacity(1);
        encode_bool(v, &mut content);
        self.write_primitive(tag, &content);
    }

    /// Encode an OCTET STRING with the given raw bytes.
    pub fn write_octet_string(&mut self, tag: Tag, bytes: &[u8]) {
        self.write_primitive(tag, bytes);
    }

    /// Encode a VisibleString from a `&str`.
    pub fn write_visible_string(&mut self, tag: Tag, s: &str) {
        self.write_primitive(tag, s.as_bytes());
    }

    /// Encode a BIT STRING.
    pub fn write_bit_string(&mut self, tag: Tag, bits: &BitString) {
        let mut content = Vec::new();
        encode_bit_string(bits, &mut content);
        self.write_primitive(tag, &content);
    }

    /// Encode an OBJECT IDENTIFIER.
    pub fn write_oid(&mut self, tag: Tag, oid: &ObjectIdentifier) {
        let mut content = Vec::new();
        encode_oid(oid, &mut content);
        self.write_primitive(tag, &content);
    }

    /// Encode a NULL (zero-length content).
    pub fn write_null(&mut self, tag: Tag) {
        self.write_primitive(tag, &[]);
    }

    // --- Inspection ---------------------------------------------------------

    /// Returns `true` if the buffer holds zero bytes (not zero TLVs).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Number of *bytes* written so far (the encoded length of the buffer, not
    /// a count of TLVs).
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Consume the writer and return the encoded bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::primitives::{
        decode_bool, decode_integer_i64, decode_oid, decode_unsigned_u64, decode_visible_string,
    };
    use crate::ber::reader::BerReader;

    #[test]
    fn write_read_bool() {
        for v in [true, false] {
            let mut w = BerWriter::new();
            w.write_bool(Tag::BOOLEAN, v);
            let bytes = w.into_bytes();
            let mut r = BerReader::new(&bytes);
            let content = r.read_expected(Tag::BOOLEAN).unwrap();
            assert_eq!(decode_bool(content).unwrap(), v);
            r.expect_done().unwrap();
        }
    }

    #[test]
    fn write_read_integer() {
        for v in [0i64, -1, 127, 128, -128, i64::MIN, i64::MAX] {
            let mut w = BerWriter::new();
            w.write_integer(Tag::INTEGER, v);
            let bytes = w.into_bytes();
            let mut r = BerReader::new(&bytes);
            let content = r.read_expected(Tag::INTEGER).unwrap();
            assert_eq!(decode_integer_i64(content).unwrap(), v, "v={v}");
        }
    }

    #[test]
    fn write_read_unsigned() {
        for v in [0u64, 1, 127, 128, u64::MAX] {
            let mut w = BerWriter::new();
            w.write_unsigned(Tag::INTEGER, v);
            let bytes = w.into_bytes();
            let mut r = BerReader::new(&bytes);
            let content = r.read_expected(Tag::INTEGER).unwrap();
            assert_eq!(decode_unsigned_u64(content).unwrap(), v, "v={v}");
        }
    }

    #[test]
    fn write_read_octet_string() {
        let data = b"test data";
        let mut w = BerWriter::new();
        w.write_octet_string(Tag::OCTET_STRING, data);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let content = r.read_expected(Tag::OCTET_STRING).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn write_read_visible_string() {
        let s = "hello world";
        let mut w = BerWriter::new();
        w.write_visible_string(Tag::VISIBLE_STRING, s);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let content = r.read_expected(Tag::VISIBLE_STRING).unwrap();
        assert_eq!(decode_visible_string(content).unwrap(), s);
    }

    #[test]
    fn write_read_oid() {
        let oid = ObjectIdentifier::from_arcs(&[1, 0, 9506, 2, 1]);
        let mut w = BerWriter::new();
        w.write_oid(Tag::OID, &oid);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let content = r.read_expected(Tag::OID).unwrap();
        assert_eq!(decode_oid(content).unwrap(), oid);
    }

    #[test]
    fn write_tlv_nested() {
        // SEQUENCE { INTEGER 42 }
        let mut w = BerWriter::new();
        w.write_tlv(Tag::SEQUENCE, |inner| {
            inner.write_integer(Tag::INTEGER, 42);
        });
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let (tag, content) = r.read_tlv().unwrap();
        assert_eq!(tag, Tag::SEQUENCE);
        r.expect_done().unwrap();

        let mut ir = BerReader::new(content);
        let (itag, icontent) = ir.read_tlv().unwrap();
        assert_eq!(itag, Tag::INTEGER);
        assert_eq!(decode_integer_i64(icontent).unwrap(), 42);
        ir.expect_done().unwrap();
    }

    #[test]
    fn write_null() {
        let mut w = BerWriter::new();
        w.write_null(Tag::NULL);
        let bytes = w.into_bytes();
        assert_eq!(bytes, &[0x05, 0x00]);
    }

    #[test]
    fn write_tlv_deeply_nested_matches_manual() {
        // Build SEQUENCE { SEQUENCE { ... { INTEGER 7 } ... } } 50 levels deep
        // via write_tlv, then assert it equals an independently-built encoding.
        const LEVELS: usize = 50;

        fn build(w: &mut BerWriter, depth: usize) {
            if depth == 0 {
                w.write_integer(Tag::INTEGER, 7);
            } else {
                w.write_tlv(Tag::SEQUENCE, |inner| build(inner, depth - 1));
            }
        }

        let mut w = BerWriter::new();
        build(&mut w, LEVELS);
        let got = w.into_bytes();

        // Independent reference: innermost is INTEGER 7 (02 01 07), then wrap
        // each level in a SEQUENCE (0x30) with a definite length. All lengths
        // here are < 128, so each wrap adds exactly 2 header bytes.
        let mut expected = vec![0x02, 0x01, 0x07];
        for _ in 0..LEVELS {
            let len = expected.len();
            assert!(len < 128, "test assumes short-form lengths");
            let mut next = Vec::with_capacity(len + 2);
            next.push(0x30);
            next.push(len as u8);
            next.extend_from_slice(&expected);
            expected = next;
        }
        assert_eq!(got, expected);

        // And it must round-trip: descend all 50 levels and read INTEGER 7.
        let mut slice: &[u8] = &got;
        for _ in 0..LEVELS {
            let mut r = BerReader::new(slice);
            let (tag, content) = r.read_tlv().unwrap();
            assert_eq!(tag, Tag::SEQUENCE);
            r.expect_done().unwrap();
            slice = content;
        }
        let mut r = BerReader::new(slice);
        let content = r.read_expected(Tag::INTEGER).unwrap();
        assert_eq!(decode_integer_i64(content).unwrap(), 7);
    }

    #[test]
    fn long_form_length() {
        // A 128-byte payload should produce a 2-byte long-form length.
        let data = vec![0xABu8; 128];
        let mut w = BerWriter::new();
        w.write_octet_string(Tag::OCTET_STRING, &data);
        let bytes = w.into_bytes();
        // Tag: 0x04, Length: 0x81 0x80, Content: 128 bytes.
        assert_eq!(bytes[0], 0x04);
        assert_eq!(bytes[1], 0x81);
        assert_eq!(bytes[2], 0x80);
        assert_eq!(&bytes[3..], data.as_slice());
    }
}
