//! Proptest property-based tests for the BER layer.
//!
//! These live in a separate file because proptest macros expand to a fair
//! amount of generated code and we want the main source files to stay readable.

use proptest::prelude::*;

use super::length::{decode_length, encode_length, LengthForm};
use super::primitives::{
    decode_integer_i64, decode_unsigned_u64, encode_integer_i64, encode_unsigned_u64,
};
use super::reader::BerReader;
use super::tag::{Tag, TagClass};

// ---------------------------------------------------------------------------
// Length round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// `encode_length` followed by `decode_length` returns the original value
    /// for any length in 0..=u32::MAX.
    #[test]
    fn prop_length_roundtrip(len in 0u32..=u32::MAX) {
        let len = len as usize;
        let mut buf = Vec::new();
        encode_length(len, &mut buf);
        let result = decode_length(&buf).expect("decode ok").expect("non-empty");
        prop_assert_eq!(result.0, LengthForm::Definite(len));
        prop_assert_eq!(result.1, buf.len());
    }
}

// ---------------------------------------------------------------------------
// Integer round-trip
// ---------------------------------------------------------------------------

proptest! {
    /// `encode_integer_i64` → `decode_integer_i64` is identity over all i64.
    #[test]
    fn prop_integer_i64_roundtrip(v: i64) {
        let mut buf = Vec::new();
        encode_integer_i64(v, &mut buf);
        let decoded = decode_integer_i64(&buf).expect("decode ok");
        prop_assert_eq!(decoded, v);
    }

    /// `encode_unsigned_u64` → `decode_unsigned_u64` is identity over all u64.
    #[test]
    fn prop_unsigned_u64_roundtrip(v: u64) {
        let mut buf = Vec::new();
        encode_unsigned_u64(v, &mut buf);
        let decoded = decode_unsigned_u64(&buf).expect("decode ok");
        prop_assert_eq!(decoded, v);
    }
}

// ---------------------------------------------------------------------------
// Tag round-trip
// ---------------------------------------------------------------------------

fn arb_tag_class() -> impl Strategy<Value = TagClass> {
    prop_oneof![
        Just(TagClass::Universal),
        Just(TagClass::Application),
        Just(TagClass::ContextSpecific),
        Just(TagClass::Private),
    ]
}

proptest! {
    /// Tag encode/decode is identity over arbitrary (class, constructed, number).
    #[test]
    fn prop_tag_roundtrip(
        class in arb_tag_class(),
        constructed: bool,
        number: u32,
    ) {
        let tag = Tag { class, constructed, number };
        let mut buf = Vec::new();
        tag.encode(&mut buf);
        let (decoded, consumed) = Tag::decode(&buf).expect("decode ok");
        prop_assert_eq!(decoded, tag);
        prop_assert_eq!(consumed, buf.len());
    }
}

// ---------------------------------------------------------------------------
// Fuzzing-style: arbitrary bytes never panic
// ---------------------------------------------------------------------------

proptest! {
    /// Feeding arbitrary bytes to a recursive `read_tlv` walk never panics and
    /// always terminates. We only assert absence of panics — errors are fine.
    #[test]
    fn prop_no_panic_on_arbitrary_bytes(data: Vec<u8>) {
        walk_no_panic(&data, 0);
    }
}

fn walk_no_panic(buf: &[u8], depth: usize) {
    if depth > 8 {
        return;
    }
    let mut r = BerReader::new(buf);
    loop {
        match r.read_tlv() {
            Err(_) => break,
            Ok((tag, content)) => {
                if tag.constructed {
                    walk_no_panic(content, depth + 1);
                }
            }
        }
    }
}
