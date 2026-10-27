//! Property-based tests for the MMS layer.
//!
//! Two invariants:
//! 1. `MmsPdu::decode` never panics on arbitrary input.
//! 2. A `Data` value built by a bounded recursive strategy survives an
//!    encode -> decode round-trip unchanged.

use proptest::prelude::*;

use crate::ber::reader::BerReader;
use crate::ber::writer::BerWriter;
use crate::mms::data::Data;
use crate::mms::pdu::MmsPdu;

/// A bounded recursive strategy for [`Data`]. Leaves are scalars; arrays and
/// structures recurse at most a few levels with small element counts.
fn data_strategy() -> impl Strategy<Value = Data> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(Data::Boolean),
        any::<i64>().prop_map(Data::Integer),
        any::<u64>().prop_map(Data::Unsigned),
        any::<f32>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Data::Float),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Data::Double),
        prop::collection::vec(any::<u8>(), 0..8).prop_map(Data::OctetString),
        "[ -~]{0,8}".prop_map(Data::VisibleString),
        any::<[u8; 8]>().prop_map(Data::UtcTime),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Data::Array),
            prop::collection::vec(inner, 0..4).prop_map(Data::Structure),
        ]
    })
}

proptest! {
    /// `MmsPdu::decode` never panics on arbitrary input.
    #[test]
    fn prop_mms_decode_no_panic(data: Vec<u8>) {
        let _ = MmsPdu::decode(&data);
    }

    /// Bounded recursive `Data` round-trips through encode -> decode.
    #[test]
    fn prop_data_roundtrip(d in data_strategy()) {
        let mut w = BerWriter::new();
        d.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let decoded = Data::decode(&mut r).expect("decode bounded Data");
        prop_assert!(r.done(), "trailing bytes");
        prop_assert_eq!(decoded, d);
    }

    /// A decoded PDU re-encodes to bytes that decode to the same PDU
    /// (round-trip stability — catches asymmetric codecs).
    #[test]
    fn prop_mms_reencode_stable(data: Vec<u8>) {
        if let Ok(pdu1) = MmsPdu::decode(&data) {
            let mut w = BerWriter::new();
            if pdu1.encode(&mut w).is_ok() {
                let bytes = w.into_bytes();
                let pdu2 = MmsPdu::decode(&bytes).expect("re-decode of self-encoded PDU");
                prop_assert_eq!(pdu1, pdu2);
            }
        }
    }
}
