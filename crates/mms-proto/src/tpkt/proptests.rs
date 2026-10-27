//! Proptest property-based tests for the TPKT layer.

use proptest::prelude::*;

use crate::tpkt::codec::Tpkt;
use crate::tpkt::TPKT_MAX_PAYLOAD;

proptest! {
    /// Feeding arbitrary bytes to `Tpkt::decode_slice` never panics.
    /// `Ok(None)` and `Err(_)` are both acceptable; panics are not.
    #[test]
    fn prop_no_panic_on_arbitrary_bytes(data: Vec<u8>) {
        let _ = Tpkt::decode_slice(&data);
    }

    /// `encode` → `decode_slice` is identity for payloads in the valid range
    /// (3..=TPKT_MAX_PAYLOAD bytes, so total_len ≥ 7).
    #[test]
    fn prop_encode_decode_identity(
        payload in proptest::collection::vec(any::<u8>(), 3..=TPKT_MAX_PAYLOAD),
    ) {
        let mut frame = Vec::new();
        Tpkt::encode(&payload, &mut frame).expect("encode");
        let (decoded, consumed) = Tpkt::decode_slice(&frame)
            .expect("decode ok")
            .expect("complete frame");
        prop_assert_eq!(consumed, frame.len());
        prop_assert_eq!(decoded, payload);
    }
}
