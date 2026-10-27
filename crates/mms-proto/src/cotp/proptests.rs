//! Proptest property-based tests for the COTP layer.

use proptest::prelude::*;

use crate::cotp::codec::CotpCodec;
use crate::cotp::params::{CotpParams, TpduSize};
use crate::cotp::pdu::{ConnectionPdu, CotpPdu};
use crate::cotp::reassembly::CotpReassembler;

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn arb_tpdu_size() -> impl Strategy<Value = TpduSize> {
    (TpduSize::MIN_EXPONENT..=TpduSize::MAX_EXPONENT).prop_map(|e| TpduSize::new(e).unwrap())
}

fn arb_tsap() -> impl Strategy<Value = Option<Vec<u8>>> {
    prop_oneof![
        Just(None),
        proptest::collection::vec(any::<u8>(), 0..=32).prop_map(Some),
    ]
}

fn arb_params() -> impl Strategy<Value = CotpParams> {
    (
        prop_oneof![Just(None), arb_tpdu_size().prop_map(Some)],
        arb_tsap(),
        arb_tsap(),
    )
        .prop_map(|(tpdu_size, src_tsap, dst_tsap)| CotpParams {
            tpdu_size,
            src_tsap,
            dst_tsap,
        })
}

fn arb_connection_pdu() -> impl Strategy<Value = ConnectionPdu> {
    (any::<u16>(), any::<u16>(), arb_params()).prop_map(|(dst, src, params)| ConnectionPdu {
        dst_ref: dst,
        src_ref: src,
        class: 0x00,
        params,
    })
}

fn arb_cotp_pdu() -> impl Strategy<Value = CotpPdu> {
    prop_oneof![
        arb_connection_pdu().prop_map(CotpPdu::ConnectionRequest),
        arb_connection_pdu().prop_map(CotpPdu::ConnectionConfirm),
        (any::<u16>(), any::<u16>(), any::<u8>()).prop_map(|(dst, src, reason)| {
            CotpPdu::DisconnectRequest {
                dst_ref: dst,
                src_ref: src,
                reason,
            }
        }),
        (
            any::<bool>(),
            proptest::collection::vec(any::<u8>(), 0..1024)
        )
            .prop_map(|(eot, payload)| CotpPdu::Data { eot, payload }),
        (any::<u16>(), any::<u8>()).prop_map(|(dst, cause)| CotpPdu::ErrorTpdu {
            dst_ref: dst,
            reject_cause: cause,
        }),
    ]
}

// ---------------------------------------------------------------------------
// No-panic on arbitrary bytes
// ---------------------------------------------------------------------------

proptest! {
    /// Feeding arbitrary bytes to `CotpCodec::decode` never panics.
    /// Errors are fine; panics are not.
    #[test]
    fn prop_no_panic_on_arbitrary_bytes(data: Vec<u8>) {
        let _ = CotpCodec::decode(&data);
    }
}

// ---------------------------------------------------------------------------
// Round-trip identity
// ---------------------------------------------------------------------------

proptest! {
    /// `encode` → `decode` is identity for arbitrary valid `CotpPdu` values.
    #[test]
    fn prop_cotp_pdu_roundtrip(pdu in arb_cotp_pdu()) {
        let mut buf = Vec::new();
        CotpCodec::encode(&pdu, &mut buf).expect("encode round-trip");
        let decoded = CotpCodec::decode(&buf).expect("decode round-trip");
        prop_assert_eq!(decoded, pdu);
    }
}

// ---------------------------------------------------------------------------
// Fragmentation / reassembly identity
// ---------------------------------------------------------------------------

proptest! {
    /// Fragmenting an arbitrary payload at every valid `TpduSize` and
    /// reassembling through `CotpReassembler` reproduces the original payload.
    #[test]
    fn prop_fragment_reassemble_identity(
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        tpdu_size in arb_tpdu_size(),
    ) {
        let frags = CotpCodec::encode_data(&payload, tpdu_size);
        prop_assert!(!frags.is_empty());

        let mut reassembler = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
        let mut result: Option<Vec<u8>> = None;

        for frag in &frags {
            let pdu = CotpCodec::decode(frag).expect("decode fragment");
            match pdu {
                CotpPdu::Data { eot, payload: p } => {
                    result = reassembler.push(&p, eot).expect("reassemble");
                }
                _ => panic!("expected Data TPDU"),
            }
        }

        prop_assert_eq!(result, Some(payload));
    }
}
