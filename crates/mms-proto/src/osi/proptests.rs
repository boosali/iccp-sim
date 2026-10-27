//! Property-based tests for the OSI upper layers.
//!
//! The central invariant: feeding arbitrary bytes to any decoder never panics
//! (it returns `Ok` or a typed `Err`). We also chain decoders the way the fuzz
//! target does, so a malformed inner payload extracted from a well-formed outer
//! frame is exercised too.

use proptest::prelude::*;

use crate::osi::acse::Acse;
use crate::osi::presentation::Presentation;
use crate::osi::session::{Session, SessionPdu};

proptest! {
    /// `Session::decode` never panics on arbitrary input.
    #[test]
    fn prop_session_decode_no_panic(data: Vec<u8>) {
        let _ = Session::decode(&data);
    }

    /// `Presentation` decoders never panic on arbitrary input.
    #[test]
    fn prop_presentation_decode_no_panic(data: Vec<u8>) {
        let _ = Presentation::decode_cp(&data);
        let _ = Presentation::decode_cpa(&data);
        let _ = Presentation::decode_data(&data);
    }

    /// `Acse::decode` never panics on arbitrary input.
    #[test]
    fn prop_acse_decode_no_panic(data: Vec<u8>) {
        let _ = Acse::decode(&data);
    }

    /// The full decode chain (session -> presentation -> acse) never panics:
    /// whatever the session yields is fed onward exactly as the fuzz target
    /// does.
    #[test]
    fn prop_decode_chain_no_panic(data: Vec<u8>) {
        if let Ok(pdu) = Session::decode(&data) {
            match pdu {
                SessionPdu::Connect(c) | SessionPdu::Accept(c) => {
                    if let Ok((_ctx, acse)) = Presentation::decode_cp(&c.user_data) {
                        let _ = Acse::decode(&acse);
                    }
                    if let Ok(cpa) = Presentation::decode_cpa(&c.user_data) {
                        let _ = Acse::decode(&cpa.acse_payload);
                    }
                }
                SessionPdu::Data(payload) => {
                    if let Ok((_pci, acse)) = Presentation::decode_data(&payload) {
                        let _ = Acse::decode(&acse);
                    }
                }
                _ => {}
            }
        }
    }
}
