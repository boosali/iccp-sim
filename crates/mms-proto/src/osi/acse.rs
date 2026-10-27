//! ISO 8650 ACSE layer (BER).
//!
//! ACSE carries the application-association control PDUs of the MMS profile.
//! Unlike Session and Presentation, ACSE's fields genuinely vary, so this is a
//! real (small) BER codec.
//!
//! # PDUs
//!
//! | PDU  | Tag (`[APPLICATION n]`) | Direction        |
//! |------|-------------------------|------------------|
//! | AARQ | `[0]` = `0x60`          | associate request|
//! | AARE | `[1]` = `0x61`          | associate response|
//! | RLRQ | `[2]` = `0x62`          | release request  |
//! | RLRE | `[3]` = `0x63`          | release response |
//! | ABRT | `[4]` = `0x64`          | abort            |
//!
//! # user-information `[30]` (IMPLICIT) encoding
//!
//! The MMS InitiatePDU (or any data-phase APDU) is wrapped as:
//!
//! ```text
//! [30] IMPLICIT (0xbe) {
//!   EXTERNAL (0x28) {
//!     indirect-reference  INTEGER  -- the MMS presentation-context id (3)
//!     single-ASN1-type [0] (0xa0)  -- the carried APDU bytes
//!   }
//! }
//! ```
//!
//! libIEC61850 emits only the `indirect-reference` (not a `direct-reference`
//! OID); on decode we accept an EXTERNAL with or without the direct-reference.

use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, TagClass};
use crate::ber::writer::BerWriter;
use crate::ber::{decode_integer_i64, decode_oid, ObjectIdentifier};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Tags and constants (const tables)
// ---------------------------------------------------------------------------

/// AARQ outer tag `[APPLICATION 0]` (constructed) = `0x60`.
const TAG_AARQ: Tag = Tag::application_constructed(0);
/// AARE outer tag `[APPLICATION 1]` (constructed) = `0x61`.
const TAG_AARE: Tag = Tag::application_constructed(1);
/// RLRQ outer tag `[APPLICATION 2]` (constructed) = `0x62`.
const TAG_RLRQ: Tag = Tag::application_constructed(2);
/// RLRE outer tag `[APPLICATION 3]` (constructed) = `0x63`.
const TAG_RLRE: Tag = Tag::application_constructed(3);
/// ABRT outer tag `[APPLICATION 4]` (constructed) = `0x64`.
const TAG_ABRT: Tag = Tag::application_constructed(4);

/// application-context-name `[1]` (constructed, EXPLICIT) = `0xa1`.
const TAG_APP_CONTEXT: Tag = Tag::context_constructed(1);
/// called-AP-title `[2]` (constructed) = `0xa2`.
const TAG_CALLED_AP_TITLE: Tag = Tag::context_constructed(2);
/// called-AE-qualifier `[3]` (constructed) = `0xa3`.
const TAG_CALLED_AE_QUAL: Tag = Tag::context_constructed(3);
/// calling-AP-title `[6]` (constructed) = `0xa6`.
const TAG_CALLING_AP_TITLE: Tag = Tag::context_constructed(6);
/// calling-AE-qualifier `[7]` (constructed) = `0xa7`.
const TAG_CALLING_AE_QUAL: Tag = Tag::context_constructed(7);
/// AARE result `[2]` (constructed) = `0xa2`.
const TAG_RESULT: Tag = Tag::context_constructed(2);
/// AARE result-source-diagnostic `[3]` (constructed) = `0xa3`.
const TAG_RESULT_DIAGNOSTIC: Tag = Tag::context_constructed(3);
/// acse-service-user diagnostic `[1]` (constructed) = `0xa1`.
const TAG_DIAG_SERVICE_USER: Tag = Tag::context_constructed(1);
/// user-information `[30]` (constructed, IMPLICIT SET) = `0xbe`.
const TAG_USER_INFO: Tag = Tag::context_constructed(30);
/// release reason / abort-source `[0]` (primitive) = `0x80`.
const TAG_REASON: Tag = Tag::context(0);
/// single-ASN1-type `[0]` (constructed) inside the EXTERNAL = `0xa0`.
const TAG_SINGLE_ASN1: Tag = Tag::context_constructed(0);

/// MMS application-context-name OID arcs (`1.0.9506.2.3`).
pub const MMS_APP_CONTEXT_ARCS: &[u32] = &[1, 0, 9506, 2, 3];

/// Default indirect-reference (MMS presentation-context id) emitted in the
/// user-information EXTERNAL.
const DEFAULT_INDIRECT_REFERENCE: i64 = 3;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A decoded AARQ (associate request).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aarq {
    /// application-context-name OID.
    pub app_context: ObjectIdentifier,
    /// calling-AP-title (OID form), if present.
    pub calling_ap_title: Option<ObjectIdentifier>,
    /// calling-AE-qualifier (INTEGER form), if present.
    pub calling_ae_qualifier: Option<i64>,
    /// called-AP-title (OID form), if present.
    pub called_ap_title: Option<ObjectIdentifier>,
    /// called-AE-qualifier (INTEGER form), if present.
    pub called_ae_qualifier: Option<i64>,
    /// The carried user-information payload (e.g. MMS Initiate bytes).
    pub user_info: Vec<u8>,
}

/// A decoded AARE (associate response).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aare {
    /// application-context-name OID.
    pub app_context: ObjectIdentifier,
    /// Association result (0 = accepted, 1 = rejected-permanent, 2 = transient).
    pub result: i64,
    /// The carried user-information payload (e.g. MMS InitiateResponse bytes).
    pub user_info: Vec<u8>,
}

/// An ACSE APDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcsePdu {
    /// Associate request.
    Aarq(Aarq),
    /// Associate response.
    Aare(Aare),
    /// Release request.
    Rlrq {
        /// reason `[0]`, if present (0 = normal).
        reason: Option<i64>,
    },
    /// Release response.
    Rlre {
        /// reason `[0]`, if present.
        reason: Option<i64>,
    },
    /// Abort.
    Abrt {
        /// abort-source `[0]` (0 = service-user, 1 = service-provider).
        source: i64,
    },
}

/// ISO 8650 ACSE codec (stateless).
#[derive(Debug)]
pub struct Acse;

impl Acse {
    /// Encode an ACSE APDU and append it to `out`.
    ///
    /// This is currently infallible — every ACSE field is an OID, an integer,
    /// or an opaque payload, none of which has a fixed-width bound that encoding
    /// can violate (unlike the session selectors). The `Result` is retained for
    /// signature symmetry with the other layer codecs and so that bounded fields
    /// added later (e.g. authentication parameters in Phase 6) can fail here
    /// without a breaking API change.
    pub fn encode(pdu: &AcsePdu, out: &mut Vec<u8>) -> Result<()> {
        let mut w = BerWriter::new();
        match pdu {
            AcsePdu::Aarq(a) => encode_aarq(&mut w, a),
            AcsePdu::Aare(a) => encode_aare(&mut w, a),
            AcsePdu::Rlrq { reason } => encode_release(&mut w, TAG_RLRQ, *reason),
            AcsePdu::Rlre { reason } => encode_release(&mut w, TAG_RLRE, *reason),
            AcsePdu::Abrt { source } => {
                w.write_tlv(TAG_ABRT, |abrt| {
                    abrt.write_integer(TAG_REASON, *source);
                });
            }
        }
        out.extend_from_slice(&w.into_bytes());
        Ok(())
    }

    /// Decode an ACSE APDU (tolerant on optional fields and unknown context
    /// tags).
    pub fn decode(buf: &[u8]) -> Result<AcsePdu> {
        let mut r = BerReader::new(buf);
        let (tag, content) = r.read_tlv().map_err(|_| Error::AcseInvalid)?;
        if tag.class != TagClass::Application || !tag.constructed {
            return Err(Error::AcseUnexpectedPdu {
                tag: first_byte(buf),
            });
        }
        match tag.number {
            0 => Ok(AcsePdu::Aarq(decode_aarq(content)?)),
            1 => Ok(AcsePdu::Aare(decode_aare(content)?)),
            2 => Ok(AcsePdu::Rlrq {
                reason: decode_reason(content)?,
            }),
            3 => Ok(AcsePdu::Rlre {
                reason: decode_reason(content)?,
            }),
            4 => Ok(AcsePdu::Abrt {
                source: decode_reason(content)?.unwrap_or(0),
            }),
            _ => Err(Error::AcseUnexpectedPdu {
                tag: first_byte(buf),
            }),
        }
    }
}

/// The first byte of `buf`, or 0 if empty (for error reporting only).
fn first_byte(buf: &[u8]) -> u8 {
    buf.first().copied().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

fn encode_aarq(w: &mut BerWriter, a: &Aarq) {
    w.write_tlv(TAG_AARQ, |aarq| {
        write_app_context(aarq, &a.app_context);
        if let Some(t) = &a.called_ap_title {
            write_ap_title(aarq, TAG_CALLED_AP_TITLE, t);
        }
        if let Some(q) = a.called_ae_qualifier {
            write_ae_qualifier(aarq, TAG_CALLED_AE_QUAL, q);
        }
        if let Some(t) = &a.calling_ap_title {
            write_ap_title(aarq, TAG_CALLING_AP_TITLE, t);
        }
        if let Some(q) = a.calling_ae_qualifier {
            write_ae_qualifier(aarq, TAG_CALLING_AE_QUAL, q);
        }
        write_user_info(aarq, &a.user_info);
    });
}

fn encode_aare(w: &mut BerWriter, a: &Aare) {
    // result-source-diagnostic is always carried as the acse-service-user
    // CHOICE branch (matching libIEC61850, which only ever emits this branch).
    // We derive its INTEGER from the result rather than hard-coding 0:
    //   result == 0 (accepted)  -> 0 = null
    //   result != 0 (rejected)  -> 1 = no-reason-given
    // libIEC61850 emits 0 even on reject; "no-reason-given" is the neutral
    // ISO 8650 code for a rejection without a more specific cause.
    let diagnostic: i64 = if a.result == 0 { 0 } else { 1 };
    w.write_tlv(TAG_AARE, |aare| {
        write_app_context(aare, &a.app_context);
        // result [2] { INTEGER }
        aare.write_tlv(TAG_RESULT, |res| {
            res.write_integer(Tag::INTEGER, a.result);
        });
        // result-source-diagnostic [3] { acse-service-user [1] { INTEGER } }
        aare.write_tlv(TAG_RESULT_DIAGNOSTIC, |diag| {
            diag.write_tlv(TAG_DIAG_SERVICE_USER, |su| {
                su.write_integer(Tag::INTEGER, diagnostic);
            });
        });
        write_user_info(aare, &a.user_info);
    });
}

fn encode_release(w: &mut BerWriter, tag: Tag, reason: Option<i64>) {
    w.write_tlv(tag, |rl| {
        if let Some(r) = reason {
            rl.write_integer(TAG_REASON, r);
        }
    });
}

/// application-context-name `[1]` EXPLICIT { OID }.
fn write_app_context(w: &mut BerWriter, oid: &ObjectIdentifier) {
    w.write_tlv(TAG_APP_CONTEXT, |ac| {
        ac.write_oid(Tag::OID, oid);
    });
}

/// AP-title (form2): `[n] { OID }`.
fn write_ap_title(w: &mut BerWriter, tag: Tag, oid: &ObjectIdentifier) {
    w.write_tlv(tag, |t| {
        t.write_oid(Tag::OID, oid);
    });
}

/// AE-qualifier (form2): `[n] { INTEGER }`.
fn write_ae_qualifier(w: &mut BerWriter, tag: Tag, q: i64) {
    w.write_tlv(tag, |t| {
        t.write_integer(Tag::INTEGER, q);
    });
}

/// user-information `[30]` { EXTERNAL { indirect-reference INTEGER,
/// single-ASN1-type `[0]` payload } }.
fn write_user_info(w: &mut BerWriter, payload: &[u8]) {
    w.write_tlv(TAG_USER_INFO, |ui| {
        ui.write_tlv(Tag::EXTERNAL, |ext| {
            ext.write_integer(Tag::INTEGER, DEFAULT_INDIRECT_REFERENCE);
            // TAG_SINGLE_ASN1 carries the constructed bit, so write_primitive
            // emits the 0xA0 header even though it does not recurse.
            ext.write_primitive(TAG_SINGLE_ASN1, payload);
        });
    });
}

// ---------------------------------------------------------------------------
// Decode helpers (tolerant)
// ---------------------------------------------------------------------------

fn decode_aarq(content: &[u8]) -> Result<Aarq> {
    let mut app_context: Option<ObjectIdentifier> = None;
    let mut calling_ap_title = None;
    let mut calling_ae_qualifier = None;
    let mut called_ap_title = None;
    let mut called_ae_qualifier = None;
    let mut user_info: Option<Vec<u8>> = None;

    let mut r = BerReader::new(content);
    while !r.done() {
        let (tag, c) = r.read_tlv().map_err(|_| Error::AcseInvalid)?;
        if tag == TAG_APP_CONTEXT {
            app_context = read_inner_oid(c);
        } else if tag == TAG_CALLED_AP_TITLE {
            called_ap_title = read_inner_oid(c);
        } else if tag == TAG_CALLED_AE_QUAL {
            called_ae_qualifier = read_inner_integer(c);
        } else if tag == TAG_CALLING_AP_TITLE {
            calling_ap_title = read_inner_oid(c);
        } else if tag == TAG_CALLING_AE_QUAL {
            calling_ae_qualifier = read_inner_integer(c);
        } else if tag == TAG_USER_INFO {
            user_info = Some(parse_user_info(c)?);
        }
        // sender ACSE requirements, auth fields, unknown tags: skip.
    }

    Ok(Aarq {
        app_context: app_context.ok_or(Error::AcseInvalid)?,
        calling_ap_title,
        calling_ae_qualifier,
        called_ap_title,
        called_ae_qualifier,
        user_info: user_info.ok_or(Error::AcseInvalid)?,
    })
}

fn decode_aare(content: &[u8]) -> Result<Aare> {
    let mut app_context: Option<ObjectIdentifier> = None;
    let mut result: Option<i64> = None;
    let mut user_info: Option<Vec<u8>> = None;

    let mut r = BerReader::new(content);
    while !r.done() {
        let (tag, c) = r.read_tlv().map_err(|_| Error::AcseInvalid)?;
        if tag == TAG_APP_CONTEXT {
            app_context = read_inner_oid(c);
        } else if tag == TAG_RESULT {
            result = read_inner_integer(c);
        } else if tag == TAG_USER_INFO {
            user_info = Some(parse_user_info(c)?);
        }
        // result-source-diagnostic, responding titles, unknown tags: skip.
    }

    Ok(Aare {
        app_context: app_context.ok_or(Error::AcseInvalid)?,
        result: result.ok_or(Error::AcseInvalid)?,
        user_info: user_info.ok_or(Error::AcseInvalid)?,
    })
}

/// Decode an optional `[0]` reason / abort-source INTEGER from an RLRQ / RLRE /
/// ABRT body. Returns `None` if absent.
fn decode_reason(content: &[u8]) -> Result<Option<i64>> {
    let mut r = BerReader::new(content);
    while !r.done() {
        let (tag, c) = r.read_tlv().map_err(|_| Error::AcseInvalid)?;
        if tag.class == TagClass::ContextSpecific && tag.number == 0 {
            return Ok(Some(decode_integer_i64(c).map_err(|_| Error::AcseInvalid)?));
        }
    }
    Ok(None)
}

/// Read the first OID nested inside an EXPLICIT context wrapper.
fn read_inner_oid(content: &[u8]) -> Option<ObjectIdentifier> {
    let mut r = BerReader::new(content);
    while !r.done() {
        let (tag, c) = r.read_tlv().ok()?;
        if tag == Tag::OID {
            return decode_oid(c).ok();
        }
    }
    None
}

/// Read the first INTEGER nested inside an EXPLICIT context wrapper.
fn read_inner_integer(content: &[u8]) -> Option<i64> {
    let mut r = BerReader::new(content);
    while !r.done() {
        let (tag, c) = r.read_tlv().ok()?;
        if tag == Tag::INTEGER {
            return decode_integer_i64(c).ok();
        }
    }
    None
}

/// Parse user-information `[30]` content: an EXTERNAL whose `[0]`
/// single-ASN1-type holds the payload. Accepts the EXTERNAL with or without a
/// direct-reference OID and/or an indirect-reference INTEGER.
fn parse_user_info(content: &[u8]) -> Result<Vec<u8>> {
    let mut r = BerReader::new(content);
    // The [30] wrapper holds one (or more) EXTERNAL; take the first.
    let (ext_tag, ext) = r.read_tlv().map_err(|_| Error::AcseInvalid)?;
    if ext_tag != Tag::EXTERNAL {
        return Err(Error::AcseInvalid);
    }
    let mut er = BerReader::new(ext);
    while !er.done() {
        let (tag, c) = er.read_tlv().map_err(|_| Error::AcseInvalid)?;
        // single-ASN1-type [0] (constructed) carries the payload.
        if tag.class == TagClass::ContextSpecific && tag.number == 0 {
            return Ok(c.to_vec());
        }
        // direct-reference OID, indirect-reference INTEGER, others: skip.
    }
    Err(Error::AcseInvalid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mms_context() -> ObjectIdentifier {
        ObjectIdentifier::from_arcs(MMS_APP_CONTEXT_ARCS)
    }

    fn roundtrip(pdu: &AcsePdu) -> AcsePdu {
        let mut buf = Vec::new();
        Acse::encode(pdu, &mut buf).expect("encode");
        Acse::decode(&buf).expect("decode")
    }

    #[test]
    fn aarq_all_optionals_present() {
        let pdu = AcsePdu::Aarq(Aarq {
            app_context: mms_context(),
            calling_ap_title: Some(ObjectIdentifier::from_arcs(&[1, 1, 999, 1])),
            calling_ae_qualifier: Some(12),
            called_ap_title: Some(ObjectIdentifier::from_arcs(&[1, 1, 999, 2])),
            called_ae_qualifier: Some(34),
            user_info: vec![0xA8, 0x03, 0x80, 0x01, 0x01],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aarq_all_optionals_absent() {
        let pdu = AcsePdu::Aarq(Aarq {
            app_context: mms_context(),
            calling_ap_title: None,
            calling_ae_qualifier: None,
            called_ap_title: None,
            called_ae_qualifier: None,
            user_info: vec![0x01, 0x02, 0x03],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aare_accepted_roundtrip() {
        let pdu = AcsePdu::Aare(Aare {
            app_context: mms_context(),
            result: 0,
            user_info: vec![0xA9, 0x02, 0x00, 0x00],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aare_rejected_decodes_fine() {
        // Rejection (result != 0) is a state-machine concern; the codec must
        // still decode it cleanly.
        let pdu = AcsePdu::Aare(Aare {
            app_context: mms_context(),
            result: 1,
            user_info: vec![0xFF],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn aare_diagnostic_derived_from_result() {
        // result == 0 -> acse-service-user diagnostic 0 (null);
        // result != 0 -> acse-service-user diagnostic 1 (no-reason-given).
        // The diagnostic is encoded as a3 05 a1 03 02 01 <byte>.
        for (result, expected_byte) in [(0i64, 0u8), (1, 1), (2, 1)] {
            let mut buf = Vec::new();
            Acse::encode(
                &AcsePdu::Aare(Aare {
                    app_context: mms_context(),
                    result,
                    user_info: vec![0x00],
                }),
                &mut buf,
            )
            .unwrap();
            // Find the result-source-diagnostic wrapper a3 05 a1 03 02 01 XX.
            let pat = [0xa3, 0x05, 0xa1, 0x03, 0x02, 0x01];
            let idx = buf
                .windows(pat.len())
                .position(|w| w == pat)
                .expect("result-source-diagnostic present");
            assert_eq!(
                buf[idx + pat.len()],
                expected_byte,
                "diagnostic byte for result {result}"
            );
        }
    }

    #[test]
    fn rlrq_rlre_with_and_without_reason() {
        for pdu in [
            AcsePdu::Rlrq { reason: Some(0) },
            AcsePdu::Rlrq { reason: None },
            AcsePdu::Rlre { reason: Some(0) },
            AcsePdu::Rlre { reason: None },
        ] {
            assert_eq!(roundtrip(&pdu), pdu);
        }
    }

    #[test]
    fn abrt_roundtrip() {
        for source in [0i64, 1] {
            let pdu = AcsePdu::Abrt { source };
            assert_eq!(roundtrip(&pdu), pdu);
        }
    }

    #[test]
    fn external_without_direct_or_indirect_reference_accepted() {
        // Hand-build an AARE whose EXTERNAL has only single-ASN1-type [0].
        let payload = vec![0x12, 0x34];
        let mut w = BerWriter::new();
        w.write_tlv(TAG_AARE, |aare| {
            write_app_context(aare, &mms_context());
            aare.write_tlv(TAG_RESULT, |res| res.write_integer(Tag::INTEGER, 0));
            aare.write_tlv(TAG_USER_INFO, |ui| {
                ui.write_tlv(Tag::EXTERNAL, |ext| {
                    // No direct/indirect reference at all.
                    ext.write_primitive(TAG_SINGLE_ASN1, &payload);
                });
            });
        });
        let decoded = Acse::decode(&w.into_bytes()).unwrap();
        match decoded {
            AcsePdu::Aare(a) => assert_eq!(a.user_info, payload),
            other => panic!("expected Aare, got {other:?}"),
        }
    }

    #[test]
    fn external_with_direct_reference_accepted() {
        // EXTERNAL with a direct-reference OID before single-ASN1-type.
        let payload = vec![0xAB, 0xCD];
        let mut w = BerWriter::new();
        w.write_tlv(TAG_AARQ, |aarq| {
            write_app_context(aarq, &mms_context());
            aarq.write_tlv(TAG_USER_INFO, |ui| {
                ui.write_tlv(Tag::EXTERNAL, |ext| {
                    ext.write_oid(Tag::OID, &ObjectIdentifier::from_arcs(&[2, 1, 1]));
                    ext.write_integer(Tag::INTEGER, 3);
                    ext.write_primitive(TAG_SINGLE_ASN1, &payload);
                });
            });
        });
        let decoded = Acse::decode(&w.into_bytes()).unwrap();
        match decoded {
            AcsePdu::Aarq(a) => assert_eq!(a.user_info, payload),
            other => panic!("expected Aarq, got {other:?}"),
        }
    }

    #[test]
    fn unknown_application_tag_is_unexpected() {
        // [APPLICATION 5] = 0x65 is not an ACSE PDU we handle.
        let mut w = BerWriter::new();
        w.write_tlv(Tag::application_constructed(5), |_| {});
        let err = Acse::decode(&w.into_bytes()).unwrap_err();
        assert!(
            matches!(err, Error::AcseUnexpectedPdu { tag: 0x65 }),
            "{err:?}"
        );
    }

    #[test]
    fn non_application_tag_is_unexpected() {
        // A plain SEQUENCE is not an ACSE APDU.
        let mut w = BerWriter::new();
        w.write_tlv(Tag::SEQUENCE, |s| s.write_integer(Tag::INTEGER, 1));
        assert!(matches!(
            Acse::decode(&w.into_bytes()),
            Err(Error::AcseUnexpectedPdu { .. })
        ));
    }

    #[test]
    fn aarq_missing_user_info_is_invalid() {
        let mut w = BerWriter::new();
        w.write_tlv(TAG_AARQ, |aarq| {
            write_app_context(aarq, &mms_context());
        });
        assert!(matches!(
            Acse::decode(&w.into_bytes()),
            Err(Error::AcseInvalid)
        ));
    }

    #[test]
    fn truncation_sweep_aarq() {
        let mut buf = Vec::new();
        Acse::encode(
            &AcsePdu::Aarq(Aarq {
                app_context: mms_context(),
                calling_ap_title: Some(ObjectIdentifier::from_arcs(&[1, 1, 1])),
                calling_ae_qualifier: Some(7),
                called_ap_title: None,
                called_ae_qualifier: None,
                user_info: vec![0x55; 20],
            }),
            &mut buf,
        )
        .unwrap();
        for len in 0..buf.len() {
            let _ = Acse::decode(&buf[..len]);
        }
    }
}
