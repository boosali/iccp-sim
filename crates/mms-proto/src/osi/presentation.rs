//! ISO 8823 Presentation layer (BER).
//!
//! # PPDUs in the MMS profile
//!
//! * **CP** (Connect Presentation, outer wire tag `0x31` — the ISO 8823
//!   CP-type / `[SET]`-form `PRES_CONNECTION_REQUEST_CONFIRM`): the
//!   presentation half of the association request. Carries the calling/called
//!   presentation selectors, a presentation-context-definition-list, and the
//!   ACSE AARQ as user data.
//! * **CPA** (CP Accept, also `0x31`): the response, with a
//!   context-definition-result-list and the ACSE AARE as user data.
//! * **Data phase**: a bare fully-encoded-data structure (`[APPLICATION 1]` =
//!   `0x61`) carrying one PDV addressed to a presentation context.
//!
//! # Fixed context profile (encode)
//!
//! The encoder emits the two-context profile libIEC61850 uses: context id 1 =
//! ACSE abstract syntax (`2.2.1.0.1`), context id 3 = MMS abstract syntax
//! (`1.0.9506.2.1`), both with transfer syntax BER (`2.1.1`).
//!
//! The CP/CPA outer tag is `0x31` on the wire (matching libIEC61850 and the
//! ISO 8823 dissectors), which BER-decodes as `[UNIVERSAL 17] constructed`
//! rather than an application-class tag.
//!
//! # Tolerant decode
//!
//! [`Presentation::decode_cp`] walks the context-definition-list and learns
//! which presentation-context-identifier the peer assigned to ACSE and MMS *by
//! matching the abstract-syntax OID* — it does not assume 1/3. The learned
//! [`PresentationContexts`] map is returned so the caller can address later
//! data PPDUs correctly. Selectors, ordering, and any extra contexts are
//! tolerated.

use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, TagClass};
use crate::ber::writer::BerWriter;
use crate::ber::{decode_oid, decode_unsigned_u64, ObjectIdentifier};
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Fixed OIDs and context ids (const tables)
// ---------------------------------------------------------------------------

/// ACSE abstract-syntax OID arcs (`2.2.1.0.1`). Encoded content: `52 01 00 01`.
const ACSE_ABSTRACT_SYNTAX_ARCS: &[u32] = &[2, 2, 1, 0, 1];
/// MMS abstract-syntax OID arcs (`1.0.9506.2.1`). Encoded content: `28 ca 22 02 01`.
const MMS_ABSTRACT_SYNTAX_ARCS: &[u32] = &[1, 0, 9506, 2, 1];
/// BER transfer-syntax OID arcs (`2.1.1`). Encoded content: `51 01`.
const BER_TRANSFER_SYNTAX_ARCS: &[u32] = &[2, 1, 1];

/// Default presentation-context-identifier for ACSE in the MMS profile.
const DEFAULT_ACSE_PCI: u32 = 1;
/// Default presentation-context-identifier for MMS in the MMS profile.
const DEFAULT_MMS_PCI: u32 = 3;

/// Mode-selector value: normal mode.
const MODE_NORMAL: i64 = 1;
/// Context-definition result: acceptance.
const RESULT_ACCEPTANCE: i64 = 0;

// --- ISO 8823 context-specific / application tags --------------------------

/// CP / CPA outer PPDU tag: wire byte `0x31`, which is `[UNIVERSAL 17]`
/// constructed in BER terms. This is what libIEC61850 and real OSI stacks emit
/// for the ISO 8823 CP-type, so we encode and require exactly this tag.
const TAG_CP: Tag = Tag {
    class: TagClass::Universal,
    constructed: true,
    number: 17,
};
/// fully-encoded-data `[APPLICATION 1]` (constructed) = `0x61`.
const TAG_FULLY_ENCODED_DATA: Tag = Tag::application_constructed(1);
/// mode-selector `[0]` (constructed) = `0xa0`.
const TAG_MODE_SELECTOR: Tag = Tag::context_constructed(0);
/// mode-value `[0]` (primitive) inside the mode-selector = `0x80`.
const TAG_MODE_VALUE: Tag = Tag::context(0);
/// normal-mode-parameters `[2]` (constructed) = `0xa2`.
const TAG_NORMAL_MODE: Tag = Tag::context_constructed(2);
/// calling-presentation-selector `[1]` (primitive) = `0x81`.
const TAG_CALLING_SEL: Tag = Tag::context(1);
/// called-presentation-selector `[2]` (primitive) = `0x82`.
const TAG_CALLED_SEL: Tag = Tag::context(2);
/// responding-presentation-selector `[3]` (primitive) = `0x83`.
const TAG_RESPONDING_SEL: Tag = Tag::context(3);
/// presentation-context-definition-list `[4]` (constructed) = `0xa4`.
const TAG_PCD_LIST: Tag = Tag::context_constructed(4);
/// presentation-context-definition-result-list `[5]` (constructed) = `0xa5`.
const TAG_PCD_RESULT_LIST: Tag = Tag::context_constructed(5);
/// single-ASN1-type `[0]` (constructed) inside a PDV = `0xa0`.
const TAG_SINGLE_ASN1: Tag = Tag::context_constructed(0);
/// result `[0]` (primitive) inside a context-result = `0x80`.
const TAG_RESULT: Tag = Tag::context(0);
/// transfer-syntax-name `[1]` (primitive) inside a context-result = `0x81`.
const TAG_RESULT_TRANSFER_SYNTAX: Tag = Tag::context(1);

// ---------------------------------------------------------------------------
// Learned context map
// ---------------------------------------------------------------------------

/// The presentation-context-identifier assignments learned from (or assumed
/// for) a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PresentationContexts {
    /// Context id assigned to the ACSE abstract syntax.
    pub acse_pci: u32,
    /// Context id assigned to the MMS abstract syntax.
    pub mms_pci: u32,
}

impl Default for PresentationContexts {
    fn default() -> Self {
        PresentationContexts {
            acse_pci: DEFAULT_ACSE_PCI,
            mms_pci: DEFAULT_MMS_PCI,
        }
    }
}

/// The outcome of decoding a CPA PPDU.
///
/// The context-definition-result-list is mapped *positionally* onto the two
/// contexts `encode_cp` offers in fixed order (ACSE first, MMS second). A
/// missing or short result-list leaves the corresponding flag `false`, so a
/// peer that refuses the MMS context is observable rather than silently
/// accepted. Extra results beyond the first two are tolerated and ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpaResult {
    /// Whether the ACSE presentation context (offered first) was accepted.
    pub acse_accepted: bool,
    /// Whether the MMS presentation context (offered second) was accepted.
    pub mms_accepted: bool,
    /// The carried ACSE payload (the AARE bytes).
    pub acse_payload: Vec<u8>,
}

/// ISO 8823 Presentation codec (stateless).
#[derive(Debug)]
pub struct Presentation;

impl Presentation {
    /// Encode a CP (Connect Presentation) PPDU carrying `acse_payload` (the
    /// ACSE AARQ bytes) using the fixed two-context profile.
    #[must_use]
    pub fn encode_cp(
        calling_sel: Option<&[u8]>,
        called_sel: Option<&[u8]>,
        acse_payload: &[u8],
    ) -> Vec<u8> {
        let ctx = PresentationContexts::default();
        let mut w = BerWriter::new();
        w.write_tlv(TAG_CP, |cp| {
            write_mode_selector(cp);
            cp.write_tlv(TAG_NORMAL_MODE, |nm| {
                write_selector(nm, TAG_CALLING_SEL, calling_sel);
                write_selector(nm, TAG_CALLED_SEL, called_sel);
                // presentation-context-definition-list.
                nm.write_tlv(TAG_PCD_LIST, |list| {
                    write_context_definition(list, ctx.acse_pci, ACSE_ABSTRACT_SYNTAX_ARCS);
                    write_context_definition(list, ctx.mms_pci, MMS_ABSTRACT_SYNTAX_ARCS);
                });
                write_fully_encoded_data(nm, ctx.acse_pci, acse_payload);
            });
        });
        w.into_bytes()
    }

    /// Decode a CP PPDU (tolerant). Returns the learned context map (by OID
    /// match) and the carried ACSE payload.
    pub fn decode_cp(buf: &[u8]) -> Result<(PresentationContexts, Vec<u8>)> {
        let nm = read_normal_mode(buf)?;
        let mut acse_pci: Option<u32> = None;
        let mut mms_pci: Option<u32> = None;
        let mut payload: Option<Vec<u8>> = None;

        let mut r = BerReader::new(nm);
        while !r.done() {
            let (tag, content) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
            if tag == TAG_PCD_LIST {
                learn_contexts(content, &mut acse_pci, &mut mms_pci)?;
            } else if tag == TAG_FULLY_ENCODED_DATA {
                let (_pci, p) = parse_fully_encoded_data(content)?;
                payload = Some(p);
            }
            // Selectors and anything else: skip.
        }

        let ctx = PresentationContexts {
            acse_pci: acse_pci
                .ok_or(Error::PresentationAbstractSyntaxUnoffered { which: "acse" })?,
            mms_pci: mms_pci.ok_or(Error::PresentationAbstractSyntaxUnoffered { which: "mms" })?,
        };
        let payload = payload.ok_or(Error::PresentationInvalid)?;
        Ok((ctx, payload))
    }

    /// Encode a CPA (CP Accept) PPDU accepting both contexts in `ctx` and
    /// carrying `acse_payload` (the ACSE AARE bytes).
    #[must_use]
    pub fn encode_cpa(
        responding_sel: Option<&[u8]>,
        ctx: &PresentationContexts,
        acse_payload: &[u8],
    ) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.write_tlv(TAG_CP, |cp| {
            write_mode_selector(cp);
            cp.write_tlv(TAG_NORMAL_MODE, |nm| {
                write_selector(nm, TAG_RESPONDING_SEL, responding_sel);
                // context-definition-result-list: accept ACSE then MMS.
                nm.write_tlv(TAG_PCD_RESULT_LIST, |list| {
                    write_context_result(list);
                    write_context_result(list);
                });
                write_fully_encoded_data(nm, ctx.acse_pci, acse_payload);
            });
        });
        w.into_bytes()
    }

    /// Decode a CPA PPDU (tolerant). Returns the per-context acceptance results
    /// plus the carried ACSE payload (see [`CpaResult`]).
    ///
    /// Whether to act on a refusal is the state machine's concern; the codec
    /// only surfaces the result-list so the caller can detect it.
    pub fn decode_cpa(buf: &[u8]) -> Result<CpaResult> {
        let nm = read_normal_mode(buf)?;
        let mut acse_accepted = false;
        let mut mms_accepted = false;
        let mut payload: Option<Vec<u8>> = None;

        let mut r = BerReader::new(nm);
        while !r.done() {
            let (tag, content) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
            if tag == TAG_PCD_RESULT_LIST {
                let (acse, mms) = parse_result_list(content)?;
                acse_accepted = acse;
                mms_accepted = mms;
            } else if tag == TAG_FULLY_ENCODED_DATA {
                let (_pci, p) = parse_fully_encoded_data(content)?;
                payload = Some(p);
            }
            // responding-selector and anything else: skip.
        }

        Ok(CpaResult {
            acse_accepted,
            mms_accepted,
            acse_payload: payload.ok_or(Error::PresentationInvalid)?,
        })
    }

    /// Encode a data-phase PPDU: a bare fully-encoded-data structure addressed
    /// to presentation context `pci`.
    #[must_use]
    pub fn encode_data(pci: u32, payload: &[u8]) -> Vec<u8> {
        let mut w = BerWriter::new();
        write_fully_encoded_data(&mut w, pci, payload);
        w.into_bytes()
    }

    /// Decode a data-phase PPDU. Returns `(pci, payload)`.
    pub fn decode_data(buf: &[u8]) -> Result<(u32, Vec<u8>)> {
        let mut r = BerReader::new(buf);
        let (tag, content) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
        if tag != TAG_FULLY_ENCODED_DATA {
            return Err(Error::PresentationInvalid);
        }
        parse_fully_encoded_data(content)
    }
}

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

fn write_mode_selector(w: &mut BerWriter) {
    w.write_tlv(TAG_MODE_SELECTOR, |ms| {
        ms.write_integer(TAG_MODE_VALUE, MODE_NORMAL);
    });
}

/// Write a presentation selector as a context-tagged OCTET STRING. An absent
/// selector is encoded as an empty value (the profile's "no selector").
fn write_selector(w: &mut BerWriter, tag: Tag, sel: Option<&[u8]>) {
    w.write_octet_string(tag, sel.unwrap_or(&[]));
}

/// Write one presentation-context-definition list item:
/// `SEQUENCE { INTEGER pci, OID abstract-syntax, SEQUENCE { OID ber } }`.
fn write_context_definition(w: &mut BerWriter, pci: u32, abstract_syntax_arcs: &[u32]) {
    w.write_tlv(Tag::SEQUENCE, |item| {
        item.write_integer(Tag::INTEGER, pci as i64);
        item.write_oid(Tag::OID, &ObjectIdentifier::from_arcs(abstract_syntax_arcs));
        // transfer-syntax-name-list: SEQUENCE OF OID (just BER).
        item.write_tlv(Tag::SEQUENCE, |ts| {
            ts.write_oid(
                Tag::OID,
                &ObjectIdentifier::from_arcs(BER_TRANSFER_SYNTAX_ARCS),
            );
        });
    });
}

/// Write one context-definition-result item:
/// `SEQUENCE { [0] INTEGER result=acceptance, [1] OID transfer-syntax }`.
fn write_context_result(w: &mut BerWriter) {
    w.write_tlv(Tag::SEQUENCE, |item| {
        item.write_integer(TAG_RESULT, RESULT_ACCEPTANCE);
        item.write_oid(
            TAG_RESULT_TRANSFER_SYNTAX,
            &ObjectIdentifier::from_arcs(BER_TRANSFER_SYNTAX_ARCS),
        );
    });
}

/// Write fully-encoded-data: `[APPLICATION 1] { SEQUENCE { INTEGER pci, [0] payload } }`.
fn write_fully_encoded_data(w: &mut BerWriter, pci: u32, payload: &[u8]) {
    w.write_tlv(TAG_FULLY_ENCODED_DATA, |fed| {
        fed.write_tlv(Tag::SEQUENCE, |pdv| {
            pdv.write_integer(Tag::INTEGER, pci as i64);
            // TAG_SINGLE_ASN1 carries the constructed bit, so write_primitive
            // emits the 0xA0 header even though it does not recurse.
            pdv.write_primitive(TAG_SINGLE_ASN1, payload);
        });
    });
}

// ---------------------------------------------------------------------------
// Decode helpers (tolerant structural walk)
// ---------------------------------------------------------------------------

/// Read the outer CP/CPA wrapper and return the normal-mode-parameters content
/// slice. Walks the CP content tolerantly, skipping the mode-selector and any
/// unknown elements.
fn read_normal_mode(buf: &[u8]) -> Result<&[u8]> {
    let mut r = BerReader::new(buf);
    let (tag, cp_content) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
    if tag != TAG_CP {
        return Err(Error::PresentationInvalid);
    }
    let mut inner = BerReader::new(cp_content);
    while !inner.done() {
        let (t, content) = inner.read_tlv().map_err(|_| Error::PresentationInvalid)?;
        if t == TAG_NORMAL_MODE {
            return Ok(content);
        }
        // mode-selector and unknown tags: skip.
    }
    Err(Error::PresentationInvalid)
}

/// Walk a presentation-context-definition-list, learning which PCI maps to ACSE
/// and which to MMS by matching the abstract-syntax OID. Extra contexts with
/// other OIDs are ignored.
fn learn_contexts(
    list: &[u8],
    acse_pci: &mut Option<u32>,
    mms_pci: &mut Option<u32>,
) -> Result<()> {
    let acse_oid = ObjectIdentifier::from_arcs(ACSE_ABSTRACT_SYNTAX_ARCS);
    let mms_oid = ObjectIdentifier::from_arcs(MMS_ABSTRACT_SYNTAX_ARCS);

    let mut r = BerReader::new(list);
    while !r.done() {
        let (tag, item) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
        if tag != Tag::SEQUENCE {
            continue; // tolerate stray elements
        }
        // Each item: INTEGER pci, OID abstract-syntax, then transfer-syntax.
        let mut ir = BerReader::new(item);
        let mut pci: Option<u32> = None;
        let mut oid: Option<ObjectIdentifier> = None;
        while !ir.done() {
            let (t, c) = ir.read_tlv().map_err(|_| Error::PresentationInvalid)?;
            if t == Tag::INTEGER && pci.is_none() {
                let v = decode_unsigned_u64(c).map_err(|_| Error::PresentationInvalid)?;
                pci = u32::try_from(v).ok();
            } else if t == Tag::OID && oid.is_none() {
                oid = decode_oid(c).ok();
            }
            // transfer-syntax SEQUENCE and anything else: skip.
        }
        if let (Some(pci), Some(oid)) = (pci, oid) {
            if oid == acse_oid {
                *acse_pci = Some(pci);
            } else if oid == mms_oid {
                *mms_pci = Some(pci);
            }
        }
    }
    Ok(())
}

/// Parse a context-definition-result-list, mapping its entries positionally
/// onto the two contexts `encode_cp` offers (ACSE first, MMS second). Returns
/// `(acse_accepted, mms_accepted)`. A result of `0` (acceptance) means
/// accepted; any other value, a malformed entry, or a missing entry counts as
/// not accepted. Extra entries beyond the first two are ignored.
fn parse_result_list(list: &[u8]) -> Result<(bool, bool)> {
    let mut accepted = [false, false];
    let mut idx = 0usize;

    let mut r = BerReader::new(list);
    while !r.done() {
        let (tag, item) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
        if tag != Tag::SEQUENCE {
            continue; // tolerate stray elements
        }
        if idx < accepted.len() {
            accepted[idx] = result_entry_accepted(item);
        }
        idx += 1;
    }

    Ok((accepted[0], accepted[1]))
}

/// Returns `true` if a single context-result entry carries `result [0] == 0`
/// (acceptance). Walks the entry tolerantly; a missing or non-zero result is
/// not accepted.
fn result_entry_accepted(item: &[u8]) -> bool {
    let mut r = BerReader::new(item);
    while !r.done() {
        let Ok((tag, c)) = r.read_tlv() else {
            return false;
        };
        if tag == TAG_RESULT {
            return decode_unsigned_u64(c) == Ok(RESULT_ACCEPTANCE as u64);
        }
        // transfer-syntax [1] and anything else: skip.
    }
    false
}

/// Parse a fully-encoded-data content slice. Returns `(pci, payload)`.
///
/// Structure: `SEQUENCE { INTEGER pci, [0] single-ASN1-type payload }`. Walks
/// the inner SEQUENCE tolerantly, taking the first INTEGER as the PCI and the
/// `[0]` element as the payload.
fn parse_fully_encoded_data(content: &[u8]) -> Result<(u32, Vec<u8>)> {
    let mut r = BerReader::new(content);
    let (tag, pdv) = r.read_tlv().map_err(|_| Error::PresentationInvalid)?;
    if tag != Tag::SEQUENCE {
        return Err(Error::PresentationInvalid);
    }
    let mut pr = BerReader::new(pdv);
    let mut pci: Option<u32> = None;
    let mut payload: Option<Vec<u8>> = None;
    while !pr.done() {
        let (t, c) = pr.read_tlv().map_err(|_| Error::PresentationInvalid)?;
        if t == Tag::INTEGER && pci.is_none() {
            let v = decode_unsigned_u64(c).map_err(|_| Error::PresentationInvalid)?;
            pci = u32::try_from(v).ok();
        } else if t.class == TagClass::ContextSpecific && t.number == 0 && payload.is_none() {
            // single-ASN1-type [0] — the carried APDU bytes.
            payload = Some(c.to_vec());
        }
    }
    match (pci, payload) {
        (Some(pci), Some(payload)) => Ok((pci, payload)),
        _ => Err(Error::PresentationInvalid),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cp_roundtrip_default_contexts() {
        let payload = vec![0x60, 0x03, 0x80, 0x01, 0x00]; // fake AARQ-ish
        let buf = Presentation::encode_cp(Some(&[0, 0, 0, 1]), Some(&[0, 0, 0, 1]), &payload);
        let (ctx, p) = Presentation::decode_cp(&buf).unwrap();
        assert_eq!(ctx, PresentationContexts::default());
        assert_eq!(p, payload);
    }

    #[test]
    fn cp_roundtrip_no_selectors() {
        let payload = vec![0xAB; 10];
        let buf = Presentation::encode_cp(None, None, &payload);
        let (ctx, p) = Presentation::decode_cp(&buf).unwrap();
        assert_eq!(ctx, PresentationContexts::default());
        assert_eq!(p, payload);
    }

    #[test]
    fn cpa_roundtrip_both_accepted() {
        let payload = vec![0x61, 0x02, 0x00, 0x00];
        let ctx = PresentationContexts::default();
        let buf = Presentation::encode_cpa(Some(&[0, 0, 0, 1]), &ctx, &payload);
        let result = Presentation::decode_cpa(&buf).unwrap();
        assert!(result.acse_accepted);
        assert!(result.mms_accepted);
        assert_eq!(result.acse_payload, payload);
    }

    /// Build a CPA with explicit per-context result codes (`None` = omit that
    /// entry entirely) so we can exercise refusal detection.
    fn build_cpa_with_results(results: &[Option<i64>], payload: &[u8]) -> Vec<u8> {
        let mut w = BerWriter::new();
        w.write_tlv(TAG_CP, |cp| {
            write_mode_selector(cp);
            cp.write_tlv(TAG_NORMAL_MODE, |nm| {
                nm.write_tlv(TAG_PCD_RESULT_LIST, |list| {
                    for r in results.iter().flatten() {
                        list.write_tlv(Tag::SEQUENCE, |item| {
                            item.write_integer(TAG_RESULT, *r);
                            item.write_oid(
                                TAG_RESULT_TRANSFER_SYNTAX,
                                &ObjectIdentifier::from_arcs(BER_TRANSFER_SYNTAX_ARCS),
                            );
                        });
                    }
                });
                write_fully_encoded_data(nm, 1, payload);
            });
        });
        w.into_bytes()
    }

    #[test]
    fn cpa_mms_context_refused_is_observable() {
        // ACSE accepted (0), MMS refused (1 = user-rejection).
        let payload = vec![0xAA, 0xBB];
        let buf = build_cpa_with_results(&[Some(0), Some(1)], &payload);
        let result = Presentation::decode_cpa(&buf).unwrap();
        assert!(result.acse_accepted);
        assert!(!result.mms_accepted, "MMS refusal must be visible");
        assert_eq!(result.acse_payload, payload);
    }

    #[test]
    fn cpa_short_result_list_treats_missing_as_not_accepted() {
        // Only one result entry (ACSE accepted); MMS entry absent.
        let payload = vec![0x01];
        let buf = build_cpa_with_results(&[Some(0)], &payload);
        let result = Presentation::decode_cpa(&buf).unwrap();
        assert!(result.acse_accepted);
        assert!(!result.mms_accepted);
    }

    #[test]
    fn data_roundtrip_both_pcis() {
        for pci in [1u32, 3] {
            let payload = vec![0x12, 0x34, 0x56];
            let buf = Presentation::encode_data(pci, &payload);
            let (got_pci, got) = Presentation::decode_data(&buf).unwrap();
            assert_eq!(got_pci, pci);
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn data_large_payload_roundtrip() {
        let payload = vec![0x7Fu8; 500];
        let buf = Presentation::encode_data(3, &payload);
        let (pci, got) = Presentation::decode_data(&buf).unwrap();
        assert_eq!(pci, 3);
        assert_eq!(got, payload);
    }

    /// Build a CP-like PPDU with an arbitrary context-definition-list so we can
    /// exercise PCI learning with custom ordering / ids / extra contexts.
    fn build_cp_with_contexts(items: &[(u32, &[u32])], acse_pci_for_data: u32) -> Vec<u8> {
        let payload = vec![0xCC; 4];
        let mut w = BerWriter::new();
        w.write_tlv(TAG_CP, |cp| {
            write_mode_selector(cp);
            cp.write_tlv(TAG_NORMAL_MODE, |nm| {
                nm.write_tlv(TAG_PCD_LIST, |list| {
                    for (pci, arcs) in items {
                        write_context_definition(list, *pci, arcs);
                    }
                });
                write_fully_encoded_data(nm, acse_pci_for_data, &payload);
            });
        });
        w.into_bytes()
    }

    #[test]
    fn learns_pci_with_mms_first_and_swapped_ids() {
        // MMS listed first with id 7, ACSE second with id 9, plus an extra
        // unknown context. Mapping must be learned by OID, not position.
        let unknown: &[u32] = &[1, 3, 9999, 1];
        let buf = build_cp_with_contexts(
            &[
                (7, MMS_ABSTRACT_SYNTAX_ARCS),
                (9, ACSE_ABSTRACT_SYNTAX_ARCS),
                (11, unknown),
            ],
            9,
        );
        let (ctx, _payload) = Presentation::decode_cp(&buf).unwrap();
        assert_eq!(ctx.mms_pci, 7);
        assert_eq!(ctx.acse_pci, 9);
    }

    #[test]
    fn missing_mms_context_is_unoffered_error() {
        // Only an ACSE context — MMS abstract syntax was never advertised.
        let buf = build_cp_with_contexts(&[(1, ACSE_ABSTRACT_SYNTAX_ARCS)], 1);
        assert!(matches!(
            Presentation::decode_cp(&buf),
            Err(Error::PresentationAbstractSyntaxUnoffered { which: "mms" })
        ));
    }

    #[test]
    fn decode_cp_garbage_is_invalid() {
        assert!(matches!(
            Presentation::decode_cp(&[0x00, 0x01, 0x02]),
            Err(Error::PresentationInvalid)
        ));
    }

    #[test]
    fn decode_data_wrong_tag_is_invalid() {
        // A SEQUENCE, not fully-encoded-data.
        let mut w = BerWriter::new();
        w.write_tlv(Tag::SEQUENCE, |s| s.write_integer(Tag::INTEGER, 1));
        assert!(matches!(
            Presentation::decode_data(&w.into_bytes()),
            Err(Error::PresentationInvalid)
        ));
    }

    #[test]
    fn truncation_sweeps_never_panic() {
        let payload = vec![0x42; 40];
        let cp = Presentation::encode_cp(Some(&[0, 1]), Some(&[0, 1]), &payload);
        let data = Presentation::encode_data(3, &payload);
        for buf in [cp, data] {
            for len in 0..buf.len() {
                let _ = Presentation::decode_cp(&buf[..len]);
                let _ = Presentation::decode_cpa(&buf[..len]);
                let _ = Presentation::decode_data(&buf[..len]);
            }
        }
    }
}
