//! The top-level [`MmsPdu`] CHOICE and its envelope types ([`ServiceError`],
//! [`RejectPdu`], [`UnconfirmedService`]).
//!
//! # MMSpdu CHOICE (context tags, all IMPLICIT)
//!
//! | Tag    | PDU                       |
//! |--------|---------------------------|
//! | `[0]`  | confirmed-RequestPDU      |
//! | `[1]`  | confirmed-ResponsePDU     |
//! | `[2]`  | confirmed-ErrorPDU        |
//! | `[3]`  | unconfirmed-PDU           |
//! | `[4]`  | rejectPDU                 |
//! | `[8]`  | initiate-RequestPDU       |
//! | `[9]`  | initiate-ResponsePDU      |
//! | `[10]` | initiate-ErrorPDU         |
//! | `[11]` | conclude-RequestPDU       |
//! | `[12]` | conclude-ResponsePDU      |
//! | `[13]` | conclude-ErrorPDU         |
//!
//! The beanit/libiec61850 ASN.1 module only lists conclude-RequestPDU `[11]`,
//! but ISO 9506-2 defines conclude-ResponsePDU `[12]` and conclude-ErrorPDU
//! `[13]` as well; we encode/decode all three so the Phase 6 state machine has
//! the full Conclude exchange available. `[11]`/`[12]` are IMPLICIT NULL.
//!
//! # confirmed-RequestPDU body
//! `SEQUENCE { invokeID Unsigned32, service ConfirmedServiceRequest }`. The
//! `invokeID` is a plain universal INTEGER, then the service CHOICE alternative
//! follows.

use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, TagClass};
use crate::ber::writer::BerWriter;
use crate::ber::{decode_integer_i64, decode_unsigned_u64};
use crate::mms::info_report::InformationReport;
use crate::mms::initiate::{InitiateRequest, InitiateResponse};
use crate::mms::service::{ConfirmedServiceRequest, ConfirmedServiceResponse};
use crate::{Error, Result};

// --- MMSpdu CHOICE tags -----------------------------------------------------

const TAG_CONFIRMED_REQUEST: u32 = 0;
const TAG_CONFIRMED_RESPONSE: u32 = 1;
const TAG_CONFIRMED_ERROR: u32 = 2;
const TAG_UNCONFIRMED: u32 = 3;
const TAG_REJECT: u32 = 4;
const TAG_INITIATE_REQUEST: u32 = 8;
const TAG_INITIATE_RESPONSE: u32 = 9;
const TAG_INITIATE_ERROR: u32 = 10;
const TAG_CONCLUDE_REQUEST: u32 = 11;
const TAG_CONCLUDE_RESPONSE: u32 = 12;
const TAG_CONCLUDE_ERROR: u32 = 13;

// --- Confirmed-ErrorPDU / RejectPDU field tags ------------------------------

const TAG_ERR_INVOKE_ID: Tag = Tag::context(0);
const TAG_ERR_SERVICE_ERROR_A: Tag = Tag::context_constructed(1);
const TAG_ERR_SERVICE_ERROR_B: Tag = Tag::context_constructed(2);
const TAG_SE_ERROR_CLASS: Tag = Tag::context_constructed(0);
const TAG_SE_ADDITIONAL_CODE: Tag = Tag::context(1);
const TAG_SE_ADDITIONAL_DESC: Tag = Tag::context(2);
const TAG_REJECT_ORIGINAL_INVOKE: Tag = Tag::context(0);
const TAG_UNCONFIRMED_INFO_REPORT: Tag = Tag::context_constructed(0);

// ---------------------------------------------------------------------------
// ServiceError
// ---------------------------------------------------------------------------

/// An MMS `ServiceError`.
///
/// `errorClass` is a CHOICE of single-INTEGER alternatives `[0]`..`[12]`; we
/// model it pragmatically as the alternative's context tag number plus the
/// INTEGER code it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// The `errorClass` CHOICE alternative tag (`vmd-state [0]` .. `others [12]`).
    pub class_tag: u8,
    /// The INTEGER code carried by the chosen `errorClass` alternative.
    pub code: i64,
    /// `additionalCode` INTEGER OPTIONAL.
    pub additional_code: Option<i64>,
    /// `additionalDescription` VisibleString OPTIONAL.
    pub additional_description: Option<String>,
}

impl ServiceError {
    fn encode(&self, w: &mut BerWriter) {
        // errorClass [0] { <class_tag> [n] INTEGER code }
        w.write_tlv(TAG_SE_ERROR_CLASS, |ec| {
            ec.write_integer(Tag::context(u32::from(self.class_tag)), self.code);
        });
        if let Some(ac) = self.additional_code {
            w.write_integer(TAG_SE_ADDITIONAL_CODE, ac);
        }
        if let Some(desc) = &self.additional_description {
            w.write_visible_string(TAG_SE_ADDITIONAL_DESC, desc);
        }
    }

    fn decode(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let mut class_tag = None;
        let mut code = None;
        let mut additional_code = None;
        let mut additional_description = None;

        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_SE_ERROR_CLASS {
                let mut ir = BerReader::new(c);
                let (ct, cc) = ir.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                if ct.class != TagClass::ContextSpecific {
                    return Err(Error::MmsInvalidPdu);
                }
                class_tag = Some(u8::try_from(ct.number).map_err(|_| Error::MmsInvalidPdu)?);
                code = Some(decode_integer_i64(cc).map_err(|_| Error::MmsInvalidPdu)?);
            } else if tag == TAG_SE_ADDITIONAL_CODE {
                additional_code = Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
            } else if tag == TAG_SE_ADDITIONAL_DESC {
                let s = crate::ber::decode_visible_string(c).map_err(|_| Error::MmsInvalidPdu)?;
                additional_description = Some(s.to_string());
            }
        }

        Ok(ServiceError {
            class_tag: class_tag.ok_or(Error::MmsInvalidPdu)?,
            code: code.ok_or(Error::MmsInvalidPdu)?,
            additional_code,
            additional_description,
        })
    }
}

// ---------------------------------------------------------------------------
// RejectPdu
// ---------------------------------------------------------------------------

/// An MMS `RejectPDU`.
///
/// `rejectReason` is a CHOICE of single-INTEGER alternatives `[1]`..`[11]`,
/// modelled pragmatically as the alternative's context tag (`reject_kind`) plus
/// the INTEGER reason code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectPdu {
    /// `originalInvokeID` OPTIONAL.
    pub original_invoke_id: Option<u32>,
    /// The `rejectReason` CHOICE alternative tag (1..=11).
    pub reject_kind: u8,
    /// The INTEGER reason carried by the chosen alternative.
    pub reason: i64,
}

impl RejectPdu {
    fn encode(&self, w: &mut BerWriter) {
        if let Some(id) = self.original_invoke_id {
            w.write_unsigned(TAG_REJECT_ORIGINAL_INVOKE, u64::from(id));
        }
        w.write_integer(Tag::context(u32::from(self.reject_kind)), self.reason);
    }

    fn decode(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let mut original_invoke_id = None;
        let mut reject_kind = None;
        let mut reason = None;

        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_REJECT_ORIGINAL_INVOKE {
                let v = decode_unsigned_u64(c).map_err(|_| Error::MmsInvalidPdu)?;
                original_invoke_id = Some(u32::try_from(v).map_err(|_| Error::MmsInvalidPdu)?);
            } else if tag.class == TagClass::ContextSpecific && tag.number >= 1 && tag.number <= 11
            {
                reject_kind = Some(u8::try_from(tag.number).map_err(|_| Error::MmsInvalidPdu)?);
                reason = Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
            }
        }

        Ok(RejectPdu {
            original_invoke_id,
            reject_kind: reject_kind.ok_or(Error::MmsInvalidPdu)?,
            reason: reason.ok_or(Error::MmsInvalidPdu)?,
        })
    }
}

// ---------------------------------------------------------------------------
// UnconfirmedService
// ---------------------------------------------------------------------------

/// The `UnconfirmedService` CHOICE — currently only `informationReport [0]`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum UnconfirmedService {
    /// `informationReport [0]`.
    InformationReport(InformationReport),
}

// ---------------------------------------------------------------------------
// MmsPdu
// ---------------------------------------------------------------------------

/// The top-level MMS PDU (`MMSpdu` CHOICE).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum MmsPdu {
    /// `confirmed-RequestPDU [0]`.
    ConfirmedRequest {
        /// `invokeID`.
        invoke_id: u32,
        /// The carried service request.
        service: ConfirmedServiceRequest,
    },
    /// `confirmed-ResponsePDU [1]`.
    ConfirmedResponse {
        /// `invokeID`.
        invoke_id: u32,
        /// The carried service response.
        service: ConfirmedServiceResponse,
    },
    /// `confirmed-ErrorPDU [2]`.
    ConfirmedError {
        /// `invokeID`.
        invoke_id: u32,
        /// The carried `ServiceError`.
        error: ServiceError,
    },
    /// `unconfirmed-PDU [3]`.
    Unconfirmed(UnconfirmedService),
    /// `rejectPDU [4]`.
    Reject(RejectPdu),
    /// `initiate-RequestPDU [8]`.
    InitiateRequest(InitiateRequest),
    /// `initiate-ResponsePDU [9]`.
    InitiateResponse(InitiateResponse),
    /// `initiate-ErrorPDU [10]`.
    InitiateError {
        /// The carried `ServiceError`.
        error: ServiceError,
    },
    /// `conclude-RequestPDU [11]` (IMPLICIT NULL).
    ConcludeRequest,
    /// `conclude-ResponsePDU [12]` (IMPLICIT NULL).
    ConcludeResponse,
    /// `conclude-ErrorPDU [13]`.
    ConcludeError {
        /// The carried `ServiceError`.
        error: ServiceError,
    },
}

impl MmsPdu {
    /// Encode this PDU into `w` as a single context-tagged TLV.
    pub fn encode(&self, w: &mut BerWriter) -> Result<()> {
        match self {
            MmsPdu::ConfirmedRequest { invoke_id, service } => {
                w.write_tlv(Tag::context_constructed(TAG_CONFIRMED_REQUEST), |body| {
                    body.write_unsigned(Tag::INTEGER, u64::from(*invoke_id));
                    service.encode(body);
                });
            }
            MmsPdu::ConfirmedResponse { invoke_id, service } => {
                w.write_tlv(Tag::context_constructed(TAG_CONFIRMED_RESPONSE), |body| {
                    body.write_unsigned(Tag::INTEGER, u64::from(*invoke_id));
                    service.encode(body);
                });
            }
            MmsPdu::ConfirmedError { invoke_id, error } => {
                w.write_tlv(Tag::context_constructed(TAG_CONFIRMED_ERROR), |body| {
                    body.write_unsigned(TAG_ERR_INVOKE_ID, u64::from(*invoke_id));
                    body.write_tlv(TAG_ERR_SERVICE_ERROR_B, |se| error.encode(se));
                });
            }
            MmsPdu::Unconfirmed(UnconfirmedService::InformationReport(report)) => {
                w.write_tlv(Tag::context_constructed(TAG_UNCONFIRMED), |body| {
                    body.write_tlv(TAG_UNCONFIRMED_INFO_REPORT, |ir| report.encode(ir));
                });
            }
            MmsPdu::Reject(reject) => {
                w.write_tlv(Tag::context_constructed(TAG_REJECT), |body| {
                    reject.encode(body);
                });
            }
            MmsPdu::InitiateRequest(req) => {
                w.write_tlv(Tag::context_constructed(TAG_INITIATE_REQUEST), |body| {
                    req.encode(body);
                });
            }
            MmsPdu::InitiateResponse(resp) => {
                w.write_tlv(Tag::context_constructed(TAG_INITIATE_RESPONSE), |body| {
                    resp.encode(body);
                });
            }
            MmsPdu::InitiateError { error } => {
                w.write_tlv(Tag::context_constructed(TAG_INITIATE_ERROR), |body| {
                    error.encode(body);
                });
            }
            MmsPdu::ConcludeRequest => {
                w.write_null(Tag::context(TAG_CONCLUDE_REQUEST));
            }
            MmsPdu::ConcludeResponse => {
                w.write_null(Tag::context(TAG_CONCLUDE_RESPONSE));
            }
            MmsPdu::ConcludeError { error } => {
                w.write_tlv(Tag::context_constructed(TAG_CONCLUDE_ERROR), |body| {
                    error.encode(body);
                });
            }
        }
        Ok(())
    }

    /// Decode an MMS PDU from `buf`.
    pub fn decode(buf: &[u8]) -> Result<MmsPdu> {
        let mut r = BerReader::new(buf);
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag.class != TagClass::ContextSpecific {
            return Err(Error::MmsInvalidPdu);
        }
        match tag.number {
            TAG_CONFIRMED_REQUEST => {
                let (invoke_id, service_tag, service_content) = decode_confirmed_envelope(content)?;
                Ok(MmsPdu::ConfirmedRequest {
                    invoke_id,
                    service: ConfirmedServiceRequest::decode(service_tag, service_content)?,
                })
            }
            TAG_CONFIRMED_RESPONSE => {
                let (invoke_id, service_tag, service_content) = decode_confirmed_envelope(content)?;
                Ok(MmsPdu::ConfirmedResponse {
                    invoke_id,
                    service: ConfirmedServiceResponse::decode(service_tag, service_content)?,
                })
            }
            TAG_CONFIRMED_ERROR => {
                let (invoke_id, error) = decode_confirmed_error(content)?;
                Ok(MmsPdu::ConfirmedError { invoke_id, error })
            }
            TAG_UNCONFIRMED => Ok(MmsPdu::Unconfirmed(decode_unconfirmed(content)?)),
            TAG_REJECT => Ok(MmsPdu::Reject(RejectPdu::decode(content)?)),
            TAG_INITIATE_REQUEST => Ok(MmsPdu::InitiateRequest(InitiateRequest::decode(content)?)),
            TAG_INITIATE_RESPONSE => {
                Ok(MmsPdu::InitiateResponse(InitiateResponse::decode(content)?))
            }
            TAG_INITIATE_ERROR => Ok(MmsPdu::InitiateError {
                error: ServiceError::decode(content)?,
            }),
            TAG_CONCLUDE_REQUEST => Ok(MmsPdu::ConcludeRequest),
            TAG_CONCLUDE_RESPONSE => Ok(MmsPdu::ConcludeResponse),
            TAG_CONCLUDE_ERROR => Ok(MmsPdu::ConcludeError {
                error: ServiceError::decode(content)?,
            }),
            other => Err(Error::MmsUnknownPduTag { tag: other }),
        }
    }
}

/// Decode a confirmed PDU envelope: `invokeID` INTEGER then the single service
/// CHOICE TLV. Returns `(invoke_id, service_tag, service_content)`.
fn decode_confirmed_envelope(content: &[u8]) -> Result<(u32, Tag, &[u8])> {
    let mut r = BerReader::new(content);
    let (id_tag, id_content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
    if id_tag != Tag::INTEGER {
        return Err(Error::MmsInvalidPdu);
    }
    let invoke_id =
        u32::try_from(decode_unsigned_u64(id_content).map_err(|_| Error::MmsInvalidPdu)?)
            .map_err(|_| Error::MmsInvalidPdu)?;
    let (service_tag, service_content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
    Ok((invoke_id, service_tag, service_content))
}

/// Decode a `Confirmed-ErrorPDU` body: `invokeID [0]`, optional
/// `modifierPosition [1]`, `serviceError`. Per ISO 9506-2 the serviceError sits
/// under `[2]`; the older outline used `[1]`. We accept either tag for the
/// service-error wrapper so we interoperate with both layouts.
fn decode_confirmed_error(content: &[u8]) -> Result<(u32, ServiceError)> {
    let mut r = BerReader::new(content);
    let mut invoke_id = None;
    let mut error = None;
    while !r.done() {
        let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag == TAG_ERR_INVOKE_ID {
            let v = decode_unsigned_u64(c).map_err(|_| Error::MmsInvalidPdu)?;
            invoke_id = Some(u32::try_from(v).map_err(|_| Error::MmsInvalidPdu)?);
        } else if tag == TAG_ERR_SERVICE_ERROR_A || tag == TAG_ERR_SERVICE_ERROR_B {
            error = Some(ServiceError::decode(c)?);
        }
        // modifierPosition [1] primitive (when serviceError is [2]) and unknown
        // fields: skip. Note [1] is ambiguous between modifierPosition
        // (primitive) and the legacy serviceError (constructed); we keyed the
        // serviceError branch on a constructed [1]/[2], and decode_integer is
        // not attempted for the primitive [1] modifierPosition (ignored).
    }
    Ok((
        invoke_id.ok_or(Error::MmsInvalidPdu)?,
        error.ok_or(Error::MmsInvalidPdu)?,
    ))
}

fn decode_unconfirmed(content: &[u8]) -> Result<UnconfirmedService> {
    let mut r = BerReader::new(content);
    while !r.done() {
        let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag == TAG_UNCONFIRMED_INFO_REPORT {
            return Ok(UnconfirmedService::InformationReport(
                InformationReport::decode(c)?,
            ));
        }
        // Other unconfirmed services: unsupported.
    }
    Err(Error::MmsInvalidPdu)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::data::Data;
    use crate::mms::getnamelist::{GetNameListRequest, GetNameListResponse, GetNameListScope};
    use crate::mms::read::{AccessResult, ReadRequest, ReadResponse};
    use crate::mms::varname::{
        Identifier, ObjectName, VariableAccessSpecification, VariableSpecification,
    };
    use crate::mms::write::{WriteResponse, WriteResult};

    fn roundtrip(pdu: &MmsPdu) -> MmsPdu {
        let mut w = BerWriter::new();
        pdu.encode(&mut w).unwrap();
        MmsPdu::decode(&w.into_bytes()).unwrap()
    }

    #[test]
    fn confirmed_request_getnamelist() {
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 42,
            service: ConfirmedServiceRequest::GetNameList(GetNameListRequest {
                object_class: 0,
                scope: GetNameListScope::VmdSpecific,
                continue_after: None,
            }),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn confirmed_response_getnamelist() {
        let pdu = MmsPdu::ConfirmedResponse {
            invoke_id: 7,
            service: ConfirmedServiceResponse::GetNameList(GetNameListResponse {
                identifiers: vec![Identifier::new("X").unwrap()],
                more_follows: false,
            }),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn confirmed_request_read_response() {
        let pdu = MmsPdu::ConfirmedResponse {
            invoke_id: 1,
            service: ConfirmedServiceResponse::Read(ReadResponse {
                access_results: vec![
                    AccessResult::Success(Data::Integer(1)),
                    AccessResult::Failure(2),
                ],
            }),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn confirmed_request_read() {
        let pdu = MmsPdu::ConfirmedRequest {
            invoke_id: 100,
            service: ConfirmedServiceRequest::Read(ReadRequest {
                spec_with_result: false,
                access: VariableAccessSpecification::ListOfVariable(vec![
                    VariableSpecification::Name(ObjectName::VmdSpecific(
                        Identifier::new("Tag1").unwrap(),
                    )),
                ]),
            }),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn write_response_pdu() {
        let pdu = MmsPdu::ConfirmedResponse {
            invoke_id: 9,
            service: ConfirmedServiceResponse::Write(WriteResponse {
                results: vec![WriteResult::Success, WriteResult::Failure(1)],
            }),
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn unsupported_service_roundtrips_bytes() {
        // status [0] is a service we do not implement; build it by hand inside
        // a confirmed request and verify it lands in Unsupported and re-encodes.
        let mut w = BerWriter::new();
        w.write_tlv(Tag::context_constructed(0), |body| {
            body.write_unsigned(Tag::INTEGER, 5);
            // service: status [0] primitive with content 0xAB.
            body.write_primitive(Tag::context(0), &[0xAB]);
        });
        let bytes = w.into_bytes();
        let pdu = MmsPdu::decode(&bytes).unwrap();
        match &pdu {
            MmsPdu::ConfirmedRequest { invoke_id, service } => {
                assert_eq!(*invoke_id, 5);
                assert_eq!(
                    service,
                    &ConfirmedServiceRequest::Unsupported {
                        tag: 0,
                        constructed: false,
                        bytes: vec![0xAB]
                    }
                );
            }
            other => panic!("expected ConfirmedRequest, got {other:?}"),
        }
        // Re-encode reproduces the original bytes.
        let mut w2 = BerWriter::new();
        pdu.encode(&mut w2).unwrap();
        assert_eq!(w2.into_bytes(), bytes);
    }

    #[test]
    fn confirmed_error_skips_modifier_position() {
        // Hand-build a Confirmed-ErrorPDU [2] whose body carries, in order:
        //   invokeID [0] INTEGER 3
        //   modifierPosition [1] (primitive) INTEGER 9   <- must be skipped
        //   serviceError [2] { errorClass [0] { access [7] INTEGER 1 } }
        // and assert it decodes with the serviceError intact and the
        // primitive modifierPosition silently ignored.
        let mut w = BerWriter::new();
        w.write_tlv(Tag::context_constructed(TAG_CONFIRMED_ERROR), |body| {
            body.write_unsigned(TAG_ERR_INVOKE_ID, 3);
            // modifierPosition [1] primitive INTEGER 9.
            body.write_integer(Tag::context(1), 9);
            // serviceError [2] constructed.
            body.write_tlv(TAG_ERR_SERVICE_ERROR_B, |se| {
                se.write_tlv(TAG_SE_ERROR_CLASS, |ec| {
                    ec.write_integer(Tag::context(7), 1);
                });
            });
        });
        let decoded = MmsPdu::decode(&w.into_bytes()).unwrap();
        match decoded {
            MmsPdu::ConfirmedError { invoke_id, error } => {
                assert_eq!(invoke_id, 3);
                assert_eq!(
                    error,
                    ServiceError {
                        class_tag: 7,
                        code: 1,
                        additional_code: None,
                        additional_description: None,
                    }
                );
            }
            other => panic!("expected ConfirmedError, got {other:?}"),
        }
    }

    #[test]
    fn reject_roundtrip() {
        for original in [Some(123u32), None] {
            let pdu = MmsPdu::Reject(RejectPdu {
                original_invoke_id: original,
                reject_kind: 1,
                reason: 2,
            });
            assert_eq!(roundtrip(&pdu), pdu);
        }
    }

    #[test]
    fn service_error_roundtrip() {
        for (ac, desc) in [(Some(7i64), Some("bad".to_string())), (None, None)] {
            let pdu = MmsPdu::ConfirmedError {
                invoke_id: 3,
                error: ServiceError {
                    class_tag: 7,
                    code: 1,
                    additional_code: ac,
                    additional_description: desc,
                },
            };
            assert_eq!(roundtrip(&pdu), pdu);
        }
    }

    #[test]
    fn initiate_request_response_roundtrip() {
        assert_eq!(
            roundtrip(&MmsPdu::InitiateRequest(InitiateRequest::default())),
            MmsPdu::InitiateRequest(InitiateRequest::default())
        );
        assert_eq!(
            roundtrip(&MmsPdu::InitiateResponse(InitiateResponse::default())),
            MmsPdu::InitiateResponse(InitiateResponse::default())
        );
    }

    #[test]
    fn initiate_error_roundtrip() {
        let pdu = MmsPdu::InitiateError {
            error: ServiceError {
                class_tag: 8,
                code: 0,
                additional_code: None,
                additional_description: None,
            },
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn conclude_pdus_roundtrip() {
        assert_eq!(roundtrip(&MmsPdu::ConcludeRequest), MmsPdu::ConcludeRequest);
        assert_eq!(
            roundtrip(&MmsPdu::ConcludeResponse),
            MmsPdu::ConcludeResponse
        );
        let ce = MmsPdu::ConcludeError {
            error: ServiceError {
                class_tag: 9,
                code: 0,
                additional_code: None,
                additional_description: None,
            },
        };
        assert_eq!(roundtrip(&ce), ce);
    }

    #[test]
    fn unconfirmed_information_report_roundtrip() {
        let pdu = MmsPdu::Unconfirmed(UnconfirmedService::InformationReport(InformationReport {
            spec: VariableAccessSpecification::VariableListName(ObjectName::VmdSpecific(
                Identifier::new("L").unwrap(),
            )),
            access_results: vec![AccessResult::Success(Data::Integer(99))],
        }));
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn unknown_pdu_tag_rejected() {
        // [5] is cancel-requestPDU per ISO, which we do not model.
        let mut w = BerWriter::new();
        w.write_tlv(Tag::context_constructed(5), |_| {});
        assert!(matches!(
            MmsPdu::decode(&w.into_bytes()),
            Err(Error::MmsUnknownPduTag { tag: 5 })
        ));
    }
}
