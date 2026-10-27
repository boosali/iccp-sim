//! MMS `Read` confirmed service (ConfirmedServiceRequest `[4]`), plus the
//! shared [`AccessResult`] type also used by `InformationReport`.
//!
//! ```asn1
//! Read-Request ::= SEQUENCE {
//!     specificationWithResult     [0] IMPLICIT BOOLEAN DEFAULT FALSE,
//!     variableAccessSpecification [1] VariableAccessSpecification }
//!
//! Read-Response ::= SEQUENCE {
//!     variableAccessSpecification [0] VariableAccessSpecification OPTIONAL,
//!     listOfAccessResult          [1] IMPLICIT SEQUENCE OF AccessResult }
//!
//! AccessResult ::= CHOICE {
//!     failure [0] IMPLICIT DataAccessError,   -- INTEGER
//!     success     Data }                       -- the Data CHOICE alternatives
//! ```
//!
//! `variableAccessSpecification [1]` in the request is EXPLICIT (it wraps the
//! `VariableAccessSpecification` CHOICE). In `AccessResult`, `success` is the
//! bare `Data` CHOICE (its own `[1]`/`[2]`/... context tag), while `failure`
//! is `[0]`.

use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::ber::{decode_bool, decode_integer_i64};
use crate::mms::data::Data;
use crate::mms::service::MmsService;
use crate::mms::varname::VariableAccessSpecification;
use crate::{Error, Result};

const TAG_SPEC_WITH_RESULT: Tag = Tag::context(0);
const TAG_REQ_VAS: Tag = Tag::context_constructed(1);
const TAG_RESP_VAS: Tag = Tag::context_constructed(0);
const TAG_LIST_OF_ACCESS_RESULT: Tag = Tag::context_constructed(1);
const TAG_ACCESS_FAILURE: Tag = Tag::context(0);

/// One entry of an MMS `listOfAccessResult`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum AccessResult {
    /// `failure [0] DataAccessError` (an INTEGER error code).
    Failure(i64),
    /// `success Data` — the read value.
    ///
    /// Note: [`Data::Unknown`] with `tag == 0` is *not* representable here. On
    /// the wire the context tag `[0]` always denotes `failure`, so a `Success`
    /// carrying `Data::Unknown { tag: 0, .. }` would encode identically to a
    /// `Failure` and round-trip back as `Failure`. The MMS `Data` CHOICE never
    /// assigns `[0]`, so this only arises from a hand-built value; `encode`
    /// debug-asserts against it.
    Success(Data),
}

impl AccessResult {
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        match self {
            AccessResult::Failure(code) => w.write_integer(TAG_ACCESS_FAILURE, *code),
            AccessResult::Success(data) => {
                debug_assert!(
                    !matches!(data, Data::Unknown { tag: 0, .. }),
                    "AccessResult::Success(Data::Unknown {{ tag: 0, .. }}) is not \
                     representable: wire tag [0] always decodes back as Failure"
                );
                data.encode(w);
            }
        }
    }

    pub(crate) fn decode(r: &mut BerReader<'_>) -> Result<Self> {
        // Peek the tag to distinguish failure [0] from a Data alternative.
        // We must re-read the same TLV either way; read it once, then dispatch
        // on the tag. failure is [0] primitive INTEGER; Data success uses
        // context tags 1..=17. The two ranges only collide if Data ever used
        // [0] — it does not.
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag == TAG_ACCESS_FAILURE {
            Ok(AccessResult::Failure(
                decode_integer_i64(content).map_err(|_| Error::MmsInvalidPdu)?,
            ))
        } else {
            // Re-interpret the TLV as a Data value.
            Ok(AccessResult::Success(super::data::Data::decode_tlv(
                tag, content,
            )?))
        }
    }
}

/// A `Read` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    /// `specificationWithResult` (DEFAULT FALSE).
    pub spec_with_result: bool,
    /// `variableAccessSpecification`.
    pub access: VariableAccessSpecification,
}

/// A `Read` response.
#[derive(Debug, Clone, PartialEq)]
pub struct ReadResponse {
    /// `listOfAccessResult`.
    pub access_results: Vec<AccessResult>,
}

impl MmsService for ReadRequest {
    const REQUEST_TAG: u32 = 4;
    type Response = ReadResponse;

    fn encode_request(&self, w: &mut BerWriter) {
        // specificationWithResult [0] BOOLEAN DEFAULT FALSE — emit only if true
        // would still round-trip, but we always emit for clarity of intent.
        if self.spec_with_result {
            w.write_bool(TAG_SPEC_WITH_RESULT, true);
        }
        // variableAccessSpecification [1] (EXPLICIT wrapper around the CHOICE).
        w.write_tlv(TAG_REQ_VAS, |inner| self.access.encode(inner));
    }

    fn decode_request(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let mut spec_with_result = false;
        let mut access: Option<VariableAccessSpecification> = None;

        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_SPEC_WITH_RESULT {
                spec_with_result = decode_bool(c).map_err(|_| Error::MmsInvalidPdu)?;
            } else if tag == TAG_REQ_VAS {
                let mut ir = BerReader::new(c);
                access = Some(VariableAccessSpecification::decode(&mut ir)?);
            }
        }

        Ok(ReadRequest {
            spec_with_result,
            access: access.ok_or(Error::MmsInvalidPdu)?,
        })
    }

    fn encode_response(resp: &Self::Response, w: &mut BerWriter) {
        // variableAccessSpecification [0] OPTIONAL is omitted; we only emit the
        // listOfAccessResult [1].
        w.write_tlv(TAG_LIST_OF_ACCESS_RESULT, |list| {
            for ar in &resp.access_results {
                ar.encode(list);
            }
        });
    }

    fn decode_response(content: &[u8]) -> Result<Self::Response> {
        let mut r = BerReader::new(content);
        let mut access_results: Option<Vec<AccessResult>> = None;

        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_LIST_OF_ACCESS_RESULT {
                let mut ir = BerReader::new(c);
                let mut results = Vec::new();
                while !ir.done() {
                    results.push(AccessResult::decode(&mut ir)?);
                }
                access_results = Some(results);
            } else if tag == TAG_RESP_VAS {
                // Optional echoed access spec: accepted and ignored.
            }
        }

        Ok(ReadResponse {
            access_results: access_results.ok_or(Error::MmsInvalidPdu)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::varname::{Identifier, ObjectName, VariableSpecification};

    fn sample_access() -> VariableAccessSpecification {
        VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
            ObjectName::VmdSpecific(Identifier::new("V1").unwrap()),
        )])
    }

    #[test]
    fn request_roundtrip_spec_true() {
        let req = ReadRequest {
            spec_with_result: true,
            access: sample_access(),
        };
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        assert_eq!(ReadRequest::decode_request(&w.into_bytes()).unwrap(), req);
    }

    #[test]
    fn request_roundtrip_spec_false() {
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::VariableListName(ObjectName::DomainSpecific {
                domain: Identifier::new("D").unwrap(),
                item: Identifier::new("L").unwrap(),
            }),
        };
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        assert_eq!(ReadRequest::decode_request(&w.into_bytes()).unwrap(), req);
    }

    #[test]
    fn response_mixed_results() {
        let resp = ReadResponse {
            access_results: vec![
                AccessResult::Success(Data::Integer(42)),
                AccessResult::Failure(10),
                AccessResult::Success(Data::VisibleString("ok".to_string())),
                AccessResult::Success(Data::Structure(vec![
                    Data::Boolean(true),
                    Data::Unsigned(7),
                ])),
            ],
        };
        let mut w = BerWriter::new();
        ReadRequest::encode_response(&resp, &mut w);
        assert_eq!(ReadRequest::decode_response(&w.into_bytes()).unwrap(), resp);
    }
}
