//! MMS `Write` confirmed service (ConfirmedServiceRequest `[5]`).
//!
//! ```asn1
//! Write-Request ::= SEQUENCE {
//!     variableAccessSpecification     VariableAccessSpecification,
//!     listOfData                      [0] IMPLICIT SEQUENCE OF Data }
//!
//! Write-Response ::= SEQUENCE OF CHOICE {
//!     failure [0] IMPLICIT DataAccessError,   -- INTEGER
//!     success [1] IMPLICIT NULL }
//! ```
//!
//! Note the request's `variableAccessSpecification` is **untagged** (the bare
//! CHOICE, whose alternatives carry `[0]`/`[1]`), unlike `Read-Request` where
//! it sits under an EXPLICIT `[1]`.

use crate::ber::decode_integer_i64;
use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::mms::data::Data;
use crate::mms::service::MmsService;
use crate::mms::varname::VariableAccessSpecification;
use crate::{Error, Result};

const TAG_LIST_OF_DATA: Tag = Tag::context_constructed(0);
const TAG_WRITE_FAILURE: Tag = Tag::context(0);
const TAG_WRITE_SUCCESS: Tag = Tag::context(1);

/// One entry of a `Write-Response`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteResult {
    /// `failure [0] DataAccessError`.
    Failure(i64),
    /// `success [1] NULL`.
    Success,
}

impl WriteResult {
    fn encode(&self, w: &mut BerWriter) {
        match self {
            WriteResult::Failure(code) => w.write_integer(TAG_WRITE_FAILURE, *code),
            WriteResult::Success => w.write_null(TAG_WRITE_SUCCESS),
        }
    }

    fn decode(r: &mut BerReader<'_>) -> Result<Self> {
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag == TAG_WRITE_FAILURE {
            Ok(WriteResult::Failure(
                decode_integer_i64(content).map_err(|_| Error::MmsInvalidPdu)?,
            ))
        } else if tag == TAG_WRITE_SUCCESS {
            Ok(WriteResult::Success)
        } else {
            Err(Error::MmsInvalidPdu)
        }
    }
}

/// A `Write` request.
#[derive(Debug, Clone, PartialEq)]
pub struct WriteRequest {
    /// `variableAccessSpecification`.
    pub access: VariableAccessSpecification,
    /// `listOfData`.
    pub data: Vec<Data>,
}

/// A `Write` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    /// One result per written variable.
    pub results: Vec<WriteResult>,
}

impl MmsService for WriteRequest {
    const REQUEST_TAG: u32 = 5;
    type Response = WriteResponse;

    fn encode_request(&self, w: &mut BerWriter) {
        // variableAccessSpecification (untagged CHOICE).
        self.access.encode(w);
        // listOfData [0] SEQUENCE OF Data.
        w.write_tlv(TAG_LIST_OF_DATA, |list| {
            for d in &self.data {
                d.encode(list);
            }
        });
    }

    fn decode_request(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        // First element is the VariableAccessSpecification CHOICE ([0] or [1]).
        let access = VariableAccessSpecification::decode(&mut r)?;
        // Then listOfData [0].
        let mut data = None;
        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_LIST_OF_DATA {
                let mut ir = BerReader::new(c);
                let mut items = Vec::new();
                while !ir.done() {
                    items.push(Data::decode(&mut ir)?);
                }
                data = Some(items);
            }
        }
        Ok(WriteRequest {
            access,
            data: data.ok_or(Error::MmsInvalidPdu)?,
        })
    }

    fn encode_response(resp: &Self::Response, w: &mut BerWriter) {
        // Write-Response is a bare SEQUENCE OF CHOICE — the response content is
        // the concatenation of the result TLVs (the outer SEQUENCE/CHOICE tag
        // is the ConfirmedServiceResponse [5] wrapper supplied by the caller).
        for r in &resp.results {
            r.encode(w);
        }
    }

    fn decode_response(content: &[u8]) -> Result<Self::Response> {
        let mut r = BerReader::new(content);
        let mut results = Vec::new();
        while !r.done() {
            results.push(WriteResult::decode(&mut r)?);
        }
        Ok(WriteResponse { results })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::varname::{Identifier, ObjectName, VariableSpecification};

    fn sample_access() -> VariableAccessSpecification {
        VariableAccessSpecification::ListOfVariable(vec![
            VariableSpecification::Name(ObjectName::VmdSpecific(Identifier::new("A").unwrap())),
            VariableSpecification::Name(ObjectName::VmdSpecific(Identifier::new("B").unwrap())),
        ])
    }

    #[test]
    fn request_roundtrip() {
        let req = WriteRequest {
            access: sample_access(),
            data: vec![Data::Integer(1), Data::Boolean(true)],
        };
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        assert_eq!(WriteRequest::decode_request(&w.into_bytes()).unwrap(), req);
    }

    #[test]
    fn response_mixed_results() {
        let resp = WriteResponse {
            results: vec![
                WriteResult::Success,
                WriteResult::Failure(3),
                WriteResult::Success,
            ],
        };
        let mut w = BerWriter::new();
        WriteRequest::encode_response(&resp, &mut w);
        assert_eq!(
            WriteRequest::decode_response(&w.into_bytes()).unwrap(),
            resp
        );
    }
}
