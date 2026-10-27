//! MMS named-variable-list services: `DefineNamedVariableList` `[11]` and
//! `DeleteNamedVariableList` `[13]`.
//!
//! ```asn1
//! DefineNamedVariableList-Request ::= SEQUENCE {
//!     variableListName    ObjectName,
//!     listOfVariable      [0] IMPLICIT SEQUENCE OF SEQUENCE {
//!         variableSpecification   VariableSpecification,
//!         alternateAccess         [5] IMPLICIT AlternateAccess OPTIONAL } }
//! DefineNamedVariableList-Response ::= NULL
//!
//! DeleteNamedVariableList-Request ::= SEQUENCE {
//!     scopeOfDelete           [0] IMPLICIT INTEGER DEFAULT 0,
//!     listOfVariableListName  [1] IMPLICIT SEQUENCE OF ObjectName OPTIONAL,
//!     domainName              [2] CHOICE { ... } OPTIONAL }
//! DeleteNamedVariableList-Response ::= SEQUENCE {
//!     numberMatched   [0] IMPLICIT Unsigned32,
//!     numberDeleted   [1] IMPLICIT Unsigned32 }
//! ```

use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::ber::{decode_integer_i64, decode_unsigned_u64};
use crate::mms::service::MmsService;
use crate::mms::varname::{ObjectName, VariableSpecification};
use crate::{Error, Result};

const TAG_DEFINE_LIST_OF_VARIABLE: Tag = Tag::context_constructed(0);
const TAG_DELETE_SCOPE: Tag = Tag::context(0);
const TAG_DELETE_LIST_OF_NAME: Tag = Tag::context_constructed(1);
const TAG_DELETE_NUM_MATCHED: Tag = Tag::context(0);
const TAG_DELETE_NUM_DELETED: Tag = Tag::context(1);

// ---------------------------------------------------------------------------
// DefineNamedVariableList
// ---------------------------------------------------------------------------

/// A `DefineNamedVariableList` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefineNvlRequest {
    /// `variableListName`.
    pub name: ObjectName,
    /// `listOfVariable`.
    pub variables: Vec<VariableSpecification>,
}

/// A `DefineNamedVariableList` response — the ASN.1 type is `NULL`, so there
/// are no fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DefineNvlResponse;

impl MmsService for DefineNvlRequest {
    const REQUEST_TAG: u32 = 11;
    type Response = DefineNvlResponse;

    fn encode_request(&self, w: &mut BerWriter) {
        // variableListName (untagged ObjectName CHOICE).
        self.name.encode(w);
        // listOfVariable [0] SEQUENCE OF SEQUENCE { variableSpecification, ... }
        w.write_tlv(TAG_DEFINE_LIST_OF_VARIABLE, |list| {
            for v in &self.variables {
                list.write_tlv(Tag::SEQUENCE, |item| v.encode(item));
            }
        });
    }

    fn decode_request(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let name = ObjectName::decode(&mut r)?;
        let mut variables = None;
        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_DEFINE_LIST_OF_VARIABLE {
                let mut ir = BerReader::new(c);
                let mut vars = Vec::new();
                while !ir.done() {
                    let (item_tag, item) = ir.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                    if item_tag != Tag::SEQUENCE {
                        return Err(Error::MmsInvalidPdu);
                    }
                    let mut vr = BerReader::new(item);
                    vars.push(VariableSpecification::decode(&mut vr)?);
                }
                variables = Some(vars);
            }
        }
        Ok(DefineNvlRequest {
            name,
            variables: variables.ok_or(Error::MmsInvalidPdu)?,
        })
    }

    fn encode_response(_resp: &Self::Response, _w: &mut BerWriter) {
        // DefineNamedVariableList-Response ::= NULL — encoded as an empty
        // ConfirmedServiceResponse [11] body (the wrapper is the caller's).
    }

    fn decode_response(_content: &[u8]) -> Result<Self::Response> {
        Ok(DefineNvlResponse)
    }
}

// ---------------------------------------------------------------------------
// DeleteNamedVariableList
// ---------------------------------------------------------------------------

/// A `DeleteNamedVariableList` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteNvlRequest {
    /// `scopeOfDelete` (DEFAULT 0). `None` means absent (the default).
    pub scope_of_delete: Option<i64>,
    /// `listOfVariableListName`.
    pub names: Vec<ObjectName>,
}

/// A `DeleteNamedVariableList` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteNvlResponse {
    /// `numberMatched`.
    pub number_matched: u32,
    /// `numberDeleted`.
    pub number_deleted: u32,
}

impl MmsService for DeleteNvlRequest {
    const REQUEST_TAG: u32 = 13;
    type Response = DeleteNvlResponse;

    fn encode_request(&self, w: &mut BerWriter) {
        if let Some(scope) = self.scope_of_delete {
            w.write_integer(TAG_DELETE_SCOPE, scope);
        }
        if !self.names.is_empty() {
            w.write_tlv(TAG_DELETE_LIST_OF_NAME, |list| {
                for n in &self.names {
                    n.encode(list);
                }
            });
        }
    }

    fn decode_request(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let mut scope_of_delete = None;
        let mut names = Vec::new();
        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_DELETE_SCOPE {
                scope_of_delete = Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
            } else if tag == TAG_DELETE_LIST_OF_NAME {
                let mut ir = BerReader::new(c);
                while !ir.done() {
                    names.push(ObjectName::decode(&mut ir)?);
                }
            }
            // domainName [2] and unknown fields: skip (tolerant).
        }
        Ok(DeleteNvlRequest {
            scope_of_delete,
            names,
        })
    }

    fn encode_response(resp: &Self::Response, w: &mut BerWriter) {
        w.write_unsigned(TAG_DELETE_NUM_MATCHED, u64::from(resp.number_matched));
        w.write_unsigned(TAG_DELETE_NUM_DELETED, u64::from(resp.number_deleted));
    }

    fn decode_response(content: &[u8]) -> Result<Self::Response> {
        let mut r = BerReader::new(content);
        let mut number_matched = 0u32;
        let mut number_deleted = 0u32;
        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_DELETE_NUM_MATCHED {
                let v = decode_unsigned_u64(c).map_err(|_| Error::MmsInvalidPdu)?;
                number_matched = u32::try_from(v).map_err(|_| Error::MmsInvalidPdu)?;
            } else if tag == TAG_DELETE_NUM_DELETED {
                let v = decode_unsigned_u64(c).map_err(|_| Error::MmsInvalidPdu)?;
                number_deleted = u32::try_from(v).map_err(|_| Error::MmsInvalidPdu)?;
            }
        }
        Ok(DeleteNvlResponse {
            number_matched,
            number_deleted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::varname::Identifier;

    #[test]
    fn define_request_roundtrip() {
        let req = DefineNvlRequest {
            name: ObjectName::DomainSpecific {
                domain: Identifier::new("D").unwrap(),
                item: Identifier::new("List").unwrap(),
            },
            variables: vec![
                VariableSpecification::Name(ObjectName::VmdSpecific(Identifier::new("A").unwrap())),
                VariableSpecification::Name(ObjectName::VmdSpecific(Identifier::new("B").unwrap())),
            ],
        };
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        assert_eq!(
            DefineNvlRequest::decode_request(&w.into_bytes()).unwrap(),
            req
        );
    }

    #[test]
    fn define_response_is_null() {
        let mut w = BerWriter::new();
        DefineNvlRequest::encode_response(&DefineNvlResponse, &mut w);
        assert!(w.into_bytes().is_empty());
        assert_eq!(
            DefineNvlRequest::decode_response(&[]).unwrap(),
            DefineNvlResponse
        );
    }

    #[test]
    fn delete_request_roundtrip_with_scope() {
        let req = DeleteNvlRequest {
            scope_of_delete: Some(1),
            names: vec![
                ObjectName::VmdSpecific(Identifier::new("L1").unwrap()),
                ObjectName::AaSpecific(Identifier::new("L2").unwrap()),
            ],
        };
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        assert_eq!(
            DeleteNvlRequest::decode_request(&w.into_bytes()).unwrap(),
            req
        );
    }

    #[test]
    fn delete_request_roundtrip_absent_scope_empty_names() {
        let req = DeleteNvlRequest {
            scope_of_delete: None,
            names: vec![],
        };
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        assert_eq!(
            DeleteNvlRequest::decode_request(&w.into_bytes()).unwrap(),
            req
        );
    }

    #[test]
    fn delete_response_roundtrip() {
        let resp = DeleteNvlResponse {
            number_matched: 5,
            number_deleted: 3,
        };
        let mut w = BerWriter::new();
        DeleteNvlRequest::encode_response(&resp, &mut w);
        assert_eq!(
            DeleteNvlRequest::decode_response(&w.into_bytes()).unwrap(),
            resp
        );
    }
}
