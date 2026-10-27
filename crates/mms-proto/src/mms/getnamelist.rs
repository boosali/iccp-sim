//! MMS `GetNameList` confirmed service (ConfirmedServiceRequest `[1]`).
//!
//! ```asn1
//! GetNameList-Request ::= SEQUENCE {
//!     objectClass     [0] ObjectClass,                -- CHOICE { basicObjectClass [0] INTEGER }
//!     objectScope     [1] CHOICE {
//!         vmdSpecific    [0] IMPLICIT NULL,
//!         domainSpecific [1] IMPLICIT Identifier,
//!         aaSpecific     [2] IMPLICIT NULL },
//!     continueAfter   [2] IMPLICIT Identifier OPTIONAL }
//!
//! GetNameList-Response ::= SEQUENCE {
//!     listOfIdentifier [0] IMPLICIT SEQUENCE OF Identifier,
//!     moreFollows      [1] IMPLICIT BOOLEAN DEFAULT TRUE }
//! ```
//!
//! `moreFollows` defaults to `TRUE`; an absent field on decode is treated as
//! `true` per the ASN.1 `DEFAULT`. We always encode it explicitly.

use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::ber::{decode_bool, decode_integer_i64};
use crate::mms::service::MmsService;
use crate::mms::varname::Identifier;
use crate::{Error, Result};

const TAG_OBJECT_CLASS: Tag = Tag::context_constructed(0);
const TAG_BASIC_OBJECT_CLASS: Tag = Tag::context(0);
const TAG_OBJECT_SCOPE: Tag = Tag::context_constructed(1);
const TAG_SCOPE_VMD: Tag = Tag::context(0);
const TAG_SCOPE_DOMAIN: Tag = Tag::context(1);
const TAG_SCOPE_AA: Tag = Tag::context(2);
const TAG_CONTINUE_AFTER: Tag = Tag::context(2);
const TAG_LIST_OF_IDENTIFIER: Tag = Tag::context_constructed(0);
const TAG_MORE_FOLLOWS: Tag = Tag::context(1);

/// `objectScope` selector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetNameListScope {
    /// `vmdSpecific [0] NULL`.
    VmdSpecific,
    /// `domainSpecific [1] Identifier`.
    DomainSpecific(Identifier),
    /// `aaSpecific [2] NULL`.
    AaSpecific,
}

/// A `GetNameList` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNameListRequest {
    /// `basicObjectClass` INTEGER (namedVariable=0, namedVariableList=2,
    /// domain=9, ...).
    pub object_class: u8,
    /// `objectScope`.
    pub scope: GetNameListScope,
    /// `continueAfter` for paginated enumeration.
    pub continue_after: Option<Identifier>,
}

/// A `GetNameList` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetNameListResponse {
    /// `listOfIdentifier`.
    pub identifiers: Vec<Identifier>,
    /// `moreFollows` (DEFAULT TRUE).
    pub more_follows: bool,
}

impl MmsService for GetNameListRequest {
    const REQUEST_TAG: u32 = 1;
    type Response = GetNameListResponse;

    fn encode_request(&self, w: &mut BerWriter) {
        // objectClass [0] { basicObjectClass [0] INTEGER }
        w.write_tlv(TAG_OBJECT_CLASS, |oc| {
            oc.write_integer(TAG_BASIC_OBJECT_CLASS, i64::from(self.object_class));
        });
        // objectScope [1] CHOICE
        w.write_tlv(TAG_OBJECT_SCOPE, |os| match &self.scope {
            GetNameListScope::VmdSpecific => os.write_null(TAG_SCOPE_VMD),
            GetNameListScope::AaSpecific => os.write_null(TAG_SCOPE_AA),
            GetNameListScope::DomainSpecific(id) => {
                id.encode(os, TAG_SCOPE_DOMAIN);
            }
        });
        if let Some(id) = &self.continue_after {
            id.encode(w, TAG_CONTINUE_AFTER);
        }
    }

    fn decode_request(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let mut object_class: Option<u8> = None;
        let mut scope: Option<GetNameListScope> = None;
        let mut continue_after: Option<Identifier> = None;

        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_OBJECT_CLASS {
                let mut ir = BerReader::new(c);
                let (it, ic) = ir.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                if it == TAG_BASIC_OBJECT_CLASS {
                    let v = decode_integer_i64(ic).map_err(|_| Error::MmsInvalidPdu)?;
                    object_class = Some(u8::try_from(v).map_err(|_| Error::MmsInvalidPdu)?);
                }
            } else if tag == TAG_OBJECT_SCOPE {
                let mut ir = BerReader::new(c);
                let (st, sc) = ir.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                scope = Some(if st == TAG_SCOPE_VMD {
                    GetNameListScope::VmdSpecific
                } else if st == TAG_SCOPE_AA {
                    GetNameListScope::AaSpecific
                } else if st == TAG_SCOPE_DOMAIN {
                    GetNameListScope::DomainSpecific(Identifier::decode(sc)?)
                } else {
                    return Err(Error::MmsInvalidPdu);
                });
            } else if tag == TAG_CONTINUE_AFTER {
                continue_after = Some(Identifier::decode(c)?);
            }
            // Unknown trailing context fields: skip (tolerant).
        }

        Ok(GetNameListRequest {
            object_class: object_class.ok_or(Error::MmsInvalidPdu)?,
            scope: scope.ok_or(Error::MmsInvalidPdu)?,
            continue_after,
        })
    }

    fn encode_response(resp: &Self::Response, w: &mut BerWriter) {
        w.write_tlv(TAG_LIST_OF_IDENTIFIER, |list| {
            for id in &resp.identifiers {
                id.encode(list, Tag::VISIBLE_STRING);
            }
        });
        w.write_bool(TAG_MORE_FOLLOWS, resp.more_follows);
    }

    fn decode_response(content: &[u8]) -> Result<Self::Response> {
        let mut r = BerReader::new(content);
        let mut identifiers: Option<Vec<Identifier>> = None;
        // DEFAULT TRUE: absent means true.
        let mut more_follows = true;

        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_LIST_OF_IDENTIFIER {
                let mut ir = BerReader::new(c);
                let mut ids = Vec::new();
                while !ir.done() {
                    let (_, ic) = ir.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                    ids.push(Identifier::decode(ic)?);
                }
                identifiers = Some(ids);
            } else if tag == TAG_MORE_FOLLOWS {
                more_follows = decode_bool(c).map_err(|_| Error::MmsInvalidPdu)?;
            }
        }

        Ok(GetNameListResponse {
            identifiers: identifiers.ok_or(Error::MmsInvalidPdu)?,
            more_follows,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt_req(req: &GetNameListRequest) -> GetNameListRequest {
        let mut w = BerWriter::new();
        req.encode_request(&mut w);
        GetNameListRequest::decode_request(&w.into_bytes()).unwrap()
    }

    fn rt_resp(resp: &GetNameListResponse) -> GetNameListResponse {
        let mut w = BerWriter::new();
        GetNameListRequest::encode_response(resp, &mut w);
        GetNameListRequest::decode_response(&w.into_bytes()).unwrap()
    }

    #[test]
    fn request_vmd_scope_no_continue() {
        let req = GetNameListRequest {
            object_class: 0,
            scope: GetNameListScope::VmdSpecific,
            continue_after: None,
        };
        assert_eq!(rt_req(&req), req);
    }

    #[test]
    fn request_domain_scope_with_continue() {
        let req = GetNameListRequest {
            object_class: 9,
            scope: GetNameListScope::DomainSpecific(Identifier::new("Dom1").unwrap()),
            continue_after: Some(Identifier::new("After").unwrap()),
        };
        assert_eq!(rt_req(&req), req);
    }

    #[test]
    fn request_aa_scope() {
        let req = GetNameListRequest {
            object_class: 2,
            scope: GetNameListScope::AaSpecific,
            continue_after: None,
        };
        assert_eq!(rt_req(&req), req);
    }

    #[test]
    fn response_more_follows_explicit() {
        for mf in [true, false] {
            let resp = GetNameListResponse {
                identifiers: vec![Identifier::new("A").unwrap(), Identifier::new("B").unwrap()],
                more_follows: mf,
            };
            assert_eq!(rt_resp(&resp), resp);
        }
    }

    #[test]
    fn response_absent_more_follows_defaults_true() {
        // Hand-build a response with only listOfIdentifier [0] (no moreFollows).
        let mut w = BerWriter::new();
        w.write_tlv(TAG_LIST_OF_IDENTIFIER, |list| {
            Identifier::new("Only")
                .unwrap()
                .encode(list, Tag::VISIBLE_STRING);
        });
        let resp = GetNameListRequest::decode_response(&w.into_bytes()).unwrap();
        assert!(resp.more_follows, "absent moreFollows must default to true");
        assert_eq!(resp.identifiers.len(), 1);
    }
}
