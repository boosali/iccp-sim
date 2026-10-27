//! The [`MmsService`] trait and the `ConfirmedServiceRequest` /
//! `ConfirmedServiceResponse` dispatch enums.
//!
//! Each confirmed service implements [`MmsService`], which ties together the
//! context tag used inside the `ConfirmedServiceRequest` / `Response` CHOICE,
//! the associated `Response` type, and the four codec entry points. The
//! dispatch enums select the alternative on the wire and delegate to the
//! per-service codecs.

use crate::ber::tag::{Tag, TagClass};
use crate::ber::writer::BerWriter;
use crate::mms::getnamelist::GetNameListRequest;
use crate::mms::read::ReadRequest;
use crate::mms::varlist::{DefineNvlRequest, DeleteNvlRequest};
use crate::mms::write::WriteRequest;
use crate::Result;

/// A confirmed MMS service.
///
/// A request type implements this trait; its [`MmsService::Response`] associated
/// type names the matching response. Both share the same context [`REQUEST_TAG`]
/// inside their respective CHOICE — the wire is self-describing, so a response
/// is decoded purely from its tag without out-of-band knowledge of the original
/// request.
///
/// [`REQUEST_TAG`]: MmsService::REQUEST_TAG
pub trait MmsService: Sized {
    /// The context tag number used inside the `ConfirmedServiceRequest` /
    /// `ConfirmedServiceResponse` CHOICE.
    const REQUEST_TAG: u32;

    /// The matching response type.
    type Response: Sized;

    /// Encode the request body (the content of the service's context tag).
    fn encode_request(&self, w: &mut BerWriter);

    /// Decode the request body from the service tag's content bytes.
    fn decode_request(content: &[u8]) -> Result<Self>;

    /// Encode the response body.
    fn encode_response(resp: &Self::Response, w: &mut BerWriter);

    /// Decode the response body from the service tag's content bytes.
    fn decode_response(content: &[u8]) -> Result<Self::Response>;
}

// ---------------------------------------------------------------------------
// ConfirmedServiceRequest
// ---------------------------------------------------------------------------

/// The `ConfirmedServiceRequest` CHOICE (only the implemented services plus a
/// tolerant catch-all).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ConfirmedServiceRequest {
    /// `getNameList [1]`.
    GetNameList(GetNameListRequest),
    /// `read [4]`.
    Read(ReadRequest),
    /// `write [5]`.
    Write(WriteRequest),
    /// `defineNamedVariableList [11]`.
    DefineNamedVariableList(DefineNvlRequest),
    /// `deleteNamedVariableList [13]`.
    DeleteNamedVariableList(DeleteNvlRequest),
    /// A service we do not implement, preserved so the state machine can answer
    /// with a `RejectPDU`. Re-encodes to exactly the input bytes.
    Unsupported {
        /// The context tag number of the unhandled service.
        tag: u32,
        /// Whether the unhandled service alternative was constructed.
        constructed: bool,
        /// The raw service-body content bytes.
        bytes: Vec<u8>,
    },
}

impl ConfirmedServiceRequest {
    /// Encode this service request as a single CHOICE-alternative TLV.
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        match self {
            ConfirmedServiceRequest::GetNameList(req) => {
                encode_service::<GetNameListRequest>(w, req);
            }
            ConfirmedServiceRequest::Read(req) => encode_service::<ReadRequest>(w, req),
            ConfirmedServiceRequest::Write(req) => encode_service::<WriteRequest>(w, req),
            ConfirmedServiceRequest::DefineNamedVariableList(req) => {
                encode_service::<DefineNvlRequest>(w, req);
            }
            ConfirmedServiceRequest::DeleteNamedVariableList(req) => {
                encode_service::<DeleteNvlRequest>(w, req);
            }
            ConfirmedServiceRequest::Unsupported {
                tag,
                constructed,
                bytes,
            } => {
                let t = Tag {
                    class: TagClass::ContextSpecific,
                    constructed: *constructed,
                    number: *tag,
                };
                w.write_primitive(t, bytes);
            }
        }
    }

    /// Decode the service from a single CHOICE-alternative `(tag, content)`.
    pub(crate) fn decode(tag: Tag, content: &[u8]) -> Result<Self> {
        match tag.number {
            GetNameListRequest::REQUEST_TAG => Ok(ConfirmedServiceRequest::GetNameList(
                GetNameListRequest::decode_request(content)?,
            )),
            ReadRequest::REQUEST_TAG => Ok(ConfirmedServiceRequest::Read(
                ReadRequest::decode_request(content)?,
            )),
            WriteRequest::REQUEST_TAG => Ok(ConfirmedServiceRequest::Write(
                WriteRequest::decode_request(content)?,
            )),
            DefineNvlRequest::REQUEST_TAG => Ok(ConfirmedServiceRequest::DefineNamedVariableList(
                DefineNvlRequest::decode_request(content)?,
            )),
            DeleteNvlRequest::REQUEST_TAG => Ok(ConfirmedServiceRequest::DeleteNamedVariableList(
                DeleteNvlRequest::decode_request(content)?,
            )),
            other => Ok(ConfirmedServiceRequest::Unsupported {
                tag: other,
                constructed: tag.constructed,
                bytes: content.to_vec(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// ConfirmedServiceResponse
// ---------------------------------------------------------------------------

/// The `ConfirmedServiceResponse` CHOICE.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ConfirmedServiceResponse {
    /// `getNameList [1]`.
    GetNameList(crate::mms::getnamelist::GetNameListResponse),
    /// `read [4]`.
    Read(crate::mms::read::ReadResponse),
    /// `write [5]`.
    Write(crate::mms::write::WriteResponse),
    /// `defineNamedVariableList [11]`.
    DefineNamedVariableList(crate::mms::varlist::DefineNvlResponse),
    /// `deleteNamedVariableList [13]`.
    DeleteNamedVariableList(crate::mms::varlist::DeleteNvlResponse),
    /// A response for a service we do not implement, preserved verbatim.
    Unsupported {
        /// The context tag number of the unhandled service.
        tag: u32,
        /// Whether the unhandled service alternative was constructed.
        constructed: bool,
        /// The raw response-body content bytes.
        bytes: Vec<u8>,
    },
}

impl ConfirmedServiceResponse {
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        match self {
            ConfirmedServiceResponse::GetNameList(resp) => {
                encode_response::<GetNameListRequest>(w, resp);
            }
            ConfirmedServiceResponse::Read(resp) => encode_response::<ReadRequest>(w, resp),
            ConfirmedServiceResponse::Write(resp) => encode_response::<WriteRequest>(w, resp),
            ConfirmedServiceResponse::DefineNamedVariableList(resp) => {
                encode_response::<DefineNvlRequest>(w, resp);
            }
            ConfirmedServiceResponse::DeleteNamedVariableList(resp) => {
                encode_response::<DeleteNvlRequest>(w, resp);
            }
            ConfirmedServiceResponse::Unsupported {
                tag,
                constructed,
                bytes,
            } => {
                let t = Tag {
                    class: TagClass::ContextSpecific,
                    constructed: *constructed,
                    number: *tag,
                };
                w.write_primitive(t, bytes);
            }
        }
    }

    pub(crate) fn decode(tag: Tag, content: &[u8]) -> Result<Self> {
        match tag.number {
            GetNameListRequest::REQUEST_TAG => Ok(ConfirmedServiceResponse::GetNameList(
                GetNameListRequest::decode_response(content)?,
            )),
            ReadRequest::REQUEST_TAG => Ok(ConfirmedServiceResponse::Read(
                ReadRequest::decode_response(content)?,
            )),
            WriteRequest::REQUEST_TAG => Ok(ConfirmedServiceResponse::Write(
                WriteRequest::decode_response(content)?,
            )),
            DefineNvlRequest::REQUEST_TAG => Ok(ConfirmedServiceResponse::DefineNamedVariableList(
                DefineNvlRequest::decode_response(content)?,
            )),
            DeleteNvlRequest::REQUEST_TAG => Ok(ConfirmedServiceResponse::DeleteNamedVariableList(
                DeleteNvlRequest::decode_response(content)?,
            )),
            other => Ok(ConfirmedServiceResponse::Unsupported {
                tag: other,
                constructed: tag.constructed,
                bytes: content.to_vec(),
            }),
        }
    }
}

/// Encode a service request under its CHOICE tag.
///
/// `DefineNamedVariableList` / `DeleteNamedVariableList` and others are all
/// IMPLICIT-tagged SEQUENCEs, so the service tag is constructed and wraps the
/// body the service encoder produces.
fn encode_service<S: MmsService>(w: &mut BerWriter, req: &S) {
    let tag = Tag::context_constructed(S::REQUEST_TAG);
    w.write_tlv(tag, |inner| req.encode_request(inner));
}

fn encode_response<S: MmsService>(w: &mut BerWriter, resp: &S::Response) {
    let tag = Tag::context_constructed(S::REQUEST_TAG);
    w.write_tlv(tag, |inner| S::encode_response(resp, inner));
}
