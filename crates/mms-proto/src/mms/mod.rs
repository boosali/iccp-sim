//! The MMS (ISO 9506) application layer: PDUs and confirmed/unconfirmed
//! services.
//!
//! This layer rides on top of the OSI upper layers ([`crate::osi`]) and is
//! driven by the association state machine (Phase 6). It is a pure BER codec
//! with no I/O.
//!
//! # Module layout
//!
//! | Module          | Contents                                              |
//! |-----------------|-------------------------------------------------------|
//! | [`pdu`]         | [`MmsPdu`] top-level CHOICE, `ServiceError`, `RejectPdu` |
//! | [`service`]     | [`MmsService`] trait + `ConfirmedService*` dispatch   |
//! | [`varname`]     | `Identifier`, `ObjectName`, `Variable*`               |
//! | [`data`]        | the recursive [`Data`] value model                    |
//! | [`initiate`]    | Initiate request/response PDUs                        |
//! | [`getnamelist`] | GetNameList service                                   |
//! | [`read`]        | Read service + `AccessResult`                         |
//! | [`mod@write`]   | Write service                                         |
//! | [`varlist`]     | Define/Delete NamedVariableList services              |
//! | [`info_report`] | InformationReport (unconfirmed)                       |
//!
//! # Tolerant decode
//! Unknown optional context fields are skipped; unsupported service tags decode
//! to an `Unsupported`/`Unknown` variant that re-encodes to the input bytes;
//! structural violations return a typed [`crate::Error`]. The recursive `Data`
//! decoder is depth-capped so a "Data bomb" errors rather than overflowing the
//! stack.

pub mod data;
pub mod getnamelist;
pub mod info_report;
pub mod initiate;
pub mod pdu;
pub mod read;
pub mod service;
pub mod varlist;
pub mod varname;
pub mod write;

#[cfg(test)]
mod proptests;

pub use data::{Data, MAX_DATA_DEPTH};
pub use getnamelist::{GetNameListRequest, GetNameListResponse, GetNameListScope};
pub use info_report::InformationReport;
pub use initiate::{InitiateRequest, InitiateResponse};
pub use pdu::{MmsPdu, RejectPdu, ServiceError, UnconfirmedService};
pub use read::{AccessResult, ReadRequest, ReadResponse};
pub use service::{ConfirmedServiceRequest, ConfirmedServiceResponse, MmsService};
pub use varlist::{DefineNvlRequest, DefineNvlResponse, DeleteNvlRequest, DeleteNvlResponse};
pub use varname::{
    Identifier, ObjectName, VariableAccessSpecification, VariableSpecification, MAX_IDENTIFIER_LEN,
};
pub use write::{WriteRequest, WriteResponse, WriteResult};
