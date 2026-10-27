//! Sans-I/O TASE.2 (IEC 60870-6 / ICCP) domain layer.
//!
//! This crate contains no `async`, no sockets and no clocks. It builds on
//! `mms-proto` to provide the TASE.2 domain model:
//!
//! * TASE.2 indication-point values ([`PointValue`]) and their MMS `Data`
//!   mapping, directed by a [`PointKind`]
//! * The [`Quality`] DataFlags octet and its `BitString` encoding
//! * Naming newtypes ([`DomainName`], [`PointName`], [`DataSetName`]) over the
//!   MMS [`Identifier`]
//! * [`DataSet`] definitions and their `DefineNamedVariableList` mapping
//!
//! The companion crate `tase2` ties these into a `tokio`-based client and
//! server.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

pub mod bilateral;
pub mod control;
pub mod dataset;
pub mod error;
pub mod ident;
pub mod names;
pub mod quality;
pub mod report;
pub mod reporting;
pub mod transfer_set;
pub mod value;

pub use bilateral::{is_protocol_internal, AccessRights, BilateralTable};
pub use control::{
    sbo_name, tag_name, CommandValue, ControlModel, DeviceKind, DeviceTag, TagValue,
};
pub use dataset::DataSet;
pub use error::{Error, Result};
pub use ident::{object_name, DataSetName, DomainName, PointName};
pub use quality::{Quality, Source, Validity};
pub use report::{
    build_information_report, decode_information_report, SpecialValues, TransferReport,
};
pub use reporting::{ReportAction, TransferSetScheduler};
pub use transfer_set::{DsConditions, DsTransferSet, TsDataSetName};
pub use value::{PointKind, PointValue, StateValue, TimeStamp};

// Re-export the MMS naming types this crate's public API speaks in, so callers
// do not need a separate `mms_proto` dependency for the common path.
pub use mms_proto::mms::{Identifier, ObjectName};
