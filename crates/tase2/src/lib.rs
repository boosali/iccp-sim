//! Async TASE.2 (IEC 60870-6 / ICCP) client and server on tokio.
//!
//! This crate provides the async runtime layer for TASE.2, built on top of
//! `mms-proto` and `tase2-proto`. It exposes:
//!
//! * TCP (and optionally TLS) transport using `tokio`
//! * Async [`Tase2Client`] and [`Tase2Server`] handles
//! * An [`EventHandler`] observer trait for connection lifecycle events
//!
//! The async runtime is concentrated in a single driver task per connection;
//! the protocol logic itself lives in the sans-I/O `mms-proto` crate. Enable
//! the `tls` feature for TLS support via `tokio-rustls`.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations, rust_2018_idioms)]

mod client;
mod control_server;
pub mod data_access_error;
mod driver;
mod error;
mod handler;
mod provider;
mod reporter;
mod serve;
mod server;
mod transport;

#[cfg(feature = "tls")]
pub mod tls;

pub use client::Tase2Client;
pub use control_server::{ControlPoint, DEFAULT_SELECT_TIMEOUT};
pub use error::{Error, Result};
pub use handler::{DefaultLoggingHandler, EventHandler, NoopHandler};
pub use provider::{
    ControlHandler, DataProvider, MapControlHandler, MapDataProvider, RejectAllControl,
    OBJECT_CLASS_DOMAIN, OBJECT_CLASS_NAMED_VARIABLE, OBJECT_CLASS_NAMED_VARIABLE_LIST,
};
pub use reporter::{run_reporting, TransferSetManager, DEFAULT_POLL_INTERVAL, DEFAULT_POOL_SIZE};
pub use serve::{
    serve_connection, serve_connection_control, serve_connection_full, serve_connection_opts,
    serve_connection_with_reports, serve_connection_with_reports_interval,
    serve_connection_with_reports_interval_control, ServeOptions,
};
pub use server::{ServerConnection, Tase2Server, UnsolicitedSender};
#[cfg(feature = "tls")]
pub use transport::DEFAULT_TLS_PORT;
pub use transport::{Transport, DEFAULT_PORT};

#[cfg(feature = "tls")]
pub use tls::{
    client_config_with_client_cert, client_config_with_roots, fingerprint_sha256_of_pem_file,
    load_certs, load_private_key, parse_hex_fingerprint, root_store_from_pem_files,
    server_config_requiring_client_cert, server_config_single_cert, tls_client_connect,
    tls_client_connect_with, CertificateChain, ClientCertPolicy, CustomVerifierFn, TlsClient,
    TlsServer, TlsServerConfig, TlsServerConnection, VerifyError,
};

// The underlying protocol crates, for users who need the full type surface.
pub use mms_proto as mms;
pub use tase2_proto as proto;

// Curated re-exports of the TASE.2 domain types used through the async API.
pub use tase2_proto::names;
pub use tase2_proto::{
    object_name, AccessRights, BilateralTable, DataSet, DataSetName, DomainName, PointKind,
    PointName, PointValue, Quality, Source, StateValue, TimeStamp, Validity,
};

// Block-5 device-control domain types.
pub use tase2_proto::{CommandValue, ControlModel, DeviceKind, DeviceTag, TagValue};

// Block-2 DS-transfer-set / reporting domain types.
pub use tase2_proto::report::{SpecialValues, TransferReport};
pub use tase2_proto::reporting::{ReportAction, TransferSetScheduler};
pub use tase2_proto::transfer_set::{DsConditions, DsTransferSet, TsDataSetName};

// Curated re-exports of the key `mms-proto` types users interact with through
// the async API, so common code does not need to reach into `tase2::mms::*`.
pub use mms_proto::assoc::{AssocConfig, DisconnectReason, Role, State};
pub use mms_proto::mms::{
    AccessResult, ConfirmedServiceRequest, ConfirmedServiceResponse, Data, DefineNvlRequest,
    DefineNvlResponse, DeleteNvlRequest, DeleteNvlResponse, GetNameListRequest,
    GetNameListResponse, Identifier, InformationReport, MmsPdu, ObjectName, ReadRequest,
    ReadResponse, RejectPdu, ServiceError, UnconfirmedService, VariableAccessSpecification,
    VariableSpecification, WriteRequest, WriteResponse, WriteResult,
};
