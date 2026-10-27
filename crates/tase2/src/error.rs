//! Error type for the async layer.

use thiserror::Error;

/// Errors surfaced by the async TASE.2 client and server.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An underlying I/O error from the transport.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A protocol error bubbled up from `mms-proto`.
    #[error("protocol error: {0}")]
    Protocol(#[from] mms_proto::Error),

    /// The association handshake failed or the association was torn down
    /// before (or instead of) reaching the data phase.
    #[error("association failed: {0:?}")]
    AssociationFailed(mms_proto::assoc::DisconnectReason),

    /// The driver task is gone; the connection is no longer usable.
    ///
    /// This covers both normal termination (e.g. the peer already completed a
    /// release, or the handle issued an abort) and abnormal loss of the driver.
    /// Any command issued after the association has closed resolves to this.
    #[error("driver shut down")]
    DriverGone,

    /// A request did not receive its matching response within the timeout.
    #[error("request timed out")]
    Timeout,

    /// The peer answered a confirmed request with a `ServiceError`.
    #[error("mms service error: class {class_tag} code {code}")]
    ServiceError {
        /// The `errorClass` CHOICE alternative tag.
        class_tag: u8,
        /// The INTEGER code carried by the chosen `errorClass` alternative.
        code: i64,
    },

    /// The peer rejected a confirmed request with a `RejectPDU`.
    #[error("request rejected by peer")]
    Rejected,

    /// A per-item MMS `DataAccessError` (`AccessResult::Failure` /
    /// `WriteResult::Failure`). The `code` is the MMS `DataAccessError` INTEGER;
    /// see [`crate::data_access_error`] for the well-known values.
    #[error("data access error: code {code}")]
    DataAccessError {
        /// The MMS `DataAccessError` code.
        code: i64,
    },

    /// A TASE.2 domain-layer error (value/quality decode, shape mismatch).
    #[error("tase2 domain error: {0}")]
    Domain(#[from] tase2_proto::Error),

    /// A response carried a different number of per-item results than the
    /// number of items requested (e.g. a `Read` answered with fewer or more
    /// `AccessResult`s than variables, or more than the supplied point kinds).
    #[error("response shape mismatch: expected {expected} results, got {got}")]
    ResponseShapeMismatch {
        /// The number of results expected (one per requested item / kind).
        expected: usize,
        /// The number of results the peer actually returned.
        got: usize,
    },

    /// A `Next_DSTransfer_Set` read returned the server's "no free instance"
    /// sentinel: every transfer-set instance in the domain is already claimed.
    #[error("no free DS transfer set: the server's pool is exhausted")]
    TransferSetsExhausted,

    /// A TLS error: handshake failure, invalid certificate, configuration
    /// error, etc. This variant is compiled unconditionally; it is only
    /// constructed by the code paths gated behind the `tls` feature.
    #[error("tls error: {0}")]
    Tls(String),
}

/// Result alias for the async layer.
pub type Result<T, E = Error> = core::result::Result<T, E>;
