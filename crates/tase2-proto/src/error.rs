//! Error type for the sans-I/O TASE.2 domain layer.

use thiserror::Error;

/// Errors surfaced by the TASE.2 domain object layer.
///
/// `PartialEq` is derived: every variant wraps comparable data
/// ([`mms_proto::Error`] is `PartialEq`), so equality is well-defined and lets
/// tests assert on specific decode failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A protocol error bubbled up from `mms-proto` (e.g. an invalid
    /// `Identifier` or a malformed `Data` value).
    #[error("mms error: {0}")]
    Mms(#[from] mms_proto::Error),

    /// A decoded [`mms_proto::mms::Data`] value did not match the shape expected
    /// for the requested [`crate::PointKind`].
    #[error("unexpected data shape (expected {expected})")]
    UnexpectedDataShape {
        /// A short description of the shape that was expected.
        expected: &'static str,
    },

    /// A DataFlags octet could not be interpreted (e.g. a bit-string of the
    /// wrong width).
    #[error("invalid DataFlags encoding")]
    InvalidFlags,

    /// A state value was outside the 2-bit range `0..=3`.
    ///
    /// Only reachable through the public [`StateValue::from_code`] constructor:
    /// the internal decode paths mask the DataFlags octet to `0..=3` before
    /// building a [`StateValue`], so a value parsed off the wire never produces
    /// this error.
    ///
    /// [`StateValue::from_code`]: crate::value::StateValue::from_code
    /// [`StateValue`]: crate::value::StateValue
    #[error("invalid state value")]
    InvalidStateValue,

    /// A `DSTransferSet` MMS structure did not have the expected shape (wrong
    /// number of components, or a component of the wrong `Data` type).
    #[error("invalid DSTransferSet structure: {reason}")]
    InvalidTransferSet {
        /// A short description of what was malformed.
        reason: &'static str,
    },

    /// An `InformationReport` could not be interpreted as a TASE.2 transfer
    /// report (e.g. the access specification was not a `variableListName`, or a
    /// special member carried the wrong `Data` type).
    #[error("invalid transfer report: {reason}")]
    InvalidReport {
        /// A short description of what was malformed.
        reason: &'static str,
    },

    /// A device name was too long to derive its SBO/TAG companion variable
    /// without overflowing the MMS `Identifier` cap (`SIZE(1..32)`, see
    /// [`mms_proto::mms::MAX_IDENTIFIER_LEN`]). The reserved `_SBO` / `_TAG`
    /// suffix (4 chars) would push the result past 32 characters.
    #[error("device name too long: {name:?} cannot take a {suffix:?} suffix within 32 chars")]
    DeviceNameTooLong {
        /// The offending device name.
        name: String,
        /// The reserved suffix that could not be appended (`_SBO` / `_TAG`).
        suffix: &'static str,
    },

    /// A device control structure (operate value or device tag) did not match
    /// the shape expected for the requested [`crate::control::DeviceKind`] or
    /// the [`crate::control::DeviceTag`] wire format.
    #[error("invalid device control structure: {reason}")]
    InvalidControl {
        /// A short description of what was malformed.
        reason: &'static str,
    },
}

/// Result alias for the TASE.2 domain layer.
pub type Result<T, E = Error> = core::result::Result<T, E>;
