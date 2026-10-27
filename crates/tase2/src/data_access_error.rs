//! Well-known MMS `DataAccessError` INTEGER codes (ISO 9506-2).
//!
//! These are the codes carried by `AccessResult::Failure` (Read /
//! InformationReport) and `WriteResult::Failure` (Write), surfaced to callers
//! as [`crate::Error::DataAccessError`] and returned by a
//! [`crate::DataProvider`] to signal per-item failures.

/// `object-invalidated` (0).
pub const OBJECT_INVALIDATED: i64 = 0;
/// `hardware-fault` (1).
pub const HARDWARE_FAULT: i64 = 1;
/// `temporarily-unavailable` (2).
pub const TEMPORARILY_UNAVAILABLE: i64 = 2;
/// `object-access-denied` (3).
pub const OBJECT_ACCESS_DENIED: i64 = 3;
/// `object-undefined` (4).
pub const OBJECT_UNDEFINED: i64 = 4;
/// `invalid-address` (5).
pub const INVALID_ADDRESS: i64 = 5;
/// `type-unsupported` (6).
pub const TYPE_UNSUPPORTED: i64 = 6;
/// `type-inconsistent` (7).
pub const TYPE_INCONSISTENT: i64 = 7;
/// `object-attribute-inconsistent` (8).
pub const OBJECT_ATTRIBUTE_INCONSISTENT: i64 = 8;
/// `object-access-unsupported` (9).
pub const OBJECT_ACCESS_UNSUPPORTED: i64 = 9;
/// `object-non-existent` (10).
pub const OBJECT_NON_EXISTENT: i64 = 10;
/// `object-value-invalid` (11).
pub const OBJECT_VALUE_INVALID: i64 = 11;
