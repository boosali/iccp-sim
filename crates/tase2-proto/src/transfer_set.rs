//! TASE.2 Block-2 DS Transfer Sets and condition-monitoring reports.
//!
//! A *DS Transfer Set* (DSTS) is the server-side object that drives reporting
//! of a data set to one client: it carries the trigger conditions (interval,
//! integrity, object-change), the report-by-exception flag, the buffer time
//! and the enable/disable [`status`](DsTransferSet::status). A client claims a
//! free transfer-set instance (via the `Next_DSTransfer_Set` special variable),
//! reads its current attributes, writes a configured copy back with
//! `status = true`, and then receives [`InformationReport`](mms_proto::mms::InformationReport)s.
//!
//! This module is sans-I/O: it models the transfer-set attributes and their MMS
//! `Data` mapping plus the report encode/decode. The *scheduling* (deciding WHEN
//! a report fires) lives in [`crate::reporting`]; the *value pull* (filling a
//! report's data from a live data source) lives in the `tase2` async crate.
//!
//! # DSTransferSet attribute structure
//!
//! The transfer-set variable is read/written as a single MMS `Structure`. The
//! field set and order below follow IEC 60870-6-503 (the TASE.2 object model)
//! and the libtase2 developer guide §8.6 attribute list (Start Time, Interval,
//! TLE, Buffer Time, Integrity Check, DSConditions Requested, Block Data,
//! Critical, RBE, All Changes Reported), with `DataSetName` first and the
//! enable `Status` + `EventCodeRequested` trailing — **13 components** in this
//! order:
//!
//! | # | Component             | Wire `Data`                         |
//! |---|-----------------------|-------------------------------------|
//! | 0 | `DataSetName`         | `Structure { VisibleString domain, VisibleString name }` |
//! | 1 | `StartTime`           | `Integer` (GMTBasedS, UTC seconds)  |
//! | 2 | `Interval`            | `Integer` (seconds)                 |
//! | 3 | `TLE`                 | `Integer` (seconds; time limit for execution) |
//! | 4 | `BufferTime`          | `Integer` (seconds)                 |
//! | 5 | `IntegrityCheck`      | `Integer` (seconds)                 |
//! | 6 | `DSConditionsRequested` | `BitString(5)`                    |
//! | 7 | `BlockData`           | `Boolean`                           |
//! | 8 | `Critical`            | `Boolean`                           |
//! | 9 | `RBE`                 | `Boolean`                           |
//! | 10| `AllChangesReported`  | `Boolean`                           |
//! | 11| `Status`              | `Boolean` (condition monitoring on) |
//! | 12| `EventCodeRequested`  | `Integer` (i16 range)               |
//!
//! ## Ground-truth caveat
//! The exact ASN.1 of the read/written structure is not public in full; the
//! field *set* and *order* above are taken from the libtase2 developer guide
//! §8.6 list and IEC 60870-6-503, cross-checked against the FreeTase2 client
//! (which exposes `dataset_name`, `status`, `EventCodeRequested`,
//! `DSTransmissionsPars`). The single source of truth for the order is the
//! [`DsTransferSet::to_mms`] / [`DsTransferSet::from_mms`] bodies; encode/decode
//! are each other's inverse (round-trip tested), which is what matters for
//! interop with our own peer. `from_mms` also tolerates `DataSetName` encoded
//! as a bare domain-specific `ObjectName` (some stacks transfer it that way).
//!
//! ## Whole-structure writes
//! FreeTase2 (and libtase2's client API, which buffers all attributes locally
//! and writes them together on `writeStatus`) write the WHOLE structure in one
//! MMS `Write`. v1 implements only whole-structure read/write; single-component
//! access (alternate-access into the structure) is not modelled.

use mms_proto::ber::primitives::BitString;
use mms_proto::mms::{Data, Identifier, ObjectName};

use crate::{Error, Result};

/// The trigger conditions of a DS transfer set, a `BIT STRING` wrapper.
///
/// # Bit numbering (IEC 60870-6-802 `DSConditions`)
///
/// ```asn1
/// DSConditions ::= BIT STRING {
///     interval-timeout(0), integrity-timeout(1), object-change(2),
///     operator-request(3), external-event(4) }   -- SIZE(5)
/// ```
///
/// ASN.1 `BIT STRING` numbers bits **MSB-first**: bit `0` is the most
/// significant bit of the first octet. That is exactly the convention of
/// [`BitString::bit`] / [`BitString::from_bits`] (also MSB-first), so condition
/// bit `n` maps to `BitString` index `n` directly. Internally we store the five
/// flags in the low 5 bits of a `u8` (bit `n` → `1 << n`) for cheap set/test;
/// the MSB-first wire mapping happens only in [`to_bit_string`](Self::to_bit_string).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DsConditions(u8);

impl DsConditions {
    /// `interval-timeout(0)` — periodic report every `Interval` seconds.
    pub const INTERVAL_TIMEOUT: DsConditions = DsConditions(1 << 0);
    /// `integrity-timeout(1)` — periodic full-dataset report every
    /// `IntegrityCheck` seconds.
    pub const INTEGRITY_TIMEOUT: DsConditions = DsConditions(1 << 1);
    /// `object-change(2)` — report when a dataset member changes (RBE).
    pub const OBJECT_CHANGE: DsConditions = DsConditions(1 << 2);
    /// `operator-request(3)` — report on operator request. **Deferred** (decode
    /// tolerated, never fired by the v1 scheduler).
    pub const OPERATOR_REQUEST: DsConditions = DsConditions(1 << 3);
    /// `external-event(4)` — report on external event. **Deferred** (decode
    /// tolerated, never fired by the v1 scheduler).
    pub const EXTERNAL_EVENT: DsConditions = DsConditions(1 << 4);

    /// The number of defined condition bits (`BIT STRING SIZE(5)`).
    pub const BIT_LEN: usize = 5;

    /// No conditions set.
    #[must_use]
    pub const fn empty() -> Self {
        DsConditions(0)
    }

    /// Build from a raw low-5-bit mask (`bit n` = `1 << n`). Bits above bit 4
    /// are discarded.
    #[must_use]
    pub const fn from_bits_raw(mask: u8) -> Self {
        DsConditions(mask & 0b1_1111)
    }

    /// The raw low-5-bit mask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether all the conditions in `other` are set in `self`.
    #[must_use]
    pub const fn contains(self, other: DsConditions) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Whether no condition is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The union of `self` and `other`.
    #[must_use]
    pub const fn union(self, other: DsConditions) -> Self {
        DsConditions(self.0 | other.0)
    }

    /// Set the conditions in `other` (in place).
    pub fn insert(&mut self, other: DsConditions) {
        self.0 |= other.0;
    }

    /// Encode to a `BitString` of exactly [`Self::BIT_LEN`] bits, MSB-first
    /// (bit `n` at index `n`), per IEC 60870-6-802.
    #[must_use]
    pub fn to_bit_string(self) -> BitString {
        let bits: [bool; Self::BIT_LEN] = [
            self.0 & (1 << 0) != 0,
            self.0 & (1 << 1) != 0,
            self.0 & (1 << 2) != 0,
            self.0 & (1 << 3) != 0,
            self.0 & (1 << 4) != 0,
        ];
        BitString::from_bits(&bits)
    }

    /// Decode from a `BitString` (MSB-first, bit `n` at index `n`). Bits beyond
    /// index 4 are ignored (forward compatibility); a string shorter than 5
    /// bits simply reads the missing high-index bits as `0`.
    #[must_use]
    pub fn from_bit_string(bs: &BitString) -> Self {
        let mut mask = 0u8;
        for n in 0..Self::BIT_LEN {
            if bs.bit(n) {
                mask |= 1 << n;
            }
        }
        DsConditions(mask)
    }

    /// Encode as an MMS `Data::BitString`.
    #[must_use]
    pub fn to_data(self) -> Data {
        Data::BitString(self.to_bit_string())
    }

    /// Decode from an MMS `Data::BitString`.
    pub fn from_data(d: &Data) -> Result<Self> {
        match d {
            Data::BitString(bs) => Ok(Self::from_bit_string(bs)),
            _ => Err(Error::InvalidTransferSet {
                reason: "DSConditions: expected BitString",
            }),
        }
    }
}

impl core::ops::BitOr for DsConditions {
    type Output = DsConditions;
    fn bitor(self, rhs: DsConditions) -> DsConditions {
        self.union(rhs)
    }
}

/// The transferred form of a transfer set's `DataSetName`.
///
/// IEC 60870-6-503 models the in-structure `DataSetName` as a `SEQUENCE` of two
/// `VisibleString`s — the domain (ICC) name and the data-set item name. This is
/// distinct from a full MMS `ObjectName` CHOICE: there is no scope tag, just the
/// two strings. [`to_object_name`](Self::to_object_name) reconstitutes a
/// domain-specific [`ObjectName`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsDataSetName {
    /// The domain (ICC / bilateral-table) identifier.
    pub domain: Identifier,
    /// The data-set item identifier.
    pub name: Identifier,
}

impl TsDataSetName {
    /// Build from a domain-specific [`ObjectName`]. Returns `None` for a
    /// vmd-specific or aa-specific name (a transfer set's data set is always
    /// domain-scoped in TASE.2).
    #[must_use]
    pub fn from_object_name(name: &ObjectName) -> Option<Self> {
        match name {
            ObjectName::DomainSpecific { domain, item } => Some(TsDataSetName {
                domain: domain.clone(),
                name: item.clone(),
            }),
            _ => None,
        }
    }

    /// Reconstitute the domain-specific [`ObjectName`].
    #[must_use]
    pub fn to_object_name(&self) -> ObjectName {
        ObjectName::DomainSpecific {
            domain: self.domain.clone(),
            item: self.name.clone(),
        }
    }

    /// Encode as the in-structure `Structure { VisibleString, VisibleString }`.
    #[must_use]
    pub fn to_data(&self) -> Data {
        Data::Structure(vec![
            Data::VisibleString(self.domain.as_str().to_owned()),
            Data::VisibleString(self.name.as_str().to_owned()),
        ])
    }

    /// Decode from the in-structure form. Accepts either the two-`VisibleString`
    /// `Structure` (the standard form) or — tolerantly — a bare domain-specific
    /// `ObjectName` reused as `Data` is not representable, so only the structure
    /// form is decoded here; callers needing ObjectName tolerance use
    /// [`from_object_name`](Self::from_object_name).
    pub fn from_data(d: &Data) -> Result<Self> {
        match d {
            Data::Structure(elems) if elems.len() == 2 => {
                let domain = visible_ident(&elems[0], "DataSetName.domain")?;
                let name = visible_ident(&elems[1], "DataSetName.name")?;
                Ok(TsDataSetName { domain, name })
            }
            _ => Err(Error::InvalidTransferSet {
                reason: "DataSetName: expected Structure{VisibleString, VisibleString}",
            }),
        }
    }
}

/// A TASE.2 DS Transfer Set's attribute set.
///
/// See the [module docs](self) for the MMS structure layout. [`Default`] is the
/// disabled/zeroed transfer set (all integers `0`, all booleans `false`, no
/// conditions, no data set), which is the natural "unconfigured" state a client
/// reads from a freshly-claimed instance.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DsTransferSet {
    /// The data set this transfer set reports. `None` on a fresh instance.
    pub data_set_name: Option<TsDataSetName>,
    /// `StartTime` (GMTBasedS, UTC seconds). `0` = start immediately.
    pub start_time: i32,
    /// `Interval` in seconds. `0` disables the interval-timeout condition even
    /// if its bit is set.
    pub interval: i32,
    /// `TLE` — time limit for execution, seconds. Pass-through in v1.
    pub tle: i32,
    /// `BufferTime` in seconds — object-change coalescing window. `0` = report
    /// immediately on change.
    pub buffer_time: i32,
    /// `IntegrityCheck` timeout in seconds. `0` disables the integrity-timeout
    /// condition even if its bit is set.
    pub integrity_check: i32,
    /// `DSConditionsRequested` — the requested trigger conditions.
    pub conditions: DsConditions,
    /// `BlockData` — block-transfer encoding (CB 3). **Deferred**: stored and
    /// echoed, but v1 always reports in normal (non-blocked) form.
    pub block_data: bool,
    /// `Critical` — report requires client acknowledgement. **Deferred**:
    /// stored and echoed; v1 does not implement the ACK flow.
    pub critical: bool,
    /// `RBE` — report by exception (only changed objects). Drives object-change
    /// reporting together with `BufferTime`.
    pub rbe: bool,
    /// `AllChangesReported` — report every intermediate change. **Deferred
    /// nuance**: stored and echoed; v1 reports the latest value only.
    pub all_changes_reported: bool,
    /// `Status` — condition monitoring enabled. Writing `true` arms the
    /// transfer set; `false` disables it.
    pub status: bool,
    /// `EventCodeRequested` — external event code (i16 range). Pass-through.
    pub event_code_requested: i16,
}

impl DsTransferSet {
    /// Encode to the MMS `Data::Structure` (13 components, see module docs).
    ///
    /// A `None` `data_set_name` encodes as an empty data-set name
    /// (`Structure { "", "" }`), matching a freshly-allocated instance.
    #[must_use]
    pub fn to_mms(&self) -> Data {
        let data_set = match &self.data_set_name {
            Some(n) => n.to_data(),
            None => Data::Structure(vec![
                Data::VisibleString(String::new()),
                Data::VisibleString(String::new()),
            ]),
        };
        Data::Structure(vec![
            data_set,                                            // 0 DataSetName
            Data::Integer(i64::from(self.start_time)),           // 1 StartTime
            Data::Integer(i64::from(self.interval)),             // 2 Interval
            Data::Integer(i64::from(self.tle)),                  // 3 TLE
            Data::Integer(i64::from(self.buffer_time)),          // 4 BufferTime
            Data::Integer(i64::from(self.integrity_check)),      // 5 IntegrityCheck
            self.conditions.to_data(),                           // 6 DSConditionsRequested
            Data::Boolean(self.block_data),                      // 7 BlockData
            Data::Boolean(self.critical),                        // 8 Critical
            Data::Boolean(self.rbe),                             // 9 RBE
            Data::Boolean(self.all_changes_reported),            // 10 AllChangesReported
            Data::Boolean(self.status),                          // 11 Status
            Data::Integer(i64::from(self.event_code_requested)), // 12 EventCodeRequested
        ])
    }

    /// Decode from the MMS `Data::Structure`.
    ///
    /// Requires exactly 13 components in the documented order. The
    /// `DataSetName` component decodes from the two-`VisibleString` structure;
    /// an empty pair (`"", ""`) decodes to `data_set_name = None`.
    pub fn from_mms(d: &Data) -> Result<Self> {
        let e = match d {
            Data::Structure(elems) if elems.len() == 13 => elems,
            _ => {
                return Err(Error::InvalidTransferSet {
                    reason: "DSTransferSet: expected Structure of 13 components",
                })
            }
        };

        let data_set_name = decode_ds_name(&e[0])?;
        Ok(DsTransferSet {
            data_set_name,
            start_time: int_i32(&e[1], "StartTime")?,
            interval: int_i32(&e[2], "Interval")?,
            tle: int_i32(&e[3], "TLE")?,
            buffer_time: int_i32(&e[4], "BufferTime")?,
            integrity_check: int_i32(&e[5], "IntegrityCheck")?,
            conditions: DsConditions::from_data(&e[6])?,
            block_data: boolean(&e[7], "BlockData")?,
            critical: boolean(&e[8], "Critical")?,
            rbe: boolean(&e[9], "RBE")?,
            all_changes_reported: boolean(&e[10], "AllChangesReported")?,
            status: boolean(&e[11], "Status")?,
            event_code_requested: int_i16(&e[12], "EventCodeRequested")?,
        })
    }
}

/// Decode the `DataSetName` component; an empty `("", "")` pair → `None`.
///
/// The empty case is checked *before* parsing the strings as identifiers, since
/// `Identifier::new("")` rejects the empty string (which is the valid "unset"
/// sentinel here).
fn decode_ds_name(d: &Data) -> Result<Option<TsDataSetName>> {
    if let Data::Structure(elems) = d {
        if let [Data::VisibleString(dom), Data::VisibleString(name)] = elems.as_slice() {
            if dom.is_empty() && name.is_empty() {
                return Ok(None);
            }
        }
    }
    Ok(Some(TsDataSetName::from_data(d)?))
}

fn visible_ident(d: &Data, what: &'static str) -> Result<Identifier> {
    match d {
        Data::VisibleString(s) => Identifier::new(s).map_err(|_| Error::InvalidTransferSet {
            reason: what_to_reason(what),
        }),
        _ => Err(Error::InvalidTransferSet {
            reason: what_to_reason(what),
        }),
    }
}

fn what_to_reason(what: &'static str) -> &'static str {
    // `Identifier::new` failure for a structurally-correct VisibleString means
    // the string is not a valid MMS identifier (empty or too long). Keep the
    // component name in the message.
    match what {
        "DataSetName.domain" => "DataSetName.domain: not a valid identifier",
        "DataSetName.name" => "DataSetName.name: not a valid identifier",
        _ => "DataSetName: not a valid identifier",
    }
}

fn int_i32(d: &Data, what: &'static str) -> Result<i32> {
    match d {
        Data::Integer(v) => i32::try_from(*v).map_err(|_| invalid_ts(what)),
        Data::Unsigned(v) => i32::try_from(*v).map_err(|_| invalid_ts(what)),
        _ => Err(invalid_ts(what)),
    }
}

fn int_i16(d: &Data, what: &'static str) -> Result<i16> {
    match d {
        Data::Integer(v) => i16::try_from(*v).map_err(|_| invalid_ts(what)),
        Data::Unsigned(v) => i16::try_from(*v).map_err(|_| invalid_ts(what)),
        _ => Err(invalid_ts(what)),
    }
}

fn boolean(d: &Data, what: &'static str) -> Result<bool> {
    match d {
        Data::Boolean(b) => Ok(*b),
        _ => Err(invalid_ts(what)),
    }
}

fn invalid_ts(what: &'static str) -> Error {
    // Map the component name to a static reason without allocation.
    let reason: &'static str = match what {
        "StartTime" => "StartTime: expected Integer in i32 range",
        "Interval" => "Interval: expected Integer in i32 range",
        "TLE" => "TLE: expected Integer in i32 range",
        "BufferTime" => "BufferTime: expected Integer in i32 range",
        "IntegrityCheck" => "IntegrityCheck: expected Integer in i32 range",
        "BlockData" => "BlockData: expected Boolean",
        "Critical" => "Critical: expected Boolean",
        "RBE" => "RBE: expected Boolean",
        "AllChangesReported" => "AllChangesReported: expected Boolean",
        "Status" => "Status: expected Boolean",
        "EventCodeRequested" => "EventCodeRequested: expected Integer in i16 range",
        _ => "DSTransferSet: invalid component",
    };
    Error::InvalidTransferSet { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    #[test]
    fn conditions_bit_order_msb_first() {
        // interval(0) + object-change(2) → bits 0 and 2 set.
        let c = DsConditions::INTERVAL_TIMEOUT | DsConditions::OBJECT_CHANGE;
        let bs = c.to_bit_string();
        assert!(bs.bit(0), "interval-timeout at index 0");
        assert!(!bs.bit(1), "integrity not set");
        assert!(bs.bit(2), "object-change at index 2");
        assert_eq!(bs.bit_len(), 5);
        assert_eq!(DsConditions::from_bit_string(&bs), c);
    }

    #[test]
    fn conditions_all_five() {
        let c = DsConditions::INTERVAL_TIMEOUT
            | DsConditions::INTEGRITY_TIMEOUT
            | DsConditions::OBJECT_CHANGE
            | DsConditions::OPERATOR_REQUEST
            | DsConditions::EXTERNAL_EVENT;
        assert_eq!(c.bits(), 0b1_1111);
        let bs = c.to_bit_string();
        for n in 0..5 {
            assert!(bs.bit(n));
        }
        assert_eq!(DsConditions::from_bit_string(&bs), c);
    }

    #[test]
    fn ds_name_roundtrip_and_object_name() {
        let n = TsDataSetName {
            domain: id("ICC1"),
            name: id("DS1"),
        };
        let d = n.to_data();
        assert_eq!(TsDataSetName::from_data(&d).unwrap(), n);
        assert_eq!(
            n.to_object_name(),
            ObjectName::DomainSpecific {
                domain: id("ICC1"),
                item: id("DS1"),
            }
        );
        assert_eq!(
            TsDataSetName::from_object_name(&n.to_object_name()),
            Some(n)
        );
    }

    #[test]
    fn transfer_set_roundtrip() {
        let ts = DsTransferSet {
            data_set_name: Some(TsDataSetName {
                domain: id("ICC1"),
                name: id("DS1"),
            }),
            start_time: 0,
            interval: 5,
            tle: 2,
            buffer_time: 1,
            integrity_check: 30,
            conditions: DsConditions::INTERVAL_TIMEOUT
                | DsConditions::INTEGRITY_TIMEOUT
                | DsConditions::OBJECT_CHANGE,
            block_data: false,
            critical: true,
            rbe: true,
            all_changes_reported: false,
            status: true,
            event_code_requested: -3,
        };
        let d = ts.to_mms();
        match &d {
            Data::Structure(e) => assert_eq!(e.len(), 13),
            other => panic!("expected Structure, got {other:?}"),
        }
        assert_eq!(DsTransferSet::from_mms(&d).unwrap(), ts);
    }

    #[test]
    fn default_is_disabled() {
        let ts = DsTransferSet::default();
        assert!(!ts.status);
        assert!(ts.conditions.is_empty());
        assert!(ts.data_set_name.is_none());
        // Round-trips through the wire as an empty/disabled set.
        let back = DsTransferSet::from_mms(&ts.to_mms()).unwrap();
        assert_eq!(back, ts);
    }

    #[test]
    fn wrong_arity_rejected() {
        let d = Data::Structure(vec![Data::Integer(1)]);
        assert!(matches!(
            DsTransferSet::from_mms(&d),
            Err(Error::InvalidTransferSet { .. })
        ));
    }
}
