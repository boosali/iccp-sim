//! TASE.2 condition-monitoring report encode/decode.
//!
//! A transfer report is an MMS [`InformationReport`] whose
//! `variableAccessSpecification` is the data set's `variableListName` (its
//! [`ObjectName`]) and whose `listOfAccessResult` carries one value per data-set
//! member, **in data-set order**.
//!
//! Four *special members* may appear among the data-set members; they are
//! recognised by NAME (see [`crate::names`]) at any position and carry the
//! report metadata:
//!
//! | Member name              | Wire `Data`                | Meaning                       |
//! |--------------------------|----------------------------|-------------------------------|
//! | `Transfer_Set_Name`      | `Structure` (ObjectName-ish) or `VisibleString` | the reporting transfer set    |
//! | `Transfer_Set_Time_Stamp`| `Integer` (GMTBasedS secs) | report timestamp              |
//! | `DSConditions_Detected`  | `BitString(5)`             | the conditions that fired     |
//! | `Event_Code_Detected`    | `Integer` (i16)            | external event code           |
//!
//! Conventionally the special members come first, but TASE.2 only requires them
//! to be *present somewhere* in the data set if requested; the decoder matches
//! them by name at any index and maps the remaining members positionally.
//!
//! This matches FreeTase2's report handling, which reads the special variables
//! `Transfer_Set_Name`, `Transfer_Set_Time_Stamp` and `DSConditions_Detected`
//! out of the reported data set by name.

use mms_proto::mms::{
    AccessResult, Data, InformationReport, ObjectName, VariableAccessSpecification,
};

use crate::names;
use crate::transfer_set::DsConditions;
use crate::{Error, Result};

/// The special-member values carried by a report, set by the server side.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct SpecialValues {
    /// `Transfer_Set_Name` value (the reporting transfer set's object name).
    pub ts_name: Option<ObjectName>,
    /// `Transfer_Set_Time_Stamp` (GMTBasedS, UTC seconds).
    pub timestamp: Option<i64>,
    /// `DSConditions_Detected`.
    pub conditions: Option<DsConditions>,
    /// `Event_Code_Detected`.
    pub event_code: Option<i16>,
}

impl SpecialValues {
    /// The `Data` for a recognised special member named `member`, or `None` if
    /// `member` is not a special name (it is then an ordinary data point).
    fn data_for(&self, member: &ObjectName) -> Option<Data> {
        match special_kind(member)? {
            Special::TsName => Some(
                self.ts_name
                    .as_ref()
                    .map_or_else(|| Data::VisibleString(String::new()), ts_name_to_data),
            ),
            Special::TimeStamp => Some(Data::Integer(self.timestamp.unwrap_or(0))),
            Special::Conditions => Some(
                self.conditions
                    .unwrap_or_else(DsConditions::empty)
                    .to_data(),
            ),
            Special::EventCode => Some(Data::Integer(i64::from(self.event_code.unwrap_or(0)))),
        }
    }
}

/// A decoded transfer report.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TransferReport {
    /// The reporting transfer set's name, from `Transfer_Set_Name`.
    pub ts_name: Option<ObjectName>,
    /// The report timestamp, from `Transfer_Set_Time_Stamp` (UTC seconds).
    pub timestamp: Option<i64>,
    /// The conditions that fired, from `DSConditions_Detected`.
    pub conditions: Option<DsConditions>,
    /// The external event code, from `Event_Code_Detected`.
    pub event_code: Option<i16>,
    /// The ordinary (non-special) member values, each paired with its **index
    /// into the original `members` slice** so the caller can align them with the
    /// data-set definition. A `Failure` access-result for a member is skipped
    /// (its index will be absent).
    pub values: Vec<(usize, Data)>,
    /// The reported data set's object name (from the access specification).
    pub dataset: ObjectName,
}

/// The four special members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Special {
    TsName,
    TimeStamp,
    Conditions,
    EventCode,
}

/// Classify a member object name as a special member, by its item identifier.
fn special_kind(member: &ObjectName) -> Option<Special> {
    let item = match member {
        ObjectName::VmdSpecific(id) => id.as_str(),
        ObjectName::DomainSpecific { item, .. } => item.as_str(),
        ObjectName::AaSpecific(id) => id.as_str(),
        _ => return None,
    };
    match item {
        names::TRANSFER_SET_NAME => Some(Special::TsName),
        names::TRANSFER_SET_TIME_STAMP => Some(Special::TimeStamp),
        names::DSCONDITIONS_DETECTED => Some(Special::Conditions),
        names::EVENT_CODE_DETECTED => Some(Special::EventCode),
        _ => None,
    }
}

/// Encode a `Transfer_Set_Name` value. We use the domain-specific
/// two-`VisibleString` `Structure` form for domain-scoped names (matching the
/// `DataSetName` convention), and a bare `VisibleString` for vmd/aa names.
fn ts_name_to_data(name: &ObjectName) -> Data {
    match name {
        ObjectName::DomainSpecific { domain, item } => Data::Structure(vec![
            Data::VisibleString(domain.as_str().to_owned()),
            Data::VisibleString(item.as_str().to_owned()),
        ]),
        ObjectName::VmdSpecific(id) | ObjectName::AaSpecific(id) => {
            Data::VisibleString(id.as_str().to_owned())
        }
        _ => Data::VisibleString(String::new()),
    }
}

/// Decode a `Transfer_Set_Name` value back to an `ObjectName`. Accepts the
/// two-`VisibleString` `Structure` (→ domain-specific) or a bare `VisibleString`
/// (→ vmd-specific). Returns `None` for an empty/unparseable value.
fn ts_name_from_data(d: &Data) -> Option<ObjectName> {
    use mms_proto::mms::Identifier;
    match d {
        Data::Structure(e) if e.len() == 2 => {
            if let (Data::VisibleString(dom), Data::VisibleString(item)) = (&e[0], &e[1]) {
                Some(ObjectName::DomainSpecific {
                    domain: Identifier::new(dom).ok()?,
                    item: Identifier::new(item).ok()?,
                })
            } else {
                None
            }
        }
        Data::VisibleString(s) => Some(ObjectName::VmdSpecific(Identifier::new(s).ok()?)),
        _ => None,
    }
}

/// Build the `InformationReport` for a transfer report (server side).
///
/// `members` is the data set's member list in order; for each member, if it is a
/// recognised special name the corresponding value from `specials` is emitted as
/// a `Success`, otherwise the next entry from `values` (consumed in order) is
/// used: `Ok(data)` → `AccessResult::Success`, `Err(code)` → an
/// `AccessResult::Failure(code)` carrying the member's MMS `DataAccessError`
/// (so a failed provider read is reported as a per-member failure on the wire,
/// not as an ambiguous zero value). `values` must contain exactly one entry per
/// **non-special** member; a shortfall yields a `Failure(object-value-invalid)`
/// for the missing tail (defensive — callers should supply the right count).
///
/// The report's access specification is `variableListName(dataset)`.
#[must_use]
pub fn build_information_report(
    dataset: &ObjectName,
    members: &[ObjectName],
    specials: &SpecialValues,
    values: Vec<core::result::Result<Data, i64>>,
) -> InformationReport {
    /// MMS `DataAccessError` "object-value-invalid" (11) — used for the
    /// defensive shortfall path (fewer supplied values than non-special
    /// members).
    const OBJECT_VALUE_INVALID: i64 = 11;

    let mut values_iter = values.into_iter();
    let mut access_results = Vec::with_capacity(members.len());
    for member in members {
        if let Some(special) = specials.data_for(member) {
            access_results.push(AccessResult::Success(special));
        } else {
            match values_iter.next() {
                Some(Ok(v)) => access_results.push(AccessResult::Success(v)),
                Some(Err(code)) => access_results.push(AccessResult::Failure(code)),
                // Defensive: fewer values than non-special members.
                None => access_results.push(AccessResult::Failure(OBJECT_VALUE_INVALID)),
            }
        }
    }
    InformationReport {
        spec: VariableAccessSpecification::VariableListName(dataset.clone()),
        access_results,
    }
}

/// Decode an `InformationReport` as a transfer report, given the reporting data
/// set's `members` (in order) so special members can be recognised by name and
/// the rest mapped positionally.
///
/// The report's access specification must be a `variableListName`; its
/// `listOfAccessResult` must have exactly one entry per member. Special members
/// populate the metadata fields (a wrong-typed special value is an error);
/// ordinary members' `Success` values are collected into `values` with their
/// member index, and `Failure` results are skipped.
pub fn decode_information_report(
    report: &InformationReport,
    members: &[ObjectName],
) -> Result<TransferReport> {
    let dataset = match &report.spec {
        VariableAccessSpecification::VariableListName(name) => name.clone(),
        _ => {
            return Err(Error::InvalidReport {
                reason: "report access spec is not a variableListName",
            })
        }
    };

    if report.access_results.len() != members.len() {
        return Err(Error::InvalidReport {
            reason: "report result count does not match data-set member count",
        });
    }

    let mut out = TransferReport {
        ts_name: None,
        timestamp: None,
        conditions: None,
        event_code: None,
        values: Vec::new(),
        dataset,
    };

    for (idx, (member, ar)) in members.iter().zip(&report.access_results).enumerate() {
        // A failed access-result for a special member leaves its field None; for
        // an ordinary member it is simply skipped.
        let data = match ar {
            AccessResult::Success(d) => d,
            AccessResult::Failure(_) => continue,
            _ => {
                return Err(Error::InvalidReport {
                    reason: "report carried an unexpected access-result variant",
                })
            }
        };

        match special_kind(member) {
            Some(Special::TsName) => out.ts_name = ts_name_from_data(data),
            Some(Special::TimeStamp) => match data {
                Data::Integer(s) => out.timestamp = Some(*s),
                _ => {
                    return Err(Error::InvalidReport {
                        reason: "Transfer_Set_Time_Stamp: expected Integer",
                    })
                }
            },
            Some(Special::Conditions) => out.conditions = Some(DsConditions::from_data(data)?),
            Some(Special::EventCode) => match data {
                Data::Integer(v) => {
                    out.event_code = Some(i16::try_from(*v).map_err(|_| Error::InvalidReport {
                        reason: "Event_Code_Detected: out of i16 range",
                    })?);
                }
                _ => {
                    return Err(Error::InvalidReport {
                        reason: "Event_Code_Detected: expected Integer",
                    })
                }
            },
            None => out.values.push((idx, data.clone())),
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mms_proto::mms::Identifier;

    fn id(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    fn dn(item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id(item),
        }
    }

    /// A data set: 4 special members (mixed positions) + 2 real points.
    fn members() -> Vec<ObjectName> {
        vec![
            dn(names::TRANSFER_SET_NAME),
            dn(names::TRANSFER_SET_TIME_STAMP),
            dn(names::DSCONDITIONS_DETECTED),
            dn(names::EVENT_CODE_DETECTED),
            dn("P1"),
            dn("P2"),
        ]
    }

    #[test]
    fn build_then_decode_roundtrip() {
        let ds = dn("DS1");
        let specials = SpecialValues {
            ts_name: Some(dn("TS1")),
            timestamp: Some(1_700_000_000),
            conditions: Some(DsConditions::INTERVAL_TIMEOUT | DsConditions::OBJECT_CHANGE),
            event_code: Some(-5),
        };
        let values = vec![Ok(Data::Float(1.5)), Ok(Data::Integer(42))];
        let report = build_information_report(&ds, &members(), &specials, values);

        // 6 results, special members carry metadata.
        assert_eq!(report.access_results.len(), 6);

        let decoded = decode_information_report(&report, &members()).unwrap();
        assert_eq!(decoded.dataset, ds);
        assert_eq!(decoded.ts_name, Some(dn("TS1")));
        assert_eq!(decoded.timestamp, Some(1_700_000_000));
        assert_eq!(
            decoded.conditions,
            Some(DsConditions::INTERVAL_TIMEOUT | DsConditions::OBJECT_CHANGE)
        );
        assert_eq!(decoded.event_code, Some(-5));
        // Ordinary members at indices 4 and 5.
        assert_eq!(
            decoded.values,
            vec![(4, Data::Float(1.5)), (5, Data::Integer(42))]
        );
    }

    #[test]
    fn specials_recognised_at_any_position() {
        // Specials interleaved with real points.
        let members = vec![
            dn("P1"),
            dn(names::DSCONDITIONS_DETECTED),
            dn("P2"),
            dn(names::TRANSFER_SET_TIME_STAMP),
        ];
        let specials = SpecialValues {
            timestamp: Some(7),
            conditions: Some(DsConditions::INTEGRITY_TIMEOUT),
            ..SpecialValues::default()
        };
        let report = build_information_report(
            &dn("DS1"),
            &members,
            &specials,
            vec![Ok(Data::Integer(1)), Ok(Data::Integer(2))],
        );
        let decoded = decode_information_report(&report, &members).unwrap();
        assert_eq!(decoded.conditions, Some(DsConditions::INTEGRITY_TIMEOUT));
        assert_eq!(decoded.timestamp, Some(7));
        assert_eq!(
            decoded.values,
            vec![(0, Data::Integer(1)), (2, Data::Integer(2))]
        );
    }

    #[test]
    fn non_variable_list_spec_rejected() {
        use mms_proto::mms::VariableSpecification;
        let report = InformationReport {
            spec: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                dn("P1"),
            )]),
            access_results: vec![AccessResult::Success(Data::Integer(1))],
        };
        assert!(matches!(
            decode_information_report(&report, &[dn("P1")]),
            Err(Error::InvalidReport { .. })
        ));
    }

    #[test]
    fn count_mismatch_rejected() {
        let report = InformationReport {
            spec: VariableAccessSpecification::VariableListName(dn("DS1")),
            access_results: vec![AccessResult::Success(Data::Integer(1))],
        };
        // members has 6 entries, results 1.
        assert!(matches!(
            decode_information_report(&report, &members()),
            Err(Error::InvalidReport { .. })
        ));
    }

    #[test]
    fn failed_member_is_skipped() {
        let members = vec![dn("P1"), dn("P2")];
        let report = InformationReport {
            spec: VariableAccessSpecification::VariableListName(dn("DS1")),
            access_results: vec![
                AccessResult::Failure(10),
                AccessResult::Success(Data::Integer(9)),
            ],
        };
        let decoded = decode_information_report(&report, &members).unwrap();
        // P1 failed → skipped; P2 present at index 1.
        assert_eq!(decoded.values, vec![(1, Data::Integer(9))]);
    }

    #[test]
    fn builder_propagates_member_failure() {
        // A failed member read (Err(code)) must surface as a per-member
        // Failure on the wire, not an ambiguous zero value; other members are
        // intact.
        let members = vec![dn("P1"), dn("P2")];
        let report = build_information_report(
            &dn("DS1"),
            &members,
            &SpecialValues::default(),
            vec![Err(10), Ok(Data::Integer(7))],
        );
        assert_eq!(report.access_results.len(), 2);
        assert_eq!(report.access_results[0], AccessResult::Failure(10));
        assert_eq!(
            report.access_results[1],
            AccessResult::Success(Data::Integer(7))
        );
        // The decoder skips the failed member, keeps P2 at its index.
        let decoded = decode_information_report(&report, &members).unwrap();
        assert_eq!(decoded.values, vec![(1, Data::Integer(7))]);
    }
}
