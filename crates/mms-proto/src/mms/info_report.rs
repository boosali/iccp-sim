//! MMS `InformationReport` unconfirmed service (UnconfirmedService `[0]`).
//!
//! ```asn1
//! InformationReport ::= SEQUENCE {
//!     variableAccessSpecification     VariableAccessSpecification,
//!     listOfAccessResult              [0] IMPLICIT SEQUENCE OF AccessResult }
//! ```
//!
//! The `variableAccessSpecification` is the **untagged** CHOICE (its
//! alternatives carry `[0]`/`[1]`); the `listOfAccessResult` then sits under
//! `[0]`. This matches libiec61850's `mmsServer_createInformationReport`
//! encoder ordering: the access spec first, then the results list.

use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::mms::read::AccessResult;
use crate::mms::varname::VariableAccessSpecification;
use crate::{Error, Result};

const TAG_LIST_OF_ACCESS_RESULT: Tag = Tag::context_constructed(0);

/// An `InformationReport`.
#[derive(Debug, Clone, PartialEq)]
pub struct InformationReport {
    /// `variableAccessSpecification`.
    pub spec: VariableAccessSpecification,
    /// `listOfAccessResult`.
    pub access_results: Vec<AccessResult>,
}

impl InformationReport {
    /// Encode the `InformationReport` body (the content of the
    /// `informationReport [0]` wrapper) into `w`.
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        // variableAccessSpecification (untagged CHOICE).
        self.spec.encode(w);
        // listOfAccessResult [0] SEQUENCE OF AccessResult.
        w.write_tlv(TAG_LIST_OF_ACCESS_RESULT, |list| {
            for ar in &self.access_results {
                ar.encode(list);
            }
        });
    }

    /// Decode an `InformationReport` from the `informationReport [0]` body.
    pub(crate) fn decode(content: &[u8]) -> Result<Self> {
        let mut r = BerReader::new(content);
        let spec = VariableAccessSpecification::decode(&mut r)?;
        let mut access_results = None;
        while !r.done() {
            let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            if tag == TAG_LIST_OF_ACCESS_RESULT {
                let mut ir = BerReader::new(c);
                let mut results = Vec::new();
                while !ir.done() {
                    results.push(AccessResult::decode(&mut ir)?);
                }
                access_results = Some(results);
            }
        }
        Ok(InformationReport {
            spec,
            access_results: access_results.ok_or(Error::MmsInvalidPdu)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mms::data::Data;
    use crate::mms::varname::{Identifier, ObjectName, VariableSpecification};

    #[test]
    fn information_report_roundtrip() {
        let report = InformationReport {
            spec: VariableAccessSpecification::ListOfVariable(vec![
                VariableSpecification::Name(ObjectName::VmdSpecific(
                    Identifier::new("V1").unwrap(),
                )),
                VariableSpecification::Name(ObjectName::VmdSpecific(
                    Identifier::new("V2").unwrap(),
                )),
            ]),
            access_results: vec![
                AccessResult::Success(Data::Integer(10)),
                AccessResult::Failure(5),
                AccessResult::Success(Data::Float(1.0)),
            ],
        };
        let mut w = BerWriter::new();
        report.encode(&mut w);
        assert_eq!(InformationReport::decode(&w.into_bytes()).unwrap(), report);
    }

    #[test]
    fn information_report_named_list() {
        let report = InformationReport {
            spec: VariableAccessSpecification::VariableListName(ObjectName::DomainSpecific {
                domain: Identifier::new("D").unwrap(),
                item: Identifier::new("RCB").unwrap(),
            }),
            access_results: vec![AccessResult::Success(Data::Boolean(true))],
        };
        let mut w = BerWriter::new();
        report.encode(&mut w);
        assert_eq!(InformationReport::decode(&w.into_bytes()).unwrap(), report);
    }
}
