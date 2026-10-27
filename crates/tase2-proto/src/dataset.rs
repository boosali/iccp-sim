//! TASE.2 data sets (named variable lists of object references).

use mms_proto::mms::{DefineNvlRequest, ObjectName, VariableSpecification};

use crate::ident::DataSetName;

/// A TASE.2 data set: a named list of object references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSet {
    /// The data set's MMS object name.
    pub name: ObjectName,
    /// The member objects, in order.
    pub entries: Vec<ObjectName>,
}

impl DataSet {
    /// Build a data set from a [`DataSetName`] and its members.
    #[must_use]
    pub fn new(name: DataSetName, entries: Vec<ObjectName>) -> Self {
        DataSet {
            name: ObjectName::VmdSpecific(name.into_identifier()),
            entries,
        }
    }

    /// Build a data set from a fully-formed object name (e.g. domain-specific).
    #[must_use]
    pub fn with_object_name(name: ObjectName, entries: Vec<ObjectName>) -> Self {
        DataSet { name, entries }
    }

    /// Convert into an MMS `DefineNamedVariableList` request: each entry becomes
    /// a `VariableSpecification::Name`.
    #[must_use]
    pub fn to_define_request(&self) -> DefineNvlRequest {
        DefineNvlRequest {
            name: self.name.clone(),
            variables: self
                .entries
                .iter()
                .cloned()
                .map(VariableSpecification::Name)
                .collect(),
        }
    }

    /// Build a data set from a `DefineNamedVariableList` request, keeping only
    /// the `name [0]` variable specifications (other, unsupported forms are
    /// dropped — Block 1 only models named references).
    #[must_use]
    pub fn from_define_request(req: &DefineNvlRequest) -> Self {
        let entries = req
            .variables
            .iter()
            .filter_map(|v| match v {
                VariableSpecification::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect();
        DataSet {
            name: req.name.clone(),
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mms_proto::mms::Identifier;

    fn vmd(s: &str) -> ObjectName {
        ObjectName::VmdSpecific(Identifier::new(s).unwrap())
    }

    #[test]
    fn roundtrip_through_define_request() {
        let ds = DataSet::with_object_name(vmd("DS1"), vec![vmd("A"), vmd("B")]);
        let req = ds.to_define_request();
        assert_eq!(req.name, vmd("DS1"));
        assert_eq!(req.variables.len(), 2);
        assert_eq!(DataSet::from_define_request(&req), ds);
    }
}
