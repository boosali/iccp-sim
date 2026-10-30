//! The simulator's [`DataProvider`]: config-driven points and datasets, plus
//! raw-shape TASE.2 special variables (`TASE2_Version`, `Supported_Features`)
//! via the vendored [`DataProvider::special_read`] hook.

use std::collections::HashMap;

use async_trait::async_trait;
use mms_proto::ber::BitString;
use mms_proto::mms::{Data, Identifier, ObjectName};
use tase2::{data_access_error, names, DataProvider};
use tase2_proto::{DataSet, DomainName, PointKind, PointValue};
use tokio::sync::RwLock;

/// Hashable key for an [`ObjectName`] (same scheme as the upstream
/// `MapDataProvider`): `"@item"` (VMD), `"domain/item"` (domain), `"~item"` (AA).
pub fn object_key(name: &ObjectName) -> String {
    match name {
        ObjectName::VmdSpecific(id) => format!("@{}", id.as_str()),
        ObjectName::DomainSpecific { domain, item } => {
            format!("{}/{}", domain.as_str(), item.as_str())
        }
        ObjectName::AaSpecific(id) => format!("~{}", id.as_str()),
        other => format!("?{other:?}"),
    }
}

/// Sort identifiers lexicographically and dedup (`Identifier` is not `Ord`).
fn sort_identifiers(ids: &mut Vec<Identifier>) {
    ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    ids.dedup_by(|a, b| a.as_str() == b.as_str());
}

/// Extract the item identifier from an object name, filtered by domain scope.
fn item_in_scope(name: &ObjectName, domain: Option<&DomainName>) -> Option<Identifier> {
    match (name, domain) {
        (ObjectName::VmdSpecific(id), None) => Some(id.clone()),
        (ObjectName::DomainSpecific { domain: d, item }, Some(want)) if d == want.identifier() => {
            Some(item.clone())
        }
        _ => None,
    }
}

#[derive(Debug, Default)]
struct Inner {
    points: HashMap<String, (ObjectName, PointKind, PointValue)>,
    data_sets: HashMap<String, DataSet>,
}

/// Config-driven provider. Points and datasets come from JSON; the TASE.2
/// special variables are served in their raw MMS shapes (which the
/// `PointValue` model cannot express).
#[derive(Debug)]
pub struct SimProvider {
    inner: RwLock<Inner>,
    /// `TASE2_Version` = (major, minor).
    version: (u64, u64),
    /// `Supported_Features` bit string (MSB-first, 4 bits).
    features: BitString,
}

impl SimProvider {
    #[must_use]
    pub fn new(
        points: HashMap<String, (ObjectName, PointKind, PointValue)>,
        data_sets: HashMap<String, DataSet>,
        version: (u64, u64),
        features: BitString,
    ) -> Self {
        Self {
            inner: RwLock::new(Inner { points, data_sets }),
            version,
            features,
        }
    }

    /// The `PointKind` of a point keyed by item name. Resolves the item name
    /// against the stored [`ObjectName`]s.
    ///
    /// NOTE: blocks on the provider lock — do NOT call from tokio worker
    /// threads. The mutation loop instead uses `SimModel::point_kinds`
    /// (immutable, built at startup).
    #[allow(dead_code)]
    pub fn point_kind_of(&self, item: &str) -> Option<PointKind> {
        let g = self.inner.blocking_read();
        g.points.values().find_map(|(n, k, _)| match n {
            ObjectName::VmdSpecific(id) => (id.as_str() == item).then_some(*k),
            ObjectName::DomainSpecific { item: i, .. } => (i.as_str() == item).then_some(*k),
            _ => None,
        })
    }
}

#[async_trait]
impl DataProvider for SimProvider {
    async fn read(&self, name: &ObjectName) -> Result<PointValue, i64> {
        self.inner
            .read()
            .await
            .points
            .get(&object_key(name))
            .map(|(_, _, v)| *v)
            .ok_or(data_access_error::OBJECT_NON_EXISTENT)
    }

    async fn write(&self, name: &ObjectName, value: PointValue) -> Result<(), i64> {
        let mut g = self.inner.write().await;
        match g.points.get_mut(&object_key(name)) {
            Some(slot) => {
                slot.2 = value;
                Ok(())
            }
            None => Err(data_access_error::OBJECT_NON_EXISTENT),
        }
    }

    async fn point_kind(&self, name: &ObjectName) -> Option<PointKind> {
        self.inner
            .read()
            .await
            .points
            .get(&object_key(name))
            .map(|(_, k, _)| *k)
    }

    async fn names(&self, object_class: u8, domain: Option<&DomainName>) -> Vec<Identifier> {
        let g = self.inner.read().await;
        let mut out: Vec<Identifier> = match object_class {
            tase2::OBJECT_CLASS_NAMED_VARIABLE => g
                .points
                .values()
                .filter_map(|(n, _, _)| item_in_scope(n, domain))
                .collect(),
            tase2::OBJECT_CLASS_NAMED_VARIABLE_LIST => g
                .data_sets
                .values()
                .filter_map(|ds| item_in_scope(&ds.name, domain))
                .collect(),
            tase2::OBJECT_CLASS_DOMAIN if domain.is_none() => {
                let mut domains: Vec<Identifier> = Vec::new();
                for (n, _, _) in g.points.values() {
                    if let ObjectName::DomainSpecific { domain, .. } = n {
                        domains.push(domain.clone());
                    }
                }
                for ds in g.data_sets.values() {
                    if let ObjectName::DomainSpecific { domain, .. } = &ds.name {
                        domains.push(domain.clone());
                    }
                }
                sort_identifiers(&mut domains);
                domains
            }
            _ => Vec::new(),
        };
        sort_identifiers(&mut out);
        out
    }

    async fn define_data_set(&self, ds: DataSet) -> Result<(), i64> {
        self.inner
            .write()
            .await
            .data_sets
            .insert(object_key(&ds.name), ds);
        Ok(())
    }

    async fn delete_data_set(&self, name: &ObjectName) -> Result<(), i64> {
        self.inner
            .write()
            .await
            .data_sets
            .remove(&object_key(name))
            .map(|_| ())
            .ok_or(data_access_error::OBJECT_NON_EXISTENT)
    }

    async fn data_set(&self, name: &ObjectName) -> Option<DataSet> {
        self.inner
            .read()
            .await
            .data_sets
            .get(&object_key(name))
            .cloned()
    }

    /// Serve `TASE2_Version` and `Supported_Features` in their raw MMS shapes.
    ///
    /// `TASE2_Version` wire shape: `Structure { Unsigned major, Unsigned minor }`.
    /// `Supported_Features` wire shape: `BitString`.
    async fn special_read(&self, name: &ObjectName) -> Option<Data> {
        let item = match name {
            ObjectName::VmdSpecific(id) => id.as_str(),
            ObjectName::DomainSpecific { item, .. } => item.as_str(),
            _ => return None,
        };
        Some(match item {
            names::TASE2_VERSION => Data::Structure(vec![
                Data::Unsigned(self.version.0),
                Data::Unsigned(self.version.1),
            ]),
            names::SUPPORTED_FEATURES => Data::BitString(self.features.clone()),
            _ => return None,
        })
    }
}
