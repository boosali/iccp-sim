//! Server-side data capability: the [`DataProvider`] trait and an in-memory
//! [`MapDataProvider`] implementation.
//!
//! A `DataProvider` answers the data-plane requests dispatched by
//! [`serve_connection`](crate::serve_connection): point reads/writes, name
//! enumeration and data-set management. Per-item failures are reported as MMS
//! `DataAccessError` codes (see [`crate::data_access_error`]).

use std::collections::HashMap;

use async_trait::async_trait;
use mms_proto::mms::{Data, Identifier, ObjectName};
use tase2_proto::{
    CommandValue, ControlModel, DataSet, DeviceKind, DeviceTag, DomainName, PointKind, PointValue,
};
use tokio::sync::RwLock;

use crate::data_access_error;

/// The server-side TASE.2 Block-1 data capability.
///
/// All methods take `&self`; implementations use interior mutability (e.g. a
/// `RwLock`) so a single provider can be shared across connections. Per-item
/// failures are MMS `DataAccessError` codes.
#[async_trait]
pub trait DataProvider: Send + Sync + 'static {
    /// Read the current value of `name`.
    async fn read(&self, name: &ObjectName) -> Result<PointValue, i64>;

    /// Write `value` to `name`.
    async fn write(&self, name: &ObjectName, value: PointValue) -> Result<(), i64>;

    /// The [`PointKind`] of `name`, if it exists. Used to decode inbound
    /// `Write` data, whose MMS shape alone is ambiguous.
    async fn point_kind(&self, name: &ObjectName) -> Option<PointKind>;

    /// Enumerate object names of `object_class`, scoped to `domain` (or VMD).
    async fn names(&self, object_class: u8, domain: Option<&DomainName>) -> Vec<Identifier>;

    /// Define (create/replace) a data set.
    async fn define_data_set(&self, ds: DataSet) -> Result<(), i64>;

    /// Delete a data set by name.
    async fn delete_data_set(&self, name: &ObjectName) -> Result<(), i64>;

    /// Fetch a data set definition by name.
    async fn data_set(&self, name: &ObjectName) -> Option<DataSet>;

    /// Serve a TASE.2 special variable whose value does not fit the
    /// [`PointValue`] mold, returning the raw MMS [`Data`] to send back.
    ///
    /// Used for the VMD-scoped variables `TASE2_Version` (a
    /// `Structure { unsigned, unsigned }`) and `Supported_Features` (a
    /// `BitString`), which OpenICCP reads during association setup. Returns
    /// `None` to fall back to the ordinary point `read` path.
    ///
    /// iccp-sim addition (default method; upstream returns `None`).
    async fn special_read(&self, _name: &ObjectName) -> Option<Data> {
        None
    }
}

/// MMS `basicObjectClass` for `namedVariable`.
pub const OBJECT_CLASS_NAMED_VARIABLE: u8 = 0;
/// MMS `basicObjectClass` for `namedVariableList`.
pub const OBJECT_CLASS_NAMED_VARIABLE_LIST: u8 = 2;
/// MMS `basicObjectClass` for `domain`.
pub const OBJECT_CLASS_DOMAIN: u8 = 9;

/// A simple in-memory [`DataProvider`] backed by hash maps.
///
/// Points and data sets are keyed by their MMS [`ObjectName`]. Intended for
/// tests and simple servers; production servers will implement
/// [`DataProvider`] over their own data model.
#[derive(Debug, Default)]
pub struct MapDataProvider {
    inner: RwLock<Inner>,
}

/// A hashable key for an [`ObjectName`]. `ObjectName` is `Eq` but not `Hash`
/// (it is a public, non-exhaustive enum), so the in-memory maps key on a
/// lossless string form: `"@item"` for vmd-specific, `"domain/item"` for
/// domain-specific, `"~item"` for aa-specific. The leading sigil keeps the
/// three scopes disjoint. The original `ObjectName` is stored in the value so
/// nothing is lost.
fn object_key(name: &ObjectName) -> String {
    match name {
        ObjectName::VmdSpecific(id) => format!("@{}", id.as_str()),
        ObjectName::DomainSpecific { domain, item } => {
            format!("{}/{}", domain.as_str(), item.as_str())
        }
        ObjectName::AaSpecific(id) => format!("~{}", id.as_str()),
        // Non-exhaustive enum: future scopes get a distinct sigil so they never
        // collide with the three known forms.
        other => format!("?{other:?}"),
    }
}

#[derive(Debug, Default)]
struct Inner {
    points: HashMap<String, (ObjectName, PointKind, PointValue)>,
    data_sets: HashMap<String, DataSet>,
}

impl MapDataProvider {
    /// Create an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a point. The kind is taken from the value.
    pub async fn insert_point(&self, name: ObjectName, value: PointValue) {
        let kind = value.kind();
        self.inner
            .write()
            .await
            .points
            .insert(object_key(&name), (name, kind, value));
    }

    /// Insert (or replace) a data set under its own object name.
    pub async fn insert_data_set(&self, ds: DataSet) {
        self.inner
            .write()
            .await
            .data_sets
            .insert(object_key(&ds.name), ds);
    }

    /// Current number of points (test/inspection helper).
    pub async fn point_count(&self) -> usize {
        self.inner.read().await.points.len()
    }
}

/// Extract the item identifier from an object name (the part enumerated by
/// `GetNameList`), filtered by domain scope.
fn item_in_scope(name: &ObjectName, domain: Option<&DomainName>) -> Option<Identifier> {
    match (name, domain) {
        (ObjectName::VmdSpecific(id), None) => Some(id.clone()),
        (ObjectName::DomainSpecific { domain: d, item }, Some(want)) if d == want.identifier() => {
            Some(item.clone())
        }
        _ => None,
    }
}

#[async_trait]
impl DataProvider for MapDataProvider {
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

    /// Note: this re-scans the full map and re-sorts on every call, so a
    /// paginated `GetNameList` enumeration is O(n log n) per page. That is fine
    /// for an in-memory test provider; a production provider should cache the
    /// sorted name list and paginate against the stored cursor instead.
    async fn names(&self, object_class: u8, domain: Option<&DomainName>) -> Vec<Identifier> {
        let g = self.inner.read().await;
        let mut out: Vec<Identifier> = match object_class {
            OBJECT_CLASS_NAMED_VARIABLE => g
                .points
                .values()
                .filter_map(|(n, _, _)| item_in_scope(n, domain))
                .collect(),
            OBJECT_CLASS_NAMED_VARIABLE_LIST => g
                .data_sets
                .values()
                .filter_map(|ds| item_in_scope(&ds.name, domain))
                .collect(),
            // Domains are derived: the distinct domain names over everything
            // the provider holds. Only meaningful at VMD scope.
            OBJECT_CLASS_DOMAIN if domain.is_none() => {
                let mut domains: Vec<Identifier> = g
                    .points
                    .values()
                    .map(|(n, _, _)| n)
                    .chain(g.data_sets.values().map(|ds| &ds.name))
                    .filter_map(|n| match n {
                        ObjectName::DomainSpecific { domain, .. } => Some(domain.clone()),
                        _ => None,
                    })
                    .collect();
                domains.sort_by(|a, b| a.as_str().cmp(b.as_str()));
                domains.dedup();
                domains
            }
            _ => Vec::new(),
        };
        // Stable, deterministic order (GetNameList enumerates lexically).
        out.sort_by(|a, b| a.as_str().cmp(b.as_str()));
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
        if self
            .inner
            .write()
            .await
            .data_sets
            .remove(&object_key(name))
            .is_some()
        {
            Ok(())
        } else {
            Err(data_access_error::OBJECT_NON_EXISTENT)
        }
    }

    async fn data_set(&self, name: &ObjectName) -> Option<DataSet> {
        self.inner
            .read()
            .await
            .data_sets
            .get(&object_key(name))
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// Block-5 device control
// ---------------------------------------------------------------------------

/// The server-side TASE.2 Block-5 device-control capability.
///
/// This is deliberately a *separate* trait from [`DataProvider`]: device control
/// is an optional capability (a server may serve only data), and its host-side
/// model (a device catalog of kind+model, plus operate/tag hooks) is unrelated
/// to point storage. A server wires a `ControlHandler` in via
/// [`serve_connection_full`](crate::serve_connection_full).
///
/// The async serve loop owns the SBO selection state and tag-inhibit checks; the
/// handler only describes the device catalog, executes the (already-authorised)
/// operate, and stores/reports tags. Per-item failures are MMS
/// `DataAccessError` codes (see [`crate::data_access_error`]).
#[async_trait]
pub trait ControlHandler: Send + Sync + 'static {
    /// The device catalog entry for `name`: its kind and control model, or
    /// `None` if `name` is not a device.
    async fn device(&self, name: &ObjectName) -> Option<(DeviceKind, ControlModel)>;

    /// Execute the operate, after the serve loop's SBO-selection and tag-inhibit
    /// checks have passed. `Err(code)` is surfaced as a `DataAccessError`.
    async fn operate(&self, name: &ObjectName, value: CommandValue) -> Result<(), i64>;

    /// The current tag of `name`, or `None` if the device has no tag set / does
    /// not support tags (the serve loop then reports the default `NoTag`).
    async fn tag(&self, name: &ObjectName) -> Option<DeviceTag>;

    /// Set the tag of `name`. `Err(code)` is surfaced as a `DataAccessError`.
    async fn set_tag(&self, name: &ObjectName, tag: DeviceTag) -> Result<(), i64>;
}

/// A [`ControlHandler`] that knows no devices: every [`device`](ControlHandler::device)
/// returns `None`, so the serve loop never treats any variable as a device.
///
/// Used as the default when a server does not implement device control.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectAllControl;

#[async_trait]
impl ControlHandler for RejectAllControl {
    async fn device(&self, _name: &ObjectName) -> Option<(DeviceKind, ControlModel)> {
        None
    }
    async fn operate(&self, _name: &ObjectName, _value: CommandValue) -> Result<(), i64> {
        Err(data_access_error::OBJECT_NON_EXISTENT)
    }
    async fn tag(&self, _name: &ObjectName) -> Option<DeviceTag> {
        None
    }
    async fn set_tag(&self, _name: &ObjectName, _tag: DeviceTag) -> Result<(), i64> {
        Err(data_access_error::OBJECT_NON_EXISTENT)
    }
}

/// An in-memory [`ControlHandler`] for tests and simple servers.
///
/// Holds a device catalog ([`insert_device`](Self::insert_device)), per-device
/// tags, and a log of successful operates ([`operations`](Self::operations)) for
/// test assertions. The operate log records exactly the operates that passed the
/// serve loop's SBO/tag checks and were executed.
#[derive(Debug, Default)]
pub struct MapControlHandler {
    inner: RwLock<ControlInner>,
}

#[derive(Debug, Default)]
struct ControlInner {
    devices: HashMap<String, (ObjectName, DeviceKind, ControlModel)>,
    tags: HashMap<String, DeviceTag>,
    operations: Vec<(ObjectName, CommandValue)>,
}

impl MapControlHandler {
    /// Create an empty handler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a device with its kind and control model.
    pub async fn insert_device(&self, name: ObjectName, kind: DeviceKind, model: ControlModel) {
        self.inner
            .write()
            .await
            .devices
            .insert(object_key(&name), (name, kind, model));
    }

    /// The log of executed operates (in order), for test assertions.
    pub async fn operations(&self) -> Vec<(ObjectName, CommandValue)> {
        self.inner.read().await.operations.clone()
    }
}

#[async_trait]
impl ControlHandler for MapControlHandler {
    async fn device(&self, name: &ObjectName) -> Option<(DeviceKind, ControlModel)> {
        self.inner
            .read()
            .await
            .devices
            .get(&object_key(name))
            .map(|(_, k, m)| (*k, *m))
    }

    async fn operate(&self, name: &ObjectName, value: CommandValue) -> Result<(), i64> {
        let mut g = self.inner.write().await;
        if !g.devices.contains_key(&object_key(name)) {
            return Err(data_access_error::OBJECT_NON_EXISTENT);
        }
        g.operations.push((name.clone(), value));
        Ok(())
    }

    async fn tag(&self, name: &ObjectName) -> Option<DeviceTag> {
        self.inner.read().await.tags.get(&object_key(name)).cloned()
    }

    async fn set_tag(&self, name: &ObjectName, tag: DeviceTag) -> Result<(), i64> {
        let mut g = self.inner.write().await;
        if !g.devices.contains_key(&object_key(name)) {
            return Err(data_access_error::OBJECT_NON_EXISTENT);
        }
        g.tags.insert(object_key(name), tag);
        Ok(())
    }
}
