//! TASE.2 bilateral-table access model (pure data, no I/O).
//!
//! In TASE.2 the **bilateral table** (BLT) is the agreement between two control
//! centres listing exactly which objects each peer may see, read, write and
//! control. The server enforces it on every access; the special variable
//! [`Bilateral_Table_ID`](crate::names::BILATERAL_TABLE_ID) lets a peer read the
//! table's version string to verify both sides agree.
//!
//! This module provides the *policy data*: a [`BilateralTable`] of per-point
//! [`AccessRights`], whole-domain grants, dataset-operation grants and device
//! control allowances, plus pure lookup queries. It performs no I/O and knows
//! nothing about associations; the async `tase2` crate binds a table to a
//! connection and enforces it at its single dispatch choke point.
//!
//! # Terminology
//!
//! Verified against libtase2 (`Tase2_BilateralTable`, the
//! support.mz-automation.de developer guide) and the FreeTase2 client: a BLT has
//! an **ID string**, and entries cover data points (with read/write flags),
//! datasets, devices (control) and information messages. libtase2 matches a BLT
//! to an association by AP-title / AE-qualifier. For v1 we bind a table
//! *per connection* at accept time (the async caller chooses which table for
//! which connection); AP-title matching can layer on top later without changing
//! this data model.
//!
//! # Protocol-internal names are always accessible
//!
//! A handful of names are part of the TASE.2 / MMS machinery rather than the
//! peer's data view: the special VMD/domain variables ([`crate::names`]) and the
//! `DSTransferSet{n}` instance variables a client uses to set up reporting. The
//! protocol *requires* these to be readable regardless of the bilateral table
//! (e.g. a peer must be able to read `Bilateral_Table_ID` to verify agreement,
//! and `Next_DSTransfer_Set` to claim an instance). [`is_protocol_internal`]
//! recognises them so the enforcement layer can let them through.

use std::collections::HashMap;

use mms_proto::mms::{Identifier, ObjectName};

use crate::ident::DomainName;

/// The access a peer has been granted to a single data point.
///
/// `#[non_exhaustive]` so future rights (e.g. a separate "report" flag) can be
/// added without breaking construction via the [`READ_ONLY`](Self::READ_ONLY) /
/// [`READ_WRITE`](Self::READ_WRITE) / [`NONE`](Self::NONE) constructors or the
/// public fields read-side.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccessRights {
    /// The peer may read the point's value.
    pub read: bool,
    /// The peer may write the point's value.
    pub write: bool,
}

impl AccessRights {
    /// No access (the default for an undisclosed point).
    pub const NONE: AccessRights = AccessRights {
        read: false,
        write: false,
    };

    /// Read-only access.
    pub const READ_ONLY: AccessRights = AccessRights {
        read: true,
        write: false,
    };

    /// Read and write access.
    pub const READ_WRITE: AccessRights = AccessRights {
        read: true,
        write: true,
    };

    /// Whether any access at all is granted (read or write).
    #[must_use]
    pub fn any(self) -> bool {
        self.read || self.write
    }
}

/// A negotiated bilateral table: the access policy for one peer.
///
/// Build one with [`new`](Self::new) and the `allow_*` builder methods, then
/// query it with [`point_rights`](Self::point_rights),
/// [`dataset_ops_allowed`](Self::dataset_ops_allowed) and
/// [`device_allowed`](Self::device_allowed). All queries are pure lookups with a
/// **default-deny** policy: anything not explicitly granted yields no access.
///
/// A specific per-point grant takes precedence over a whole-domain grant.
#[derive(Debug, Clone, Default)]
pub struct BilateralTable {
    /// The `Bilateral_Table_ID` value reported to the peer (a VisibleString).
    pub id: String,
    /// Per-point rights, keyed by [`object_key`].
    points: HashMap<String, AccessRights>,
    /// Whole-domain point grants, keyed by domain identifier string.
    domain_points: HashMap<String, AccessRights>,
    /// Domains in which dataset define/delete/read operations are allowed.
    dataset_domains: HashMap<String, ()>,
    /// Devices (by [`object_key`]) the peer may select/operate/tag.
    devices: HashMap<String, ()>,
}

impl BilateralTable {
    /// A new, empty table (default-deny) with the given `Bilateral_Table_ID`.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        BilateralTable {
            id: id.into(),
            ..Self::default()
        }
    }

    /// Grant `rights` on a specific point. A specific grant overrides any
    /// whole-domain grant for the same point.
    #[must_use]
    pub fn allow_point(mut self, name: &ObjectName, rights: AccessRights) -> Self {
        self.points.insert(object_key(name), rights);
        self
    }

    /// Grant `rights` on every point in `domain` (a wholesale grant). Specific
    /// per-point grants still take precedence.
    #[must_use]
    pub fn allow_domain_points(mut self, domain: &DomainName, rights: AccessRights) -> Self {
        self.domain_points
            .insert(domain.as_str().to_owned(), rights);
        self
    }

    /// Allow dataset operations (define / delete / read by name) in `domain`.
    #[must_use]
    pub fn allow_dataset_ops(mut self, domain: &DomainName) -> Self {
        self.dataset_domains.insert(domain.as_str().to_owned(), ());
        self
    }

    /// Allow the peer to select / operate / tag the device `name`.
    #[must_use]
    pub fn allow_device(mut self, name: &ObjectName) -> Self {
        self.devices.insert(object_key(name), ());
        self
    }

    /// The rights the peer has on `name`.
    ///
    /// A specific per-point grant takes precedence; otherwise the whole-domain
    /// grant (if `name` is domain-specific) applies; otherwise
    /// [`AccessRights::NONE`].
    #[must_use]
    pub fn point_rights(&self, name: &ObjectName) -> AccessRights {
        if let Some(r) = self.points.get(&object_key(name)) {
            return *r;
        }
        if let ObjectName::DomainSpecific { domain, .. } = name {
            if let Some(r) = self.domain_points.get(domain.as_str()) {
                return *r;
            }
        }
        AccessRights::NONE
    }

    /// Whether dataset operations are allowed in the domain of `domain_of`.
    ///
    /// Returns `false` for a non-domain-specific name (datasets are always
    /// domain-scoped in TASE.2).
    #[must_use]
    pub fn dataset_ops_allowed(&self, domain_of: &ObjectName) -> bool {
        match domain_of {
            ObjectName::DomainSpecific { domain, .. } => {
                self.dataset_domains.contains_key(domain.as_str())
            }
            _ => false,
        }
    }

    /// Whether the peer may control the device `name`.
    #[must_use]
    pub fn device_allowed(&self, name: &ObjectName) -> bool {
        self.devices.contains_key(&object_key(name))
    }

    /// Whether `domain` is enumerable by the peer (`GetNameList` with object
    /// class *domain*): true iff the table mentions the domain in any grant —
    /// a per-point grant (even an explicit-deny one), a wholesale domain grant,
    /// dataset ops, or a device.
    #[must_use]
    pub fn domain_visible(&self, domain: &Identifier) -> bool {
        let d = domain.as_str();
        self.domain_points.contains_key(d)
            || self.dataset_domains.contains_key(d)
            || key_in_domain(self.points.keys(), d)
            || key_in_domain(self.devices.keys(), d)
    }
}

/// The `DSTransferSet` instance-name prefix Phase 10's reporter uses for pooled
/// instances (`DSTransferSet1 .. DSTransferSetN`). Kept in sync with the
/// reporter's `instance_name` builder.
const DS_TRANSFER_SET_PREFIX: &str = "DSTransferSet";

/// Whether `item` is a protocol-internal name that is always accessible
/// regardless of the bilateral table.
///
/// These are the TASE.2 special VMD/domain variables ([`crate::names`]) and the
/// `DSTransferSet{n}` reporting-instance variables. The protocol requires a peer
/// to access them to bootstrap (read `Bilateral_Table_ID` to verify agreement,
/// read `Next_DSTransfer_Set` to claim an instance, read/write a `DSTransferSet`
/// instance to configure reporting), so the enforcement layer lets them through
/// even when the table grants the peer no point access.
///
/// `item` is the item identifier portion of an [`ObjectName`] (not the domain).
#[must_use]
pub fn is_protocol_internal(item: &str) -> bool {
    use crate::names;
    matches!(
        item,
        names::BILATERAL_TABLE_ID
            | names::TASE2_VERSION
            | names::SUPPORTED_FEATURES
            | names::NEXT_DSTRANSFER_SET_NAME
            | names::TRANSFER_SET_NAME
            | names::TRANSFER_SET_TIME_STAMP
            | names::DSCONDITIONS_DETECTED
            | names::EVENT_CODE_DETECTED
    ) || is_transfer_set_instance(item)
}

/// Whether `item` names a pooled transfer-set instance (`DSTransferSet{n}`,
/// `n >= 1`).
fn is_transfer_set_instance(item: &str) -> bool {
    match item.strip_prefix(DS_TRANSFER_SET_PREFIX) {
        // `DSTransferSet` followed by a non-empty, all-digit suffix.
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// A stable string key for an [`ObjectName`], matching the keying used by the
/// async provider/control layers so lookups agree across crates: `"@item"` for
/// vmd-specific, `"domain/item"` for domain-specific, `"~item"` for aa-specific.
/// Whether any `domain/item` key (see [`object_key`]) lives in `domain`.
///
/// O(grants) linear scan; tables are small and built once at startup.
fn key_in_domain<'a>(keys: impl Iterator<Item = &'a String>, domain: &str) -> bool {
    keys.filter_map(|k| k.split_once('/'))
        .any(|(d, _)| d == domain)
}

fn object_key(name: &ObjectName) -> String {
    match name {
        ObjectName::VmdSpecific(id) => format!("@{}", id.as_str()),
        ObjectName::DomainSpecific { domain, item } => {
            format!("{}/{}", domain.as_str(), item.as_str())
        }
        ObjectName::AaSpecific(id) => format!("~{}", id.as_str()),
        other => format!("?{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mms_proto::mms::Identifier;

    fn dn(domain: &str, item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain: Identifier::new(domain).unwrap(),
            item: Identifier::new(item).unwrap(),
        }
    }

    fn dom(s: &str) -> DomainName {
        DomainName::from(Identifier::new(s).unwrap())
    }

    #[test]
    fn default_deny() {
        let blt = BilateralTable::new("BLT-1");
        assert_eq!(blt.id, "BLT-1");
        assert_eq!(blt.point_rights(&dn("D1", "P1")), AccessRights::NONE);
        assert!(!blt.point_rights(&dn("D1", "P1")).any());
        assert!(!blt.dataset_ops_allowed(&dn("D1", "DS1")));
        assert!(!blt.device_allowed(&dn("D1", "DEV1")));
    }

    #[test]
    fn specific_point_grant() {
        let blt = BilateralTable::new("x").allow_point(&dn("D1", "P1"), AccessRights::READ_ONLY);
        assert_eq!(blt.point_rights(&dn("D1", "P1")), AccessRights::READ_ONLY);
        // A different point in the same domain is still denied.
        assert_eq!(blt.point_rights(&dn("D1", "P2")), AccessRights::NONE);
    }

    #[test]
    fn specific_overrides_domain() {
        // Whole domain read-only, but P2 explicitly read-write, P3 explicitly
        // none — the specific grant wins in both directions.
        let blt = BilateralTable::new("x")
            .allow_domain_points(&dom("D2"), AccessRights::READ_ONLY)
            .allow_point(&dn("D2", "P2"), AccessRights::READ_WRITE)
            .allow_point(&dn("D2", "P3"), AccessRights::NONE);
        assert_eq!(blt.point_rights(&dn("D2", "P1")), AccessRights::READ_ONLY);
        assert_eq!(blt.point_rights(&dn("D2", "P2")), AccessRights::READ_WRITE);
        assert_eq!(blt.point_rights(&dn("D2", "P3")), AccessRights::NONE);
    }

    #[test]
    fn domain_visible_iff_any_grant() {
        let blt = BilateralTable::new("x")
            .allow_point(&dn("D1", "P1"), AccessRights::READ_ONLY)
            .allow_domain_points(&dom("D2"), AccessRights::READ_WRITE)
            .allow_dataset_ops(&dom("D3"))
            .allow_device(&dn("D4", "DEV1"));
        for granted in ["D1", "D2", "D3", "D4"] {
            assert!(
                blt.domain_visible(&Identifier::new(granted).unwrap()),
                "{granted} has a grant"
            );
        }
        // No grant of any kind -> not enumerable.
        assert!(!blt.domain_visible(&Identifier::new("D9").unwrap()));
        // A NONE per-point grant is an explicit mention -> the domain exists
        // for this peer even though the point itself is denied.
        let blt = BilateralTable::new("x").allow_point(&dn("D5", "P1"), AccessRights::NONE);
        assert!(blt.domain_visible(&Identifier::new("D5").unwrap()));
    }

    #[test]
    fn dataset_and_device_grants() {
        let blt = BilateralTable::new("x")
            .allow_dataset_ops(&dom("D2"))
            .allow_device(&dn("D1", "DEV1"));
        assert!(blt.dataset_ops_allowed(&dn("D2", "DS1")));
        assert!(!blt.dataset_ops_allowed(&dn("D1", "DS1")));
        assert!(blt.device_allowed(&dn("D1", "DEV1")));
        assert!(!blt.device_allowed(&dn("D1", "DEV2")));
        // VMD-specific names are never dataset-op targets.
        assert!(!blt.dataset_ops_allowed(&ObjectName::VmdSpecific(Identifier::new("DS1").unwrap())));
    }

    #[test]
    fn protocol_internal_recognition() {
        use crate::names;
        assert!(is_protocol_internal(names::BILATERAL_TABLE_ID));
        assert!(is_protocol_internal(names::TASE2_VERSION));
        assert!(is_protocol_internal(names::SUPPORTED_FEATURES));
        assert!(is_protocol_internal(names::NEXT_DSTRANSFER_SET_NAME));
        assert!(is_protocol_internal(names::TRANSFER_SET_NAME));
        assert!(is_protocol_internal("DSTransferSet1"));
        assert!(is_protocol_internal("DSTransferSet12"));
        // Not protocol-internal:
        assert!(!is_protocol_internal("P1"));
        assert!(!is_protocol_internal("DSTransferSet")); // no numeric suffix
        assert!(!is_protocol_internal("DSTransferSetX")); // non-numeric suffix
        assert!(!is_protocol_internal("MyDSTransferSet1")); // wrong prefix
    }

    #[test]
    fn access_rights_helpers() {
        assert!(!AccessRights::NONE.any());
        assert!(AccessRights::READ_ONLY.any());
        assert_eq!(
            (AccessRights::READ_ONLY.read, AccessRights::READ_ONLY.write),
            (true, false)
        );
        assert_eq!(
            (
                AccessRights::READ_WRITE.read,
                AccessRights::READ_WRITE.write
            ),
            (true, true)
        );
        assert_eq!(AccessRights::default(), AccessRights::NONE);
    }
}
