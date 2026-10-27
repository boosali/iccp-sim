//! Server-side Block-5 device-control logic: SBO selection state and the
//! routing helpers the serve loop calls before falling back to the provider.
//!
//! # Selection state
//! [`ControlPoint`] holds the per-connection select-before-operate selection
//! table: a map from the selected device's [`ObjectName`] to a deadline
//! (`Instant`). A selection is recorded on a successful read of `<dev>_SBO`,
//! consumed (one-shot) by a matching operate, and expires lazily — checked at
//! operate time against the deadline, so no background task is needed.
//!
//! ## Select timeout
//! libtase2 lets the server configure a select timeout for all SBO devices
//! (developer guide: "the client has to send an 'operate' message before the
//! select timeout"). The standard does not fix a default; this implementation
//! uses [`DEFAULT_SELECT_TIMEOUT`] (30 s), a common SBO value, configurable via
//! [`ControlPoint::with_timeout`].
//!
//! # Routing
//! [`ControlPoint::handle_read`] / [`handle_write`](ControlPoint::handle_write)
//! return `Some(..)` when the accessed name is a device companion (`_SBO` /
//! `_TAG`) or a device operate target, and `None` when the name is not
//! control-related (the serve loop then falls back to the data provider). The
//! whole-device check is keyed on the [`ControlHandler`] device catalog, so a
//! plain data point whose name happens to end in `_SBO`/`_TAG` but is not a
//! device is left to the provider.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mms_proto::mms::{Data, Identifier, ObjectName};
use tase2_proto::control::{strip_sbo_suffix, strip_tag_suffix};
use tase2_proto::{CommandValue, ControlModel, DeviceTag};
use tokio::sync::Mutex;

use crate::data_access_error;
use crate::provider::ControlHandler;

/// Default SBO select timeout (30 s). See the module docs for the rationale —
/// the standard does not fix a default; 30 s is a common SBO select window.
pub const DEFAULT_SELECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of concurrently-live SBO selections per connection.
///
/// A client normally selects one device, operates it, and the selection is
/// consumed; live selections accumulate only if a client selects many devices
/// without operating them (or its selects never expire). Capping the table
/// bounds the per-connection memory a misbehaving or buggy peer can pin: a
/// select beyond this cap (after sweeping expired entries) is rejected with
/// `object-access-denied`. 64 is generous for any realistic SBO workflow.
pub const MAX_SELECTIONS: usize = 64;

/// Per-connection device-control state: the SBO selection table.
///
/// One [`ControlPoint`] is created per served connection (selection is
/// per-association: a device selected on one connection is not operable from
/// another).
#[derive(Debug)]
pub struct ControlPoint {
    /// device object name (string key) -> (object name, select deadline).
    selections: Mutex<HashMap<String, (ObjectName, Instant)>>,
    select_timeout: Duration,
}

impl Default for ControlPoint {
    fn default() -> Self {
        Self::new()
    }
}

impl ControlPoint {
    /// A control point with the [default select timeout](DEFAULT_SELECT_TIMEOUT).
    #[must_use]
    pub fn new() -> Self {
        Self::with_timeout(DEFAULT_SELECT_TIMEOUT)
    }

    /// A control point with an explicit select timeout (use a short value in
    /// tests to exercise expiry).
    #[must_use]
    pub fn with_timeout(select_timeout: Duration) -> Self {
        ControlPoint {
            selections: Mutex::new(HashMap::new()),
            select_timeout,
        }
    }

    /// Handle a Read of `name`.
    ///
    /// Returns:
    /// * `Some(Ok(data))` when `name` is a `<dev>_SBO` select (SBO device →
    ///   selection recorded, checkback Integer returned) or a `<dev>_TAG` read
    ///   (the device's [`DeviceTag`] structure, or `NoTag` default);
    /// * `Some(Err(code))` when `name` is a companion of a *known* device but the
    ///   access is invalid (e.g. selecting a Direct device);
    /// * `None` when `name` is not control-related (fall back to the provider).
    pub async fn handle_read<C: ControlHandler + ?Sized>(
        &self,
        handler: &C,
        name: &ObjectName,
    ) -> Option<Result<Data, i64>> {
        // _SBO select?
        if let Some(device) = companion_device(name, CompanionKind::Sbo) {
            let (_, model) = handler.device(&device).await?;
            return Some(self.do_select(&device, model).await);
        }
        // _TAG read?
        if let Some(device) = companion_device(name, CompanionKind::Tag) {
            // Confirm it is a real device before serving the tag.
            handler.device(&device).await?;
            let tag = handler.tag(&device).await.unwrap_or_default();
            return Some(Ok(tag.to_mms()));
        }
        None
    }

    /// Handle a Write of `name` with `data`.
    ///
    /// Returns:
    /// * `Some(Ok(()))` on a successful operate or tag write;
    /// * `Some(Err(code))` when `name` is a device (or `<dev>_TAG`) but the
    ///   write is rejected (bad value, tag inhibit, missing/expired SBO
    ///   selection, or a handler error);
    /// * `None` when `name` is not control-related (fall back to the provider).
    pub async fn handle_write<C: ControlHandler + ?Sized>(
        &self,
        handler: &C,
        name: &ObjectName,
        data: &Data,
    ) -> Option<Result<(), i64>> {
        // _TAG write?
        if let Some(device) = companion_device(name, CompanionKind::Tag) {
            handler.device(&device).await?;
            let tag = match DeviceTag::from_mms(data) {
                Ok(t) => t,
                Err(_) => return Some(Err(data_access_error::TYPE_INCONSISTENT)),
            };
            return Some(handler.set_tag(&device, tag).await);
        }
        // _SBO is read-only for select; a write to it is not handled here. (If
        // it names a real device's companion we still must not fall through to
        // the provider for it, but selecting via write is unsupported.)
        if let Some(device) = companion_device(name, CompanionKind::Sbo) {
            if handler.device(&device).await.is_some() {
                return Some(Err(data_access_error::OBJECT_ACCESS_UNSUPPORTED));
            }
            return None;
        }

        // Operate? Only if `name` is itself a known device.
        let (kind, model) = handler.device(name).await?;
        Some(self.do_operate(handler, name, kind, model, data).await)
    }

    /// Record (or refresh) a selection for an SBO device, returning the
    /// checkback Integer. Selecting a Direct device is rejected with
    /// `object-access-unsupported` (SBO select is meaningless for it).
    ///
    /// Before recording, expired selections are swept (the only purge path
    /// besides [`consume_selection`](Self::consume_selection)'s per-device
    /// removal), and the live count is capped at [`MAX_SELECTIONS`]: a select
    /// that would exceed the cap *after* sweeping — and is not a refresh of an
    /// already-selected device — is rejected with `object-access-denied`. This
    /// bounds the per-connection selection table.
    async fn do_select(&self, device: &ObjectName, model: ControlModel) -> Result<Data, i64> {
        match model {
            ControlModel::Sbo => {
                let now = Instant::now();
                let mut sels = self.selections.lock().await;
                // Sweep expired entries.
                sels.retain(|_, (_, deadline)| *deadline >= now);
                let dev_key = key(device);
                // A new device (not a refresh) at the cap is rejected.
                if sels.len() >= MAX_SELECTIONS && !sels.contains_key(&dev_key) {
                    return Err(data_access_error::OBJECT_ACCESS_DENIED);
                }
                let deadline = now + self.select_timeout;
                sels.insert(dev_key, (device.clone(), deadline));
                // libtase2 select returns an integer "check back name value".
                // We return a non-zero checkback id to signal success.
                Ok(Data::Integer(1))
            }
            // Direct (and any future non-SBO model): SBO select is meaningless.
            _ => Err(data_access_error::OBJECT_ACCESS_UNSUPPORTED),
        }
    }

    /// Run the operate after enforcing the tag-inhibit and (for SBO) selection
    /// checks.
    ///
    /// The tag-inhibit check here is **advisory**: it is a convenience gate read
    /// from `handler.tag` at operate time, subject to an inherent
    /// cross-association TOCTOU window (another association may set/clear the tag
    /// concurrently). The host's [`operate`](ControlHandler::operate) handler is
    /// the final authority and must re-validate any safety-critical inhibit.
    ///
    /// For an SBO device the selection is consumed (one-shot) **before**
    /// `handler.operate` is called, so a selection is spent even when the
    /// operate subsequently fails — a failed operate requires a fresh select to
    /// retry. (Spec-review note: this matches "selection is consumed by the
    /// operate" rather than "consumed only on operate success".)
    async fn do_operate<C: ControlHandler + ?Sized>(
        &self,
        handler: &C,
        device: &ObjectName,
        kind: tase2_proto::DeviceKind,
        model: ControlModel,
        data: &Data,
    ) -> Result<(), i64> {
        // Decode the operate value, directed by the device kind.
        let value = match CommandValue::from_mms(kind, data) {
            Ok(v) => v,
            Err(_) => return Err(data_access_error::TYPE_INCONSISTENT),
        };

        // Tag-inhibit check: an inhibiting tag blocks the operate
        // (object-access-denied, code 3).
        if let Some(tag) = handler.tag(device).await {
            if tag.inhibits_operate() {
                return Err(data_access_error::OBJECT_ACCESS_DENIED);
            }
        }

        // SBO: require a live, un-expired selection by this association, and
        // consume it (one-shot). A missing/expired selection is
        // object-access-denied.
        if model == ControlModel::Sbo && !self.consume_selection(device).await {
            return Err(data_access_error::OBJECT_ACCESS_DENIED);
        }

        handler.operate(device, value).await
    }

    /// Check for a live selection of `device` and remove it (one-shot). Returns
    /// `true` if a valid, un-expired selection existed. An expired selection is
    /// removed and treated as absent.
    async fn consume_selection(&self, device: &ObjectName) -> bool {
        let mut sels = self.selections.lock().await;
        match sels.remove(&key(device)) {
            Some((_, deadline)) => Instant::now() <= deadline,
            None => false,
        }
    }
}

/// Which reserved companion suffix a name might carry.
#[derive(Debug, Clone, Copy)]
enum CompanionKind {
    Sbo,
    Tag,
}

/// If `name` is a `<dev>_SBO` / `<dev>_TAG` companion (per `kind`), return the
/// base device's [`ObjectName`] (same scope, suffix stripped). `None` if the
/// name does not carry that suffix, or if stripping it yields an invalid
/// identifier.
fn companion_device(name: &ObjectName, kind: CompanionKind) -> Option<ObjectName> {
    match name {
        ObjectName::VmdSpecific(id) => {
            let base = strip(kind, id.as_str())?;
            Some(ObjectName::VmdSpecific(Identifier::new(base).ok()?))
        }
        ObjectName::DomainSpecific { domain, item } => {
            let base = strip(kind, item.as_str())?;
            Some(ObjectName::DomainSpecific {
                domain: domain.clone(),
                item: Identifier::new(base).ok()?,
            })
        }
        ObjectName::AaSpecific(id) => {
            let base = strip(kind, id.as_str())?;
            Some(ObjectName::AaSpecific(Identifier::new(base).ok()?))
        }
        _ => None,
    }
}

/// Strip the companion suffix indicated by `kind` from `s`.
fn strip(kind: CompanionKind, s: &str) -> Option<&str> {
    match kind {
        CompanionKind::Sbo => strip_sbo_suffix(s),
        CompanionKind::Tag => strip_tag_suffix(s),
    }
}

/// A stable string key for an [`ObjectName`], matching the provider's keying so
/// selections and device lookups agree. (`ObjectName` is not `Hash`.)
fn key(name: &ObjectName) -> String {
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
    use crate::provider::MapControlHandler;
    use tase2_proto::DeviceKind;

    fn dev(item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain: Identifier::new("ICC1").unwrap(),
            item: Identifier::new(item).unwrap(),
        }
    }

    #[tokio::test]
    async fn sbo_operate_requires_selection() {
        let h = MapControlHandler::new();
        h.insert_device(dev("SW1"), DeviceKind::Command, ControlModel::Sbo)
            .await;
        let cp = ControlPoint::new();

        // Operate without select → denied.
        let op = CommandValue::Command(1).to_mms();
        let r = cp.handle_write(&h, &dev("SW1"), &op).await.unwrap();
        assert_eq!(r, Err(data_access_error::OBJECT_ACCESS_DENIED));

        // Select → checkback Integer.
        let sbo = dev("SW1_SBO");
        let sel = cp.handle_read(&h, &sbo).await.unwrap();
        assert!(matches!(sel, Ok(Data::Integer(_))));

        // Operate → ok, logged.
        let r = cp.handle_write(&h, &dev("SW1"), &op).await.unwrap();
        assert_eq!(r, Ok(()));
        assert_eq!(h.operations().await.len(), 1);

        // Operate again without re-select → denied (consumed).
        let r = cp.handle_write(&h, &dev("SW1"), &op).await.unwrap();
        assert_eq!(r, Err(data_access_error::OBJECT_ACCESS_DENIED));
    }

    #[tokio::test]
    async fn selection_table_capped_and_swept() {
        let h = MapControlHandler::new();
        // MAX_SELECTIONS + 1 distinct SBO devices.
        for i in 0..=MAX_SELECTIONS {
            h.insert_device(
                dev(&format!("D{i}")),
                DeviceKind::Command,
                ControlModel::Sbo,
            )
            .await;
        }
        // Short timeout so the post-expiry retry resolves quickly.
        let cp = ControlPoint::with_timeout(Duration::from_millis(20));

        // Select the first MAX_SELECTIONS rapidly → all granted.
        for i in 0..MAX_SELECTIONS {
            let sel = cp
                .handle_read(&h, &dev(&format!("D{i}_SBO")))
                .await
                .unwrap();
            assert!(matches!(sel, Ok(Data::Integer(_))), "select {i} granted");
        }
        // The (MAX+1)-th distinct device at the cap → rejected.
        let over = cp
            .handle_read(&h, &dev(&format!("D{MAX_SELECTIONS}_SBO")))
            .await
            .unwrap();
        assert_eq!(over, Err(data_access_error::OBJECT_ACCESS_DENIED));

        // After the selections expire, a sweep frees the table and a select
        // succeeds again.
        tokio::time::sleep(Duration::from_millis(40)).await;
        let again = cp
            .handle_read(&h, &dev(&format!("D{MAX_SELECTIONS}_SBO")))
            .await
            .unwrap();
        assert!(
            matches!(again, Ok(Data::Integer(_))),
            "select succeeds after expiry sweep"
        );
    }

    #[tokio::test]
    async fn select_expires() {
        let h = MapControlHandler::new();
        h.insert_device(dev("SW1"), DeviceKind::Command, ControlModel::Sbo)
            .await;
        let cp = ControlPoint::with_timeout(Duration::from_millis(20));
        let _ = cp.handle_read(&h, &dev("SW1_SBO")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let r = cp
            .handle_write(&h, &dev("SW1"), &CommandValue::Command(1).to_mms())
            .await
            .unwrap();
        assert_eq!(r, Err(data_access_error::OBJECT_ACCESS_DENIED));
    }

    #[tokio::test]
    async fn direct_operate_no_select() {
        let h = MapControlHandler::new();
        h.insert_device(dev("SP1"), DeviceKind::SetPointReal, ControlModel::Direct)
            .await;
        let cp = ControlPoint::new();
        let r = cp
            .handle_write(&h, &dev("SP1"), &CommandValue::SetPointReal(2.0).to_mms())
            .await
            .unwrap();
        assert_eq!(r, Ok(()));
        // Selecting a direct device is unsupported.
        let sel = cp.handle_read(&h, &dev("SP1_SBO")).await.unwrap();
        assert_eq!(sel, Err(data_access_error::OBJECT_ACCESS_UNSUPPORTED));
    }

    #[tokio::test]
    async fn tag_inhibits_operate() {
        let h = MapControlHandler::new();
        h.insert_device(dev("SW1"), DeviceKind::Command, ControlModel::Direct)
            .await;
        // Set an inhibiting tag via the _TAG write path.
        let tag = DeviceTag::new(tase2_proto::TagValue::OpenAndCloseInhibit, "test");
        let cp = ControlPoint::new();
        let w = cp
            .handle_write(&h, &dev("SW1_TAG"), &tag.to_mms())
            .await
            .unwrap();
        assert_eq!(w, Ok(()));
        // Now operate → denied.
        let r = cp
            .handle_write(&h, &dev("SW1"), &CommandValue::Command(1).to_mms())
            .await
            .unwrap();
        assert_eq!(r, Err(data_access_error::OBJECT_ACCESS_DENIED));
        // Tag read round-trips.
        let read = cp.handle_read(&h, &dev("SW1_TAG")).await.unwrap().unwrap();
        assert_eq!(DeviceTag::from_mms(&read).unwrap(), tag);
    }

    #[tokio::test]
    async fn non_device_falls_through() {
        let h = MapControlHandler::new();
        let cp = ControlPoint::new();
        // No devices registered: a plain point name is not control-related.
        assert!(cp.handle_read(&h, &dev("P1")).await.is_none());
        assert!(cp
            .handle_write(&h, &dev("P1"), &Data::Integer(1))
            .await
            .is_none());
        // A _SBO/_TAG suffix on a non-device also falls through.
        assert!(cp.handle_read(&h, &dev("P1_SBO")).await.is_none());
        assert!(cp.handle_read(&h, &dev("P1_TAG")).await.is_none());
    }
}
