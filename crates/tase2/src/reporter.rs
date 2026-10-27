//! Server-side DS-transfer-set reporting engine.
//!
//! [`TransferSetManager`] binds the sans-I/O scheduler
//! ([`TransferSetScheduler`](tase2_proto::reporting::TransferSetScheduler)) to a
//! live [`DataProvider`] and a connection's unsolicited-send path. It is the
//! "host fills" half of the "core schedules, host fills" split: when the
//! scheduler emits a [`ReportAction::BuildReport`], the manager pulls the data
//! set's current member values from the provider, assembles the special members
//! (transfer-set name, timestamp, conditions, event code) and builds the
//! [`InformationReport`].
//!
//! # Transfer-set instance pool
//!
//! A domain owns a fixed pool of transfer-set instances named
//! `DSTransferSet1 .. DSTransferSetN` (default [`DEFAULT_POOL_SIZE`]). A client
//! reads the `Next_DSTransfer_Set` special variable to claim the next free
//! instance (the manager returns its object name and marks it allocated); it
//! then reads / writes that instance's attributes. Writing `Status = true`
//! enables condition monitoring (the scheduler is armed with the data set's
//! resolved member list); `Status = false` disables it.
//!
//! # Concurrency
//!
//! The manager is shared across the serve loop and the host (which may call
//! [`notify_point_changed`](TransferSetManager::notify_point_changed)). Internal
//! state is behind a `Mutex`; point-change notifications are also fanned out to
//! an internal channel so the polling task observes host-driven changes
//! promptly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use mms_proto::mms::{Data, Identifier, InformationReport, ObjectName};
use tokio::sync::{mpsc, Mutex};

use tase2_proto::names;
use tase2_proto::report::{build_information_report, SpecialValues};
use tase2_proto::reporting::{ReportAction, TransferSetScheduler};
use tase2_proto::transfer_set::{DsConditions, DsTransferSet};

use crate::provider::DataProvider;

/// Default number of transfer-set instances per domain.
pub const DEFAULT_POOL_SIZE: usize = 8;

/// The base name of a pooled transfer-set instance: `DSTransferSet{n}` for
/// `n` in `1..=pool_size`. libtase2 names its instances `DSTransferSet` /
/// `DSTransferSet1`, …; we use the 1-based numeric suffix uniformly.
fn instance_name(domain: &Identifier, n: usize) -> ObjectName {
    ObjectName::DomainSpecific {
        domain: domain.clone(),
        // `Identifier::new` cannot fail for this bounded ASCII string.
        item: Identifier::new(format!("DSTransferSet{n}"))
            .expect("pooled transfer-set instance name is a valid identifier"),
    }
}

/// State for one transfer-set instance in the pool.
#[derive(Debug, Clone)]
struct Instance {
    /// The instance's object name (`domain/DSTransferSetN`).
    name: ObjectName,
    /// Whether a client has claimed this instance (via `Next_DSTransfer_Set`).
    allocated: bool,
    /// The last-written attributes (the locally-buffered copy a client reads
    /// back). `Default` (disabled) until first written.
    value: DsTransferSet,
}

/// Per-domain transfer-set state.
#[derive(Debug)]
struct DomainState {
    instances: Vec<Instance>,
}

impl DomainState {
    fn new(domain: &Identifier, pool_size: usize) -> Self {
        let instances = (1..=pool_size)
            .map(|n| Instance {
                name: instance_name(domain, n),
                allocated: false,
                value: DsTransferSet::default(),
            })
            .collect();
        DomainState { instances }
    }

    fn find_mut(&mut self, name: &ObjectName) -> Option<&mut Instance> {
        self.instances.iter_mut().find(|i| &i.name == name)
    }

    fn find(&self, name: &ObjectName) -> Option<&Instance> {
        self.instances.iter().find(|i| &i.name == name)
    }

    /// Allocate and return the next free instance's name, or `None` if the pool
    /// is exhausted.
    fn allocate_next(&mut self) -> Option<ObjectName> {
        let inst = self.instances.iter_mut().find(|i| !i.allocated)?;
        inst.allocated = true;
        Some(inst.name.clone())
    }
}

#[derive(Debug)]
struct Inner {
    domains: HashMap<String, DomainState>,
    scheduler: TransferSetScheduler,
    pool_size: usize,
}

/// The server-side transfer-set manager.
#[derive(Debug)]
pub struct TransferSetManager<P: DataProvider> {
    inner: Mutex<Inner>,
    provider: Arc<P>,
    /// Host/serve-loop point-change notifications, drained by the polling task.
    change_tx: mpsc::Sender<ObjectName>,
    change_rx: Mutex<mpsc::Receiver<ObjectName>>,
}

/// Depth of the point-change notification channel.
const CHANGE_DEPTH: usize = 256;

impl<P: DataProvider> TransferSetManager<P> {
    /// Create a manager with the [default pool size](DEFAULT_POOL_SIZE).
    #[must_use]
    pub fn new(provider: Arc<P>) -> Self {
        Self::with_pool_size(provider, DEFAULT_POOL_SIZE)
    }

    /// Create a manager with an explicit per-domain pool size (clamped to at
    /// least 1).
    #[must_use]
    pub fn with_pool_size(provider: Arc<P>, pool_size: usize) -> Self {
        let (change_tx, change_rx) = mpsc::channel(CHANGE_DEPTH);
        TransferSetManager {
            inner: Mutex::new(Inner {
                domains: HashMap::new(),
                scheduler: TransferSetScheduler::new(),
                pool_size: pool_size.max(1),
            }),
            provider,
            change_tx,
            change_rx: Mutex::new(change_rx),
        }
    }

    /// Whether `name` is the `Next_DSTransfer_Set` special variable.
    #[must_use]
    pub fn is_next_transfer_set(name: &ObjectName) -> bool {
        item_str(name) == names::NEXT_DSTRANSFER_SET_NAME
    }

    /// The domain key + identifier of an object name, if domain-specific.
    fn domain_of(name: &ObjectName) -> Option<&Identifier> {
        match name {
            ObjectName::DomainSpecific { domain, .. } => Some(domain),
            _ => None,
        }
    }

    /// Handle a Read of a transfer-set-related variable.
    ///
    /// Returns `Some(data)` if `name` is the `Next_DSTransfer_Set` allocator
    /// (→ the allocated instance's object name, encoded as a two-`VisibleString`
    /// structure) or a known transfer-set instance (→ its attribute structure).
    /// Returns `None` if `name` is not managed here (the caller falls back to
    /// the provider).
    pub async fn handle_read(&self, name: &ObjectName) -> Option<Data> {
        let domain = Self::domain_of(name)?;
        let mut inner = self.inner.lock().await;
        let pool_size = inner.pool_size;
        let domain_key = domain.as_str().to_owned();
        let state = inner
            .domains
            .entry(domain_key)
            .or_insert_with(|| DomainState::new(domain, pool_size));

        if item_str(name) == names::NEXT_DSTRANSFER_SET_NAME {
            // Allocate the next free instance and return its name.
            return Some(match state.allocate_next() {
                Some(obj) => object_name_to_data(&obj),
                // Pool exhausted: return an empty name.
                None => object_name_to_data(&ObjectName::VmdSpecific(
                    Identifier::new("NONE").expect("static identifier"),
                )),
            });
        }

        state.find(name).map(|inst| inst.value.to_mms())
    }

    /// Handle a Write of a transfer-set instance variable.
    ///
    /// Returns `Some(Ok(()))` on a successful write to a known instance,
    /// `Some(Err(code))` for a malformed structure (`TYPE_INCONSISTENT`) or an
    /// enable referencing a data set the provider does not have
    /// (`OBJECT_NON_EXISTENT`), or `None` if `name` is not a managed
    /// transfer-set instance (the caller falls back to the provider).
    ///
    /// On `Status = true` the scheduler is enabled with the data set's resolved
    /// member list; on `Status = false` it is disabled. When `Status = true` and
    /// a `DataSetName` is given that the provider cannot resolve, the write fails
    /// (`OBJECT_NON_EXISTENT`) and the instance is **not** claimed or enabled —
    /// enabling reporting against a missing data set would otherwise be a silent
    /// no-op. A `Status = true` with no `DataSetName` is tolerated (enabled with
    /// no members; it simply never has anything to report).
    pub async fn handle_write(&self, name: &ObjectName, data: &Data) -> Option<Result<(), i64>> {
        let domain = Self::domain_of(name)?;
        let ts_item = match name {
            ObjectName::DomainSpecific { item, .. } => item.clone(),
            _ => return None,
        };

        // First: is this a managed transfer-set instance at all? If not, the
        // caller must fall back to the provider — so this check (and the pool's
        // lazy creation) happens *before* any provider call or hard failure, so
        // a write to a non-instance name never returns a spurious error.
        {
            let mut inner = self.inner.lock().await;
            let pool_size = inner.pool_size;
            let domain_key = domain.as_str().to_owned();
            let state = inner
                .domains
                .entry(domain_key)
                .or_insert_with(|| DomainState::new(domain, pool_size));
            state.find(name)?;
        }

        // Known instance: now parse and (if enabling) resolve members.
        let ts = match DsTransferSet::from_mms(data) {
            Ok(ts) => ts,
            // TYPE_INCONSISTENT: the structure did not match the TS shape.
            Err(_) => return Some(Err(crate::data_access_error::TYPE_INCONSISTENT)),
        };

        // Resolve the data set's members (for enabling) before re-taking the
        // lock, to avoid holding the manager mutex across a provider await. When
        // enabling with a named data set, a provider miss is a hard failure.
        let members: Vec<ObjectName> = match &ts.data_set_name {
            Some(ds) => {
                let ds_obj = ds.to_object_name();
                match self.provider.data_set(&ds_obj).await {
                    Some(d) => d.entries,
                    None if ts.status => {
                        // Enabling against a non-existent data set: fail the
                        // write without claiming/enabling the instance (I6/M5).
                        return Some(Err(crate::data_access_error::OBJECT_NON_EXISTENT));
                    }
                    None => Vec::new(),
                }
            }
            None => Vec::new(),
        };

        let mut inner = self.inner.lock().await;
        let pool_size = inner.pool_size;
        let domain_key = domain.as_str().to_owned();
        let state = inner
            .domains
            .entry(domain_key)
            .or_insert_with(|| DomainState::new(domain, pool_size));

        // Re-confirm the instance still exists (it cannot disappear, but the
        // borrow needs re-establishing after the await above).
        state.find(name)?;

        let status = ts.status;
        // Store the buffered copy.
        if let Some(inst) = state.find_mut(name) {
            inst.value = ts.clone();
            // A write implicitly claims the instance.
            inst.allocated = true;
        }

        // Arm or disarm the scheduler.
        if status {
            inner.scheduler.enable(ts_item, ts, members, Instant::now());
        } else {
            inner.scheduler.disable(&ts_item);
        }
        Some(Ok(()))
    }

    /// Notify that a point changed, for host-driven (or serve-loop-driven)
    /// object-change reporting. Fans the name out to the polling task; if the
    /// channel is full the notification is dropped (object-change is
    /// best-effort coalesced anyway).
    pub fn notify_point_changed(&self, name: &ObjectName) {
        let _ = self.change_tx.try_send(name.clone());
    }

    /// The earliest pending scheduler deadline across all enabled transfer
    /// sets, if any. Lets the poll loop tighten its sleep when a report is due
    /// sooner than the ceiling tick (see [`run_reporting`]).
    pub async fn next_deadline(&self) -> Option<Instant> {
        self.inner.lock().await.scheduler.next_deadline()
    }

    /// Apply any queued point-change notifications to the scheduler, then poll
    /// the scheduler at `now` and build the due reports.
    ///
    /// Returns the assembled [`InformationReport`]s ready to send. Member values
    /// are pulled from the provider; a member that fails to read is reported as
    /// an access `Failure`.
    async fn tick(&self, now: Instant) -> Vec<InformationReport> {
        // Drain pending changes into the scheduler.
        {
            let mut rx = self.change_rx.lock().await;
            let mut inner = self.inner.lock().await;
            while let Ok(name) = rx.try_recv() {
                inner.scheduler.point_changed(&name, now);
            }
        }

        let actions = {
            let mut inner = self.inner.lock().await;
            inner.scheduler.poll(now)
        };

        let mut reports = Vec::with_capacity(actions.len());
        for action in actions {
            let ReportAction::BuildReport {
                ts_name,
                dataset,
                conditions,
            } = action
            else {
                continue;
            };
            if let Some(report) = self.build_report(&ts_name, &dataset, conditions).await {
                reports.push(report);
            }
        }
        reports
    }

    /// Build one report: resolve the data set, pull non-special member values,
    /// assemble the specials.
    async fn build_report(
        &self,
        ts_name: &Identifier,
        dataset: &ObjectName,
        conditions: DsConditions,
    ) -> Option<InformationReport> {
        let ds = self.provider.data_set(dataset).await?;
        let members = ds.entries;

        // Pull a value for every non-special member, in member order. A failed
        // provider read is threaded through as `Err(code)` so the builder emits
        // a per-member `AccessResult::Failure` (rather than an ambiguous zero).
        let mut values: Vec<core::result::Result<Data, i64>> = Vec::new();
        for member in &members {
            if is_special(member) {
                continue;
            }
            values.push(self.provider.read(member).await.map(|v| v.to_mms()));
        }

        let domain = match dataset {
            ObjectName::DomainSpecific { domain, .. } => domain.clone(),
            _ => return None,
        };
        // `SpecialValues` is `#[non_exhaustive]`; build via `Default` + fields.
        let mut specials = SpecialValues::default();
        specials.ts_name = Some(ObjectName::DomainSpecific {
            domain,
            item: ts_name.clone(),
        });
        specials.timestamp = Some(now_unix_secs());
        specials.conditions = Some(conditions);
        specials.event_code = Some(0);

        Some(build_information_report(
            dataset, &members, &specials, values,
        ))
    }
}

/// The current wall-clock time as UNIX seconds, for the report timestamp.
///
/// The scheduler works purely in monotonic `Instant`s (no wall clock). The
/// report timestamp (`Transfer_Set_Time_Stamp`, GMTBasedS) is a wall-clock
/// value, so the host samples the system clock here at **report-build time**
/// (which is the poll instant, not the original condition-trigger instant; for
/// the implemented periodic/object-change conditions the two coincide to within
/// one poll tick).
fn now_unix_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whether a member is one of the four special transfer-report members.
fn is_special(member: &ObjectName) -> bool {
    matches!(
        item_str(member),
        names::TRANSFER_SET_NAME
            | names::TRANSFER_SET_TIME_STAMP
            | names::DSCONDITIONS_DETECTED
            | names::EVENT_CODE_DETECTED
    )
}

/// The item identifier of an object name as a `&str`.
fn item_str(name: &ObjectName) -> &str {
    match name {
        ObjectName::VmdSpecific(id) | ObjectName::AaSpecific(id) => id.as_str(),
        ObjectName::DomainSpecific { item, .. } => item.as_str(),
        _ => "",
    }
}

/// Encode an object name as the two-`VisibleString` structure a client decodes
/// from `Next_DSTransfer_Set` / `Transfer_Set_Name`.
fn object_name_to_data(name: &ObjectName) -> Data {
    match name {
        ObjectName::DomainSpecific { domain, item } => Data::Structure(vec![
            Data::VisibleString(domain.as_str().to_owned()),
            Data::VisibleString(item.as_str().to_owned()),
        ]),
        ObjectName::VmdSpecific(id) | ObjectName::AaSpecific(id) => Data::Structure(vec![
            Data::VisibleString(String::new()),
            Data::VisibleString(id.as_str().to_owned()),
        ]),
        _ => Data::Structure(vec![
            Data::VisibleString(String::new()),
            Data::VisibleString(String::new()),
        ]),
    }
}

// ---------------------------------------------------------------------------
// Polling integration
// ---------------------------------------------------------------------------

use crate::server::UnsolicitedSender;
use std::time::Duration;

/// The default (ceiling) poll interval for the reporting task.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Floor on the reporting sleep, so a cluster of near-term deadlines (or a
/// deadline already in the past) cannot spin the loop hot.
const POLL_FLOOR: Duration = Duration::from_millis(1);

/// Run the reporting poll loop against a connection's unsolicited-send handle
/// until it closes.
///
/// Each iteration drains point-change notifications, polls the scheduler, sends
/// the due reports via `sender` as unsolicited `InformationReport`s, then sleeps
/// until the **sooner** of the scheduler's next deadline and `ceiling` (with a
/// 1 ms floor). Using the scheduler's
/// [`next_deadline`](TransferSetManager::next_deadline) means report latency is
/// not quantized to `ceiling` when a condition is due sooner; `ceiling` remains
/// the fallback poll cadence (and the upper bound on how long an object-change
/// notification waits before its buffer deadline is armed). Returns when the
/// send path fails (the association closed).
///
/// This is normally driven from inside
/// [`serve_connection_with_reports`](crate::serve_connection_with_reports),
/// which races it against the request loop; it is exposed for callers that wire
/// the serve loop and reporting task manually. Obtain `sender` from
/// [`ServerConnection::unsolicited_sender`](crate::ServerConnection::unsolicited_sender).
pub async fn run_reporting<P: DataProvider>(
    sender: &UnsolicitedSender,
    manager: &TransferSetManager<P>,
    ceiling: Duration,
) {
    loop {
        let now = Instant::now();
        let reports = manager.tick(now).await;
        for report in reports {
            let pdu = mms_proto::mms::MmsPdu::Unconfirmed(
                mms_proto::mms::UnconfirmedService::InformationReport(report),
            );
            if sender.send(pdu).await.is_err() {
                return;
            }
        }

        // Sleep until min(next_deadline, now + ceiling), floored at POLL_FLOOR.
        let now = Instant::now();
        let ceiling_at = now + ceiling;
        let wake_at = match manager.next_deadline().await {
            Some(deadline) if deadline < ceiling_at => deadline.max(now + POLL_FLOOR),
            _ => ceiling_at,
        };
        tokio::time::sleep_until(wake_at.into()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::MapDataProvider;
    use tase2_proto::transfer_set::TsDataSetName;
    use tase2_proto::{DataSet, PointValue};

    fn id(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    fn dn(item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id(item),
        }
    }

    #[tokio::test]
    async fn next_transfer_set_allocates_distinct_instances() {
        let provider = Arc::new(MapDataProvider::new());
        let mgr = TransferSetManager::with_pool_size(provider, 2);
        let next = ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id(names::NEXT_DSTRANSFER_SET_NAME),
        };
        let a = mgr.handle_read(&next).await.unwrap();
        let b = mgr.handle_read(&next).await.unwrap();
        assert_ne!(a, b, "two allocations must differ");
        // Pool of 2 exhausted → third returns the empty-domain sentinel
        // (Structure{"", "NONE"}) the client maps to TransferSetsExhausted.
        let c = mgr.handle_read(&next).await.unwrap();
        match c {
            Data::Structure(e) => {
                assert_eq!(e.len(), 2);
                assert_eq!(e[0], Data::VisibleString(String::new()), "empty domain");
            }
            other => panic!("expected sentinel structure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn write_status_true_enables_scheduler() {
        let provider = Arc::new(MapDataProvider::new());
        // Data set with one real point.
        provider
            .insert_point(dn("P1"), PointValue::Discrete(1))
            .await;
        provider
            .insert_data_set(DataSet::with_object_name(dn("DS1"), vec![dn("P1")]))
            .await;

        let mgr = TransferSetManager::new(provider);
        // Claim an instance.
        let next = ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id(names::NEXT_DSTRANSFER_SET_NAME),
        };
        let _ = mgr.handle_read(&next).await.unwrap();
        let inst = ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id("DSTransferSet1"),
        };

        // Write an enabled TS: interval 1s (won't fire in this fast test).
        let mut ts = DsTransferSet::default();
        ts.data_set_name = Some(TsDataSetName {
            domain: id("ICC1"),
            name: id("DS1"),
        });
        ts.interval = 0; // disabled interval
        ts.buffer_time = 0;
        ts.conditions = DsConditions::OBJECT_CHANGE;
        ts.rbe = true;
        ts.status = true;

        let res = mgr.handle_write(&inst, &ts.to_mms()).await;
        assert!(matches!(res, Some(Ok(()))));

        // A point change → tick produces one report.
        mgr.notify_point_changed(&dn("P1"));
        let reports = mgr.tick(Instant::now()).await;
        assert_eq!(reports.len(), 1, "object-change report expected");

        // Read back the buffered TS copy.
        let back = mgr.handle_read(&inst).await.unwrap();
        assert_eq!(DsTransferSet::from_mms(&back).unwrap(), ts);

        // Disable.
        ts.status = false;
        let _ = mgr.handle_write(&inst, &ts.to_mms()).await;
        mgr.notify_point_changed(&dn("P1"));
        let reports = mgr.tick(Instant::now()).await;
        assert!(reports.is_empty(), "disabled TS must not report");
    }

    #[tokio::test]
    async fn write_to_unknown_instance_falls_through() {
        let provider = Arc::new(MapDataProvider::new());
        let mgr = TransferSetManager::new(provider);
        // A regular point name, not a transfer-set instance.
        let mut ts = DsTransferSet::default();
        ts.status = false;
        // "SomePoint" is not DSTransferSetN → None (fall back to provider).
        let res = mgr.handle_write(&dn("SomePoint"), &ts.to_mms()).await;
        assert!(res.is_none());
    }

    #[tokio::test]
    async fn enable_with_missing_dataset_fails_without_claiming() {
        // I6/M5: enabling against a data set the provider does not have fails
        // (OBJECT_NON_EXISTENT) and does NOT claim or enable the instance.
        let provider = Arc::new(MapDataProvider::new());
        let mgr = TransferSetManager::new(provider);
        let inst = ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id("DSTransferSet1"),
        };

        let mut ts = DsTransferSet::default();
        ts.data_set_name = Some(TsDataSetName {
            domain: id("ICC1"),
            name: id("NoSuchDS"),
        });
        ts.conditions = DsConditions::OBJECT_CHANGE;
        ts.rbe = true;
        ts.status = true;

        let res = mgr.handle_write(&inst, &ts.to_mms()).await;
        assert_eq!(
            res,
            Some(Err(crate::data_access_error::OBJECT_NON_EXISTENT)),
            "enable against missing data set must fail per-item"
        );

        // The instance must not have been claimed: a Next_DSTransfer_Set read
        // still hands out DSTransferSet1.
        let next = ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id(names::NEXT_DSTRANSFER_SET_NAME),
        };
        let allocated = mgr.handle_read(&next).await.unwrap();
        assert_eq!(
            allocated,
            object_name_to_data(&inst),
            "first free instance should still be DSTransferSet1"
        );
    }
}
