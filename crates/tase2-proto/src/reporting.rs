//! The pure (sans-I/O) DS-transfer-set scheduler.
//!
//! [`TransferSetScheduler`] decides **when** and **which** conditions fire for
//! each enabled transfer set. It is the "core schedules, host fills" seam:
//!
//! * The core **schedules** — it owns the per-transfer-set deadlines (interval,
//!   integrity, object-change buffer) and emits [`ReportAction::BuildReport`]
//!   when a deadline elapses.
//! * The host **fills** — on receiving a `BuildReport`, the async layer pulls
//!   the current member values from its data source and assembles the report.
//!
//! The scheduler **never holds point values**: it only knows each transfer
//! set's dataset member *names* (to route [`point_changed`](TransferSetScheduler::point_changed))
//! and its timing. Time is **injected**: every method that needs the current
//! instant takes a [`now: Instant`](std::time::Instant) argument; the scheduler
//! never calls `Instant::now()` itself, so it is deterministic and testable with
//! a stub clock.
//!
//! # Conditions implemented (v1)
//!
//! * **IntervalTimeout** — fires every `interval` seconds from the anchor.
//!   Reschedules drift-free (`next = previous_deadline + interval`).
//! * **IntegrityTimeout** — fires every `integrity_check` seconds, independently
//!   of the interval. Also drift-free.
//! * **ObjectChange** (RBE) — a [`point_changed`](TransferSetScheduler::point_changed)
//!   touching a member arms a one-shot deadline `now + buffer_time`; further
//!   changes within the window *coalesce* (the deadline is not pushed out). A
//!   `buffer_time` of `0` fires immediately (deadline = `now`).
//!
//! Edge rules:
//! * `interval == 0` disables the interval condition even if its bit is set;
//!   likewise `integrity_check == 0` disables integrity.
//! * A condition bit that is not requested is never scheduled.
//! * Multiple conditions of one transfer set that come due at the same
//!   [`poll`](TransferSetScheduler::poll) merge into **one** action with the
//!   triggering condition bits OR-ed together.
//!
//! Deferred conditions (`OperatorRequest`, `ExternalEvent`) are accepted in the
//! requested bitmask but never scheduled by v1.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mms_proto::mms::{Identifier, ObjectName};

use crate::transfer_set::{DsConditions, DsTransferSet};

/// An action the driver must carry out, emitted by
/// [`TransferSetScheduler::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportAction {
    /// Build and send a report for `ts_name`'s `dataset`, because `conditions`
    /// fired. The driver pulls the member values from its data source.
    BuildReport {
        /// The transfer set that triggered.
        ts_name: Identifier,
        /// The data set to report (the transfer set's `DataSetName` as a
        /// domain-specific [`ObjectName`]).
        dataset: ObjectName,
        /// The condition bits that fired this report (OR-ed if several came due
        /// together).
        conditions: DsConditions,
    },
}

/// Per-transfer-set scheduling state.
#[derive(Debug)]
struct Entry {
    /// The data set reported (domain-specific object name).
    dataset: ObjectName,
    /// The dataset member names, used to route `point_changed`.
    members: Vec<ObjectName>,
    /// Requested conditions (the raw bitmask, including deferred bits).
    requested: DsConditions,
    /// Interval period; `None` when the interval condition is inactive
    /// (bit unset or `interval == 0`).
    interval: Option<Duration>,
    /// Next interval deadline (only meaningful when `interval` is `Some`).
    interval_due: Instant,
    /// Integrity period; `None` when inactive.
    integrity: Option<Duration>,
    /// Next integrity deadline.
    integrity_due: Instant,
    /// Object-change buffer window. `Some(Duration::ZERO)` means fire-immediate;
    /// `None` means the object-change condition is inactive (bit unset, or RBE
    /// disabled).
    buffer: Option<Duration>,
    /// An armed object-change deadline (set by `point_changed`, cleared when the
    /// report fires). `None` when no change is pending.
    change_due: Option<Instant>,
}

impl Entry {
    /// The earliest pending deadline across all active conditions, if any.
    fn next_deadline(&self) -> Option<Instant> {
        let mut out: Option<Instant> = None;
        let mut consider = |t: Instant| {
            out = Some(match out {
                Some(cur) if cur <= t => cur,
                _ => t,
            });
        };
        if self.interval.is_some() {
            consider(self.interval_due);
        }
        if self.integrity.is_some() {
            consider(self.integrity_due);
        }
        if let Some(due) = self.change_due {
            consider(due);
        }
        out
    }
}

/// The pure DS-transfer-set scheduler. Keyed by transfer-set name
/// ([`Identifier`]).
#[derive(Debug, Default)]
pub struct TransferSetScheduler {
    entries: HashMap<Identifier, Entry>,
}

/// Convert a non-negative second count to a `Duration`, treating `0` (and any
/// negative value, which cannot fire) as "inactive".
fn secs_to_period(seconds: i32) -> Option<Duration> {
    if seconds > 0 {
        Some(Duration::from_secs(seconds as u64))
    } else {
        None
    }
}

impl TransferSetScheduler {
    /// Create an empty scheduler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install (or replace) a transfer set, anchoring its periodic deadlines at
    /// `now`. Called when a client writes the transfer set with `Status = true`.
    ///
    /// `members` is the resolved list of the data set's member object names
    /// (used to route [`point_changed`](Self::point_changed)). Re-enabling an
    /// existing name replaces the entry cleanly (deadlines re-anchored, any
    /// pending change dropped).
    ///
    /// `StartTime` from the transfer set is **not** honoured as an absolute wall
    /// clock in v1 (the scheduler has no wall clock); periodic conditions are
    /// anchored at `now + period`. A future enhancement could offset the first
    /// deadline by `StartTime`.
    pub fn enable(
        &mut self,
        ts_name: Identifier,
        ts: DsTransferSet,
        members: Vec<ObjectName>,
        now: Instant,
    ) {
        let dataset = ts
            .data_set_name
            .as_ref()
            .map(|n| n.to_object_name())
            // A transfer set enabled without a data set has nothing to report;
            // we still install it (so disable/replace behaves), with an empty
            // vmd-specific placeholder name it will never actually report.
            .unwrap_or_else(|| ObjectName::VmdSpecific(placeholder_dataset()));

        let interval_active =
            ts.conditions.contains(DsConditions::INTERVAL_TIMEOUT) && ts.interval > 0;
        let integrity_active =
            ts.conditions.contains(DsConditions::INTEGRITY_TIMEOUT) && ts.integrity_check > 0;
        // Object change reports only when the bit is requested AND RBE is on.
        let change_active = ts.conditions.contains(DsConditions::OBJECT_CHANGE) && ts.rbe;

        let interval = if interval_active {
            secs_to_period(ts.interval)
        } else {
            None
        };
        let integrity = if integrity_active {
            secs_to_period(ts.integrity_check)
        } else {
            None
        };
        let buffer = if change_active {
            // buffer_time <= 0 → fire immediately (ZERO window).
            Some(secs_to_period(ts.buffer_time).unwrap_or(Duration::ZERO))
        } else {
            None
        };

        let interval_due = interval.map_or(now, |p| now + p);
        let integrity_due = integrity.map_or(now, |p| now + p);

        let entry = Entry {
            dataset,
            members,
            requested: ts.conditions,
            interval,
            interval_due,
            integrity,
            integrity_due,
            buffer,
            change_due: None,
        };
        self.entries.insert(ts_name, entry);
    }

    /// Disable a transfer set (client wrote `Status = false`, or the instance
    /// was released). Cancels all its pending deadlines. No-op if not enabled.
    pub fn disable(&mut self, ts_name: &Identifier) {
        self.entries.remove(ts_name);
    }

    /// Whether a transfer set is currently enabled.
    #[must_use]
    pub fn is_enabled(&self, ts_name: &Identifier) -> bool {
        self.entries.contains_key(ts_name)
    }

    /// Number of enabled transfer sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no transfer set is enabled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Notify that `dataset_member` was written/updated. Arms the object-change
    /// buffer of every enabled transfer set whose data set contains the member.
    ///
    /// The first change in a window sets the deadline to `now + buffer_time`;
    /// further changes within the window coalesce (the deadline is not extended,
    /// so a steady stream of changes still produces exactly one report per
    /// window). A zero buffer arms `now` (fires on the next [`poll`](Self::poll)).
    pub fn point_changed(&mut self, dataset_member: &ObjectName, now: Instant) {
        for entry in self.entries.values_mut() {
            let Some(buffer) = entry.buffer else {
                continue;
            };
            if entry.members.iter().any(|m| m == dataset_member) && entry.change_due.is_none() {
                entry.change_due = Some(now + buffer);
            }
        }
    }

    /// Evaluate all deadlines against `now` and emit the due reports.
    ///
    /// For each transfer set, every condition whose deadline is `<= now` fires;
    /// those conditions merge into a single [`ReportAction::BuildReport`] with
    /// their bits OR-ed. Interval and integrity deadlines reschedule drift-free
    /// (`next = old_deadline + period`, catching up past multiple missed periods
    /// without drift); the object-change deadline is one-shot (cleared until the
    /// next change).
    ///
    /// The returned actions are in an unspecified (per-transfer-set) order.
    #[must_use]
    pub fn poll(&mut self, now: Instant) -> Vec<ReportAction> {
        let mut actions = Vec::new();
        for (ts_name, entry) in &mut self.entries {
            let mut fired = DsConditions::empty();

            if let Some(period) = entry.interval {
                if entry.interval_due <= now {
                    fired.insert(DsConditions::INTERVAL_TIMEOUT);
                    entry.interval_due = advance(entry.interval_due, period, now);
                }
            }
            if let Some(period) = entry.integrity {
                if entry.integrity_due <= now {
                    fired.insert(DsConditions::INTEGRITY_TIMEOUT);
                    entry.integrity_due = advance(entry.integrity_due, period, now);
                }
            }
            if let Some(due) = entry.change_due {
                if due <= now {
                    fired.insert(DsConditions::OBJECT_CHANGE);
                    entry.change_due = None;
                }
            }

            if !fired.is_empty() {
                // Report only the bits that were actually requested (defensive;
                // we never schedule unrequested bits, so this is a no-op in
                // practice but keeps the contract explicit).
                let conditions = DsConditions::from_bits_raw(fired.bits() & entry.requested.bits());
                if !conditions.is_empty() {
                    actions.push(ReportAction::BuildReport {
                        ts_name: ts_name.clone(),
                        dataset: entry.dataset.clone(),
                        conditions,
                    });
                }
            }
        }
        actions
    }

    /// The earliest pending deadline across all transfer sets, if any. The
    /// driver may use this to tighten its poll tick; purely informational.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries.values().filter_map(Entry::next_deadline).min()
    }
}

/// Advance a periodic deadline drift-free: the smallest `due + k*period` that is
/// strictly greater than `now`. Catches up multiple missed periods in one step
/// without accumulating drift, and never loops unboundedly (computed with
/// division).
fn advance(due: Instant, period: Duration, now: Instant) -> Instant {
    // due <= now (we only call this when the deadline elapsed). Compute how many
    // whole periods have elapsed since `due` and skip past them.
    let behind = now.saturating_duration_since(due);
    let period_ns = period.as_nanos().max(1);
    let skipped = behind.as_nanos() / period_ns; // periods fully elapsed
                                                 // next = due + (skipped + 1) * period
    let steps = skipped.saturating_add(1);
    // Convert back to a Duration carefully (cap to avoid overflow on absurd input).
    let total_ns = steps.saturating_mul(period_ns);
    let add = u64::try_from(total_ns).map_or(Duration::from_secs(u64::MAX), Duration::from_nanos);
    due + add
}

/// A placeholder data-set identifier for a transfer set enabled without a data
/// set. It is a valid MMS identifier that no real data set should use.
fn placeholder_dataset() -> Identifier {
    // `Identifier::new` cannot fail for this static string.
    Identifier::new("__no_dataset__").expect("static placeholder identifier is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer_set::TsDataSetName;

    fn id(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    fn dn(item: &str) -> ObjectName {
        ObjectName::DomainSpecific {
            domain: id("ICC1"),
            item: id(item),
        }
    }

    /// A transfer set reporting data set `ICC1/DS1` with the given conditions.
    fn ts(conditions: DsConditions, interval: i32, integrity: i32, buffer: i32) -> DsTransferSet {
        DsTransferSet {
            data_set_name: Some(TsDataSetName {
                domain: id("ICC1"),
                name: id("DS1"),
            }),
            interval,
            integrity_check: integrity,
            buffer_time: buffer,
            conditions,
            rbe: conditions.contains(DsConditions::OBJECT_CHANGE),
            status: true,
            ..DsTransferSet::default()
        }
    }

    fn members() -> Vec<ObjectName> {
        vec![dn("P1"), dn("P2")]
    }

    fn only(actions: &[ReportAction]) -> &ReportAction {
        assert_eq!(actions.len(), 1, "expected exactly one action");
        &actions[0]
    }

    fn fired_conditions(a: &ReportAction) -> DsConditions {
        let ReportAction::BuildReport { conditions, .. } = a;
        *conditions
    }

    #[test]
    fn interval_drift_free_over_ten_fires() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::INTERVAL_TIMEOUT, 10, 0, 0),
            members(),
            t0,
        );
        // No fire before the first deadline.
        assert!(s.poll(t0 + Duration::from_secs(9)).is_empty());

        // Fire at each multiple of 10s, even when polled slightly late, with no
        // accumulated drift: the k-th fire must still be scheduled off k*10s.
        for k in 1..=10u64 {
            // Poll 1ms after the exact deadline (simulating a late tick).
            let late = t0 + Duration::from_secs(k * 10) + Duration::from_millis(1);
            let actions = s.poll(late);
            assert_eq!(
                fired_conditions(only(&actions)),
                DsConditions::INTERVAL_TIMEOUT,
                "fire {k}"
            );
        }
        // After 10 fires the next deadline is 110s (drift-free), not earlier.
        assert!(s.poll(t0 + Duration::from_secs(109)).is_empty());
        assert!(!s.poll(t0 + Duration::from_secs(110)).is_empty());
    }

    #[test]
    fn integrity_independent_of_interval() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(
                DsConditions::INTERVAL_TIMEOUT | DsConditions::INTEGRITY_TIMEOUT,
                10,
                30,
                0,
            ),
            members(),
            t0,
        );
        // At 10s: interval only.
        assert_eq!(
            fired_conditions(only(&s.poll(t0 + Duration::from_secs(10)))),
            DsConditions::INTERVAL_TIMEOUT
        );
        // At 20s: interval only.
        assert_eq!(
            fired_conditions(only(&s.poll(t0 + Duration::from_secs(20)))),
            DsConditions::INTERVAL_TIMEOUT
        );
        // At 30s: BOTH interval and integrity, merged into one action.
        assert_eq!(
            fired_conditions(only(&s.poll(t0 + Duration::from_secs(30)))),
            DsConditions::INTERVAL_TIMEOUT | DsConditions::INTEGRITY_TIMEOUT
        );
    }

    #[test]
    fn merged_conditions_same_instant() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        // interval == integrity == 10 → both come due at exactly 10s.
        s.enable(
            id("TS1"),
            ts(
                DsConditions::INTERVAL_TIMEOUT | DsConditions::INTEGRITY_TIMEOUT,
                10,
                10,
                0,
            ),
            members(),
            t0,
        );
        let actions = s.poll(t0 + Duration::from_secs(10));
        assert_eq!(
            fired_conditions(only(&actions)),
            DsConditions::INTERVAL_TIMEOUT | DsConditions::INTEGRITY_TIMEOUT
        );
    }

    #[test]
    fn rbe_coalesces_three_changes_into_one() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::OBJECT_CHANGE, 0, 0, 5),
            members(),
            t0,
        );
        // Three changes within the 5s window.
        s.point_changed(&dn("P1"), t0 + Duration::from_secs(1));
        s.point_changed(&dn("P2"), t0 + Duration::from_secs(2));
        s.point_changed(&dn("P1"), t0 + Duration::from_secs(3));
        // Before the window closes (armed at t0+1 → due t0+6): nothing.
        assert!(s.poll(t0 + Duration::from_secs(5)).is_empty());
        // At t0+6: exactly one object-change report.
        let actions = s.poll(t0 + Duration::from_secs(6));
        assert_eq!(
            fired_conditions(only(&actions)),
            DsConditions::OBJECT_CHANGE
        );
        // No further report without a new change.
        assert!(s.poll(t0 + Duration::from_secs(20)).is_empty());
    }

    #[test]
    fn zero_buffer_fires_immediately() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::OBJECT_CHANGE, 0, 0, 0),
            members(),
            t0,
        );
        s.point_changed(&dn("P1"), t0);
        // Same instant poll fires (deadline == now).
        let actions = s.poll(t0);
        assert_eq!(
            fired_conditions(only(&actions)),
            DsConditions::OBJECT_CHANGE
        );
    }

    #[test]
    fn change_to_unrelated_member_is_ignored() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::OBJECT_CHANGE, 0, 0, 0),
            members(),
            t0,
        );
        s.point_changed(&dn("OTHER"), t0);
        assert!(s.poll(t0 + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn zero_interval_disables_even_with_bit() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        // Interval bit set but interval == 0 → never fires.
        s.enable(
            id("TS1"),
            ts(DsConditions::INTERVAL_TIMEOUT, 0, 0, 0),
            members(),
            t0,
        );
        assert!(s.poll(t0 + Duration::from_secs(1000)).is_empty());
        assert_eq!(s.next_deadline(), None);
    }

    #[test]
    fn disable_cancels() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::INTERVAL_TIMEOUT, 10, 0, 0),
            members(),
            t0,
        );
        s.disable(&id("TS1"));
        assert!(s.poll(t0 + Duration::from_secs(100)).is_empty());
        assert!(s.is_empty());
    }

    #[test]
    fn reenable_replaces_cleanly() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::OBJECT_CHANGE, 0, 0, 100),
            members(),
            t0,
        );
        // Arm a long pending change.
        s.point_changed(&dn("P1"), t0);
        // Re-enable with a short interval; the pending change must be dropped.
        s.enable(
            id("TS1"),
            ts(DsConditions::INTERVAL_TIMEOUT, 10, 0, 0),
            members(),
            t0 + Duration::from_secs(1),
        );
        // The old object-change deadline (t0+100) must NOT fire.
        let actions = s.poll(t0 + Duration::from_secs(11));
        assert_eq!(
            fired_conditions(only(&actions)),
            DsConditions::INTERVAL_TIMEOUT
        );
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn next_deadline_is_earliest() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        s.enable(
            id("TS1"),
            ts(DsConditions::INTERVAL_TIMEOUT, 30, 0, 0),
            members(),
            t0,
        );
        s.enable(
            id("TS2"),
            ts(DsConditions::INTERVAL_TIMEOUT, 10, 0, 0),
            members(),
            t0,
        );
        assert_eq!(s.next_deadline(), Some(t0 + Duration::from_secs(10)));
    }

    #[test]
    fn operator_request_bit_never_fires() {
        let mut s = TransferSetScheduler::new();
        let t0 = Instant::now();
        // Deferred bits requested but nothing else: never scheduled.
        s.enable(
            id("TS1"),
            ts(
                DsConditions::OPERATOR_REQUEST | DsConditions::EXTERNAL_EVENT,
                10,
                10,
                10,
            ),
            members(),
            t0,
        );
        assert!(s.poll(t0 + Duration::from_secs(1000)).is_empty());
        assert_eq!(s.next_deadline(), None);
    }
}
