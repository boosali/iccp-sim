//! Server-side request loop: drive a [`ServerConnection`] from a
//! [`DataProvider`].
//!
//! [`serve_connection_opts`] is the single real implementation; it receives
//! confirmed requests and answers them using the provider, optional Block-2
//! transfer-set [`manager`](TransferSetManager), optional Block-5 device-control
//! [`handler`](ControlHandler) and an optional bilateral-table access policy,
//! until the association closes. The historical `serve_connection*` entry points
//! ([`serve_connection`], [`serve_connection_full`], [`serve_connection_control`],
//! [`serve_connection_with_reports`] and the interval/control variants) are now
//! thin wrappers over the shared dispatch core, preserved so existing callers and
//! tests keep working.
//!
//! It implements the TASE.2 Block-1 subset: `GetNameList` (with `continueAfter`
//! chunking), `Read` (both `listOfVariable` and `variableListName`), `Write`,
//! and define/delete of named variable lists; plus Block-2 transfer-set
//! variables and Block-5 device control where wired in.
//!
//! # Bilateral-table access control (Phase 12)
//!
//! [`dispatch_request`] is the single choke point at which the negotiated
//! [`BilateralTable`] is enforced. When [`ServeOptions::access`] is `Some`, every
//! object reference is filtered through the table **before** the transfer-set /
//! control / provider routing decision:
//!
//! * **Read** of a data point requires [`AccessRights::read`]; otherwise a
//!   per-item `object-access-denied` `Failure`.
//! * **Write** of a data point requires [`AccessRights::write`]; otherwise a
//!   per-item `object-access-denied` `Failure`.
//! * **GetNameList** filters the returned identifiers per object class so names
//!   the peer cannot see are *invisible* — the BLT defines the peer's view.
//!   Protocol-internal names are always shown. For the named-variable (point)
//!   class, a name is shown iff the peer may read it; for the
//!   named-variable-LIST (dataset) class, iff dataset ops are allowed in the
//!   domain. The dataset-op grant gates only the dataset-name class — it never
//!   widens point visibility. Filtering is applied *before* chunking so
//!   `continueAfter` stays consistent.
//! * **Define / Delete** of a named variable list, and **Read by
//!   `variableListName`**, require dataset operations to be allowed in the
//!   target domain.
//! * **Device** select (`_SBO` read), operate (device write) and tag (`_TAG`
//!   read/write) require [`device_allowed`](BilateralTable::device_allowed),
//!   enforced *before* the control layer's own SBO/tag checks.
//! * **Transfer-set** variable reads/writes and `Next_DSTransfer_Set` are always
//!   permitted (protocol-internal). A transfer-set *enable* that references a
//!   data set is access-checked at enable time: the data set's domain must allow
//!   dataset ops, else a per-item `object-access-denied`. Report content then
//!   follows dataset rights implicitly.
//! * **`Bilateral_Table_ID`** reads are answered from the table's `id` when a
//!   table is set (otherwise they fall through to the provider as before).
//!
//! With `access: None` no enforcement is applied (back-compatible).

use std::sync::Arc;
use std::time::Duration;

use mms_proto::mms::{
    AccessResult, ConfirmedServiceRequest, ConfirmedServiceResponse, Data, DefineNvlResponse,
    DeleteNvlResponse, GetNameListResponse, GetNameListScope, Identifier, ObjectName, ReadResponse,
    ServiceError, VariableAccessSpecification, VariableSpecification, WriteResponse, WriteResult,
};
use tase2_proto::bilateral::is_protocol_internal;
use tase2_proto::{BilateralTable, DataSet, DomainName, PointValue};

use crate::control_server::ControlPoint;
use crate::data_access_error;
use crate::error::Result;
use crate::provider::{ControlHandler, DataProvider};
use crate::reporter::{run_reporting, TransferSetManager, DEFAULT_POLL_INTERVAL};
use crate::server::ServerConnection;

/// Maximum number of identifiers returned per `GetNameList` response before
/// signalling `moreFollows` and waiting for the client's `continueAfter`.
const NAME_LIST_CHUNK: usize = 100;

/// MMS `ServiceError` errorClass `service-error` ([12] "others") used to reject
/// services this server does not implement.
const ERROR_CLASS_OTHERS: u8 = 12;
/// MMS `service-error` code for an unsupported service.
const SERVICE_ERROR_UNSUPPORTED: i64 = 0;

/// MMS `ServiceError` errorClass `definition` ([2]). A failed
/// `DefineNamedVariableList` cannot be reported in its NULL success PDU, so the
/// provider's `DataAccessError` code is surfaced via a `definition`-class
/// `ServiceError` (the closest errorClass for an object-definition operation),
/// carrying the provider code in `additionalCode`.
const ERROR_CLASS_DEFINITION: u8 = 2;

/// Options for [`serve_connection_opts`], the consolidated serve entry point.
///
/// `#[non_exhaustive]` so new fields don't break callers; build it with
/// [`ServeOptions::new`] plus the `with_*` builder setters:
///
/// ```no_run
/// # use std::sync::Arc;
/// # use std::time::Duration;
/// # use tase2::{ServeOptions, BilateralTable};
/// # fn demo<P: tase2::DataProvider>() {
/// let options = ServeOptions::<P>::new()
///     .with_access(Arc::new(BilateralTable::new("BLT-1")))
///     .with_poll_ceiling(Duration::from_millis(50));
/// # let _ = options;
/// # }
/// ```
#[non_exhaustive]
pub struct ServeOptions<P: DataProvider> {
    /// Optional Block-2 transfer-set manager. When `Some`, transfer-set
    /// variables are routed through it and a concurrent reporting poll loop runs.
    pub transfer_sets: Option<Arc<TransferSetManager<P>>>,
    /// Optional Block-5 device control: a handler plus the per-connection SBO
    /// selection state ([`ControlPoint`]).
    pub control: Option<(Arc<dyn ControlHandler>, ControlPoint)>,
    /// Optional bilateral-table access policy. `None` = no enforcement
    /// (back-compatible). `Some(table)` enforces the table on every access.
    // Phase 14 may add an accept-time hook that maps a peer's AP-title/AE-qualifier
    // to the table to bind here, rather than the caller choosing it directly.
    pub access: Option<Arc<BilateralTable>>,
    /// Ceiling poll interval for the reporting loop (only used when
    /// `transfer_sets` is `Some`).
    pub poll_ceiling: Duration,
}

impl<P: DataProvider> Default for ServeOptions<P> {
    fn default() -> Self {
        ServeOptions {
            transfer_sets: None,
            control: None,
            access: None,
            poll_ceiling: DEFAULT_POLL_INTERVAL,
        }
    }
}

impl<P: DataProvider> ServeOptions<P> {
    /// A new options value with everything defaulted (no reporting, no control,
    /// no access enforcement, [`DEFAULT_POLL_INTERVAL`] ceiling).
    ///
    /// `ServeOptions` is `#[non_exhaustive]`, so build it with [`new`](Self::new)
    /// plus these builder setters rather than a struct literal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable Block-2 transfer-set reporting via `manager`.
    #[must_use]
    pub fn with_transfer_sets(mut self, manager: Arc<TransferSetManager<P>>) -> Self {
        self.transfer_sets = Some(manager);
        self
    }

    /// Enable Block-5 device control via `handler` with the given per-connection
    /// SBO selection state.
    #[must_use]
    pub fn with_control(mut self, handler: Arc<dyn ControlHandler>, control: ControlPoint) -> Self {
        self.control = Some((handler, control));
        self
    }

    /// Enforce the bilateral-table `access` policy on every access.
    #[must_use]
    pub fn with_access(mut self, access: Arc<BilateralTable>) -> Self {
        self.access = Some(access);
        self
    }

    /// Set the reporting poll ceiling (only used when transfer sets are
    /// enabled).
    #[must_use]
    pub fn with_poll_ceiling(mut self, poll_ceiling: Duration) -> Self {
        self.poll_ceiling = poll_ceiling;
        self
    }
}

impl<P: DataProvider> core::fmt::Debug for ServeOptions<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServeOptions")
            .field("transfer_sets", &self.transfer_sets.is_some())
            .field("control", &self.control.is_some())
            .field("access", &self.access.as_ref().map(|t| t.id.as_str()))
            .field("poll_ceiling", &self.poll_ceiling)
            .finish()
    }
}

/// The single consolidated serve entry point.
///
/// Serves `conn` from `provider` until the association closes, applying the
/// Block-2 transfer-set reporting, Block-5 device control and bilateral-table
/// access policy configured in `options`. When
/// [`options.transfer_sets`](ServeOptions::transfer_sets) is `Some`, a reporting
/// poll loop runs concurrently with the request loop.
///
/// All the historical `serve_connection*` functions delegate here (directly or
/// via the shared dispatch core).
pub async fn serve_connection_opts<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: Arc<P>,
    options: ServeOptions<P>,
) -> Result<()> {
    let ServeOptions {
        transfer_sets,
        control,
        access,
        poll_ceiling,
    } = options;
    let ctl = control.as_ref().map(|(h, cp)| (h.as_ref(), cp));
    let access = access.as_deref();
    match transfer_sets {
        Some(manager) => {
            serve_reports_inner(conn, &provider, &manager, poll_ceiling, ctl, access).await
        }
        None => {
            while let Some((invoke_id, req)) = conn.recv_request().await {
                dispatch_request::<P>(conn, provider.as_ref(), None, ctl, access, invoke_id, req)
                    .await?;
            }
            Ok(())
        }
    }
}

/// Serve a single associated connection until it closes (Block-1 only, no
/// access control).
///
/// Returns `Ok(())` when the peer releases or the association otherwise closes
/// cleanly. Transport/encode errors while sending a response propagate as
/// `Err`.
pub async fn serve_connection<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: &P,
) -> Result<()> {
    while let Some((invoke_id, req)) = conn.recv_request().await {
        dispatch_request::<P>(conn, provider, None, None, None, invoke_id, req).await?;
    }
    Ok(())
}

/// Data provider + optional Block-2 transfer-set `manager` + optional Block-5
/// device-control `handler`, with no access control.
///
/// Request routing is, in order: transfer-set variables (`manager`, if any) →
/// device control (`handler`, if any) → the data provider. When `handler` is
/// `Some`, a fresh per-connection [`ControlPoint`] (default select timeout) holds
/// the SBO selection state for this association.
///
/// This and the other non-`opts` wrappers are retained for source
/// compatibility; new code should prefer [`serve_connection_opts`].
pub async fn serve_connection_full<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: &P,
    manager: Option<&TransferSetManager<P>>,
    handler: Option<Arc<dyn ControlHandler>>,
) -> Result<()> {
    let control = handler.as_ref().map(|h| (h.as_ref(), ControlPoint::new()));
    while let Some((invoke_id, req)) = conn.recv_request().await {
        let ctl = control.as_ref().map(|(h, cp)| (*h, cp));
        dispatch_request::<P>(conn, provider, manager, ctl, None, invoke_id, req).await?;
    }
    Ok(())
}

/// As [`serve_connection_full`] but with a caller-supplied [`ControlPoint`], so
/// the SBO select timeout (and any future per-connection control config) can be
/// chosen explicitly. No Block-2 reporting, no access control.
pub async fn serve_connection_control<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: &P,
    handler: Arc<dyn ControlHandler>,
    control: ControlPoint,
) -> Result<()> {
    let ctl = (handler.as_ref(), &control);
    while let Some((invoke_id, req)) = conn.recv_request().await {
        dispatch_request::<P>(conn, provider, None, Some(ctl), None, invoke_id, req).await?;
    }
    Ok(())
}

/// Serve a connection with TASE.2 Block-2 DS-transfer-set reporting enabled
/// (no access control).
///
/// Like [`serve_connection`], but additionally:
/// * routes Read/Write of transfer-set variables (the `Next_DSTransfer_Set`
///   allocator and `DSTransferSet{n}` instances) through `manager` before
///   falling back to the provider;
/// * notifies `manager.point_changed` after each successful `Write` to a point,
///   driving object-change (RBE) reporting;
/// * runs the reporting poll loop concurrently (default
///   [`DEFAULT_POLL_INTERVAL`]), sending `InformationReport`s as conditions
///   fire.
pub async fn serve_connection_with_reports<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: Arc<P>,
    manager: Arc<TransferSetManager<P>>,
) -> Result<()> {
    serve_connection_with_reports_interval(conn, provider, manager, DEFAULT_POLL_INTERVAL).await
}

/// [`serve_connection_with_reports_interval`] plus a Block-5 device-control
/// `handler` and an explicit [`ControlPoint`] (so a caller can configure the
/// SBO select timeout). No access control.
pub async fn serve_connection_with_reports_interval_control<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: Arc<P>,
    manager: Arc<TransferSetManager<P>>,
    poll_interval: Duration,
    handler: Arc<dyn ControlHandler>,
    control: ControlPoint,
) -> Result<()> {
    serve_reports_inner(
        conn,
        &provider,
        &manager,
        poll_interval,
        Some((handler.as_ref(), &control)),
        None,
    )
    .await
}

/// [`serve_connection_with_reports`] with an explicit reporting poll interval
/// (use short intervals in tests). No access control.
pub async fn serve_connection_with_reports_interval<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: Arc<P>,
    manager: Arc<TransferSetManager<P>>,
    poll_interval: Duration,
) -> Result<()> {
    serve_reports_inner(conn, &provider, &manager, poll_interval, None, None).await
}

/// Shared body of the reporting serve loop. `control` carries the optional
/// device-control handler + per-connection [`ControlPoint`]; `access` the
/// optional bilateral-table policy.
async fn serve_reports_inner<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: &Arc<P>,
    manager: &Arc<TransferSetManager<P>>,
    poll_interval: Duration,
    control: Option<(&dyn ControlHandler, &ControlPoint)>,
    access: Option<&BilateralTable>,
) -> Result<()> {
    let sender = conn.unsolicited_sender();
    let report_mgr = manager.clone();
    // The reporting loop sends via the cloneable unsolicited sender, so it runs
    // concurrently with the request loop (which holds `&mut conn`).
    let reporting = run_reporting(&sender, &report_mgr, poll_interval);
    tokio::pin!(reporting);

    loop {
        tokio::select! {
            // Bias the request path: a request and a tick that come ready
            // together resolve the request first.
            biased;
            maybe_req = conn.recv_request() => {
                match maybe_req {
                    Some((invoke_id, req)) => {
                        dispatch_request::<P>(conn, provider.as_ref(), Some(manager.as_ref()), control, access, invoke_id, req).await?;
                    }
                    None => return Ok(()),
                }
            }
            // The reporting loop only returns when the send path fails (the
            // association closed); treat that as a clean stop.
            () = &mut reporting => return Ok(()),
        }
    }
}

/// Dispatch a single confirmed request. This is the single access-control choke
/// point: when `access` is `Some`, the bilateral table is enforced here before
/// transfer-set / control / provider routing.
#[allow(clippy::too_many_arguments)]
async fn dispatch_request<P: DataProvider>(
    conn: &mut ServerConnection,
    provider: &P,
    manager: Option<&TransferSetManager<P>>,
    control: Option<(&dyn ControlHandler, &ControlPoint)>,
    access: Option<&BilateralTable>,
    invoke_id: u32,
    req: ConfirmedServiceRequest,
) -> Result<()> {
    match req {
        ConfirmedServiceRequest::GetNameList(r) => {
            let resp = handle_get_name_list(provider, access, &r).await;
            conn.respond(invoke_id, ConfirmedServiceResponse::GetNameList(resp))
                .await?;
        }
        ConfirmedServiceRequest::Read(r) => {
            let resp =
                handle_read_with_manager(provider, manager, control, access, &r.access).await;
            conn.respond(invoke_id, ConfirmedServiceResponse::Read(resp))
                .await?;
        }
        ConfirmedServiceRequest::Write(r) => {
            let resp =
                handle_write_with_manager(provider, manager, control, access, &r.access, &r.data)
                    .await;
            conn.respond(invoke_id, ConfirmedServiceResponse::Write(resp))
                .await?;
        }
        ConfirmedServiceRequest::DefineNamedVariableList(r) => {
            match handle_define(provider, access, &r).await {
                Ok(resp) => {
                    conn.respond(
                        invoke_id,
                        ConfirmedServiceResponse::DefineNamedVariableList(resp),
                    )
                    .await?;
                }
                Err(code) => {
                    conn.respond_error(invoke_id, definition_error(code))
                        .await?;
                }
            }
        }
        ConfirmedServiceRequest::DeleteNamedVariableList(r) => {
            let resp = handle_delete(provider, access, &r).await;
            conn.respond(
                invoke_id,
                ConfirmedServiceResponse::DeleteNamedVariableList(resp),
            )
            .await?;
        }
        ConfirmedServiceRequest::Unsupported { .. } => {
            conn.respond_error(invoke_id, unsupported_service_error())
                .await?;
        }
        // Any service variant added to the enum in future but not handled
        // here is treated as unsupported.
        _ => {
            conn.respond_error(invoke_id, unsupported_service_error())
                .await?;
        }
    }
    Ok(())
}

fn unsupported_service_error() -> ServiceError {
    ServiceError {
        class_tag: ERROR_CLASS_OTHERS,
        code: SERVICE_ERROR_UNSUPPORTED,
        additional_code: None,
        additional_description: None,
    }
}

/// A `definition`-class `ServiceError` carrying a provider `DataAccessError`
/// code in `additionalCode` (the errorClass `definition` alternative itself has
/// no fine-grained code, so the provider's intent is preserved alongside).
fn definition_error(code: i64) -> ServiceError {
    ServiceError {
        class_tag: ERROR_CLASS_DEFINITION,
        code: 0,
        additional_code: Some(code),
        additional_description: None,
    }
}

/// The item identifier portion of an object name, as a `&str`.
fn item_str(name: &ObjectName) -> &str {
    match name {
        ObjectName::VmdSpecific(id) | ObjectName::AaSpecific(id) => id.as_str(),
        ObjectName::DomainSpecific { item, .. } => item.as_str(),
        _ => "",
    }
}

/// Handle `GetNameList`, applying access filtering *before* `continueAfter`
/// chunking so the cursor is resolved against the peer's filtered view and the
/// returned identifiers never expose a name the peer may not see.
///
/// # Side channel (accepted)
/// Because the cursor is matched against the *filtered* list, a `continueAfter`
/// value naming an object the peer cannot see is not found and yields an empty
/// final page — indistinguishable from a genuinely non-existent name, so the
/// continuation path itself leaks nothing. The residual name-existence side
/// channel is the per-item read distinction (a denied read of an existing-but-
/// hidden point returns `object-access-denied`, an absent name
/// `object-non-existent`): a peer probing a guessed name can tell "exists but
/// hidden" from "absent". This is accepted as low severity — a BLT peer already
/// knows its own table (the set of names it is entitled to), and the signal
/// reveals only existence, never a hidden name's value or rights.
async fn handle_get_name_list<P: DataProvider>(
    provider: &P,
    access: Option<&BilateralTable>,
    req: &mms_proto::mms::GetNameListRequest,
) -> GetNameListResponse {
    let domain: Option<DomainName> = match &req.scope {
        GetNameListScope::DomainSpecific(id) => Some(DomainName::from(id.clone())),
        GetNameListScope::VmdSpecific | GetNameListScope::AaSpecific => None,
        _ => None,
    };
    let mut all = provider.names(req.object_class, domain.as_ref()).await;

    // Access filtering: names the peer cannot see are removed from the peer's
    // view *before* chunking, so the `continueAfter` cursor stays consistent
    // across pages. Protocol-internal names are always visible; named-variable
    // (point) names are visible iff readable; named-variable-list (dataset)
    // names are visible iff dataset ops are allowed in the domain.
    if let Some(table) = access {
        all.retain(|item| is_name_visible(table, req.object_class, domain.as_ref(), item));
    }

    // Apply continueAfter: return up to NAME_LIST_CHUNK names strictly after the
    // continuation cursor. `all` is whatever order the provider returned; the
    // MapDataProvider sorts it, which makes the cursor well-defined.
    let start = match &req.continue_after {
        Some(after) => all
            .iter()
            .position(|id| id == after)
            .map_or(all.len(), |p| p + 1),
        None => 0,
    };
    let end = (start + NAME_LIST_CHUNK).min(all.len());
    let chunk: Vec<Identifier> = all.get(start..end).unwrap_or(&[]).to_vec();
    let more_follows = end < all.len();

    GetNameListResponse {
        identifiers: chunk,
        more_follows,
    }
}

/// Whether an enumerated `item` of `object_class` in `domain` is visible to the
/// peer under `table`.
fn is_name_visible(
    table: &BilateralTable,
    object_class: u8,
    domain: Option<&DomainName>,
    item: &Identifier,
) -> bool {
    use crate::provider::{
        OBJECT_CLASS_DOMAIN, OBJECT_CLASS_NAMED_VARIABLE, OBJECT_CLASS_NAMED_VARIABLE_LIST,
    };
    // Protocol-internal names are always visible regardless of the table.
    if is_protocol_internal(item.as_str()) {
        return true;
    }
    let obj = match domain {
        Some(d) => ObjectName::DomainSpecific {
            domain: d.identifier().clone(),
            item: item.clone(),
        },
        None => ObjectName::VmdSpecific(item.clone()),
    };
    match object_class {
        OBJECT_CLASS_NAMED_VARIABLE => table.point_rights(&obj).read,
        OBJECT_CLASS_NAMED_VARIABLE_LIST => table.dataset_ops_allowed(&obj),
        // Domain enumeration: `item` is the domain name itself; visible iff
        // the table mentions the domain in any grant.
        OBJECT_CLASS_DOMAIN => table.domain_visible(item),
        // Unknown classes: nothing to show.
        _ => false,
    }
}

/// Resolve a `VariableAccessSpecification` into the ordered list of object
/// references to access.
///
/// Returns `None` only for a `variableListName` naming a data set the provider
/// does not have — distinct from `Some(empty)` for an empty `listOfVariable`.
/// A single `data_set` fetch resolves the name, so there is no TOCTOU window
/// between an existence check and the fetch.
async fn resolve_read_targets<P: DataProvider>(
    provider: &P,
    access: &VariableAccessSpecification,
) -> Option<Vec<ObjectName>> {
    match access {
        VariableAccessSpecification::ListOfVariable(vars) => Some(
            vars.iter()
                .filter_map(|v| match v {
                    VariableSpecification::Name(n) => Some(n.clone()),
                    _ => None,
                })
                .collect(),
        ),
        VariableAccessSpecification::VariableListName(name) => {
            provider.data_set(name).await.map(|ds| ds.entries)
        }
        _ => Some(Vec::new()),
    }
}

/// Whether `name` is an `_SBO`/`_TAG` control companion whose base device the
/// table does **not** allow. Returns `true` only for that denied-companion case,
/// so the choke point can fail just that item *before* the control layer runs.
///
/// A non-companion name (a plain point or a direct operate target) returns
/// `false` here; direct-operate device authorisation is handled in
/// [`write_denial`] via [`BilateralTable::device_allowed`].
fn denied_control_target(table: &BilateralTable, name: &ObjectName) -> bool {
    use tase2_proto::control::{strip_sbo_suffix, strip_tag_suffix};
    // The device an access targets: the base name with any `_SBO`/`_TAG` suffix
    // stripped, else the name itself (a direct operate target).
    let device = base_device_name(name, strip_sbo_suffix)
        .or_else(|| base_device_name(name, strip_tag_suffix));
    match device {
        // A `_SBO`/`_TAG` companion: deny iff its device is not allowed.
        Some(dev) => !table.device_allowed(&dev),
        // Not a companion: it is a potential direct operate/select target. We
        // cannot tell here whether it is a device (that needs the handler), so
        // defer: an operate on a denied device is caught by the control layer
        // returning a device + our device check in handle_write below. Treat a
        // plain name as not-a-control-target here.
        None => false,
    }
}

/// Strip a control suffix from `name`'s item identifier, returning the base
/// device object name in the same scope, or `None` if the suffix is absent.
fn base_device_name(name: &ObjectName, strip: fn(&str) -> Option<&str>) -> Option<ObjectName> {
    match name {
        ObjectName::VmdSpecific(id) => Some(ObjectName::VmdSpecific(
            Identifier::new(strip(id.as_str())?).ok()?,
        )),
        ObjectName::DomainSpecific { domain, item } => Some(ObjectName::DomainSpecific {
            domain: domain.clone(),
            item: Identifier::new(strip(item.as_str())?).ok()?,
        }),
        ObjectName::AaSpecific(id) => Some(ObjectName::AaSpecific(
            Identifier::new(strip(id.as_str())?).ok()?,
        )),
        _ => None,
    }
}

/// Read, consulting `manager` (if any) for transfer-set variables before the
/// provider. A `manager` read that returns `Some(data)` is the authoritative
/// value for that target; otherwise the provider is queried.
async fn handle_read_with_manager<P: DataProvider>(
    provider: &P,
    manager: Option<&TransferSetManager<P>>,
    control: Option<(&dyn ControlHandler, &ControlPoint)>,
    access: Option<&BilateralTable>,
    spec: &VariableAccessSpecification,
) -> ReadResponse {
    // Dataset-by-name read: the whole list requires dataset ops in its domain.
    if let VariableAccessSpecification::VariableListName(name) = spec {
        if let Some(table) = access {
            if !is_protocol_internal(item_str(name)) && !table.dataset_ops_allowed(name) {
                return ReadResponse {
                    access_results: vec![AccessResult::Failure(
                        data_access_error::OBJECT_ACCESS_DENIED,
                    )],
                };
            }
        }
    }

    let Some(targets) = resolve_read_targets(provider, spec).await else {
        // The named variable list does not exist: a single failure entry.
        return ReadResponse {
            access_results: vec![AccessResult::Failure(
                data_access_error::OBJECT_NON_EXISTENT,
            )],
        };
    };
    let mut access_results = Vec::with_capacity(targets.len());
    for name in &targets {
        // Access control choke point (read side).
        if let Some(table) = access {
            if let Some(denial) = read_denial(table, name) {
                access_results.push(AccessResult::Failure(denial));
                continue;
            }
        }
        // Bilateral_Table_ID: when a table is set, answer its id directly
        // (routed before the provider). With no table this falls through to the
        // provider as before.
        if let Some(table) = access {
            if item_str(name) == tase2_proto::names::BILATERAL_TABLE_ID {
                access_results.push(AccessResult::Success(Data::VisibleString(table.id.clone())));
                continue;
            }
        }
        // Transfer-set variables (Next_DSTransfer_Set, DSTransferSet{n}) are
        // served by the manager when present.
        if let Some(mgr) = manager {
            if let Some(data) = mgr.handle_read(name).await {
                access_results.push(AccessResult::Success(data));
                continue;
            }
        }
        // Device control: `<dev>_SBO` select and `<dev>_TAG` read are served by
        // the control handler before the provider fallback.
        if let Some((handler, cp)) = control {
            if let Some(outcome) = cp.handle_read(handler, name).await {
                access_results.push(match outcome {
                    Ok(data) => AccessResult::Success(data),
                    Err(code) => AccessResult::Failure(code),
                });
                continue;
            }
        }
        // TASE.2 special variables whose value is not a `PointValue`
        // (`TASE2_Version`, `Supported_Features`): let the provider supply the
        // raw MMS `Data` before falling back to the point read.
        // iccp-sim addition (see `DataProvider::special_read`).
        if let Some(data) = provider.special_read(name).await {
            access_results.push(AccessResult::Success(data));
            continue;
        }
        let ar = match provider.read(name).await {
            Ok(value) => AccessResult::Success(value.to_mms()),
            Err(code) => AccessResult::Failure(code),
        };
        access_results.push(ar);
    }
    ReadResponse { access_results }
}

/// The `DataAccessError` code to fail a read of `name` with under `table`, or
/// `None` if the read is permitted. Protocol-internal names and device control
/// companions are routed to their own checks.
fn read_denial(table: &BilateralTable, name: &ObjectName) -> Option<i64> {
    let item = item_str(name);
    // Protocol-internal (special vars, transfer-set instances): always readable.
    if is_protocol_internal(item) {
        return None;
    }
    // Device control companions (`_SBO` select, `_TAG` read): gated by device
    // allowance, enforced before the control layer.
    if denied_control_target(table, name) {
        return Some(data_access_error::OBJECT_ACCESS_DENIED);
    }
    if is_control_companion(name) {
        // Allowed device companion: let the control layer handle it.
        return None;
    }
    // Plain data point: needs read rights.
    if table.point_rights(name).read {
        None
    } else {
        Some(data_access_error::OBJECT_ACCESS_DENIED)
    }
}

/// Whether `name` ends in a control companion suffix (`_SBO`/`_TAG`).
fn is_control_companion(name: &ObjectName) -> bool {
    use tase2_proto::control::{strip_sbo_suffix, strip_tag_suffix};
    let item = item_str(name);
    strip_sbo_suffix(item).is_some() || strip_tag_suffix(item).is_some()
}

/// Write, consulting `manager` (if any) for transfer-set instance writes before
/// the provider. A successful point write notifies the manager so object-change
/// reporting can fire.
async fn handle_write_with_manager<P: DataProvider>(
    provider: &P,
    manager: Option<&TransferSetManager<P>>,
    control: Option<(&dyn ControlHandler, &ControlPoint)>,
    access: Option<&BilateralTable>,
    spec: &VariableAccessSpecification,
    data: &[Data],
) -> WriteResponse {
    // Dataset-by-name write: the whole list requires dataset ops in its domain
    // (symmetric with the read path). Per-item write rights are still enforced
    // below for each resolved member; this upfront gate denies the whole write
    // with a single Failure when the dataset's domain lacks dataset ops, rather
    // than relying on the per-item rights alone.
    if let VariableAccessSpecification::VariableListName(name) = spec {
        if let Some(table) = access {
            if !is_protocol_internal(item_str(name)) && !table.dataset_ops_allowed(name) {
                return WriteResponse {
                    results: vec![WriteResult::Failure(
                        data_access_error::OBJECT_ACCESS_DENIED,
                    )],
                };
            }
        }
    }

    let Some(targets) = resolve_read_targets(provider, spec).await else {
        // The named variable list does not exist: a single failure entry.
        return WriteResponse {
            results: vec![WriteResult::Failure(data_access_error::OBJECT_NON_EXISTENT)],
        };
    };
    let mut results = Vec::with_capacity(targets.len());
    for (i, name) in targets.iter().enumerate() {
        let result = match data.get(i) {
            None => WriteResult::Failure(data_access_error::TYPE_INCONSISTENT),
            Some(d) => {
                // Access control choke point (write side).
                if let Some(table) = access {
                    if let Some(denial) = write_denial(table, name, d) {
                        results.push(WriteResult::Failure(denial));
                        continue;
                    }
                }
                // Transfer-set instance write?
                if let Some(mgr) = manager {
                    if let Some(outcome) = mgr.handle_write(name, d).await {
                        match outcome {
                            Ok(()) => results.push(WriteResult::Success),
                            Err(code) => results.push(WriteResult::Failure(code)),
                        }
                        continue;
                    }
                }
                // Device control: operate (write of a device variable) and
                // `<dev>_TAG` write are served by the control handler before the
                // provider fallback.
                if let Some((handler, cp)) = control {
                    if let Some(outcome) = cp.handle_write(handler, name, d).await {
                        results.push(match outcome {
                            Ok(()) => WriteResult::Success,
                            Err(code) => WriteResult::Failure(code),
                        });
                        continue;
                    }
                }
                let r = write_one(provider, name, d).await;
                // A successful point write drives object-change reporting.
                if matches!(r, WriteResult::Success) {
                    if let Some(mgr) = manager {
                        mgr.notify_point_changed(name);
                    }
                }
                r
            }
        };
        results.push(result);
    }
    WriteResponse { results }
}

/// The `DataAccessError` code to fail a write of `name` with under `table`, or
/// `None` if permitted.
///
/// * Protocol-internal transfer-set variables are always writable, **except** a
///   transfer-set *enable* that references a data set whose domain is not
///   dataset-op-allowed — that is denied at enable time.
/// * Device companions / operate targets are gated by device allowance.
/// * Plain data points need write rights.
fn write_denial(table: &BilateralTable, name: &ObjectName, data: &Data) -> Option<i64> {
    let item = item_str(name);
    if is_protocol_internal(item) {
        // A transfer-set instance enable referencing a disallowed data set's
        // domain is denied at enable time. (Other internal writes — disable, or
        // non-instance specials — are permitted.)
        if let Some(ds_obj) = enable_dataset_target(data) {
            if !table.dataset_ops_allowed(&ds_obj) {
                return Some(data_access_error::OBJECT_ACCESS_DENIED);
            }
        }
        return None;
    }
    // Device operate / `_TAG` / `_SBO` write: gated by device allowance.
    if denied_control_target(table, name) {
        return Some(data_access_error::OBJECT_ACCESS_DENIED);
    }
    if is_control_companion(name) {
        return None;
    }
    // A non-companion write is either a plain data-point write or a *direct*
    // device operate (write straight to the device variable). The host grants a
    // device via `allow_device`, not `allow_point`, so authorise the write iff
    // EITHER the point write flag is set (data point) OR the name is an allowed
    // device (direct operate). Both being absent is a denied access — which
    // covers the "operate a disallowed device" case before the control layer
    // ever sees it.
    if table.point_rights(name).write || table.device_allowed(name) {
        None
    } else {
        Some(data_access_error::OBJECT_ACCESS_DENIED)
    }
}

/// If `data` is a transfer-set structure being *enabled* (`status = true`) with
/// a referenced data set, return that data set's [`ObjectName`]; else `None`.
fn enable_dataset_target(data: &Data) -> Option<ObjectName> {
    let ts = tase2_proto::DsTransferSet::from_mms(data).ok()?;
    if !ts.status {
        return None;
    }
    let ds = ts.data_set_name?;
    Some(ds.to_object_name())
}

async fn write_one<P: DataProvider>(
    provider: &P,
    name: &ObjectName,
    data: &mms_proto::mms::Data,
) -> WriteResult {
    let Some(kind) = provider.point_kind(name).await else {
        return WriteResult::Failure(data_access_error::OBJECT_NON_EXISTENT);
    };
    let value = match PointValue::from_mms(kind, data) {
        Ok(v) => v,
        Err(_) => return WriteResult::Failure(data_access_error::TYPE_INCONSISTENT),
    };
    match provider.write(name, value).await {
        Ok(()) => WriteResult::Success,
        Err(code) => WriteResult::Failure(code),
    }
}

async fn handle_define<P: DataProvider>(
    provider: &P,
    access: Option<&BilateralTable>,
    req: &mms_proto::mms::DefineNvlRequest,
) -> core::result::Result<DefineNvlResponse, i64> {
    // DefineNamedVariableList-Response is NULL on success; a provider-side
    // failure is surfaced by the caller as a `definition`-class `ServiceError`
    // (see `definition_error`).
    let ds = DataSet::from_define_request(req);
    // Access: defining a data set requires dataset ops in the target domain.
    if let Some(table) = access {
        if !table.dataset_ops_allowed(&ds.name) {
            return Err(data_access_error::OBJECT_ACCESS_DENIED);
        }
    }
    provider
        .define_data_set(ds)
        .await
        .map(|()| DefineNvlResponse)
}

async fn handle_delete<P: DataProvider>(
    provider: &P,
    access: Option<&BilateralTable>,
    req: &mms_proto::mms::DeleteNvlRequest,
) -> DeleteNvlResponse {
    let mut matched = 0u32;
    let mut deleted = 0u32;
    for name in &req.names {
        matched += 1;
        // Access: deleting requires dataset ops in the target domain. A denied
        // delete is counted as matched-but-not-deleted (it is not removed).
        if let Some(table) = access {
            if !table.dataset_ops_allowed(name) {
                continue;
            }
        }
        if provider.delete_data_set(name).await.is_ok() {
            deleted += 1;
        }
    }
    DeleteNvlResponse {
        number_matched: matched,
        number_deleted: deleted,
    }
}
