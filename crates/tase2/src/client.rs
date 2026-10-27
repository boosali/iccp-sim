//! Async TASE.2 / MMS client.

use std::time::Duration;

use mms_proto::assoc::{AssocConfig, DisconnectReason, Role};
use mms_proto::mms::{ConfirmedServiceRequest, ConfirmedServiceResponse, MmsPdu};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::driver::{self, Command, DriverEvent};
use crate::error::{Error, Result};
use crate::handler::{EventHandler, NoopHandler};
use crate::transport::Transport;

/// Channel depth for commands and the confirmed/lifecycle event stream.
const EVENT_DEPTH: usize = 32;

/// Channel depth for unsolicited reports. Reports can burst, so this is wider
/// than the command/event channel; it is still bounded for backpressure.
const REPORT_DEPTH: usize = 64;

/// Default deadline for a confirmed request to receive its matching response.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Connect timeout for the underlying TCP socket.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Async TASE.2 / MMS client over TCP (and, later, TLS).
///
/// The client owns an internal driver task. It is a single-owner handle:
/// [`request`](Self::request) and [`recv_unsolicited`](Self::recv_unsolicited)
/// take `&mut self`, mirroring the reference `Client104` style (no `Arc<Mutex>`
/// around the receive half). Dropping the client tears the association down.
///
/// Inbound PDUs arrive on two independent channels: confirmed responses
/// correlate to the single in-flight [`request`](Self::request), while
/// unsolicited reports surface through [`recv_unsolicited`](Self::recv_unsolicited).
/// Both channels are bounded; **the holder must keep draining the report side**
/// (e.g. in its own task) — a peer that floods reports while the user never
/// calls [`recv_unsolicited`](Self::recv_unsolicited) will, by design, stall the
/// driver via backpressure (see the driver module docs).
#[derive(Debug)]
pub struct Tase2Client {
    cmd_tx: mpsc::Sender<Command>,
    evt_rx: mpsc::Receiver<DriverEvent>,
    report_rx: mpsc::Receiver<MmsPdu>,
    /// Client-side monotonic invoke-id allocator. A plain `u32` is sufficient:
    /// `&mut self` on every send means there is never concurrent access. Wraps
    /// explicitly on overflow.
    next_invoke_id: u32,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Tase2Client {
    /// Connect using a [`NoopHandler`].
    pub async fn connect(transport: Transport, config: AssocConfig) -> Result<Self> {
        Self::connect_with(transport, config, NoopHandler).await
    }

    /// Connect with a custom [`EventHandler`].
    pub async fn connect_with<H: EventHandler>(
        transport: Transport,
        config: AssocConfig,
        handler: H,
    ) -> Result<Self> {
        let stream = open_stream(&transport).await?;
        Self::spawn(stream, config, handler).await
    }

    /// Spawn the client driver around an already-established stream and await
    /// the association coming up. Used by [`connect_with`](Self::connect_with)
    /// (and, later, the TLS entry point) so both paths produce the same handle.
    pub(crate) async fn spawn<S, H>(stream: S, config: AssocConfig, handler: H) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        H: EventHandler,
    {
        let (cmd_tx, cmd_rx) = mpsc::channel(EVENT_DEPTH);
        let (evt_tx, mut evt_rx) = mpsc::channel(EVENT_DEPTH);
        let (report_tx, report_rx) = mpsc::channel(REPORT_DEPTH);
        let task = tokio::spawn(driver::run(
            stream,
            Role::Client,
            config,
            handler,
            cmd_rx,
            evt_tx,
            report_tx,
            true,
        ));

        // Wait for the association to come up (or fail).
        loop {
            match evt_rx.recv().await {
                Some(DriverEvent::AssociationUp) => break,
                Some(DriverEvent::Closed(reason)) => {
                    return Err(Error::AssociationFailed(reason));
                }
                // No confirmed-path PDUs are expected before AssociationUp.
                Some(DriverEvent::Service(_)) => continue,
                None => return Err(Error::DriverGone),
            }
        }

        Ok(Self {
            cmd_tx,
            evt_rx,
            report_rx,
            next_invoke_id: 0,
            task,
        })
    }

    /// Send a confirmed service request and await its matching response.
    ///
    /// The invoke-id is allocated client-side and used to correlate the
    /// response. A `ConfirmedError` for this invoke-id maps to
    /// [`Error::ServiceError`]; a `RejectPDU` to [`Error::Rejected`]. Because
    /// `&mut self` allows only one request in flight, any confirmed PDU whose
    /// invoke-id does *not* match is stale (e.g. the late answer to a request
    /// that already timed out) and is dropped with a `warn`. If the association
    /// closes before the response arrives, returns [`Error::AssociationFailed`].
    /// The wait is bounded by a fixed timeout, after which [`Error::Timeout`] is
    /// returned.
    pub async fn request(
        &mut self,
        service: ConfirmedServiceRequest,
    ) -> Result<ConfirmedServiceResponse> {
        let invoke_id = self.next_invoke_id;
        self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
        let pdu = MmsPdu::ConfirmedRequest { invoke_id, service };
        self.cmd_tx
            .send(Command::SendService(pdu))
            .await
            .map_err(|_| Error::DriverGone)?;

        tokio::time::timeout(REQUEST_TIMEOUT, self.await_response(invoke_id))
            .await
            .map_err(|_| Error::Timeout)?
    }

    /// Loop over confirmed-path events until the response for `invoke_id`
    /// arrives. Stale confirmed PDUs (non-matching invoke-id) are dropped.
    async fn await_response(&mut self, invoke_id: u32) -> Result<ConfirmedServiceResponse> {
        loop {
            match self.evt_rx.recv().await {
                Some(DriverEvent::Service(pdu)) => match pdu {
                    MmsPdu::ConfirmedResponse {
                        invoke_id: id,
                        service,
                    } if id == invoke_id => return Ok(service),
                    MmsPdu::ConfirmedError {
                        invoke_id: id,
                        error,
                    } if id == invoke_id => {
                        return Err(Error::ServiceError {
                            class_tag: error.class_tag,
                            code: error.code,
                        });
                    }
                    MmsPdu::Reject(ref reject) if reject.original_invoke_id == Some(invoke_id) => {
                        return Err(Error::Rejected);
                    }
                    // Only one request can be in flight (&mut self), so a
                    // confirmed PDU for any other invoke-id is stale — drop it.
                    other => {
                        tracing::warn!(
                            target: "tase2::client",
                            expected = invoke_id,
                            ?other,
                            "dropping stale confirmed PDU (no matching in-flight request)"
                        );
                    }
                },
                Some(DriverEvent::AssociationUp) => {}
                Some(DriverEvent::Closed(reason)) => {
                    return Err(Error::AssociationFailed(reason));
                }
                None => return Err(Error::DriverGone),
            }
        }
    }

    /// Receive the next unsolicited PDU (e.g. an `InformationReport`).
    ///
    /// Reads only from the report channel, independent of any in-flight
    /// [`request`](Self::request). Returns `None` when the association closes.
    pub async fn recv_unsolicited(&mut self) -> Option<MmsPdu> {
        self.report_rx.recv().await
    }

    /// Gracefully release the association (MMS Conclude) and wait for the driver
    /// to finish.
    ///
    /// Returns `Ok(())` only when the association closed via a normal release.
    /// Any other close reason is reported as [`Error::AssociationFailed`].
    pub async fn release(self) -> Result<()> {
        // Best-effort send; if the driver already exited, fall through to drain.
        let _ = self.cmd_tx.send(Command::Release).await;
        Self::drain_to_close(self.evt_rx, self.task).await
    }

    /// Abruptly tear the association down. Waits for the driver to wind down so
    /// the task does not outlive the handle.
    pub async fn abort(self) {
        let _ = self.cmd_tx.send(Command::Abort).await;
        let _ = Self::drain_to_close(self.evt_rx, self.task).await;
    }

    /// Drain the lifecycle channel until `Closed`, then await the driver task.
    /// Maps the close reason to a `Result` (`NormalRelease` → `Ok`).
    async fn drain_to_close(
        mut evt_rx: mpsc::Receiver<DriverEvent>,
        task: tokio::task::JoinHandle<Result<()>>,
    ) -> Result<()> {
        let mut reason: Option<DisconnectReason> = None;
        while let Some(evt) = evt_rx.recv().await {
            if let DriverEvent::Closed(r) = evt {
                reason = Some(r);
                break;
            }
        }
        // Propagate a driver-task error if one occurred; otherwise ignore the
        // join outcome (the task self-terminates on close).
        if let Ok(Err(e)) = task.await {
            return Err(e);
        }
        match reason {
            Some(DisconnectReason::NormalRelease) | None => Ok(()),
            Some(other) => Err(Error::AssociationFailed(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// TASE.2 Block-1 data API
// ---------------------------------------------------------------------------

use mms_proto::mms::{
    AccessResult, DefineNvlRequest, DeleteNvlRequest, GetNameListRequest, GetNameListScope,
    Identifier, ObjectName, ReadRequest, VariableAccessSpecification, VariableSpecification,
    WriteResult,
};
use tase2_proto::{DataSet, DomainName, PointKind, PointValue};

/// Map an MMS `AccessResult` to a per-item TASE.2 decode result.
fn access_result_to_value(kind: PointKind, ar: &AccessResult) -> Result<PointValue> {
    match ar {
        AccessResult::Failure(code) => Err(Error::DataAccessError { code: *code }),
        AccessResult::Success(data) => Ok(PointValue::from_mms(kind, data)?),
        _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
    }
}

impl Tase2Client {
    /// Read a single point and decode it as `kind`.
    pub async fn read_point(&mut self, name: &ObjectName, kind: PointKind) -> Result<PointValue> {
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                name.clone(),
            )]),
        };
        let resp = self.read_raw(req).await?;
        let ar = resp
            .access_results
            .first()
            .ok_or(Error::Protocol(mms_proto::Error::MmsInvalidPdu))?;
        access_result_to_value(kind, ar)
    }

    /// Read several points in one `Read` (a `listOfVariable`). The outer
    /// `Result` covers transport/PDU failures; each inner `Result` is the
    /// per-item outcome (an `AccessResult::Failure` becomes
    /// [`Error::DataAccessError`], a shape mismatch a domain error).
    pub async fn read_points(
        &mut self,
        names: &[(ObjectName, PointKind)],
    ) -> Result<Vec<Result<PointValue>>> {
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(
                names
                    .iter()
                    .map(|(n, _)| VariableSpecification::Name(n.clone()))
                    .collect(),
            ),
        };
        let resp = self.read_raw(req).await?;
        let kinds: Vec<PointKind> = names.iter().map(|(_, k)| *k).collect();
        zip_results(&kinds, &resp.access_results)
    }

    /// Read a named data set, decoding each member with the matching kind in
    /// `kinds` (positional). Returns per-item results like
    /// [`read_points`](Self::read_points).
    ///
    /// # Result shape
    /// On success the inner vector has one entry per `kind`. A response whose
    /// number of `AccessResult`s does not match `kinds.len()` is normally a
    /// top-level [`Error::ResponseShapeMismatch`]. There is one exception: a
    /// response carrying *exactly one* `Failure` when `kinds.len() != 1` means
    /// the **data set itself** failed (e.g. it was deleted, so the server
    /// answers with a single `object-non-existent`) — that is surfaced as a
    /// top-level [`Error::DataAccessError`].
    pub async fn read_data_set(
        &mut self,
        name: &ObjectName,
        kinds: &[PointKind],
    ) -> Result<Vec<Result<PointValue>>> {
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::VariableListName(name.clone()),
        };
        let resp = self.read_raw(req).await?;
        // Whole-data-set failure: a single Failure entry where more than one
        // (or zero) was expected. The set as a whole could not be read.
        if kinds.len() != 1 && resp.access_results.len() == 1 {
            if let Some(AccessResult::Failure(code)) = resp.access_results.first() {
                return Err(Error::DataAccessError { code: *code });
            }
        }
        zip_results(kinds, &resp.access_results)
    }

    /// Write a single point.
    pub async fn write_point(&mut self, name: &ObjectName, value: &PointValue) -> Result<()> {
        let req = mms_proto::mms::WriteRequest {
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                name.clone(),
            )]),
            data: vec![value.to_mms()],
        };
        let resp = match self.request(ConfirmedServiceRequest::Write(req)).await? {
            ConfirmedServiceResponse::Write(r) => r,
            other => return Err(unexpected_response(&other)),
        };
        match resp.results.first() {
            Some(WriteResult::Success) => Ok(()),
            Some(WriteResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            Some(_) | None => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Enumerate object names of `object_class`, scoped to `domain` (or VMD).
    ///
    /// Follows the `continueAfter` continuation loop until `more_follows` is
    /// false, concatenating all pages.
    pub async fn get_name_list(
        &mut self,
        object_class: u8,
        domain: Option<&DomainName>,
    ) -> Result<Vec<Identifier>> {
        let scope = match domain {
            Some(d) => GetNameListScope::DomainSpecific(d.identifier().clone()),
            None => GetNameListScope::VmdSpecific,
        };
        let mut out: Vec<Identifier> = Vec::new();
        let mut continue_after: Option<Identifier> = None;
        loop {
            let req = GetNameListRequest {
                object_class,
                scope: scope.clone(),
                continue_after: continue_after.clone(),
            };
            let resp = match self
                .request(ConfirmedServiceRequest::GetNameList(req))
                .await?
            {
                ConfirmedServiceResponse::GetNameList(r) => r,
                other => return Err(unexpected_response(&other)),
            };
            let more = resp.more_follows;
            let last = resp.identifiers.last().cloned();
            out.extend(resp.identifiers);
            if !more {
                break;
            }
            // Continue from the last identifier returned. If the page was empty
            // yet claimed more_follows, stop to avoid an infinite loop.
            match last {
                Some(id) => continue_after = Some(id),
                None => break,
            }
        }
        Ok(out)
    }

    /// Define a named variable list (data set).
    pub async fn define_data_set(&mut self, ds: &DataSet) -> Result<()> {
        let req: DefineNvlRequest = ds.to_define_request();
        match self
            .request(ConfirmedServiceRequest::DefineNamedVariableList(req))
            .await?
        {
            ConfirmedServiceResponse::DefineNamedVariableList(_) => Ok(()),
            other => Err(unexpected_response(&other)),
        }
    }

    /// Delete a named variable list (data set) by name.
    pub async fn delete_data_set(&mut self, name: &ObjectName) -> Result<()> {
        let req = DeleteNvlRequest {
            scope_of_delete: None,
            names: vec![name.clone()],
        };
        match self
            .request(ConfirmedServiceRequest::DeleteNamedVariableList(req))
            .await?
        {
            ConfirmedServiceResponse::DeleteNamedVariableList(_) => Ok(()),
            other => Err(unexpected_response(&other)),
        }
    }

    /// Read the `Bilateral_Table_ID` special variable, to verify both sides
    /// agree on which bilateral table is in force.
    ///
    /// In libtase2 / FreeTase2 the bilateral table identifier is a domain
    /// (ICC) variable, so pass the relevant `domain`; passing `None` reads the
    /// VMD-scoped variant. If the domain-scoped read fails with
    /// `object-non-existent` (a server that only exposes the VMD-scoped name),
    /// this falls back to a VMD-scoped read automatically. Returns the table ID
    /// as a `String` (VisibleString on the wire).
    pub async fn read_bilateral_table_id(&mut self, domain: Option<&DomainName>) -> Result<String> {
        match self.read_bilateral_table_id_scoped(domain).await {
            // Domain-scoped miss: fall back to the VMD-scoped name.
            Err(Error::DataAccessError { code })
                if domain.is_some() && code == crate::data_access_error::OBJECT_NON_EXISTENT =>
            {
                self.read_bilateral_table_id_scoped(None).await
            }
            other => other,
        }
    }

    /// Read `Bilateral_Table_ID` in exactly the given scope (no fallback).
    async fn read_bilateral_table_id_scoped(
        &mut self,
        domain: Option<&DomainName>,
    ) -> Result<String> {
        let item = Identifier::new(names::BILATERAL_TABLE_ID).map_err(Error::from)?;
        let name = match domain {
            Some(d) => ObjectName::DomainSpecific {
                domain: d.identifier().clone(),
                item,
            },
            None => ObjectName::VmdSpecific(item),
        };
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                name,
            )]),
        };
        let resp = self.read_raw(req).await?;
        match resp.access_results.first() {
            Some(AccessResult::Success(Data::VisibleString(s))) => Ok(s.clone()),
            Some(AccessResult::Success(_)) => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
            Some(AccessResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Issue a `Read` and unwrap the `Read` response variant.
    async fn read_raw(&mut self, req: ReadRequest) -> Result<mms_proto::mms::ReadResponse> {
        match self.request(ConfirmedServiceRequest::Read(req)).await? {
            ConfirmedServiceResponse::Read(r) => Ok(r),
            other => Err(unexpected_response(&other)),
        }
    }
}

// ---------------------------------------------------------------------------
// TASE.2 Block-2 DS-transfer-set client API
// ---------------------------------------------------------------------------

use mms_proto::mms::Data;
use tase2_proto::names;
use tase2_proto::report::{decode_information_report, TransferReport};
use tase2_proto::transfer_set::DsTransferSet;

/// Decode the `Next_DSTransfer_Set` read result (a two-`VisibleString`
/// structure of `{domain, item}`) into an [`ObjectName`].
///
/// The server signals an exhausted pool with a sentinel that has **no domain
/// scope** (empty domain string) — `{"", "NONE"}`. That is not a usable
/// domain-specific transfer-set name, so it maps to
/// [`Error::TransferSetsExhausted`] rather than a bogus `DomainSpecific`.
fn parse_next_ts(data: &Data) -> Result<ObjectName> {
    match data {
        Data::Structure(e) if e.len() == 2 => {
            if let (Data::VisibleString(dom), Data::VisibleString(item)) = (&e[0], &e[1]) {
                // Exhaustion sentinel: empty domain (no scope). A real instance
                // is always domain-scoped.
                if dom.is_empty() {
                    return Err(Error::TransferSetsExhausted);
                }
                let dom_id = Identifier::new(dom).map_err(Error::from)?;
                let item_id = Identifier::new(item).map_err(Error::from)?;
                Ok(ObjectName::DomainSpecific {
                    domain: dom_id,
                    item: item_id,
                })
            } else {
                Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu))
            }
        }
        _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
    }
}

impl Tase2Client {
    /// Claim a free DS-transfer-set instance by reading the domain's
    /// `Next_DSTransfer_Set` special variable. Returns the allocated instance's
    /// [`ObjectName`].
    pub async fn next_transfer_set(&mut self, domain: &DomainName) -> Result<ObjectName> {
        let name = ObjectName::DomainSpecific {
            domain: domain.identifier().clone(),
            item: Identifier::new(names::NEXT_DSTRANSFER_SET_NAME).map_err(Error::from)?,
        };
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                name,
            )]),
        };
        let resp = self.read_raw(req).await?;
        match resp.access_results.first() {
            Some(AccessResult::Success(data)) => parse_next_ts(data),
            Some(AccessResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Read a DS-transfer-set instance's attributes.
    pub async fn read_transfer_set(&mut self, ts: &ObjectName) -> Result<DsTransferSet> {
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                ts.clone(),
            )]),
        };
        let resp = self.read_raw(req).await?;
        match resp.access_results.first() {
            Some(AccessResult::Success(data)) => Ok(DsTransferSet::from_mms(data)?),
            Some(AccessResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Write a DS-transfer-set instance's attributes (whole-structure write).
    ///
    /// Writing with `value.status == true` arms condition monitoring on the
    /// server; `false` disables it.
    pub async fn write_transfer_set(
        &mut self,
        ts: &ObjectName,
        value: &DsTransferSet,
    ) -> Result<()> {
        let req = mms_proto::mms::WriteRequest {
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                ts.clone(),
            )]),
            data: vec![value.to_mms()],
        };
        let resp = match self.request(ConfirmedServiceRequest::Write(req)).await? {
            ConfirmedServiceResponse::Write(r) => r,
            other => return Err(unexpected_response(&other)),
        };
        match resp.results.first() {
            Some(WriteResult::Success) => Ok(()),
            Some(WriteResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            Some(_) | None => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Decode an inbound unsolicited PDU as a TASE.2 transfer report, given the
    /// reporting data set's `members` (in order) so the special members can be
    /// recognised and the rest mapped positionally.
    ///
    /// This is a synchronous helper over a PDU already obtained from
    /// [`recv_unsolicited`](Self::recv_unsolicited); the async receive surface is
    /// unchanged. A PDU that is not an `InformationReport`, or one whose access
    /// spec is not a `variableListName`, is a decode error.
    pub fn decode_report(&self, pdu: &MmsPdu, members: &[ObjectName]) -> Result<TransferReport> {
        let report = match pdu {
            MmsPdu::Unconfirmed(mms_proto::mms::UnconfirmedService::InformationReport(r)) => r,
            _ => return Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        };
        Ok(decode_information_report(report, members)?)
    }
}

// ---------------------------------------------------------------------------
// TASE.2 Block-5 device-control client API
// ---------------------------------------------------------------------------

use tase2_proto::control::{sbo_name, tag_name};
use tase2_proto::{CommandValue, DeviceTag};

impl Tase2Client {
    /// Select a device for select-before-operate, by reading its `<dev>_SBO`
    /// companion variable.
    ///
    /// The device name must be domain- or vmd-scoped; this derives the `_SBO`
    /// companion in the same scope. On success the server returns a checkback
    /// value (libtase2 "check back name value", an Integer); any successful read
    /// is taken as a granted selection. A per-item `Failure` (e.g. selecting a
    /// direct device) maps to [`Error::DataAccessError`].
    pub async fn select_device(&mut self, dev: &ObjectName) -> Result<()> {
        let sbo = sbo_companion(dev)?;
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                sbo,
            )]),
        };
        let resp = self.read_raw(req).await?;
        match resp.access_results.first() {
            // Any success (the checkback) means the selection was granted.
            Some(AccessResult::Success(_)) => Ok(()),
            Some(AccessResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Operate a device by writing `value` to the device variable.
    ///
    /// For a direct device this is the whole operation; for an SBO device a
    /// prior [`select_device`](Self::select_device) on this same connection must
    /// not have expired (the server consumes the selection). A rejected operate
    /// (no/expired selection, tag inhibit, bad value) maps to
    /// [`Error::DataAccessError`].
    pub async fn operate_device(&mut self, dev: &ObjectName, value: CommandValue) -> Result<()> {
        let req = mms_proto::mms::WriteRequest {
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                dev.clone(),
            )]),
            data: vec![value.to_mms()],
        };
        self.write_first(req).await
    }

    /// Read a device's tag, from its `<dev>_TAG` companion variable.
    pub async fn read_tag(&mut self, dev: &ObjectName) -> Result<DeviceTag> {
        let tag = tag_companion(dev)?;
        let req = ReadRequest {
            spec_with_result: false,
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                tag,
            )]),
        };
        let resp = self.read_raw(req).await?;
        match resp.access_results.first() {
            Some(AccessResult::Success(data)) => Ok(DeviceTag::from_mms(data)?),
            Some(AccessResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }

    /// Set a device's tag, by writing its `<dev>_TAG` companion variable.
    pub async fn set_tag(&mut self, dev: &ObjectName, tag: DeviceTag) -> Result<()> {
        let tag_var = tag_companion(dev)?;
        let req = mms_proto::mms::WriteRequest {
            access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
                tag_var,
            )]),
            data: vec![tag.to_mms()],
        };
        self.write_first(req).await
    }

    /// Issue a single-variable `Write` and unwrap the first per-item result.
    async fn write_first(&mut self, req: mms_proto::mms::WriteRequest) -> Result<()> {
        let resp = match self.request(ConfirmedServiceRequest::Write(req)).await? {
            ConfirmedServiceResponse::Write(r) => r,
            other => return Err(unexpected_response(&other)),
        };
        match resp.results.first() {
            Some(WriteResult::Success) => Ok(()),
            Some(WriteResult::Failure(code)) => Err(Error::DataAccessError { code: *code }),
            Some(_) | None => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
        }
    }
}

/// Derive the `<dev>_SBO` companion object name, in the same scope as `dev`.
fn sbo_companion(dev: &ObjectName) -> Result<ObjectName> {
    companion_with(dev, sbo_name)
}

/// Derive the `<dev>_TAG` companion object name, in the same scope as `dev`.
fn tag_companion(dev: &ObjectName) -> Result<ObjectName> {
    companion_with(dev, tag_name)
}

/// Derive a companion object name by applying `derive` (a `tase2_proto` name
/// helper, e.g. [`sbo_name`] / [`tag_name`]) to `dev`'s item identifier, keeping
/// `dev`'s scope. Errors if `dev` has no item identifier or the suffix would
/// overflow the 32-char identifier cap.
fn companion_with(
    dev: &ObjectName,
    derive: fn(&Identifier) -> tase2_proto::Result<Identifier>,
) -> Result<ObjectName> {
    match dev {
        ObjectName::VmdSpecific(id) => {
            Ok(ObjectName::VmdSpecific(derive(id).map_err(Error::from)?))
        }
        ObjectName::DomainSpecific { domain, item } => Ok(ObjectName::DomainSpecific {
            domain: domain.clone(),
            item: derive(item).map_err(Error::from)?,
        }),
        ObjectName::AaSpecific(id) => Ok(ObjectName::AaSpecific(derive(id).map_err(Error::from)?)),
        _ => Err(Error::Protocol(mms_proto::Error::MmsInvalidPdu)),
    }
}

/// Decode each access result with the matching kind, positionally, requiring an
/// exact one-to-one correspondence.
///
/// A mismatch between the number of supplied `kinds` and the number of
/// `results` is a top-level [`Error::ResponseShapeMismatch`] (the peer answered
/// the wrong shape), not a silent truncation. On a length match, the returned
/// vector has one inner result per item.
fn zip_results(kinds: &[PointKind], results: &[AccessResult]) -> Result<Vec<Result<PointValue>>> {
    if kinds.len() != results.len() {
        return Err(Error::ResponseShapeMismatch {
            expected: kinds.len(),
            got: results.len(),
        });
    }
    Ok(kinds
        .iter()
        .zip(results.iter())
        .map(|(&kind, ar)| access_result_to_value(kind, ar))
        .collect())
}

/// A confirmed response whose service did not match the request maps to a
/// protocol error.
fn unexpected_response(_resp: &ConfirmedServiceResponse) -> Error {
    Error::Protocol(mms_proto::Error::MmsInvalidPdu)
}

async fn open_stream(transport: &Transport) -> Result<TcpStream> {
    match transport {
        Transport::Tcp { addr } => {
            let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out")
                })??;
            stream.set_nodelay(true)?;
            Ok(stream)
        }
        #[cfg(feature = "tls")]
        Transport::Tls { .. } => {
            // TLS connections go through crate::tls::tls_client_connect_with;
            // this path should never be reached from connect_with.
            Err(crate::error::Error::Tls(
                "use tls_client_connect_with for TLS transports".into(),
            ))
        }
    }
}
