//! Async TASE.2 / MMS server.

use std::net::SocketAddr;

use mms_proto::assoc::{AssociationInfo, AssocConfig, DisconnectReason, Role};
use mms_proto::mms::{
    ConfirmedServiceRequest, ConfirmedServiceResponse, MmsPdu, ServiceError, UnconfirmedService,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::driver::{self, Command, DriverEvent};
use crate::error::{Error, Result};
use crate::handler::{EventHandler, NoopHandler};

/// Channel depth for commands and the confirmed/lifecycle event stream.
const EVENT_DEPTH: usize = 32;

/// Channel depth for unsolicited inbound reports. Bounded for backpressure.
const REPORT_DEPTH: usize = 64;

/// Async TASE.2 / MMS server. Bind a port, then `accept().await` returns a
/// [`ServerConnection`] for each peer that completes the association handshake.
#[derive(Debug)]
pub struct Tase2Server {
    listener: TcpListener,
    config: AssocConfig,
}

impl Tase2Server {
    /// Bind a listening socket.
    pub async fn bind(addr: SocketAddr, config: AssocConfig) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, config })
    }

    /// The address the server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Accept one connection using a [`NoopHandler`].
    ///
    /// Spawns the driver for the accepted socket and waits for the association
    /// to come up before returning. A peer that fails the handshake yields
    /// [`Error::AssociationFailed`].
    pub async fn accept(&self) -> Result<ServerConnection> {
        self.accept_with(NoopHandler).await
    }

    /// Accept one connection with a custom [`EventHandler`].
    pub async fn accept_with<H: EventHandler>(&self, handler: H) -> Result<ServerConnection> {
        let (stream, peer) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        ServerConnection::spawn(stream, peer, self.config.clone(), handler).await
    }
}

/// A single connected, associated peer.
///
/// Single-owner handle: [`recv_request`](Self::recv_request) and the `respond*`
/// / `send_unsolicited` methods take `&mut self`. Dropping it tears the
/// association down.
///
/// Inbound confirmed requests arrive on the correlation channel and surface
/// through [`recv_request`](Self::recv_request); unsolicited PDUs (rare on the
/// server side, but a peer may push reports) arrive on a separate report
/// channel via [`recv_report`](Self::recv_report). Both channels are bounded;
/// **the holder must keep draining** — a peer that floods one stream while the
/// user never drains it will, by design, stall the driver via backpressure
/// (see the driver module docs).
#[derive(Debug)]
pub struct ServerConnection {
    peer: SocketAddr,
    peer_info: AssociationInfo,
    cmd_tx: mpsc::Sender<Command>,
    evt_rx: mpsc::Receiver<DriverEvent>,
    report_rx: mpsc::Receiver<MmsPdu>,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl ServerConnection {
    pub(crate) async fn spawn<S, H>(
        stream: S,
        peer: SocketAddr,
        config: AssocConfig,
        handler: H,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        H: EventHandler,
    {
        let (cmd_tx, cmd_rx) = mpsc::channel(EVENT_DEPTH);
        let (evt_tx, mut evt_rx) = mpsc::channel(EVENT_DEPTH);
        let (report_tx, report_rx) = mpsc::channel(REPORT_DEPTH);
        let task = tokio::spawn(driver::run(
            stream,
            Role::Server,
            config,
            handler,
            cmd_rx,
            evt_tx,
            report_tx,
            false,
        ));

        // Wait for the association to come up (or fail), capturing the peer
        // identity from the `AssociationUp` event.
        let peer_info = loop {
            match evt_rx.recv().await {
                Some(DriverEvent::AssociationUp(info)) => break info,
                Some(DriverEvent::Closed(reason)) => {
                    return Err(Error::AssociationFailed(reason));
                }
                Some(DriverEvent::Service(_)) => continue,
                None => return Err(Error::DriverGone),
            }
        };

        Ok(Self {
            peer,
            peer_info,
            cmd_tx,
            evt_rx,
            report_rx,
            task,
        })
    }

    /// The peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The connecting client's OSI/ACSE identity observed during the handshake
    /// (AP title, AE qualifier, TSEL, SSEL, PSEL). See
    /// [`AssociationInfo`] for which fields are populated.
    pub fn association_info(&self) -> &AssociationInfo {
        &self.peer_info
    }

    /// Receive the next inbound confirmed request as `(invoke_id, service)`.
    ///
    /// Returns `None` when the association closes. Unsolicited PDUs travel on a
    /// separate channel ([`recv_report`](Self::recv_report)) and never appear
    /// here; any non-request confirmed-path PDU (which the server should not
    /// normally receive) is logged at `warn` and skipped.
    pub async fn recv_request(&mut self) -> Option<(u32, ConfirmedServiceRequest)> {
        loop {
            match self.evt_rx.recv().await? {
                DriverEvent::Service(MmsPdu::ConfirmedRequest { invoke_id, service }) => {
                    return Some((invoke_id, service));
                }
                DriverEvent::Service(other) => {
                    tracing::warn!(
                        target: "tase2::server",
                        ?other,
                        "ignoring unexpected confirmed-path PDU on server connection"
                    );
                    continue;
                }
                DriverEvent::AssociationUp(_) => continue,
                DriverEvent::Closed(_) => return None,
            }
        }
    }

    /// Receive the next unsolicited PDU pushed by the peer (e.g. an
    /// `InformationReport`). Returns `None` when the association closes.
    pub async fn recv_report(&mut self) -> Option<MmsPdu> {
        self.report_rx.recv().await
    }

    /// Respond to a confirmed request with a successful response.
    pub async fn respond(&mut self, invoke_id: u32, resp: ConfirmedServiceResponse) -> Result<()> {
        let pdu = MmsPdu::ConfirmedResponse {
            invoke_id,
            service: resp,
        };
        self.send(pdu).await
    }

    /// Respond to a confirmed request with a `ServiceError`.
    pub async fn respond_error(&mut self, invoke_id: u32, err: ServiceError) -> Result<()> {
        let pdu = MmsPdu::ConfirmedError {
            invoke_id,
            error: err,
        };
        self.send(pdu).await
    }

    /// Send an unsolicited PDU (e.g. an `InformationReport`).
    pub async fn send_unsolicited(&mut self, pdu: MmsPdu) -> Result<()> {
        debug_assert!(
            matches!(
                pdu,
                MmsPdu::Unconfirmed(UnconfirmedService::InformationReport(_))
            ),
            "send_unsolicited expects an unconfirmed PDU"
        );
        self.send(pdu).await
    }

    /// A cloneable handle for sending unsolicited PDUs concurrently with the
    /// request loop.
    ///
    /// The send path is a cloneable channel to the driver, so a background task
    /// (e.g. the reporting poll loop) can push `InformationReport`s while the
    /// owner keeps `&mut self` for [`recv_request`](Self::recv_request) /
    /// `respond`. Used by
    /// [`serve_connection_with_reports`](crate::serve_connection_with_reports).
    pub fn unsolicited_sender(&self) -> UnsolicitedSender {
        UnsolicitedSender {
            cmd_tx: self.cmd_tx.clone(),
        }
    }

    /// Gracefully release the association and wait for the driver to finish.
    ///
    /// Returns `Ok(())` only when the association closed via a normal release;
    /// any other close reason is reported as [`Error::AssociationFailed`].
    pub async fn release(self) -> Result<()> {
        let _ = self.cmd_tx.send(Command::Release).await;
        let mut evt_rx = self.evt_rx;
        let mut reason: Option<DisconnectReason> = None;
        while let Some(evt) = evt_rx.recv().await {
            if let DriverEvent::Closed(r) = evt {
                reason = Some(r);
                break;
            }
        }
        if let Ok(Err(e)) = self.task.await {
            return Err(e);
        }
        match reason {
            Some(DisconnectReason::NormalRelease) | None => Ok(()),
            Some(other) => Err(Error::AssociationFailed(other)),
        }
    }

    async fn send(&self, pdu: MmsPdu) -> Result<()> {
        self.cmd_tx
            .send(Command::SendService(pdu))
            .await
            .map_err(|_| Error::DriverGone)
    }
}

/// A cloneable handle for sending unsolicited PDUs on a [`ServerConnection`].
///
/// Obtained via [`ServerConnection::unsolicited_sender`]. Sending fails with
/// [`Error::DriverGone`] once the association has closed.
#[derive(Debug, Clone)]
pub struct UnsolicitedSender {
    cmd_tx: mpsc::Sender<Command>,
}

impl UnsolicitedSender {
    /// Send an unsolicited PDU (an `InformationReport`).
    pub async fn send(&self, pdu: MmsPdu) -> Result<()> {
        debug_assert!(
            matches!(
                pdu,
                MmsPdu::Unconfirmed(UnconfirmedService::InformationReport(_))
            ),
            "UnsolicitedSender expects an unconfirmed PDU"
        );
        self.cmd_tx
            .send(Command::SendService(pdu))
            .await
            .map_err(|_| Error::DriverGone)
    }
}
