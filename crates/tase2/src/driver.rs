//! Shared driver task — owns the [`MmsConnection`] state machine plus a
//! transport stream and shuttles MMS PDUs in both directions. Used by both the
//! client and server flavours of the public API.
//!
//! This is the only place in the crate that touches the clock: the sans-I/O
//! state machine takes the current [`std::time::Instant`] explicitly, and the
//! driver supplies it once per `handle()` invocation site.
//!
//! # The select loop and backpressure
//!
//! The driver runs a single `biased` [`tokio::select!`] over three sources, in
//! priority order: outbound user commands (`cmd_rx`), the periodic timer tick,
//! and inbound socket bytes. Commands are biased first so a `Release`/`Abort`
//! always wins a race with newly-arrived bytes, and the tick is preferred over
//! reads so deadlines are evaluated promptly even under a steady inbound load.
//!
//! Inbound PDUs are routed onto **two** bounded channels: `evt_tx` carries the
//! association lifecycle ([`DriverEvent::AssociationUp`] /
//! [`DriverEvent::Closed`]) plus the confirmed-correlation PDUs a request waits
//! on (`ConfirmedResponse` / `ConfirmedError` / `Reject`), while `report_tx`
//! carries everything else (unconfirmed `InformationReport`s, inbound
//! `ConfirmedRequest`s on the server, etc.). Splitting the streams means a flood
//! of unsolicited reports can never starve or poison the request-correlation
//! path, and vice-versa.
//!
//! Both channels are bounded, so delivery is a `send().await` that suspends the
//! whole select loop when a channel is full. That is deliberate backpressure: a
//! peer that floods PDUs faster than the user drains them will, by design, stall
//! the driver (and therefore stop reading the socket, pushing back on the peer)
//! rather than buffer without bound. The user-facing contract is that the holder
//! of a [`Tase2Client`](crate::Tase2Client) /
//! [`ServerConnection`](crate::ServerConnection) keeps draining both the request
//! and report sides.

use std::time::Duration;

use bytes::{Buf, BytesMut};
use mms_proto::assoc::{
    AssocConfig, DisconnectReason, MmsAction, MmsConnection, MmsInput, Role, State,
};
use mms_proto::mms::MmsPdu;
use mms_proto::tpkt::Tpkt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::handler::EventHandler;

/// Upper bound on bytes buffered while waiting for one TPKT frame to be fully
/// received.
///
/// A single TPKT packet is at most [`mms_proto::tpkt::TPKT_MAX_LEN`] (65 535)
/// octets. Two of those is a comfortable ceiling: a peer that dribbles header
/// bytes without ever finishing a frame is detected quickly and disconnected
/// rather than being allowed to grow the buffer without bound.
const MAX_RX_BUFFERED: usize = 2 * mms_proto::tpkt::TPKT_MAX_LEN;

/// How often the driver pulses the state machine's timers.
const TICK_INTERVAL: Duration = Duration::from_millis(250);

/// Commands the user-facing handle sends to the driver task.
#[derive(Debug)]
pub(crate) enum Command {
    /// Send an MMS PDU in the data phase.
    SendService(MmsPdu),
    /// Begin a graceful MMS Conclude release.
    Release,
    /// Hard teardown from the local side.
    Abort,
}

/// Lifecycle and confirmed-correlation events the driver pushes onto the
/// primary `evt_tx` channel.
///
/// Confirmed-correlation PDUs (`ConfirmedResponse` / `ConfirmedError` /
/// `Reject`) and inbound `ConfirmedRequest`s travel here as
/// [`DriverEvent::Service`]; unconfirmed PDUs go on the separate report channel
/// instead (see [`run`]).
#[derive(Debug)]
pub(crate) enum DriverEvent {
    /// An inbound confirmed-path MMS PDU for the upper layer.
    Service(MmsPdu),
    /// The association reached the data phase.
    AssociationUp,
    /// The association was torn down for the given reason.
    Closed(DisconnectReason),
}

/// Classify an inbound PDU: `true` if it belongs on the confirmed/correlation
/// channel (`evt_tx`), `false` if it is an unsolicited report for `report_tx`.
///
/// Confirmed responses/errors and rejects correlate to an in-flight client
/// request; inbound confirmed *requests* are the server's work queue — both ride
/// `evt_tx`. Unconfirmed PDUs (information reports) are unsolicited and ride
/// `report_tx`. Anything else is treated as a report so it never blocks a
/// pending request.
fn is_confirmed_path(pdu: &MmsPdu) -> bool {
    matches!(
        pdu,
        MmsPdu::ConfirmedRequest { .. }
            | MmsPdu::ConfirmedResponse { .. }
            | MmsPdu::ConfirmedError { .. }
            | MmsPdu::Reject(_)
    )
}

/// Run the driver until the underlying stream closes or the state machine asks
/// for a disconnect. `cmd_rx` receives user commands; `evt_tx` carries the
/// association lifecycle plus confirmed-path PDUs, and `report_tx` carries
/// unsolicited PDUs (see the module docs for the channel split rationale).
///
/// `associate_on_start` is set by the client so the handshake begins
/// immediately; the server leaves it `false` and waits for the peer's COTP CR.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<S, H>(
    stream: S,
    role: Role,
    config: AssocConfig,
    handler: H,
    mut cmd_rx: mpsc::Receiver<Command>,
    evt_tx: mpsc::Sender<DriverEvent>,
    report_tx: mpsc::Sender<MmsPdu>,
    associate_on_start: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    H: EventHandler,
{
    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let mut conn = MmsConnection::new(role, config);
    let mut rx_buf = BytesMut::with_capacity(2048);
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Client side: kick off the handshake before entering the loop.
    if associate_on_start {
        let now = std::time::Instant::now();
        let actions = conn.handle(MmsInput::Associate, now);
        if !apply_actions(actions, &handler, &mut write_half, &evt_tx, &report_tx).await? {
            return Ok(());
        }
    }

    loop {
        tokio::select! {
            biased;

            // Outbound user commands.
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    // The handle was dropped. Abort the association locally so
                    // the driver always terminates (no task leak) and the peer
                    // sees a clean teardown.
                    let now = std::time::Instant::now();
                    let actions = conn.handle(MmsInput::Abort, now);
                    let _ = apply_actions(actions, &handler, &mut write_half, &evt_tx, &report_tx).await;
                    return Ok(());
                };
                let now = std::time::Instant::now();
                let actions = match cmd {
                    Command::SendService(pdu) => conn.handle(MmsInput::SendService(pdu), now),
                    Command::Release => conn.handle(MmsInput::Release, now),
                    Command::Abort => conn.handle(MmsInput::Abort, now),
                };
                if !apply_actions(actions, &handler, &mut write_half, &evt_tx, &report_tx).await? {
                    return Ok(());
                }
            }

            // Periodic timer kick.
            _ = tick.tick() => {
                let now = std::time::Instant::now();
                let actions = conn.handle(MmsInput::Tick, now);
                if !apply_actions(actions, &handler, &mut write_half, &evt_tx, &report_tx).await? {
                    return Ok(());
                }
            }

            // Inbound bytes from the peer.
            res = read_half.read_buf(&mut rx_buf) => {
                let n = res?;
                if n == 0 {
                    // EOF: the peer closed the socket. Feed an Abort so the
                    // state machine emits its disconnect and we finish.
                    let now = std::time::Instant::now();
                    let actions = conn.handle(MmsInput::Abort, now);
                    let _ = apply_actions(actions, &handler, &mut write_half, &evt_tx, &report_tx).await;
                    return Ok(());
                }
                // Drain every complete TPKT frame before selecting again.
                while let Some((payload, consumed)) = Tpkt::decode_slice(&rx_buf)? {
                    rx_buf.advance(consumed);
                    let now = std::time::Instant::now();
                    let actions = conn.handle(MmsInput::TpktPayload(payload), now);
                    if !apply_actions(actions, &handler, &mut write_half, &evt_tx, &report_tx).await? {
                        return Ok(());
                    }
                }
                // After draining complete frames, anything still buffered is an
                // in-flight prefix. A peer that holds the buffer above the cap
                // without ever finishing a frame is broken or malicious;
                // disconnect rather than keep growing.
                if rx_buf.len() > MAX_RX_BUFFERED {
                    handler.on_protocol_error(&format!(
                        "rx buffer exceeded {MAX_RX_BUFFERED} bytes ({} buffered) without a complete TPKT frame",
                        rx_buf.len()
                    ));
                    let _ = evt_tx
                        .send(DriverEvent::Closed(DisconnectReason::PeerAbort))
                        .await;
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "tpkt rx buffer overflow without a complete frame",
                    )));
                }
            }
        }
    }
}

/// Apply the action list emitted by one `handle()` call. Returns `Ok(false)`
/// when the driver should exit (the state machine disconnected, or the event
/// receiver was dropped).
async fn apply_actions<W, H>(
    actions: Vec<MmsAction>,
    handler: &H,
    write: &mut W,
    evt_tx: &mpsc::Sender<DriverEvent>,
    report_tx: &mpsc::Sender<MmsPdu>,
) -> Result<bool>
where
    W: AsyncWrite + Unpin,
    H: EventHandler,
{
    let mut keep_going = true;
    for action in actions {
        match action {
            MmsAction::SendBytes(bytes) => {
                write.write_all(&bytes).await?;
                write.flush().await?;
                handler.on_bytes_sent(bytes.len());
            }
            MmsAction::DeliverService(pdu) => {
                handler.on_service_received(&pdu);
                // Route confirmed-path PDUs to the correlation channel and
                // unsolicited reports to the report channel (see module docs).
                let sent = if is_confirmed_path(&pdu) {
                    evt_tx.send(DriverEvent::Service(pdu)).await.is_ok()
                } else {
                    report_tx.send(pdu).await.is_ok()
                };
                if !sent {
                    keep_going = false;
                }
            }
            MmsAction::AssociationUp => {
                handler.on_association_up();
                if evt_tx.send(DriverEvent::AssociationUp).await.is_err() {
                    keep_going = false;
                }
            }
            MmsAction::StateChanged(state) => {
                handler.on_state_changed(state);
                debug_assert_ne!(state, State::Idle);
            }
            MmsAction::Disconnect(reason) => {
                handler.on_disconnect(&reason);
                let _ = evt_tx.send(DriverEvent::Closed(reason)).await;
                keep_going = false;
            }
            // `MmsAction` is `#[non_exhaustive]`; tolerate future variants.
            _ => {}
        }
    }
    Ok(keep_going)
}
