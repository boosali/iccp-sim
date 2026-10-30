//! The [`MmsConnection`] association state machine (sans-I/O).
//!
//! This is the orchestration layer that ties COTP framing, the OSI upper
//! layers (Session / Presentation / ACSE) and the MMS PDUs into a single
//! input → action machine. It owns no sockets and no clock: every entry point
//! takes the current [`Instant`] explicitly so the machine is fully
//! deterministic and testable. The driver crate feeds real bytes, real time,
//! and writes the [`MmsAction::SendBytes`] verbatim.
//!
//! # Wire stages
//!
//! The MMS-over-OSI handshake is exactly two round trips after TCP connect:
//!
//! ```text
//! TCP connect
//!   client → COTP CR ───────────────────────────────▶ server
//!   client ◀─────────────────────────────── COTP CC  server
//!   client → CN(CP(AARQ(InitiateRequest))) ─────────▶ server
//!   client ◀── AC(CPA(AARE(InitiateResponse)))        server
//! ASSOCIATED — data phase (MMS PDUs over Session DATA)
//! ```
//!
//! # State transition diagram
//!
//! ```text
//!                Associate (client)               CC
//!   Idle ───────────────────────────▶ Associating(CotpConnect)
//!     ▲                                          │
//!     │ (server) CR → send CC                    │ send CN(CP(AARQ))
//!     │                                          ▼
//!     └──────────────────────▶ Associating(OsiConnect)
//!                                                │
//!                          AC(CPA(AARE)) ok      │  server: CN(CP(AARQ)) → send AC
//!                                                ▼
//!                                          Associated ──── Release ──▶ Releasing
//!                                                │                        │
//!                                  Abort / error / DR / peer close        │ ConcludeResponse / timeout
//!                                                ▼                        ▼
//!                                             Closed ◀────────────────────┘
//! ```
//!
//! Every actual state change emits exactly one [`MmsAction::StateChanged`]. A
//! [`MmsAction::Disconnect`] is always immediately followed by a transition to
//! [`State::Closed`] (and thus its `StateChanged(Closed)`), mirroring the
//! IEC 60870-5-104 reference machine. After `Closed` every input is absorbed
//! with no actions.

use std::time::Instant;

use crate::ber::ObjectIdentifier;
use crate::cotp::params::{CotpParams, TpduSize};
use crate::cotp::pdu::{ConnectionPdu, CotpPdu};
use crate::cotp::reassembly::CotpReassembler;
use crate::cotp::CotpCodec;
use crate::mms::{InitiateResponse, MmsPdu};
use crate::osi::acse::{Aare, Aarq, Acse, AcsePdu, MMS_APP_CONTEXT_ARCS};
use crate::osi::presentation::{Presentation, PresentationContexts};
use crate::osi::session::{Session, SessionConnect, SessionPdu};
use crate::tpkt::Tpkt;
use crate::Error;

use super::config::AssocConfig;
use super::timers::Deadlines;

/// A fixed, non-zero COTP source reference for connections this machine
/// originates or accepts. Class 0 ignores references beyond CR/CC echoing.
const LOCAL_SRC_REF: u16 = 1;

/// Connection role. The client initiates the association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Initiates the association (sends the COTP CR and the CN).
    Client,
    /// Waits for and answers an inbound association.
    Server,
}

/// The sub-stage of the [`State::Associating`] handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssocStage {
    /// Client-only: the COTP CR has been sent and we are awaiting the CC. A
    /// server never occupies this stage — on receiving a CR it replies with a
    /// CC and moves directly to [`AssocStage::OsiConnect`].
    CotpConnect,
    /// COTP is up; awaiting the OSI CN→AC exchange.
    OsiConnect,
}

/// High-level association state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing has happened yet.
    Idle,
    /// The handshake is in progress at the given stage.
    Associating(AssocStage),
    /// The association is up; the MMS data phase is active.
    Associated,
    /// A graceful release is in progress (Conclude exchange).
    Releasing,
    /// The association is finished; the transport should be torn down.
    ///
    /// This is terminal: a `Closed` connection absorbs every subsequent input
    /// with no actions. [`MmsConnection`] is single-use — to reconnect (e.g.
    /// after an abort or a failed setup) the driver must construct a fresh
    /// [`MmsConnection::new`].
    Closed,
}

/// Inputs to the state machine.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum MmsInput {
    /// One complete TPKT payload (the COTP TPDU bytes). The driver runs
    /// [`Tpkt::decode_slice`] over the TCP stream and feeds each payload here.
    TpktPayload(Vec<u8>),
    /// Client only: begin the handshake (valid in [`State::Idle`]).
    Associate,
    /// Begin a graceful MMS Conclude release (valid in [`State::Associated`]).
    Release,
    /// Hard teardown from the local side.
    Abort,
    /// Send an MMS PDU in the data phase (valid in [`State::Associated`]).
    SendService(MmsPdu),
    /// Timer pulse — evaluate deadlines.
    Tick,
}

/// The peer's OSI/ACSE identity as observed during the association handshake.
///
/// On the **server** this is the calling client's identity, decoded from the
/// inbound handshake PDUs: the COTP CR (TSEL), the SPSE CN (SSEL), the SPSE CP
/// (PSEL) and the ACSE AARQ (AP title + AE qualifier). On the **client** the
/// peer is the called server, whose identity is not carried in the AARE, so
/// every field is `None`.
///
/// All fields are `Option` because the wire allows any of them to be absent.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AssociationInfo {
    /// The peer's AP title (OID), if present in its AARQ.
    pub ap_title: Option<ObjectIdentifier>,
    /// The peer's AE qualifier, if present in its AARQ.
    pub ae_qualifier: Option<i64>,
    /// The peer's COTP transport selector (TSEL), from its CR.
    pub tsel: Option<Vec<u8>>,
    /// The peer's session selector (SSEL), from its CN.
    pub ssel: Option<Vec<u8>>,
    /// The peer's presentation selector (PSEL), from its CP.
    pub psel: Option<Vec<u8>>,
}

/// Actions emitted by the state machine for the driver to perform.
#[derive(Debug, PartialEq)]
#[non_exhaustive]
pub enum MmsAction {
    /// Fully framed bytes (one or more concatenated `TPKT(COTP(...))` frames).
    /// The driver writes them to the socket verbatim.
    SendBytes(Vec<u8>),
    /// An inbound MMS PDU for the upper layer.
    DeliverService(MmsPdu),
    /// The association reached [`State::Associated`], with the observed peer
    /// identity (see [`AssociationInfo`]).
    AssociationUp(AssociationInfo),
    /// The state changed to the carried value.
    StateChanged(State),
    /// The connection should be torn down for the given reason.
    Disconnect(DisconnectReason),
}

/// Why an association was torn down.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DisconnectReason {
    /// The local side issued [`MmsInput::Abort`].
    LocalAbort,
    /// The peer aborted (ACSE ABRT, or a session ABORT SPDU).
    PeerAbort,
    /// A graceful MMS Conclude completed.
    NormalRelease,
    /// The setup deadline elapsed during the handshake.
    SetupTimeout,
    /// The release deadline elapsed during a graceful release.
    ReleaseTimeout,
    /// A COTP Disconnect Request (DR) was received.
    CotpDisconnect {
        /// The DR reason code.
        reason: u8,
    },
    /// The CPA reported the MMS presentation context was refused.
    MmsContextRefused,
    /// The AARE carried a non-zero association result.
    AcseRejected {
        /// The ACSE association result code.
        result: i64,
    },
    /// A decode error or state violation. Carries the typed error.
    Protocol(Error),
}

/// The MMS association state machine.
#[derive(Debug)]
pub struct MmsConnection {
    role: Role,
    config: AssocConfig,
    state: State,
    reassembler: CotpReassembler,
    /// The learned presentation-context map (server: from the peer's CP;
    /// client: the fixed contexts we offered, against which we validate data).
    contexts: PresentationContexts,
    /// Monotonic invoke-id allocator for confirmed requests.
    next_invoke_id: u32,
    /// The negotiated Initiate parameters, available once [`State::Associated`]
    /// is reached. The client stores the peer's `InitiateResponse`; the server
    /// stores the response it sent (the negotiated outcome). Carries
    /// `local_detail` (max MMS PDU size) and `max_outstanding*` for the driver.
    negotiated: Option<InitiateResponse>,
    /// The peer's observed OSI/ACSE identity, accumulated during the handshake
    /// (TSEL from the CR; the rest from the CN/CP/AARQ). Empty on the client
    /// side, where the peer's identity is not carried in the AARE.
    peer_info: AssociationInfo,
    deadlines: Deadlines,
    actions: Vec<MmsAction>,
}

impl MmsConnection {
    /// Create a new connection in [`State::Idle`].
    pub fn new(role: Role, config: AssocConfig) -> Self {
        let max_reassembly = config.max_reassembly;
        MmsConnection {
            role,
            config,
            state: State::Idle,
            reassembler: CotpReassembler::new(max_reassembly),
            contexts: PresentationContexts::default(),
            next_invoke_id: 0,
            negotiated: None,
            peer_info: AssociationInfo::default(),
            deadlines: Deadlines::default(),
            actions: Vec::new(),
        }
    }

    /// The current high-level state.
    pub fn state(&self) -> State {
        self.state
    }

    /// The connection role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The negotiated Initiate parameters, available once the association is
    /// [`State::Associated`]. `None` before the handshake completes.
    ///
    /// The client returns the peer's `InitiateResponse`; the server returns the
    /// response it generated (the negotiated outcome of its own offer against
    /// the peer's request). The driver uses `local_detail` for outbound MMS PDU
    /// chunking and `max_outstanding*` for request throttling.
    pub fn negotiated(&self) -> Option<&InitiateResponse> {
        self.negotiated.as_ref()
    }

    /// Allocate the next invoke id for a confirmed request (monotonic,
    /// wrapping).
    pub fn next_invoke_id(&mut self) -> u32 {
        let id = self.next_invoke_id;
        self.next_invoke_id = self.next_invoke_id.wrapping_add(1);
        id
    }

    /// Drive the machine with an input and return the resulting actions.
    pub fn handle(&mut self, input: MmsInput, now: Instant) -> Vec<MmsAction> {
        match input {
            MmsInput::TpktPayload(bytes) => self.on_tpkt(bytes, now),
            MmsInput::Associate => self.on_associate(now),
            MmsInput::Release => self.on_release(now),
            MmsInput::Abort => self.on_abort(),
            MmsInput::SendService(pdu) => self.on_send_service(pdu),
            MmsInput::Tick => {}
        }
        self.run_timers(now);
        std::mem::take(&mut self.actions)
    }

    // -----------------------------------------------------------------
    // User-initiated transitions
    // -----------------------------------------------------------------

    fn on_associate(&mut self, now: Instant) {
        if self.role != Role::Client || self.state != State::Idle {
            return;
        }
        self.deadlines.setup = Some(now + self.config.setup_timeout);
        let cr = CotpPdu::ConnectionRequest(ConnectionPdu {
            dst_ref: 0,
            src_ref: LOCAL_SRC_REF,
            class: 0,
            params: CotpParams {
                tpdu_size: Some(self.config.tpdu_size),
                src_tsap: Some(self.config.local_tsap.clone()),
                dst_tsap: Some(self.config.remote_tsap.clone()),
            },
        });
        match self.frame_cotp_control(&cr) {
            Ok(bytes) => {
                self.actions.push(MmsAction::SendBytes(bytes));
                self.transition(State::Associating(AssocStage::CotpConnect));
            }
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    fn on_release(&mut self, now: Instant) {
        if self.state != State::Associated {
            return;
        }
        match self.frame_mms(&MmsPdu::ConcludeRequest) {
            Ok(bytes) => {
                self.actions.push(MmsAction::SendBytes(bytes));
                self.deadlines.release = Some(now + self.config.release_timeout);
                self.transition(State::Releasing);
            }
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    fn on_abort(&mut self) {
        if self.state == State::Closed {
            return;
        }
        // TCP close is the abort; we emit no wire bytes, only the disconnect.
        self.fail(DisconnectReason::LocalAbort);
    }

    fn on_send_service(&mut self, pdu: MmsPdu) {
        if self.state != State::Associated {
            return;
        }
        match self.frame_mms(&pdu) {
            Ok(bytes) => self.actions.push(MmsAction::SendBytes(bytes)),
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    // -----------------------------------------------------------------
    // Inbound TPKT payload (a complete COTP TPDU)
    // -----------------------------------------------------------------

    fn on_tpkt(&mut self, bytes: Vec<u8>, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        let pdu = match CotpCodec::decode(&bytes) {
            Ok(p) => p,
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        match pdu {
            CotpPdu::ConnectionRequest(conn) => self.on_cr(conn, now),
            CotpPdu::ConnectionConfirm(conn) => self.on_cc(conn, now),
            CotpPdu::DisconnectRequest { reason, .. } => {
                self.fail(DisconnectReason::CotpDisconnect { reason });
            }
            CotpPdu::ErrorTpdu { .. } => {
                self.fail(DisconnectReason::Protocol(Error::CotpTruncated));
            }
            CotpPdu::Data { eot, payload } => self.on_dt(&payload, eot, now),
        }
    }

    /// COTP CR — server only, accepts the connection by replying with a CC.
    fn on_cr(&mut self, conn: ConnectionPdu, now: Instant) {
        if self.role != Role::Server || self.state != State::Idle {
            return self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu));
        }
        // Arm the setup deadline so a peer that opens COTP and then goes silent
        // does not wedge the server in Associating forever.
        self.deadlines.setup = Some(now + self.config.setup_timeout);
        let tpdu_size = negotiate_size(self.config.tpdu_size, conn.params.tpdu_size);
        self.config.tpdu_size = tpdu_size;
        // Remember the calling client's TSEL (its src TSAP) for the
        // `AssociationUp` identity.
        self.peer_info.tsel = conn.params.src_tsap.clone();
        let cc = CotpPdu::ConnectionConfirm(ConnectionPdu {
            dst_ref: conn.src_ref,
            src_ref: LOCAL_SRC_REF,
            class: 0,
            params: CotpParams {
                tpdu_size: Some(tpdu_size),
                // Echo the calling/called TSAPs back (swapped per COTP rules).
                src_tsap: conn.params.dst_tsap.clone(),
                dst_tsap: conn.params.src_tsap.clone(),
            },
        });
        match self.frame_cotp_control(&cc) {
            Ok(bytes) => {
                self.actions.push(MmsAction::SendBytes(bytes));
                self.transition(State::Associating(AssocStage::OsiConnect));
            }
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    /// COTP CC — client only, completes COTP; sends the CN(CP(AARQ(Init))).
    fn on_cc(&mut self, conn: ConnectionPdu, _now: Instant) {
        if self.role != Role::Client || self.state != State::Associating(AssocStage::CotpConnect) {
            return self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu));
        }
        let tpdu_size = negotiate_size(self.config.tpdu_size, conn.params.tpdu_size);
        self.config.tpdu_size = tpdu_size;

        // Build InitiateRequest → AARQ → CP → CN.
        let mut w = crate::ber::writer::BerWriter::new();
        if let Err(e) = MmsPdu::InitiateRequest(self.config.initiate.clone()).encode(&mut w) {
            return self.fail(DisconnectReason::Protocol(e));
        }
        let init_bytes = w.into_bytes();

        let aarq = AcsePdu::Aarq(Aarq {
            app_context: ObjectIdentifier::from_arcs(MMS_APP_CONTEXT_ARCS),
            calling_ap_title: self.config.local_ap_title.clone(),
            calling_ae_qualifier: self.config.local_ae_qualifier,
            called_ap_title: self.config.remote_ap_title.clone(),
            called_ae_qualifier: self.config.remote_ae_qualifier,
            user_info: init_bytes,
        });
        let mut aarq_bytes = Vec::new();
        if let Err(e) = Acse::encode(&aarq, &mut aarq_bytes) {
            return self.fail(DisconnectReason::Protocol(e));
        }

        let cp = Presentation::encode_cp(
            self.config.local_psel.as_deref(),
            self.config.remote_psel.as_deref(),
            &aarq_bytes,
        );
        let cn = SessionPdu::Connect(SessionConnect {
            calling_selector: self.config.local_ssel.clone(),
            called_selector: self.config.remote_ssel.clone(),
            user_data: cp,
        });
        let mut session_bytes = Vec::new();
        if let Err(e) = Session::encode(&cn, &mut session_bytes) {
            return self.fail(DisconnectReason::Protocol(e));
        }
        match self.frame_session(&session_bytes) {
            Ok(bytes) => {
                self.actions.push(MmsAction::SendBytes(bytes));
                self.transition(State::Associating(AssocStage::OsiConnect));
            }
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    /// COTP DT — reassemble, then dispatch the complete session SPDU.
    fn on_dt(&mut self, payload: &[u8], eot: bool, now: Instant) {
        let tsdu = match self.reassembler.push(payload, eot) {
            Ok(Some(t)) => t,
            Ok(None) => return, // more fragments expected
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        let spdu = match Session::decode(&tsdu) {
            Ok(s) => s,
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        match self.state {
            State::Associating(AssocStage::OsiConnect) => self.on_handshake_spdu(spdu, now),
            State::Associated | State::Releasing => self.on_data_spdu(spdu),
            _ => self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu)),
        }
    }

    // -----------------------------------------------------------------
    // OSI handshake SPDUs (OsiConnect stage)
    // -----------------------------------------------------------------

    fn on_handshake_spdu(&mut self, spdu: SessionPdu, _now: Instant) {
        match (self.role, spdu) {
            // Server receives the CN carrying CP(AARQ(InitiateRequest)).
            (Role::Server, SessionPdu::Connect(c)) => self.on_server_connect(c),
            // Client receives the AC carrying CPA(AARE(InitiateResponse)).
            (Role::Client, SessionPdu::Accept(c)) => self.on_client_accept(c),
            (_, SessionPdu::Abort { .. }) => self.fail(DisconnectReason::PeerAbort),
            _ => self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu)),
        }
    }

    fn on_server_connect(&mut self, c: SessionConnect) {
        // Learn the presentation contexts and extract the AARQ.
        let (ctx, aarq_bytes) = match Presentation::decode_cp(&c.user_data) {
            Ok(x) => x,
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        self.contexts = ctx;

        // Capture the calling client's session selector (SSEL) and presentation
        // selector (PSEL) for the `AssociationUp` identity.
        if !c.calling_selector.as_deref().unwrap_or(&[]).is_empty() {
            self.peer_info.ssel = c.calling_selector.clone();
        }
        self.peer_info.psel = Presentation::calling_selector(&c.user_data);

        let aarq = match Acse::decode(&aarq_bytes) {
            Ok(AcsePdu::Aarq(a)) => a,
            Ok(_) => return self.fail(DisconnectReason::Protocol(Error::AcseInvalid)),
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        // Capture the calling client's AP title and AE qualifier.
        self.peer_info.ap_title = aarq.calling_ap_title;
        self.peer_info.ae_qualifier = aarq.calling_ae_qualifier;
        // Verify the application-context is the MMS profile.
        if aarq.app_context != ObjectIdentifier::from_arcs(MMS_APP_CONTEXT_ARCS) {
            return self.fail(DisconnectReason::Protocol(Error::AcseInvalid));
        }
        // Decode the InitiateRequest carried in the AARQ user-info.
        let init_req = match MmsPdu::decode(&aarq.user_info) {
            Ok(MmsPdu::InitiateRequest(r)) => r,
            Ok(_) => return self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu)),
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };

        // Build the InitiateResponse by negotiating down from our config.
        let init_resp = negotiate_response(&self.config.initiate, &init_req);
        let mut w = crate::ber::writer::BerWriter::new();
        if let Err(e) = MmsPdu::InitiateResponse(init_resp.clone()).encode(&mut w) {
            return self.fail(DisconnectReason::Protocol(e));
        }
        let init_bytes = w.into_bytes();

        let aare = AcsePdu::Aare(Aare {
            app_context: ObjectIdentifier::from_arcs(MMS_APP_CONTEXT_ARCS),
            result: 0,
            user_info: init_bytes,
        });
        let mut aare_bytes = Vec::new();
        if let Err(e) = Acse::encode(&aare, &mut aare_bytes) {
            return self.fail(DisconnectReason::Protocol(e));
        }

        let cpa = Presentation::encode_cpa(
            self.config.local_psel.as_deref(),
            &self.contexts,
            &aare_bytes,
        );
        let ac = SessionPdu::Accept(SessionConnect {
            calling_selector: self.config.local_ssel.clone(),
            called_selector: self.config.remote_ssel.clone(),
            user_data: cpa,
        });
        let mut session_bytes = Vec::new();
        if let Err(e) = Session::encode(&ac, &mut session_bytes) {
            return self.fail(DisconnectReason::Protocol(e));
        }
        match self.frame_session(&session_bytes) {
            Ok(bytes) => {
                self.actions.push(MmsAction::SendBytes(bytes));
                // Store the negotiated outcome (the response we sent).
                self.negotiated = Some(init_resp);
                self.deadlines.clear();
                self.transition(State::Associated);
                self.actions
                    .push(MmsAction::AssociationUp(self.peer_info.clone()));
            }
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    fn on_client_accept(&mut self, c: SessionConnect) {
        let cpa = match Presentation::decode_cpa(&c.user_data) {
            Ok(x) => x,
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        if !cpa.mms_accepted {
            return self.fail(DisconnectReason::MmsContextRefused);
        }
        let aare = match Acse::decode(&cpa.acse_payload) {
            Ok(AcsePdu::Aare(a)) => a,
            Ok(_) => return self.fail(DisconnectReason::Protocol(Error::AcseInvalid)),
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        if aare.result != 0 {
            return self.fail(DisconnectReason::AcseRejected {
                result: aare.result,
            });
        }
        // Decode and retain the negotiated InitiateResponse.
        let init_resp = match MmsPdu::decode(&aare.user_info) {
            Ok(MmsPdu::InitiateResponse(r)) => r,
            Ok(_) => return self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu)),
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        // The client addresses the responder with the contexts it offered.
        self.contexts = PresentationContexts::default();
        self.negotiated = Some(init_resp);
        self.deadlines.clear();
        self.transition(State::Associated);
        // Client side: the called server's identity is not carried in the
        // AARE, so the peer info stays empty here.
        self.actions
            .push(MmsAction::AssociationUp(self.peer_info.clone()));
    }

    // -----------------------------------------------------------------
    // Data-phase SPDUs (Associated / Releasing)
    // -----------------------------------------------------------------

    fn on_data_spdu(&mut self, spdu: SessionPdu) {
        let payload = match spdu {
            SessionPdu::Data(p) => p,
            // A FINISH / DISCONNECT SPDU is a peer-driven normal close.
            SessionPdu::Finish { .. } | SessionPdu::Disconnect { .. } => {
                return self.fail(DisconnectReason::NormalRelease);
            }
            SessionPdu::Abort { .. } => return self.fail(DisconnectReason::PeerAbort),
            _ => return self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu)),
        };

        let (pci, apdu) = match Presentation::decode_data(&payload) {
            Ok(x) => x,
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };

        // ACSE PDUs travel on the ACSE context; MMS PDUs on the MMS context.
        if pci == self.contexts.acse_pci {
            return self.on_acse_data(&apdu);
        }
        if pci != self.contexts.mms_pci {
            return self.fail(DisconnectReason::Protocol(
                Error::PresentationContextUnknown { pci },
            ));
        }

        let mms = match MmsPdu::decode(&apdu) {
            Ok(p) => p,
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        };
        match mms {
            MmsPdu::ConcludeRequest => self.on_conclude_request(),
            MmsPdu::ConcludeResponse => {
                if self.state == State::Releasing {
                    self.fail(DisconnectReason::NormalRelease);
                } else {
                    self.fail(DisconnectReason::Protocol(Error::MmsInvalidPdu));
                }
            }
            other => self.actions.push(MmsAction::DeliverService(other)),
        }
    }

    fn on_acse_data(&mut self, apdu: &[u8]) {
        match Acse::decode(apdu) {
            Ok(AcsePdu::Rlrq { .. }) => {
                // Respond with RLRE then close normally.
                if let Ok(bytes) = self.frame_acse(&AcsePdu::Rlre { reason: Some(0) }) {
                    self.actions.push(MmsAction::SendBytes(bytes));
                }
                self.fail(DisconnectReason::NormalRelease);
            }
            Ok(AcsePdu::Rlre { .. }) => self.fail(DisconnectReason::NormalRelease),
            Ok(AcsePdu::Abrt { .. }) => self.fail(DisconnectReason::PeerAbort),
            Ok(_) => self.fail(DisconnectReason::Protocol(Error::AcseInvalid)),
            Err(e) => self.fail(DisconnectReason::Protocol(e)),
        }
    }

    fn on_conclude_request(&mut self) {
        // Reply with a ConcludeResponse and close normally.
        match self.frame_mms(&MmsPdu::ConcludeResponse) {
            Ok(bytes) => self.actions.push(MmsAction::SendBytes(bytes)),
            Err(e) => return self.fail(DisconnectReason::Protocol(e)),
        }
        self.fail(DisconnectReason::NormalRelease);
    }

    // -----------------------------------------------------------------
    // Framing helpers
    // -----------------------------------------------------------------

    /// Frame a single COTP control TPDU (CR/CC) as `TPKT(COTP)`.
    fn frame_cotp_control(&self, pdu: &CotpPdu) -> Result<Vec<u8>, Error> {
        let mut cotp = Vec::new();
        CotpCodec::encode(pdu, &mut cotp)?;
        let mut out = Vec::new();
        Tpkt::encode(&cotp, &mut out)?;
        Ok(out)
    }

    /// Fragment session bytes into DT TPDUs, frame each in TPKT, and
    /// concatenate into one byte block.
    fn frame_session(&self, session_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let frags = CotpCodec::encode_data(session_bytes, self.config.tpdu_size);
        let mut out = Vec::new();
        for frag in &frags {
            Tpkt::encode(frag, &mut out)?;
        }
        Ok(out)
    }

    /// Frame an MMS PDU for the data phase: MMS → Presentation(MMS pci) →
    /// Session DATA → COTP → TPKT.
    fn frame_mms(&self, pdu: &MmsPdu) -> Result<Vec<u8>, Error> {
        let mut w = crate::ber::writer::BerWriter::new();
        pdu.encode(&mut w)?;
        let mms_bytes = w.into_bytes();
        let pres = Presentation::encode_data(self.contexts.mms_pci, &mms_bytes);
        let mut session_bytes = Vec::new();
        Session::encode(&SessionPdu::Data(pres), &mut session_bytes)?;
        self.frame_session(&session_bytes)
    }

    /// Frame an ACSE PDU for the data phase (addressed to the ACSE context).
    fn frame_acse(&self, pdu: &AcsePdu) -> Result<Vec<u8>, Error> {
        let mut acse_bytes = Vec::new();
        Acse::encode(pdu, &mut acse_bytes)?;
        let pres = Presentation::encode_data(self.contexts.acse_pci, &acse_bytes);
        let mut session_bytes = Vec::new();
        Session::encode(&SessionPdu::Data(pres), &mut session_bytes)?;
        self.frame_session(&session_bytes)
    }

    // -----------------------------------------------------------------
    // State helpers
    // -----------------------------------------------------------------

    fn transition(&mut self, to: State) {
        if self.state != to {
            self.state = to;
            self.actions.push(MmsAction::StateChanged(to));
        }
    }

    /// Emit a disconnect and move to [`State::Closed`].
    fn fail(&mut self, reason: DisconnectReason) {
        if self.state == State::Closed {
            return;
        }
        self.deadlines.clear();
        self.reassembler.clear();
        self.actions.push(MmsAction::Disconnect(reason));
        self.transition(State::Closed);
    }

    // -----------------------------------------------------------------
    // Timers (run at the tail of every handle)
    // -----------------------------------------------------------------

    fn run_timers(&mut self, now: Instant) {
        if matches!(self.state, State::Associating(_)) && self.deadlines.setup_expired(now) {
            self.fail(DisconnectReason::SetupTimeout);
            return;
        }
        if self.state == State::Releasing && self.deadlines.release_expired(now) {
            self.fail(DisconnectReason::ReleaseTimeout);
        }
    }
}

/// Negotiate the TPDU size as the smaller of ours and the peer's (if proposed).
fn negotiate_size(ours: TpduSize, theirs: Option<TpduSize>) -> TpduSize {
    match theirs {
        Some(t) if t.exponent() < ours.exponent() => t,
        _ => ours,
    }
}

/// Build an `InitiateResponse` by negotiating each numeric parameter down to
/// the smaller of our offer and the peer's proposal. BIT STRING capability
/// fields echo ours.
fn negotiate_response(
    ours: &crate::mms::InitiateRequest,
    req: &crate::mms::InitiateRequest,
) -> crate::mms::InitiateResponse {
    let min_opt = |a: Option<i64>, b: Option<i64>| match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    };
    crate::mms::InitiateResponse {
        local_detail: min_opt(ours.local_detail, req.local_detail),
        max_outstanding_calling: ours
            .max_outstanding_calling
            .min(req.max_outstanding_calling),
        max_outstanding_called: ours.max_outstanding_called.min(req.max_outstanding_called),
        nesting_level: min_opt(ours.nesting_level, req.nesting_level),
        version: ours.version.min(req.version),
        parameter_cbb: ours.parameter_cbb.clone(),
        services_supported: ours.services_supported.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::writer::BerWriter;
    use crate::mms::read::ReadRequest;
    use crate::mms::service::ConfirmedServiceRequest;
    use crate::mms::varname::{
        Identifier, ObjectName, VariableAccessSpecification, VariableSpecification,
    };
    use std::time::Duration;

    fn t0() -> Instant {
        Instant::now()
    }

    /// Split a SendBytes byte block into the individual TPKT payloads.
    fn tpkt_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut pos = 0;
        while let Some((payload, consumed)) = Tpkt::decode_slice(&bytes[pos..]).unwrap() {
            out.push(payload);
            pos += consumed;
            if pos >= bytes.len() {
                break;
            }
        }
        out
    }

    /// Feed every TPKT payload from `bytes` into `conn` and collect all actions.
    fn feed(conn: &mut MmsConnection, bytes: &[u8], now: Instant) -> Vec<MmsAction> {
        let mut all = Vec::new();
        for p in tpkt_payloads(bytes) {
            all.extend(conn.handle(MmsInput::TpktPayload(p), now));
        }
        all
    }

    fn take_send_bytes(actions: &[MmsAction]) -> Vec<u8> {
        actions
            .iter()
            .find_map(|a| match a {
                MmsAction::SendBytes(b) => Some(b.clone()),
                _ => None,
            })
            .expect("expected SendBytes")
    }

    fn canned_read() -> MmsPdu {
        MmsPdu::ConfirmedRequest {
            invoke_id: 1,
            service: ConfirmedServiceRequest::Read(ReadRequest {
                spec_with_result: false,
                access: VariableAccessSpecification::ListOfVariable(vec![
                    VariableSpecification::Name(ObjectName::VmdSpecific(
                        Identifier::new("Tag1").unwrap(),
                    )),
                ]),
            }),
        }
    }

    #[test]
    fn full_pure_handshake() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        let mut server = MmsConnection::new(Role::Server, AssocConfig::default());

        // Client begins: CR.
        let a = client.handle(MmsInput::Associate, t);
        assert_eq!(
            a,
            vec![
                MmsAction::SendBytes(take_send_bytes(&a)),
                MmsAction::StateChanged(State::Associating(AssocStage::CotpConnect)),
            ]
        );
        let cr = take_send_bytes(&a);

        // Server gets CR → CC.
        let a = feed(&mut server, &cr, t);
        assert_eq!(
            server.state(),
            State::Associating(AssocStage::OsiConnect),
            "server moves to OsiConnect after CC"
        );
        let cc = take_send_bytes(&a);

        // Client gets CC → CN.
        let a = feed(&mut client, &cc, t);
        assert_eq!(client.state(), State::Associating(AssocStage::OsiConnect));
        let cn = take_send_bytes(&a);

        // Server gets CN → AC, becomes Associated.
        let a = feed(&mut server, &cn, t);
        assert!(a.iter().any(|x| matches!(x, MmsAction::AssociationUp(_))));
        assert_eq!(server.state(), State::Associated);
        let ac = take_send_bytes(&a);

        // Client gets AC → Associated.
        let a = feed(&mut client, &ac, t);
        assert!(a.iter().any(|x| matches!(x, MmsAction::AssociationUp(_))));
        assert_eq!(client.state(), State::Associated);
    }

    #[test]
    fn read_request_flows_both_ways() {
        let (mut client, mut server, t) = associated_pair();

        let req = canned_read();
        let a = client.handle(MmsInput::SendService(req.clone()), t);
        let bytes = take_send_bytes(&a);

        let a = feed(&mut server, &bytes, t);
        assert!(
            a.iter()
                .any(|x| matches!(x, MmsAction::DeliverService(p) if *p == req)),
            "server delivers the read request"
        );

        // Response flows back.
        let resp = MmsPdu::ConfirmedResponse {
            invoke_id: 1,
            service: crate::mms::service::ConfirmedServiceResponse::Read(
                crate::mms::read::ReadResponse {
                    access_results: vec![crate::mms::read::AccessResult::Success(
                        crate::mms::data::Data::Integer(7),
                    )],
                },
            ),
        };
        let a = server.handle(MmsInput::SendService(resp.clone()), t);
        let bytes = take_send_bytes(&a);
        let a = feed(&mut client, &bytes, t);
        assert!(a
            .iter()
            .any(|x| matches!(x, MmsAction::DeliverService(p) if *p == resp)));
    }

    #[test]
    fn graceful_release() {
        let (mut client, mut server, t) = associated_pair();

        let a = client.handle(MmsInput::Release, t);
        assert_eq!(client.state(), State::Releasing);
        let conclude_req = take_send_bytes(&a);

        // Server auto-replies and closes.
        let a = feed(&mut server, &conclude_req, t);
        assert!(a.contains(&MmsAction::Disconnect(DisconnectReason::NormalRelease)));
        assert_eq!(server.state(), State::Closed);
        let conclude_resp = take_send_bytes(&a);

        // Client sees the response and closes.
        let a = feed(&mut client, &conclude_resp, t);
        assert!(a.contains(&MmsAction::Disconnect(DisconnectReason::NormalRelease)));
        assert_eq!(client.state(), State::Closed);
    }

    #[test]
    fn setup_timeout() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        client.handle(MmsInput::Associate, t);
        let later = t + Duration::from_secs(11);
        let a = client.handle(MmsInput::Tick, later);
        assert!(a.contains(&MmsAction::Disconnect(DisconnectReason::SetupTimeout)));
        assert_eq!(client.state(), State::Closed);
    }

    #[test]
    fn server_setup_timeout_after_cr() {
        // A server that receives a CR (sends CC, enters OsiConnect) but then
        // hears nothing must time out rather than wedge in Associating.
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        let mut server = MmsConnection::new(Role::Server, AssocConfig::default());
        let cr = take_send_bytes(&client.handle(MmsInput::Associate, t));
        feed(&mut server, &cr, t);
        assert_eq!(server.state(), State::Associating(AssocStage::OsiConnect));
        // Peer goes silent; advance past the setup deadline.
        let later = t + Duration::from_secs(11);
        let a = server.handle(MmsInput::Tick, later);
        assert!(a.contains(&MmsAction::Disconnect(DisconnectReason::SetupTimeout)));
        assert_eq!(server.state(), State::Closed);
    }

    #[test]
    fn negotiated_available_after_handshake() {
        let (client, server, _t) = associated_pair();
        let c = client.negotiated().expect("client negotiated");
        let s = server.negotiated().expect("server negotiated");
        // Both sides agree on the negotiated outcome (default vs default).
        assert_eq!(c.local_detail, s.local_detail);
        assert_eq!(c.max_outstanding_calling, s.max_outstanding_calling);
        assert_eq!(c.max_outstanding_called, s.max_outstanding_called);
        assert_eq!(c.version, s.version);
    }

    #[test]
    fn release_timeout() {
        let (mut client, _server, t) = associated_pair();
        client.handle(MmsInput::Release, t);
        let later = t + Duration::from_secs(11);
        let a = client.handle(MmsInput::Tick, later);
        assert!(a.contains(&MmsAction::Disconnect(DisconnectReason::ReleaseTimeout)));
        assert_eq!(client.state(), State::Closed);
    }

    #[test]
    fn cpa_mms_refused_disconnects() {
        // Drive a client to OsiConnect, then feed an AC whose CPA refuses MMS.
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        let mut server = MmsConnection::new(Role::Server, AssocConfig::default());
        let cr = take_send_bytes(&client.handle(MmsInput::Associate, t));
        let cc = take_send_bytes(&feed(&mut server, &cr, t));
        feed(&mut client, &cc, t);
        assert_eq!(client.state(), State::Associating(AssocStage::OsiConnect));

        // Build an AC with a CPA that refuses the MMS context.
        let cpa = build_cpa_refusing_mms();
        let ac = build_ac(cpa);
        let a = feed(&mut client, &ac, t);
        assert!(a.contains(&MmsAction::Disconnect(DisconnectReason::MmsContextRefused)));
    }

    #[test]
    fn aare_rejected_disconnects() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        let mut server = MmsConnection::new(Role::Server, AssocConfig::default());
        let cr = take_send_bytes(&client_cr(&mut client, t));
        let cc = take_send_bytes(&feed(&mut server, &cr, t));
        feed(&mut client, &cc, t);

        // Build a CPA that accepts contexts but carries an AARE with result=1.
        let cpa = build_cpa_with_aare_result(1);
        let ac = build_ac(cpa);
        let a = feed(&mut client, &ac, t);
        assert!(
            a.contains(&MmsAction::Disconnect(DisconnectReason::AcseRejected {
                result: 1
            }))
        );
    }

    #[test]
    fn data_phase_pci_mismatch_disconnects() {
        let (mut client, _server, t) = associated_pair();
        // Build a data SPDU addressed to an unknown PCI (99).
        let mms = {
            let mut w = BerWriter::new();
            canned_read().encode(&mut w).unwrap();
            w.into_bytes()
        };
        let pres = Presentation::encode_data(99, &mms);
        let mut sess = Vec::new();
        Session::encode(&SessionPdu::Data(pres), &mut sess).unwrap();
        let bytes = frame_session_bytes(&sess);
        let a = feed(&mut client, &bytes, t);
        assert!(a.iter().any(|x| matches!(
            x,
            MmsAction::Disconnect(DisconnectReason::Protocol(
                Error::PresentationContextUnknown { pci: 99 }
            ))
        )));
    }

    #[test]
    fn cotp_dr_disconnects() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        client_cr(&mut client, t);
        let dr = CotpPdu::DisconnectRequest {
            dst_ref: 1,
            src_ref: 2,
            reason: 0x80,
        };
        let mut cotp = Vec::new();
        CotpCodec::encode(&dr, &mut cotp).unwrap();
        let mut tpkt = Vec::new();
        Tpkt::encode(&cotp, &mut tpkt).unwrap();
        let a = feed(&mut client, &tpkt, t);
        assert!(
            a.contains(&MmsAction::Disconnect(DisconnectReason::CotpDisconnect {
                reason: 0x80
            }))
        );
    }

    #[test]
    fn out_of_stage_accept_while_idle_is_protocol() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        // An AC arriving in Idle is a protocol violation: but it arrives as a
        // DT, which in Idle is out-of-stage.
        let ac = build_ac(build_cpa_with_aare_result(0));
        let a = feed(&mut client, &ac, t);
        assert!(a
            .iter()
            .any(|x| matches!(x, MmsAction::Disconnect(DisconnectReason::Protocol(_)))));
        assert_eq!(client.state(), State::Closed);
    }

    #[test]
    fn garbage_tpkt_payload_is_protocol() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        client_cr(&mut client, t);
        let a = client.handle(MmsInput::TpktPayload(vec![0xFF, 0xFF, 0xFF]), t);
        assert!(a
            .iter()
            .any(|x| matches!(x, MmsAction::Disconnect(DisconnectReason::Protocol(_)))));
        assert_eq!(client.state(), State::Closed);
    }

    #[test]
    fn closed_absorbs_all_inputs() {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        client.handle(MmsInput::Abort, t);
        assert_eq!(client.state(), State::Closed);
        for input in [
            MmsInput::Associate,
            MmsInput::Release,
            MmsInput::Abort,
            MmsInput::SendService(canned_read()),
            MmsInput::Tick,
            MmsInput::TpktPayload(vec![0x01, 0x02, 0x03]),
        ] {
            assert!(
                client.handle(input, t).is_empty(),
                "closed connection must absorb all inputs"
            );
        }
    }

    #[test]
    fn fragmented_inbound_reassembles() {
        let (mut client, mut server, t) = associated_pair();
        // Use a tiny TPDU size on the server so the response fragments.
        server.config.tpdu_size = TpduSize::new(7).unwrap();
        // Build a large read response.
        let mut results = Vec::new();
        for i in 0..50 {
            results.push(crate::mms::read::AccessResult::Success(
                crate::mms::data::Data::Integer(i),
            ));
        }
        let resp = MmsPdu::ConfirmedResponse {
            invoke_id: 1,
            service: crate::mms::service::ConfirmedServiceResponse::Read(
                crate::mms::read::ReadResponse {
                    access_results: results,
                },
            ),
        };
        let a = server.handle(MmsInput::SendService(resp.clone()), t);
        let bytes = take_send_bytes(&a);
        // Multiple TPKT frames expected.
        assert!(tpkt_payloads(&bytes).len() > 1, "response must fragment");
        let a = feed(&mut client, &bytes, t);
        assert!(a
            .iter()
            .any(|x| matches!(x, MmsAction::DeliverService(p) if *p == resp)));
    }

    #[test]
    fn random_bytes_never_panic_on_associated() {
        let (mut client, _server, t) = associated_pair();
        let mut seed = 0x1234_5678u32;
        for _ in 0..2000 {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let len = (seed % 40) as usize;
            let mut buf = Vec::with_capacity(len);
            let mut s = seed;
            for _ in 0..len {
                s = s.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                buf.push((s >> 16) as u8);
            }
            let _ = client.handle(MmsInput::TpktPayload(buf), t);
            assert!(
                matches!(client.state(), State::Associated | State::Closed),
                "state must stay Associated or be Closed, got {:?}",
                client.state()
            );
            if client.state() == State::Closed {
                break;
            }
        }
    }

    // ---- test helpers --------------------------------------------------

    fn client_cr(client: &mut MmsConnection, t: Instant) -> Vec<MmsAction> {
        // Idempotent: only emit CR if still Idle.
        if client.state() == State::Idle {
            client.handle(MmsInput::Associate, t)
        } else {
            Vec::new()
        }
    }

    /// Drive a fresh client+server pair all the way to Associated.
    fn associated_pair() -> (MmsConnection, MmsConnection, Instant) {
        let t = t0();
        let mut client = MmsConnection::new(Role::Client, AssocConfig::default());
        let mut server = MmsConnection::new(Role::Server, AssocConfig::default());
        let cr = take_send_bytes(&client.handle(MmsInput::Associate, t));
        let cc = take_send_bytes(&feed(&mut server, &cr, t));
        let cn = take_send_bytes(&feed(&mut client, &cc, t));
        let ac = take_send_bytes(&feed(&mut server, &cn, t));
        feed(&mut client, &ac, t);
        assert_eq!(client.state(), State::Associated);
        assert_eq!(server.state(), State::Associated);
        (client, server, t)
    }

    /// Frame raw session bytes (DATA) into a TPKT/COTP block at default size.
    fn frame_session_bytes(session: &[u8]) -> Vec<u8> {
        let frags = CotpCodec::encode_data(session, TpduSize::SIZE_1024);
        let mut out = Vec::new();
        for f in &frags {
            Tpkt::encode(f, &mut out).unwrap();
        }
        out
    }

    /// Build a CPA that accepts ACSE but refuses MMS, carrying a valid AARE.
    fn build_cpa_refusing_mms() -> Vec<u8> {
        build_cpa_inner(true, false, 0)
    }

    /// Build a CPA accepting both contexts, with an AARE carrying `result`.
    fn build_cpa_with_aare_result(result: i64) -> Vec<u8> {
        build_cpa_inner(true, true, result)
    }

    fn build_cpa_inner(acse_ok: bool, mms_ok: bool, aare_result: i64) -> Vec<u8> {
        use crate::ber::tag::Tag;
        let aare = AcsePdu::Aare(Aare {
            app_context: ObjectIdentifier::from_arcs(MMS_APP_CONTEXT_ARCS),
            result: aare_result,
            user_info: {
                let mut w = BerWriter::new();
                MmsPdu::InitiateResponse(crate::mms::InitiateResponse::default())
                    .encode(&mut w)
                    .unwrap();
                w.into_bytes()
            },
        });
        let mut aare_bytes = Vec::new();
        Acse::encode(&aare, &mut aare_bytes).unwrap();

        // Hand-build a CPA PPDU with explicit result codes.
        let tag_cp = Tag {
            class: crate::ber::tag::TagClass::Universal,
            constructed: true,
            number: 17,
        };
        let tag_normal = Tag::context_constructed(2);
        let tag_mode_sel = Tag::context_constructed(0);
        let tag_mode_val = Tag::context(0);
        let tag_result_list = Tag::context_constructed(5);
        let tag_result = Tag::context(0);
        let tag_xfer = Tag::context(1);
        let tag_fed = Tag::application_constructed(1);
        let tag_single = Tag::context_constructed(0);
        let ber_oid = ObjectIdentifier::from_arcs(&[2, 1, 1]);

        let mut w = BerWriter::new();
        w.write_tlv(tag_cp, |cp| {
            cp.write_tlv(tag_mode_sel, |ms| ms.write_integer(tag_mode_val, 1));
            cp.write_tlv(tag_normal, |nm| {
                nm.write_tlv(tag_result_list, |list| {
                    for ok in [acse_ok, mms_ok] {
                        list.write_tlv(Tag::SEQUENCE, |item| {
                            item.write_integer(tag_result, if ok { 0 } else { 1 });
                            item.write_oid(tag_xfer, &ber_oid);
                        });
                    }
                });
                nm.write_tlv(tag_fed, |fed| {
                    fed.write_tlv(Tag::SEQUENCE, |pdv| {
                        pdv.write_integer(Tag::INTEGER, 1); // acse pci
                        pdv.write_primitive(tag_single, &aare_bytes);
                    });
                });
            });
        });
        w.into_bytes()
    }

    /// Wrap CPA bytes in an AC SessionPdu and frame to TPKT/COTP.
    fn build_ac(cpa: Vec<u8>) -> Vec<u8> {
        let ac = SessionPdu::Accept(SessionConnect {
            calling_selector: Some(vec![0, 1]),
            called_selector: Some(vec![0, 1]),
            user_data: cpa,
        });
        let mut sess = Vec::new();
        Session::encode(&ac, &mut sess).unwrap();
        frame_session_bytes(&sess)
    }
}
