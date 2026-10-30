//! Functional self-test: the simulator exercises itself.
//!
//! `--self-test` binds a temporary server on 127.0.0.1 with an ephemeral
//! (non-privileged) port, then drives a real TASE.2 client over TCP through
//! the full protocol stack: COTP/ACSE association, MMS initiate, the
//! `TASE2_Version` / `Supported_Features` / `Bilateral_Table_ID` reads,
//! point and dataset enumeration, a point read, DS-transfer-set claim +
//! arming, reception of a COV report (driven by the server's self-mutation
//! loop), a graceful release, and a server-side verification that the
//! client's configured OSI/ACSE identity actually arrived in the handshake.
//!
//! Every line reports PASS/FAIL/SKIP for an operation that was really
//! performed and verified — there are no fake passes. Any FAIL makes
//! `run()` return `false`, and `main` turns that into a non-zero process
//! exit code.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mms_proto::assoc::AssociationInfo;
use tase2::{
    names, object_name, AccessResult, ConfirmedServiceRequest, ConfirmedServiceResponse, Data,
    DomainName, DsTransferSet, EventHandler, Identifier, ObjectName, PointKind, PointValue,
    ReadRequest, Tase2Client, Tase2Server, TransferSetManager, Transport,
    VariableAccessSpecification, VariableSpecification,
};
use tase2_proto::transfer_set::DsConditions;

use crate::config::{build_assoc_config, build_model, AssocCfg, SideAssocCfg, SimConfig};
use crate::provider::SimProvider;
use crate::{spawn_mutation_task, ServeOptions};

/// Overall per-stage timeout.
const STAGE_TIMEOUT: Duration = Duration::from_secs(20);

const DOMAIN: &str = "ICC1";
const BILATERAL_ID: &str = "BLT1";
const POINT: &str = "P1";
const DATASET: &str = "DS1";
const POINT_INITIAL: i32 = 0;

/// Client-side identity the test connects with (and what the server side
/// must observe in the handshake).
const CLIENT_AP_TITLE: &str = "1.2.3.4";
const CLIENT_TSEL: &[u8] = &[0, 0, 0, 17];
const CLIENT_SSEL: &[u8] = &[18, 35];
const CLIENT_PSEL: &[u8] = &[0, 18];

/// Server-side local identity (the client's `remote` side matches these).
const SERVER_TSEL: &[u8] = &[0, 0, 0, 1];
const SERVER_SSEL: &[u8] = &[0, 1];
const SERVER_PSEL: &[u8] = &[0, 0, 0, 1];

/// Records the server's view of the connecting client's association
/// identity (populated from the handshake via `on_association_up`).
#[derive(Default)]
struct Capture {
    peer: Mutex<Option<AssociationInfo>>,
}

impl EventHandler for Capture {
    fn on_association_up(&self, peer: &AssociationInfo) {
        *self.peer.lock().unwrap() = Some(peer.clone());
    }
}

// The accept loop hands an `Arc<Capture>` to `accept_with`, which requires the
// handler itself to implement `EventHandler`. Delegate to the inner capture.
/// Newtype so the accept loop can pass a shared handler to `accept_with`
/// (which takes the handler by value) while the test body still reads the
/// captured identity through the same `Arc`.
#[derive(Clone)]
struct CaptureHandler(Arc<Capture>);

impl EventHandler for CaptureHandler {
    fn on_association_up(&self, peer: &AssociationInfo) {
        *self.0.peer.lock().unwrap() = Some(peer.clone());
    }
}

/// Run the self-test. Returns `true` only if every stage passed.
pub async fn run() -> bool {
    let ok = run_inner().await;
    println!("{}", if ok { "RESULT: PASS" } else { "RESULT: FAIL" });
    ok
}

async fn run_inner() -> bool {
    println!("ICCP-SIM SELF TEST");
    println!("------------------");

    // ---- server side -------------------------------------------------------
    let cfg: SimConfig = serde_json::from_str(
        r#"{
            "mode": "server",
            "ip": "127.0.0.1",
            "port": 0,
            "domain": "ICC1",
            "bilateral_table_id": "BLT1",
            "tase2_version": { "major": 1, "minor": 0 },
            "supported_features": ["ds_transfer", "cov", "bilateral_access"],
            "association": {
                "local":  { "tsel": "0.0.0.1", "ssel": "0.1", "psel": "0.0.0.1" },
                "remote": { "tsel": "0.0.0.17", "ssel": "18.35", "psel": "0.18" }
            },
            "points": [ { "name": "P1", "kind": "discrete", "initial": 0 } ],
            "datasets": [ { "name": "DS1", "members": ["P1"] } ],
            "mutation": { "interval_secs": 1, "points": [ { "name": "P1", "values": [0, 1] } ] }
        }"#,
    )
    .expect("self-test server config");

    let model = build_model(&cfg).expect("build self-test model");
    let server_assoc = build_assoc_config(&cfg.association).expect("server association");

    let server = Tase2Server::bind(
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        server_assoc,
    )
    .await
    .expect("bind self-test server");
    let port = server.local_addr().expect("server local address").port();
    let addr: SocketAddr = (Ipv4Addr::LOCALHOST, port).into();
    println!("    (temporary server listening on {addr})");

    let provider = model.provider.clone();
    let bilateral = model.bilateral.clone();
    let manager = Arc::new(TransferSetManager::new(provider.clone()));

    // Drive OBJECT_CHANGE reports so the client's transfer set fires.
    let mutation = spawn_mutation_task(model, manager.clone()).await;

    // Accept loop in the background: serve the single test client.
    let server = Arc::new(server);
    let capture = Arc::new(Capture::default());
    let server_task = {
        let server = server.clone();
        let provider = provider.clone();
        let bilateral = bilateral.clone();
        let manager = manager.clone();
        let capture = capture.clone();
        tokio::spawn(async move {
            loop {
                let conn = match server.accept_with(CaptureHandler(capture.clone())).await {
                    Ok(c) => c,
                    Err(_) => break, // listener dropped / task aborted
                };
                let provider = provider.clone();
                let bilateral = bilateral.clone();
                let manager = manager.clone();
                tokio::spawn(async move {
                    let mut conn = conn;
                    let options = ServeOptions::<SimProvider>::new()
                        .with_transfer_sets(manager)
                        .with_access(bilateral)
                        .with_poll_ceiling(Duration::from_millis(200));
                    let _ = tase2::serve_connection_opts(&mut conn, provider, options).await;
                });
            }
        })
    };

    // Client association: local = this test's identity, remote = the server's
    // configured local side.
    let client_assoc = build_assoc_config(&AssocCfg {
        local: SideAssocCfg {
            ap_title: Some(CLIENT_AP_TITLE.to_owned()),
            ae_qualifier: Some(1),
            tsel: Some(CLIENT_TSEL.to_vec()),
            ssel: Some(CLIENT_SSEL.to_vec()),
            psel: Some(CLIENT_PSEL.to_vec()),
        },
        remote: SideAssocCfg {
            ap_title: None,
            ae_qualifier: Some(1),
            tsel: Some(SERVER_TSEL.to_vec()),
            ssel: Some(SERVER_SSEL.to_vec()),
            psel: Some(SERVER_PSEL.to_vec()),
        },
    })
    .expect("client association");

    // ---- TCP + COTP/ACSE association + MMS initiate ------------------------
    let mut client = match tokio::time::timeout(
        STAGE_TIMEOUT,
        Tase2Client::connect(Transport::tcp(addr), client_assoc),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            println!("FAIL TCP connection");
            println!("      {e}");
            teardown(mutation, server, server_task).await;
            return false;
        }
        Err(_) => {
            println!("FAIL TCP connection");
            println!("      timed out after {STAGE_TIMEOUT:?}");
            teardown(mutation, server, server_task).await;
            return false;
        }
    };
    println!("PASS TCP connection");
    // `connect` only returns after the full handshake: COTP CR/CC, ACSE
    // AARQ/AARE, and the MMS initiate pair — all verified by construction.
    println!("PASS COTP/ACSE association");
    println!("PASS MMS initiate");

    // ---- service stages ------------------------------------------------------
    let ok = client_side(&mut client).await;

    // ---- graceful release ------------------------------------------------------
    // MMS Conclude while the server still serves; the association must end
    // cleanly.
    let release_ok = tokio::time::timeout(STAGE_TIMEOUT, client.release())
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);
    println!(
        "{} graceful association release",
        if release_ok { "PASS" } else { "FAIL" }
    );

    // ---- server-side identity verification ---------------------------------------
    // The client's configured local identity must be the identity the server
    // observed in the handshake — proof that the config→wire mapping works.
    let peer_ok = verify_peer_identity(&capture);
    println!(
        "{} client association identity verified at server",
        if peer_ok { "PASS" } else { "FAIL" }
    );

    // ---- teardown ----------------------------------------------------------------
    teardown(mutation, server, server_task).await;
    ok && release_ok && peer_ok
}

/// Stop the mutation loop, drop the listener, and abort the accept loop.
/// Taking the `Arc` and task handle by value releases the listener (the
/// accept loop held the last clone) so the bind is freed on shutdown.
async fn teardown(
    mutation: tokio::task::JoinHandle<()>,
    server: Arc<Tase2Server>,
    server_task: tokio::task::JoinHandle<()>,
) {
    mutation.abort();
    drop(server);
    server_task.abort();
}

/// All the client-side service stages, in order, against the connected
/// `client`. Returns `true` only if every stage passed.
async fn client_side(client: &mut Tase2Client) -> bool {
    let mut passed = true;
    let mut stage = |name: &str, ok: bool| -> bool {
        println!("{} {name}", if ok { "PASS" } else { "FAIL" });
        if !ok {
            passed = false;
        }
        ok
    };

    let domain_id = Identifier::new(DOMAIN).unwrap();
    let domain = DomainName::from(domain_id);

    // ---- TASE2_Version -----------------------------------------------------
    let version_name = object_name(
        Some(&domain),
        &Identifier::new(names::TASE2_VERSION).unwrap(),
    );
    let version = tokio::time::timeout(STAGE_TIMEOUT, read_version(client, &version_name))
        .await
        .ok()
        .flatten();
    if stage("TASE2_Version", version.is_some()) {
        if let Some((maj, min)) = version {
            println!("      {maj}.{min}");
        }
    }

    // ---- Supported_Features --------------------------------------------------
    let features_name = object_name(
        Some(&domain),
        &Identifier::new(names::SUPPORTED_FEATURES).unwrap(),
    );
    let features = tokio::time::timeout(STAGE_TIMEOUT, read_features(client, &features_name))
        .await
        .ok()
        .flatten();
    if stage("Supported_Features", features.is_some()) {
        if let Some(bits) = &features {
            let labels = ["ds_transfer", "cov", "device_control", "bilateral_access"];
            let list: Vec<&str> = bits
                .iter()
                .zip(labels)
                .filter(|(b, _)| **b)
                .map(|(_, n)| n)
                .collect();
            println!("      advertised: {}", list.join(", "));
            let dc_advertised = bits.get(2).copied().unwrap_or(false);
            // The test server configures ds_transfer + cov + bilateral_access
            // and must NOT advertise device_control.
            stage("device_control not advertised by default", !dc_advertised);
        }
    }

    // ---- Bilateral_Table_ID ----------------------------------------------------
    let blt = tokio::time::timeout(STAGE_TIMEOUT, client.read_bilateral_table_id(Some(&domain)))
        .await
        .ok()
        .and_then(|r| r.ok());
    let blt_ok = blt.as_deref() == Some(BILATERAL_ID);
    if stage("Bilateral_Table_ID", blt_ok) {
        if let Some(id) = blt {
            println!("      {id}");
        }
    }

    // ---- point / dataset enumeration -------------------------------------------
    let points = tokio::time::timeout(
        STAGE_TIMEOUT,
        client.get_name_list(tase2::OBJECT_CLASS_NAMED_VARIABLE, Some(&domain)),
    )
    .await
    .ok()
    .and_then(|r| r.ok());
    let points_ok = points
        .as_ref()
        .map(|ids| ids.iter().any(|i| i.as_str() == POINT))
        .unwrap_or(false);
    if stage("point enumeration", points_ok) {
        if let Some(ids) = &points {
            println!(
                "      points: {}",
                ids.iter()
                    .map(|i| i.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let datasets = tokio::time::timeout(
        STAGE_TIMEOUT,
        client.get_name_list(tase2::OBJECT_CLASS_NAMED_VARIABLE_LIST, Some(&domain)),
    )
    .await
    .ok()
    .and_then(|r| r.ok());
    let datasets_ok = datasets
        .as_ref()
        .map(|ids| ids.iter().any(|i| i.as_str() == DATASET))
        .unwrap_or(false);
    if stage("dataset enumeration", datasets_ok) {
        if let Some(ids) = &datasets {
            println!(
                "      datasets: {}",
                ids.iter()
                    .map(|i| i.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    // ---- point read ---------------------------------------------------------------
    let p_name = object_name(Some(&domain), &Identifier::new(POINT).unwrap());
    let value = tokio::time::timeout(
        STAGE_TIMEOUT,
        client.read_point(&p_name, PointKind::Discrete),
    )
    .await
    .ok()
    .and_then(|r| r.ok());
    let read_ok = value.as_ref() == Some(&PointValue::Discrete(POINT_INITIAL));
    if stage("point read", read_ok) {
        if let Some(v) = &value {
            println!("      {POINT} = {v:?}");
        }
    }

    // ---- transfer set claim + arm ---------------------------------------------------
    let ts_name = tokio::time::timeout(STAGE_TIMEOUT, client.next_transfer_set(&domain))
        .await
        .ok()
        .and_then(|r| r.ok());
    let arm_ok = match ts_name {
        Some(ts_name) => {
            let ds_obj = object_name(Some(&domain), &Identifier::new(DATASET).unwrap());
            let mut ts = DsTransferSet::default();
            ts.data_set_name = tase2::TsDataSetName::from_object_name(&ds_obj);
            ts.interval = 0;
            ts.buffer_time = 0;
            ts.integrity_check = 0;
            // object-change only; RBE on so a single P1 step fires one report.
            ts.conditions = DsConditions::OBJECT_CHANGE;
            ts.rbe = true;
            ts.status = true;
            ts.event_code_requested = 0;
            let write =
                tokio::time::timeout(STAGE_TIMEOUT, client.write_transfer_set(&ts_name, &ts))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
            if write {
                println!("      armed for object_change on {DATASET}");
            }
            write
        }
        None => false,
    };
    stage("transfer set", arm_ok);

    // ---- COV report reception ---------------------------------------------------------
    // The server mutates P1 every second; with object_change + rbe the first
    // step must produce a report. Wait for at least one decoded report.
    let members = report_members(&domain);
    let mut report_seen = false;
    let mut first_report = None;
    let deadline = tokio::time::Instant::now() + STAGE_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        if let Some(pdu) = tokio::time::timeout_at(deadline, client.recv_unsolicited())
            .await
            .ok()
            .flatten()
        {
            if let Ok(rep) = client.decode_report(&pdu, &members) {
                report_seen = true;
                first_report = Some(rep);
                break;
            }
        }
    }
    if stage("COV report received", report_seen) {
        if let Some(rep) = &first_report {
            println!(
                "      conditions={:?} values={:?}",
                rep.conditions, rep.values
            );
        }
    }

    passed
}

/// The 4 ICCP control members (wire order) + the test point member.
fn report_members(domain: &DomainName) -> Vec<ObjectName> {
    const CONTROL: [&str; 4] = [
        names::TRANSFER_SET_NAME,
        names::TRANSFER_SET_TIME_STAMP,
        names::DSCONDITIONS_DETECTED,
        names::EVENT_CODE_DETECTED,
    ];
    let mut out = Vec::with_capacity(5);
    for cm in CONTROL {
        out.push(object_name(Some(domain), &Identifier::new(cm).unwrap()));
    }
    out.push(object_name(Some(domain), &Identifier::new(POINT).unwrap()));
    out
}

/// Read `TASE2_Version` (Structure { Unsigned, Unsigned }).
async fn read_version(client: &mut Tase2Client, name: &ObjectName) -> Option<(u64, u64)> {
    let req = ReadRequest {
        spec_with_result: false,
        access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
            name.clone(),
        )]),
    };
    let resp = match client.request(ConfirmedServiceRequest::Read(req)).await {
        Ok(ConfirmedServiceResponse::Read(r)) => r,
        _ => return None,
    };
    match resp.access_results.first()? {
        AccessResult::Success(Data::Structure(v)) if v.len() == 2 => {
            let major = match &v[0] {
                Data::Unsigned(n) => *n,
                _ => return None,
            };
            let minor = match &v[1] {
                Data::Unsigned(n) => *n,
                _ => return None,
            };
            Some((major, minor))
        }
        _ => None,
    }
}

/// Read `Supported_Features` (BitString) as a bit vector (MSB-first order).
async fn read_features(client: &mut Tase2Client, name: &ObjectName) -> Option<Vec<bool>> {
    let req = ReadRequest {
        spec_with_result: false,
        access: VariableAccessSpecification::ListOfVariable(vec![VariableSpecification::Name(
            name.clone(),
        )]),
    };
    let resp = match client.request(ConfirmedServiceRequest::Read(req)).await {
        Ok(ConfirmedServiceResponse::Read(r)) => r,
        _ => return None,
    };
    match resp.access_results.first()? {
        AccessResult::Success(Data::BitString(bs)) => {
            Some((0..bs.bit_len()).map(|i| bs.bit(i)).collect())
        }
        _ => None,
    }
}

/// Server-side check: the client's configured local identity must be the
/// identity the server observed in the handshake (AP title, AE qualifier,
/// TSEL/SSEL/PSEL).
fn verify_peer_identity(capture: &Arc<Capture>) -> bool {
    let peer = capture.peer.lock().unwrap().clone();
    let peer = match peer {
        Some(p) => p,
        None => {
            println!("      (no association observed by the server)");
            return false;
        }
    };
    let mut ok = true;
    for (name, expected, actual) in [
        ("tsel", CLIENT_TSEL, peer.tsel.as_deref()),
        ("ssel", CLIENT_SSEL, peer.ssel.as_deref()),
        ("psel", CLIENT_PSEL, peer.psel.as_deref()),
    ] {
        let actual = actual.unwrap_or(&[]);
        if actual != expected {
            println!(
                "      {name}: expected {}, got {}",
                bytes(expected),
                bytes(actual)
            );
            ok = false;
        }
    }
    let ae_ok = peer.ae_qualifier == Some(1);
    if !ae_ok {
        println!(
            "      ae_qualifier: expected Some(1), got {:?}",
            peer.ae_qualifier
        );
    }
    let ap_ok = peer.ap_title.as_ref().map(|o| o.to_string()).as_deref() == Some(CLIENT_AP_TITLE);
    if !ap_ok {
        println!(
            "      ap_title: expected {CLIENT_AP_TITLE}, got {:?}",
            peer.ap_title
        );
    }
    ok &= ae_ok && ap_ok;
    if ok {
        println!(
            "      identity confirmed: ap={CLIENT_AP_TITLE} ae=1 tsel={} ssel={} psel={}",
            bytes(CLIENT_TSEL),
            bytes(CLIENT_SSEL),
            bytes(CLIENT_PSEL)
        );
    }
    ok
}

fn bytes(b: &[u8]) -> String {
    b.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(".")
}
