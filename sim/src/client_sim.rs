//! The client (calling) role for `iccp-sim`.
//!
//! A real ICCP/TASE.2 *caller*: connect to a peer, read
//! `TASE2_Version` / `Supported_Features` / `Bilateral_Table_ID`, enumerate the
//! domain's points and data sets, read them, then claim a DS-transfer-set and
//! arm condition monitoring so incoming COV reports are decoded and logged.
//!
//! This exists so `iccp-sim` can exercise a *real* (or second) ICCP peer and
//! round-trip interop tests, not just act as the simulator.

use std::net::SocketAddr;
use std::time::Duration;

use tase2::{
    names, object_name, DomainName, DsTransferSet, Identifier, ObjectName, Tase2Client, Transport,
};

use crate::config::{build_assoc_config, build_conditions, ClientCfg};

/// The four ICCP control members, in wire order. Prepended to a data set's
/// point members to form the full member list a report is decoded against.
const CONTROL_MEMBERS: [&str; 4] = [
    names::TRANSFER_SET_NAME,
    names::TRANSFER_SET_TIME_STAMP,
    names::DSCONDITIONS_DETECTED,
    names::EVENT_CODE_DETECTED,
];

/// Run the client for the configured duration.
///
/// `run_for_secs == 0` means: stay associated until the peer closes it.
pub async fn run(cfg: &ClientCfg) -> Result<(), String> {
    let ip: std::net::IpAddr = cfg
        .peer_ip
        .parse()
        .map_err(|e| format!("bad peer_ip {:?}: {e}", cfg.peer_ip))?;
    let addr: SocketAddr = (ip, cfg.port).into();

    let assoc =
        build_assoc_config(&cfg.association).map_err(|e| format!("bad association config: {e}"))?;
    let transport = Transport::tcp(addr);
    let mut client = Tase2Client::connect(transport, assoc)
        .await
        .map_err(|e| format!("associate {addr} failed: {e}"))?;
    tracing::info!(%addr, "associated as TASE.2 client");

    let domain_id =
        Identifier::new(&cfg.domain).map_err(|e| format!("bad domain {:?}: {e}", cfg.domain))?;
    let domain = DomainName::from(domain_id);

    let result = async {
        discovery(&mut client, &domain).await;
        if !cfg.dataset.is_empty() {
            arm_transfer_set(&mut client, &domain, cfg).await;
        }
        let members = data_set_members(cfg);
        recv_loop(&mut client, &members, cfg.run_for_secs).await
    }
    .await;

    // Conclude the association gracefully.
    let _ = client.release().await;
    result
}

/// Read the VMD special variables and enumerate the domain. Best-effort: each
/// step logs on failure and the client keeps going (the peer may not expose
/// every optional variable).
async fn discovery(client: &mut Tase2Client, domain: &DomainName) {
    // TASE2_Version (Structure { Unsigned major, Unsigned minor }): try the
    // domain-scoped name first, then the VMD-scoped one.
    let version_name = object_name(Some(domain), &version_item());
    let version = match read_version(client, &version_name).await {
        Some(v) => Some(v),
        None => {
            let vmd = ObjectName::VmdSpecific(version_item());
            read_version(client, &vmd).await
        }
    };
    match version {
        Some((major, minor)) => tracing::info!(major, minor, "peer TASE2_Version"),
        None => tracing::warn!("peer did not serve TASE2_Version"),
    }

    // Supported_Features (BitString), domain-scoped like the version read.
    let features_name = object_name(Some(domain), &features_item());
    if let Some(bits) = read_features(client, &features_name).await {
        tracing::info!(?bits, "peer Supported_Features");
    }

    // Bilateral_Table_ID.
    match client.read_bilateral_table_id(Some(domain)).await {
        Ok(id) => tracing::info!(%id, "peer Bilateral_Table_ID"),
        Err(e) => tracing::warn!(%e, "read Bilateral_Table_ID failed"),
    }

    // Enumerate points and data sets in the domain.
    if let Ok(ids) = client
        .get_name_list(tase2::OBJECT_CLASS_NAMED_VARIABLE, Some(domain))
        .await
    {
        tracing::info!(count = ids.len(), "domain points");
    } else {
        tracing::warn!("GetNameList(points) failed");
    }
    if let Ok(ids) = client
        .get_name_list(tase2::OBJECT_CLASS_NAMED_VARIABLE_LIST, Some(domain))
        .await
    {
        tracing::info!(count = ids.len(), "domain datasets");
    } else {
        tracing::warn!("GetNameList(datasets) failed");
    }
}

async fn read_version(client: &mut Tase2Client, name: &ObjectName) -> Option<(u64, u64)> {
    let req = mms_proto::mms::ReadRequest {
        spec_with_result: false,
        access: mms_proto::mms::VariableAccessSpecification::ListOfVariable(vec![
            mms_proto::mms::VariableSpecification::Name(name.clone()),
        ]),
    };
    let resp = match client
        .request(mms_proto::mms::ConfirmedServiceRequest::Read(req))
        .await
    {
        Ok(mms_proto::mms::ConfirmedServiceResponse::Read(r)) => r,
        _ => return None,
    };
    match resp.access_results.first()? {
        mms_proto::mms::AccessResult::Success(mms_proto::mms::Data::Structure(v))
            if v.len() == 2 =>
        {
            let major = match &v[0] {
                mms_proto::mms::Data::Unsigned(n) => *n,
                _ => return None,
            };
            let minor = match &v[1] {
                mms_proto::mms::Data::Unsigned(n) => *n,
                _ => return None,
            };
            Some((major, minor))
        }
        _ => None,
    }
}

async fn read_features(client: &mut Tase2Client, name: &ObjectName) -> Option<Vec<bool>> {
    let req = mms_proto::mms::ReadRequest {
        spec_with_result: false,
        access: mms_proto::mms::VariableAccessSpecification::ListOfVariable(vec![
            mms_proto::mms::VariableSpecification::Name(name.clone()),
        ]),
    };
    let resp = match client
        .request(mms_proto::mms::ConfirmedServiceRequest::Read(req))
        .await
    {
        Ok(mms_proto::mms::ConfirmedServiceResponse::Read(r)) => r,
        _ => return None,
    };
    match resp.access_results.first()? {
        mms_proto::mms::AccessResult::Success(mms_proto::mms::Data::BitString(bs)) => {
            Some((0..bs.bit_len()).map(|i| bs.bit(i)).collect())
        }
        _ => None,
    }
}

/// Claim a DS-transfer-set instance and arm condition monitoring against
/// `cfg.dataset` in `domain`.
async fn arm_transfer_set(client: &mut Tase2Client, domain: &DomainName, cfg: &ClientCfg) {
    // 1. Claim a free instance.
    let ts_name = match client.next_transfer_set(domain).await {
        Ok(n) => {
            tracing::info!(ts = name_display(&n), "claimed DS transfer set");
            n
        }
        Err(e) => {
            tracing::warn!(%e, "Next_DSTransfer_Set failed; cannot arm reports");
            return;
        }
    };

    // 2. Build the transfer-set attributes.
    let ds_item = match Identifier::new(&cfg.dataset) {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!(%e, "bad dataset name {:?}; cannot arm", cfg.dataset);
            return;
        }
    };
    let ds_obj = object_name(Some(domain), &ds_item);
    let conditions = match build_conditions(&cfg.transfer_set.conditions) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(%e, "bad conditions; cannot arm");
            return;
        }
    };
    let mut ts = DsTransferSet::default();
    ts.data_set_name = tase2::TsDataSetName::from_object_name(&ds_obj);
    ts.interval = cfg.transfer_set.interval;
    ts.buffer_time = cfg.transfer_set.buffer_time;
    ts.integrity_check = cfg.transfer_set.integrity_check;
    ts.conditions = conditions;
    ts.rbe = cfg.transfer_set.rbe;
    ts.status = true;
    ts.event_code_requested = cfg.transfer_set.event_code;

    // 3. Write the attributes to arm it.
    match client.write_transfer_set(&ts_name, &ts).await {
        Ok(()) => {
            tracing::info!(
                dataset = name_display(&ds_obj),
                "transfer set armed; awaiting reports"
            )
        }
        Err(e) => tracing::warn!(%e, "write_transfer_set failed"),
    }
}

/// Drain unsolicited reports, decoding each against the configured data set's
/// members (the 4 ICCP control members + the data set's point members). Stops
/// when the association closes, or after `run_for_secs` if set.
async fn recv_loop(
    client: &mut Tase2Client,
    members: &[ObjectName],
    run_for_secs: u64,
) -> Result<(), String> {
    let deadline =
        (run_for_secs > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(run_for_secs));

    let mut count = 0u64;
    loop {
        let next = match deadline {
            Some(d) => match tokio::time::timeout_at(d, client.recv_unsolicited()).await {
                Ok(v) => v,
                Err(_) => {
                    tracing::info!(reports = count, "run_for_secs elapsed");
                    return Ok(());
                }
            },
            None => client.recv_unsolicited().await,
        };

        let Some(pdu) = next else {
            tracing::info!(reports = count, "association closed by peer");
            return Ok(());
        };

        match client.decode_report(&pdu, members) {
            Ok(rep) => {
                count += 1;
                let ts = rep.ts_name.as_ref().map(name_display);
                tracing::info!(
                    report = count,
                    ts = ?ts,
                    timestamp = ?rep.timestamp,
                    conditions = ?rep.conditions,
                    event_code = ?rep.event_code,
                    values = ?rep.values,
                    "COV report"
                );
            }
            Err(e) => {
                tracing::debug!(%e, "failed to decode report");
            }
        }
    }
}

/// The full member list a report is decoded against: the 4 ICCP control
/// members (in wire order) followed by the data set's point members. This must
/// match the server's member order, which is how the sim server (and, per the
/// ICCP convention, a real peer) reports a data set.
fn data_set_members(cfg: &ClientCfg) -> Vec<ObjectName> {
    let Some(domain) = Identifier::new(&cfg.domain).ok().map(DomainName::from) else {
        return Vec::new();
    };
    let mut members: Vec<ObjectName> = Vec::with_capacity(4 + cfg.dataset_points.len());
    for cm in CONTROL_MEMBERS {
        if let Ok(item) = Identifier::new(cm) {
            members.push(object_name(Some(&domain), &item));
        }
    }
    for p in &cfg.dataset_points {
        if let Ok(item) = Identifier::new(p) {
            members.push(object_name(Some(&domain), &item));
        }
    }
    members
}

fn version_item() -> Identifier {
    Identifier::new(names::TASE2_VERSION).unwrap()
}

fn features_item() -> Identifier {
    Identifier::new(names::SUPPORTED_FEATURES).unwrap()
}

/// Printable form of an [`ObjectName`] for logging.
fn name_display(name: &ObjectName) -> String {
    match name {
        ObjectName::VmdSpecific(i) => i.as_str().to_owned(),
        ObjectName::DomainSpecific { domain, item } => {
            format!("{}/{}", domain.as_str(), item.as_str())
        }
        ObjectName::AaSpecific(i) => i.as_str().to_owned(),
        _ => "?".to_owned(),
    }
}
