//! JSON configuration for the ICCP/TASE.2 simulator.
//!
//! See `config.example.json` for a complete annotated example.
//! Everything a real OpenICCP client cares about on association — the
//! domain, the Bilateral Table ID, `TASE2_Version`, `Supported_Features`,
//! access rights, points, and datasets — is configurable here without a
//! recompile.

use std::collections::HashMap;
use std::path::Path;

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use tase2::{
    object_name, names, AccessRights, BilateralTable, DataSet, DomainName, Identifier, ObjectName,
    PointKind, PointValue, Quality, StateValue, TimeStamp,
};

/// The four feature bits the simulator can advertise (ICCP/IEC 61968-18-2
/// feature naming, mapped onto the TASE.2 feature-bit order used by libtase2
/// clients).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    /// Data Set Transfer (ICCP data-set transfer set).
    DsTransfer,
    /// Condition Monitoring (reports / COV).
    Cov,
    /// Device Control (command points).
    DeviceControl,
    /// Bilateral Access (Bilateral Table).
    BilateralAccess,
}

impl Feature {
    const ALL: [Feature; 4] = [
        Feature::DsTransfer,
        Feature::Cov,
        Feature::DeviceControl,
        Feature::BilateralAccess,
    ];

    /// The MSB-first bit position used when building the `Supported_Features`
    /// bit string. libtase2 client code tests these as:
    /// DS transfer = bit 0, COV = bit 1, device control = bit 2,
    /// bilateral access = bit 3 (all read from the low end of the bit string).
    fn bit_index(self) -> usize {
        match self {
            Feature::DsTransfer => 0,
            Feature::Cov => 1,
            Feature::DeviceControl => 2,
            Feature::BilateralAccess => 3,
        }
    }

    /// MSB-first bit vector for the enabled features (4-bit string).
    pub fn bit_vector(enabled: &[Feature]) -> Vec<bool> {
        let mut bits = vec![false; 4];
        for f in enabled {
            bits[f.bit_index()] = true;
        }
        bits
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SimConfig {
    /// Which role to run: `server` (default, the simulator) or `client`
    /// (a TASE.2 caller).
    pub mode: Mode,
    /// Client-mode settings; ignored when `mode == "server"`.
    pub client: ClientCfg,
    /// MMS domain the client associates to (OpenICCP domain name).
    pub domain: String,
    /// IPv4 address to bind (default "0.0.0.0" = all interfaces).
    pub ip: String,
    /// TCP port to listen on (default 102).
    pub port: u16,
    /// Identifier advertised as `Bilateral_Table_ID` (typically BLT1).
    pub bilateral_table_id: String,
    /// `TASE2_Version` served to the client.
    pub tase2_version: Tase2VersionCfg,
    /// Which `Supported_Features` bits are set.
    pub supported_features: Vec<Feature>,
    /// Access grants, applied to the Bilateral Table.
    pub access: AccessCfg,
    /// Indication points to serve.
    pub points: Vec<PointCfg>,
    /// Datasets (transfer-set members). The four ICCP control members
    /// (`Transfer_Set_Name`, `Transfer_Set_Time_Stamp`, `DSConditions_Detected`,
    /// `Event_Code_Detected`) are prepended automatically and must not be
    /// listed.
    pub datasets: Vec<DsCfg>,
    /// Optional self-mutation loop that drives OBJECT_CHANGE reports.
    pub mutation: MutationCfg,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Server,
            client: ClientCfg::default(),
            domain: "ICC1".into(),
            ip: "0.0.0.0".into(),
            port: 102,
            bilateral_table_id: "BLT1".into(),
            tase2_version: Tase2VersionCfg::default(),
            supported_features: Feature::ALL.to_vec(),
            access: AccessCfg::default(),
            points: vec![],
            datasets: vec![],
            mutation: MutationCfg::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tase2VersionCfg {
    pub major: u32,
    pub minor: u32,
}

impl Default for Tase2VersionCfg {
    fn default() -> Self {
        Self { major: 1, minor: 0 }
    }
}

/// Domain-level access grants with per-point overrides.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AccessCfg {
    /// Points of `domain` get this access (default: read-only).
    pub domain_read: bool,
    pub domain_read_write: bool,
    /// Allow CREATE/DELETE data-set operations on `domain`.
    pub dataset_ops: bool,
    /// Per-point overrides, e.g. `{"P1": "read_write"}`.
    pub points: HashMap<String, AccessLevel>,
}

impl Default for AccessCfg {
    fn default() -> Self {
        Self {
            domain_read: true,
            domain_read_write: false,
            dataset_ops: true,
            points: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    None,
    ReadOnly,
    ReadWrite,
}

impl From<AccessLevel> for AccessRights {
    fn from(level: AccessLevel) -> Self {
        match level {
            AccessLevel::None => AccessRights::NONE,
            AccessLevel::ReadOnly => AccessRights::READ_ONLY,
            AccessLevel::ReadWrite => AccessRights::READ_WRITE,
        }
    }
}

/// A point. `kind` is any TASE.2 point kind (e.g. `discrete`,
/// `discrete_q_time_tag`, `real`, `state_q_time_tag_extended` …).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointCfg {
    pub name: String,
    #[serde(deserialize_with = "kind_from_str")]
    pub kind: PointKind,
    /// Initial value, interpreted according to `kind`:
    /// `discrete`/`*_q*` → integer 0/1; `real*` → number; `state*` →
    /// `"between" | "closed" | "tripped" | "invalid"` or a number 0..=3.
    pub initial: serde_json::Value,
}

/// A dataset. Members are point names in `domain`; the four ICCP control
/// members are prepended automatically.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DsCfg {
    pub name: String,
    pub members: Vec<String>,
}

/// Self-mutation loop: every `interval_secs`, each listed point advances to
/// its next `values` entry (wrapping). Drives OBJECT_CHANGE reports so a
/// client's transfer set produces traffic without any external input.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MutationCfg {
    /// Seconds between steps; 0 (default) disables mutation.
    pub interval_secs: u64,
    pub points: Vec<MutationPointCfg>,
}

impl Default for MutationCfg {
    fn default() -> Self {
        Self { interval_secs: 0, points: vec![] }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationPointCfg {
    pub name: String,
    pub values: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Client (calling role) configuration
// ---------------------------------------------------------------------------

/// Which role `iccp-sim` runs as. The `server` role is the simulator (it
/// listens and is associated to); the `client` role is a TASE.2 caller (it
/// connects out, enumerates, and receives reports) — handy for exercising a
/// real (or second) ICCP peer and for round-trip interop tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// The "called" role: bind a port and serve associations.
    #[default]
    Server,
    /// The "calling" role: connect to a peer and act as a TASE.2 client.
    Client,
}

/// Client-mode configuration. Only used when `mode == "client"`; the
/// server-only fields above (`points`, `datasets`, `access`, `mutation`,
/// `bilateral_table_id`, …) are ignored in this mode.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ClientCfg {
    /// Peer (server) host to connect to (default `127.0.0.1`).
    pub peer_ip: String,
    /// Peer (server) port (default 102).
    pub port: u16,
    /// Domain to enumerate and read from the peer (default `ICC1`).
    pub domain: String,
    /// Data set name in the peer's domain to arm a DS-transfer-set against
    /// (condition-monitoring / COV reports).
    pub dataset: String,
    /// The point members of that data set, in order (e.g. `["P1", "P2"]`).
    /// The client uses these to decode incoming COV reports (a report carries
    /// one value per member, so the member list must be known up front — the
    /// 4 ICCP control members are prepended automatically).
    pub dataset_points: Vec<String>,
    /// The DS-transfer-set attributes the client writes to arm reporting.
    pub transfer_set: TransferSetCfg,
    /// Seconds the client stays associated before concluding (0 = run
    /// indefinitely until the peer drops the association).
    pub run_for_secs: u64,
}

impl Default for ClientCfg {
    fn default() -> Self {
        Self {
            peer_ip: "127.0.0.1".into(),
            port: 102,
            domain: "ICC1".into(),
            dataset: String::new(),
            dataset_points: Vec::new(),
            transfer_set: TransferSetCfg::default(),
            run_for_secs: 0,
        }
    }
}

/// DS-transfer-set attributes the client writes (`Next_DSTransfer_Set` claim
/// + attribute write) to arm condition monitoring. `status` is forced `true`
/// when arming; the remaining fields control which trigger conditions fire and
/// how.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TransferSetCfg {
    /// Trigger condition names: `interval_timeout`, `integrity_timeout`,
    /// `object_change`, `operator_request`, `external_event`.
    pub conditions: Vec<String>,
    /// `Interval` in seconds (drives `interval_timeout`).
    pub interval: i32,
    /// `IntegrityCheck` in seconds (drives `integrity_timeout`).
    pub integrity_check: i32,
    /// `BufferTime` in seconds (object-change coalescing window).
    pub buffer_time: i32,
    /// `EventCodeRequested` (i16).
    pub event_code: i16,
    /// `RBE` — report by exception (only changed objects).
    pub rbe: bool,
}

impl Default for TransferSetCfg {
    fn default() -> Self {
        Self {
            conditions: vec!["object_change".to_owned()],
            interval: 0,
            integrity_check: 0,
            buffer_time: 0,
            event_code: 0,
            rbe: true,
        }
    }
}

// ---------------------------------------------------------------------------
// serde helpers
// ---------------------------------------------------------------------------

fn kind_from_str<'de, D>(deserializer: D) -> Result<PointKind, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_point_kind(&s).ok_or_else(|| de::Error::custom(format!("unknown point kind {s:?}")))
}

/// Parse a TASE.2 point kind name: `"{family}[_{suffixes…}]"` where family is
/// `real|discrete|state` and suffixes are `q`, `q_time_tag`, `q_time_tag_extended`,
/// `extended` (in that order).
pub fn parse_point_kind(s: &str) -> Option<PointKind> {
    let mut rest = s;
    let base = if let Some(r) = rest.strip_prefix("real") {
        rest = r;
        PointKind::Real
    } else if let Some(r) = rest.strip_prefix("discrete") {
        rest = r;
        PointKind::Discrete
    } else if let Some(r) = rest.strip_prefix("state") {
        rest = r;
        PointKind::State
    } else {
        return None;
    };
    Some(match rest {
        "" => base,
        "_q" => next_in_family(base, 1),
        "_q_time_tag" => next_in_family(base, 2),
        "_extended" => next_in_family(base, 3),
        "_q_time_tag_extended" => next_in_family(base, 4),
        _ => return None,
    })
}

/// `PointKind` has no conversion methods; derive the sibling variants of a
/// plain-family kind explicitly.
fn next_in_family(kind: PointKind, tier: u8) -> PointKind {
    // Explicit table: (family_base_variant) -> [plain, q, q_time_tag, extended, q_time_tag_extended]
    match kind {
        PointKind::Real => match tier {
            0 => PointKind::Real,
            1 => PointKind::RealQ,
            2 => PointKind::RealQTimeTag,
            3 => PointKind::RealExtended,
            _ => PointKind::RealQTimeTagExtended,
        },
        PointKind::Discrete => match tier {
            0 => PointKind::Discrete,
            1 => PointKind::DiscreteQ,
            2 => PointKind::DiscreteQTimeTag,
            3 => PointKind::DiscreteExtended,
            _ => PointKind::DiscreteQTimeTagExtended,
        },
        PointKind::State => match tier {
            0 => PointKind::State,
            1 => PointKind::StateQ,
            2 => PointKind::StateQTimeTag,
            3 => PointKind::StateExtended,
            _ => PointKind::StateQTimeTagExtended,
        },
        _ => kind,
    }
}

/// Build a `PointValue` from a JSON scalar, matching `kind`. Quality is
/// default (valid/telemetered), timestamp is "now", COV is 0 — good enough
/// for a simulator; the mutation loop overwrites the value on each step.
pub fn initial_value(kind: PointKind, raw: &serde_json::Value) -> Result<PointValue, SimError> {
    let q = Quality::default();
    let ts = TimeStamp::from_seconds(now_secs());
    let real = |raw: &serde_json::Value| {
        raw.as_f64()
            .ok_or_else(|| SimError::Config("real point needs a numeric value".into()))
    };
    let discrete = |raw: &serde_json::Value| -> i32 {
        raw.as_i64()
            .or_else(|| raw.as_u64().map(|v| v as i64))
            .and_then(|v| i32::try_from(v).ok())
            .unwrap_or(0)
    };
    let state = |raw: &serde_json::Value| -> Result<StateValue, SimError> {
        if let Some(s) = raw.as_str() {
            Ok(match s.to_ascii_lowercase().as_str() {
                "between" | "0" => StateValue::Between,
                "closed" | "on" | "1" => StateValue::Closed,
                "tripped" | "open" | "2" => StateValue::TrippedOpen,
                "invalid" | "3" => StateValue::Invalid,
                other => return Err(SimError::Config(format!("bad state value {other:?}"))),
            })
        } else {
            let n = raw
                .as_u64()
                .ok_or_else(|| SimError::Config("state point needs 0..=3 or a name".into()))?;
            StateValue::from_code(n as u8).map_err(|e| SimError::Config(e.to_string()))
        }
    };

    Ok(match kind {
        PointKind::Real => PointValue::Real(real(raw)? as f32),
        PointKind::Discrete => PointValue::Discrete(discrete(raw)),
        PointKind::State => PointValue::State(state(raw)?),

        PointKind::RealQ => PointValue::RealQ { value: real(raw)? as f32, quality: q },
        PointKind::DiscreteQ => PointValue::DiscreteQ { value: discrete(raw), quality: q },
        PointKind::StateQ => PointValue::StateQ { value: state(raw)?, quality: q },

        PointKind::RealQTimeTag => PointValue::RealQTimeTag { value: real(raw)? as f32, quality: q, timestamp: ts },
        PointKind::DiscreteQTimeTag => PointValue::DiscreteQTimeTag { value: discrete(raw), quality: q, timestamp: ts },
        PointKind::StateQTimeTag => PointValue::StateQTimeTag { value: state(raw)?, quality: q, timestamp: ts },

        PointKind::RealExtended => PointValue::RealExtended { value: real(raw)? as f32, quality: q, timestamp: ts, cov: 0 },
        PointKind::DiscreteExtended => PointValue::DiscreteExtended { value: discrete(raw), quality: q, timestamp: ts, cov: 0 },
        PointKind::StateExtended => PointValue::StateExtended { value: state(raw)?, quality: q, timestamp: ts, cov: 0 },

        PointKind::RealQTimeTagExtended => PointValue::RealQTimeTagExtended { value: real(raw)? as f32, quality: q, timestamp: ts, cov: 0 },
        PointKind::DiscreteQTimeTagExtended => PointValue::DiscreteQTimeTagExtended { value: discrete(raw), quality: q, timestamp: ts, cov: 0 },
        PointKind::StateQTimeTagExtended => PointValue::StateQTimeTagExtended { value: state(raw)?, quality: q, timestamp: ts, cov: 0 },

        _ => return Err(SimError::Config("unsupported point kind".into())),
    })
}

fn value_for_kind(kind: PointKind, raw: &serde_json::Value) -> Option<PointValue> {
    initial_value(kind, raw).ok()
}

/// Translate a config condition name to its [`DsConditions`] bit, or `None`
/// for an unrecognized name.
fn condition_from_str(s: &str) -> Option<tase2_proto::transfer_set::DsConditions> {
    use tase2_proto::transfer_set::DsConditions as C;
    Some(match s {
        "interval_timeout" => C::INTERVAL_TIMEOUT,
        "integrity_timeout" => C::INTEGRITY_TIMEOUT,
        "object_change" => C::OBJECT_CHANGE,
        "operator_request" => C::OPERATOR_REQUEST,
        "external_event" => C::EXTERNAL_EVENT,
        _ => return None,
    })
}

/// Build the requested [`DsConditions`] mask from a list of condition names.
pub fn build_conditions(names: &[String]) -> Result<tase2_proto::transfer_set::DsConditions, SimError> {
    let mut mask = tase2_proto::transfer_set::DsConditions::empty();
    for n in names {
        let Some(bit) = condition_from_str(n) else {
            return Err(SimError::Config(format!("unknown condition {n:?}")));
        };
        mask.insert(bit);
    }
    Ok(mask)
}

/// Seconds since the Unix epoch (for default timestamps).
fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SimError {
    #[error("config: {0}")]
    Config(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// Config loading and model construction
// ---------------------------------------------------------------------------

pub struct SimModel {
    /// The config-driven provider (shared with the serve loop and mutation task).
    pub provider: std::sync::Arc<crate::provider::SimProvider>,
    /// Config item name (e.g. "P1") → [`PointKind`]; immutable after startup,
    /// so the mutation loop can resolve kinds without taking the provider's
    /// async lock (`point_kind_of` blocks, which panics on a tokio worker).
    pub point_kinds: HashMap<String, PointKind>,
    pub bilateral: std::sync::Arc<BilateralTable>,
    /// Parsed bind address (validated in `build_model`).
    pub bind_ip: std::net::Ipv4Addr,
    pub port: u16,
    pub mutation: MutationCfg,
    pub domain: String,
}

pub fn load_config_file(path: &Path) -> Result<SimConfig, SimError> {
    let raw = std::fs::read_to_string(path)?;
    let cfg: SimConfig = serde_json::from_str(&raw)?;
    Ok(cfg)
}

/// The four ICCP control member names, in wire order.
const CONTROL_MEMBERS: [&str; 4] = [
    names::TRANSFER_SET_NAME,
    names::TRANSFER_SET_TIME_STAMP,
    names::DSCONDITIONS_DETECTED,
    names::EVENT_CODE_DETECTED,
];

pub fn build_model(cfg: &SimConfig) -> Result<SimModel, SimError> {
    let bind_ip: std::net::Ipv4Addr = cfg
        .ip
        .parse()
        .map_err(|e| SimError::Config(format!("bad bind ip {:?}: {e}", cfg.ip)))?;

    // Fail fast if the mutation loop would never have a value to write:
    // `idx % 0` would panic (integer division by zero) at runtime.
    for mp in &cfg.mutation.points {
        if mp.values.is_empty() {
            return Err(SimError::Config(format!(
                "mutation point {:?} has an empty values list",
                mp.name
            )));
        }
    }

    let domain = DomainName::from(Identifier::new(&cfg.domain).map_err(|e| SimError::Config(e.to_string()))?);

    // ---- points -----------------------------------------------------------
    // Points are keyed by their full [`ObjectName`] key (as the provider's
    // read/write lookups require); `point_items` keeps the config-level item
    // name (e.g. "P1") → ObjectName for dataset members and access overrides.
    let mut points: HashMap<String, (ObjectName, PointKind, PointValue)> = HashMap::new();
    let mut point_items: HashMap<String, ObjectName> = HashMap::new();
    let mut point_kinds: HashMap<String, PointKind> = HashMap::new();
    for p in &cfg.points {
        if point_items.contains_key(&p.name) {
            return Err(SimError::Config(format!("duplicate point name {:?}", p.name)));
        }
        let name = object_name(Some(&domain), &Identifier::new(&p.name).map_err(|e| SimError::Config(e.to_string()))?);
        let value = initial_value(p.kind, &p.initial)?;
        point_items.insert(p.name.clone(), name.clone());
        points.insert(crate::provider::object_key(&name), (name.clone(), p.kind, value));
        point_kinds.insert(p.name.clone(), p.kind);
    }

    // ---- datasets ---------------------------------------------------------
    let mut data_sets: HashMap<String, DataSet> = HashMap::new();
    for d in &cfg.datasets {
        if data_sets.contains_key(&d.name) {
            return Err(SimError::Config(format!("duplicate dataset name {:?}", d.name)));
        }
        for m in &d.members {
            if !point_items.contains_key(m) {
                return Err(SimError::Config(format!(
                    "dataset {:?} references unknown point {:?}",
                    d.name, m
                )));
            }
        }
        let mut members: Vec<ObjectName> = Vec::with_capacity(4 + d.members.len());
        for cm in CONTROL_MEMBERS {
            members.push(object_name(
                Some(&domain),
                &Identifier::new(cm).map_err(|e| SimError::Config(e.to_string()))?,
            ));
        }
        for m in &d.members {
            members.push(point_items[m].clone());
        }
        let ds_name = object_name(
            Some(&domain),
            &Identifier::new(&d.name).map_err(|e| SimError::Config(e.to_string()))?,
        );
        data_sets.insert(crate::provider::object_key(&ds_name), DataSet::with_object_name(ds_name, members));
    }

    // ---- version + features ------------------------------------------------
    let version = (cfg.tase2_version.major as u64, cfg.tase2_version.minor as u64);
    let features = mms_proto::ber::BitString::from_bits(&Feature::bit_vector(&cfg.supported_features));

    // ---- bilateral table ----------------------------------------------------
    let bilat = BilateralTable::new(&cfg.bilateral_table_id);
    let base = if cfg.access.domain_read_write {
        AccessRights::READ_WRITE
    } else if cfg.access.domain_read {
        AccessRights::READ_ONLY
    } else {
        AccessRights::NONE
    };
    let mut bilat = if base != AccessRights::NONE {
        bilat.allow_domain_points(&domain, base)
    } else {
        bilat
    };
    if cfg.access.dataset_ops {
        bilat = bilat.allow_dataset_ops(&domain);
    }
    for (point, level) in &cfg.access.points {
        if let Some(name) = point_items.get(point) {
            bilat = bilat.allow_point(name, (*level).into());
        } else {
            return Err(SimError::Config(format!("access override references unknown point {point:?}")));
        }
    }

    // ---- provider ----------------------------------------------------------
    let provider: std::sync::Arc<crate::provider::SimProvider> =
        std::sync::Arc::new(crate::provider::SimProvider::new(points, data_sets, version, features));

    Ok(SimModel {
        provider,
        point_kinds,
        bilateral: std::sync::Arc::new(bilat),
        bind_ip,
        port: cfg.port,
        mutation: cfg.mutation.clone(),
        domain: cfg.domain.clone(),
    })
}

/// Build a mutation step value for `point` (must exist) from a JSON value.
/// Uses the immutable startup-side map rather than the provider's async lock
/// (which would panic when called from a tokio worker thread).
pub fn mutation_value(model: &SimModel, point_name: &str, raw: &serde_json::Value) -> Option<PointValue> {
    let kind = *model.point_kinds.get(point_name)?;
    value_for_kind(kind, raw)
}
