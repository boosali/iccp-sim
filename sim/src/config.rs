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
    names, object_name, AccessRights, BilateralTable, DataSet, DomainName, Identifier, ObjectName,
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
    /// Features advertised by default. Device Control is deliberately
    /// excluded: no `ControlHandler` is wired into the default serving path,
    /// so advertising it would lie about capability. Enable `device_control`
    /// explicitly in a config once functional device control is in place.
    const DEFAULT: [Feature; 3] = [Feature::DsTransfer, Feature::Cov, Feature::BilateralAccess];

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
    /// Server-mode (called role) association addressing: this server's own
    /// OSI/ACSE identity and its expectation of the calling peer. Only used
    /// when `mode == "server"`; the client's own association lives in
    /// `client.association`.
    pub association: AssocCfg,
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
            supported_features: Feature::DEFAULT.to_vec(),
            association: AssocCfg::default(),
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
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct MutationCfg {
    /// Seconds between steps; 0 (default) disables mutation.
    pub interval_secs: u64,
    pub points: Vec<MutationPointCfg>,
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
    /// Association addressing (AP title / AE qualifier / TSEL / SSEL / PSEL),
    /// split into `local` (this client) and `remote` (the peer it connects
    /// to). Absent (or left empty) keeps the libIEC61850 defaults.
    pub association: AssocCfg,
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
            association: AssocCfg::default(),
            run_for_secs: 0,
        }
    }
}

/// Association addressing, explicit about which side of the link each value
/// belongs to. `local` is this process (the client or server running
/// `iccp-sim`); `remote` is the ICCP peer. Every field is optional; an
/// empty/absent value keeps the corresponding libIEC61850 default from
/// [`mms_proto::assoc::AssocConfig::default`], so an empty block is a no-op.
///
/// The five identifiers, from transport to application layer:
///
/// * **TSEL** (COTP TSAP) — transport-layer service access point
/// * **SSEL** (session selector) — OSI session layer
/// * **PSEL** (presentation selector) — OSI presentation layer
/// * **AE qualifier** — ACSE application-entity qualifier
/// * **AP title** — ACSE application-process title (dotted OID arcs)
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssocCfg {
    /// This process's association identity (what the peer sees as the caller
    /// or the responder, respectively).
    pub local: SideAssocCfg,
    /// The peer's association identity. On the client these are the values
    /// the client sends as the called/calling-side context of the handshake;
    /// on the server they document the expected caller (the stack does not
    /// validate the caller's identity against them).
    pub remote: SideAssocCfg,
}

/// One side (local or remote) of the association identity.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideAssocCfg {
    /// AP title, as dotted OID arcs (e.g. `"1.2.3.4"`).
    pub ap_title: Option<String>,
    /// AE qualifier (signed integer).
    pub ae_qualifier: Option<i64>,
    /// COTP TSAP (TSEL). A dotted-decimal string (`"0.0.0.1"`) or a byte
    /// array (`[0,0,0,1]`).
    #[serde(default, deserialize_with = "de_optional_bytes")]
    pub tsel: Option<Vec<u8>>,
    /// Session selector (SSEL). A dotted-decimal string or a byte array.
    #[serde(default, deserialize_with = "de_optional_bytes")]
    pub ssel: Option<Vec<u8>>,
    /// Presentation selector (PSEL). A dotted-decimal string or a byte array.
    #[serde(default, deserialize_with = "de_optional_bytes")]
    pub psel: Option<Vec<u8>>,
}

/// DS-transfer-set attributes the client writes (`Next_DSTransfer_Set` claim
/// then attribute write) to arm condition monitoring. `status` is forced
/// `true` when arming; the remaining fields control which trigger conditions
/// fire and how.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TransferSetCfg {
    /// Trigger condition names (`interval_timeout`, `integrity_timeout`,
    /// `object_change`, `operator_request`, `external_event`).
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

/// Decode an optional byte selector from either a dotted-decimal string
/// (`"0.0.0.1"`) or a JSON byte array (`[0, 0, 0, 1]`). An empty string decodes
/// to `None` so `{"tsel": ""}` behaves like leaving the field out (use the
/// libIEC61850 default).
fn de_optional_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BytesInput {
        Str(String),
        Array(Vec<u8>),
    }
    match BytesInput::deserialize(deserializer)? {
        BytesInput::Str(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Ok(None);
            }
            s.split('.')
                .map(|part| {
                    part.trim()
                        .parse::<u8>()
                        .map_err(|e| de::Error::custom(format!("bad selector byte {part:?}: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some)
        }
        BytesInput::Array(bytes) => {
            if bytes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(bytes))
            }
        }
    }
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
    } else {
        let r = rest.strip_prefix("state")?;
        rest = r;
        PointKind::State
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

/// Short human description of a raw JSON value for error messages.
fn describe_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => format!("\"{s}\""),
        other => other.to_string(),
    }
}

/// Build a `PointValue` from a JSON scalar, matching `kind`. Quality is
/// default (valid/telemetered), timestamp is "now", COV is 0 — good enough
/// for a simulator; the mutation loop overwrites the value on each step.
///
/// Every configured value is validated strictly: a value that does not fit
/// the point kind is a configuration error, never silently coerced to a
/// default (an invalid discrete value must not become 0, since a bad test
/// config would then look like valid ICCP behavior).
pub fn initial_value(kind: PointKind, raw: &serde_json::Value) -> Result<PointValue, SimError> {
    let q = Quality::default();
    let ts = TimeStamp::from_seconds(now_secs());
    let real = |raw: &serde_json::Value| {
        raw.as_f64()
            .ok_or_else(|| SimError::Config("real point needs a numeric value".into()))
    };
    let discrete = |raw: &serde_json::Value| -> Result<i32, SimError> {
        let v = raw
            .as_i64()
            .or_else(|| raw.as_u64().and_then(|v| i64::try_from(v).ok()));
        match v {
            Some(n) => i32::try_from(n).map_err(|e| {
                SimError::Config(format!("invalid discrete value {n} (out of range): {e}"))
            }),
            None => Err(SimError::Config(format!(
                "invalid discrete value {}",
                describe_value(raw)
            ))),
        }
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
        PointKind::Discrete => PointValue::Discrete(discrete(raw)?),
        PointKind::State => PointValue::State(state(raw)?),

        PointKind::RealQ => PointValue::RealQ {
            value: real(raw)? as f32,
            quality: q,
        },
        PointKind::DiscreteQ => PointValue::DiscreteQ {
            value: discrete(raw)?,
            quality: q,
        },
        PointKind::StateQ => PointValue::StateQ {
            value: state(raw)?,
            quality: q,
        },

        PointKind::RealQTimeTag => PointValue::RealQTimeTag {
            value: real(raw)? as f32,
            quality: q,
            timestamp: ts,
        },
        PointKind::DiscreteQTimeTag => PointValue::DiscreteQTimeTag {
            value: discrete(raw)?,
            quality: q,
            timestamp: ts,
        },
        PointKind::StateQTimeTag => PointValue::StateQTimeTag {
            value: state(raw)?,
            quality: q,
            timestamp: ts,
        },

        PointKind::RealExtended => PointValue::RealExtended {
            value: real(raw)? as f32,
            quality: q,
            timestamp: ts,
            cov: 0,
        },
        PointKind::DiscreteExtended => PointValue::DiscreteExtended {
            value: discrete(raw)?,
            quality: q,
            timestamp: ts,
            cov: 0,
        },
        PointKind::StateExtended => PointValue::StateExtended {
            value: state(raw)?,
            quality: q,
            timestamp: ts,
            cov: 0,
        },

        PointKind::RealQTimeTagExtended => PointValue::RealQTimeTagExtended {
            value: real(raw)? as f32,
            quality: q,
            timestamp: ts,
            cov: 0,
        },
        PointKind::DiscreteQTimeTagExtended => PointValue::DiscreteQTimeTagExtended {
            value: discrete(raw)?,
            quality: q,
            timestamp: ts,
            cov: 0,
        },
        PointKind::StateQTimeTagExtended => PointValue::StateQTimeTagExtended {
            value: state(raw)?,
            quality: q,
            timestamp: ts,
            cov: 0,
        },

        _ => return Err(SimError::Config("unsupported point kind".into())),
    })
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
pub fn build_conditions(
    names: &[String],
) -> Result<tase2_proto::transfer_set::DsConditions, SimError> {
    let mut mask = tase2_proto::transfer_set::DsConditions::empty();
    for n in names {
        let Some(bit) = condition_from_str(n) else {
            return Err(SimError::Config(format!("unknown condition {n:?}")));
        };
        mask.insert(bit);
    }
    Ok(mask)
}

/// Build the MMS [`AssocConfig`] from an [`AssocCfg`].
///
/// Every `None`/empty field keeps the libIEC61850 default from
/// `AssocConfig::default()` (unchanged out-of-the-box behavior). The mapping
/// is side-by-side and the same for client and server roles:
///
/// * `local.*` → `local_*` fields (this process's identity). For the client
///   these are exactly the values transmitted as the calling side of the
///   handshake: TSEL as the CR's src-TSAP, SSEL/PSEL as the CN's calling
///   selector and the CP's calling selector, AP title / AE qualifier as the
///   calling values in the AARQ. For the server they are the selectors used
///   in the CC/AC/AARE replies and echoed back to the caller.
/// * `remote.*` → `remote_*` fields (the peer). For the client these name
///   the called side of the handshake (CR dst-TSAP, called AP title/AE
///   qualifier, called session/presentation selectors); for the server they
///   document the expected caller. The stack does not validate the peer's
///   identity against these values.
pub fn build_assoc_config(assoc: &AssocCfg) -> Result<mms_proto::assoc::AssocConfig, SimError> {
    let mut cfg = mms_proto::assoc::AssocConfig::default();
    // Local side: this process's identity. An empty AP title keeps the
    // libIEC61850 default (no AP title), matching the selector fields.
    if let Some(ap) = &assoc.local.ap_title {
        if !ap.trim().is_empty() {
            cfg.local_ap_title = Some(parse_ap_title("local", ap)?);
        }
    }
    cfg.local_ae_qualifier = assoc.local.ae_qualifier;
    if let Some(t) = &assoc.local.tsel {
        cfg.local_tsap = t.clone();
    }
    cfg.local_ssel = assoc.local.ssel.clone();
    cfg.local_psel = assoc.local.psel.clone();
    // Remote side: the peer.
    if let Some(ap) = &assoc.remote.ap_title {
        if !ap.trim().is_empty() {
            cfg.remote_ap_title = Some(parse_ap_title("remote", ap)?);
        }
    }
    cfg.remote_ae_qualifier = assoc.remote.ae_qualifier;
    if let Some(t) = &assoc.remote.tsel {
        cfg.remote_tsap = t.clone();
    }
    cfg.remote_ssel = assoc.remote.ssel.clone();
    cfg.remote_psel = assoc.remote.psel.clone();
    Ok(cfg)
}

/// Parse a dotted-decimal AP title (OID arcs, e.g. `"1.2.3.4"`) into an
/// [`ObjectIdentifier`], failing with a clear error that names the side
/// (local/remote) and the offending arc.
fn parse_ap_title(side: &str, ap: &str) -> Result<mms_proto::ber::ObjectIdentifier, SimError> {
    let ap = ap.trim();
    if ap.is_empty() {
        return Err(SimError::Config(format!(
            "association {side}: empty AP title"
        )));
    }
    let arcs: Vec<u32> = ap
        .split('.')
        .map(|part| {
            part.trim().parse().map_err(|e| {
                SimError::Config(format!(
                    "association {side}: bad AP title arc {part:?}: {e}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if arcs.is_empty() {
        return Err(SimError::Config(format!(
            "association {side}: empty AP title"
        )));
    }
    Ok(mms_proto::ber::ObjectIdentifier::from_arcs(&arcs))
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
    // Reject mutation values that do not fit the point's kind at startup;
    // the mutation loop would otherwise skip them silently at runtime.
    validate_mutation_values(cfg)?;

    let domain = DomainName::from(
        Identifier::new(&cfg.domain).map_err(|e| SimError::Config(e.to_string()))?,
    );

    // ---- points -----------------------------------------------------------
    // Points are keyed by their full [`ObjectName`] key (as the provider's
    // read/write lookups require); `point_items` keeps the config-level item
    // name (e.g. "P1") → ObjectName for dataset members and access overrides.
    let mut points: HashMap<String, (ObjectName, PointKind, PointValue)> = HashMap::new();
    let mut point_items: HashMap<String, ObjectName> = HashMap::new();
    let mut point_kinds: HashMap<String, PointKind> = HashMap::new();
    for p in &cfg.points {
        if point_items.contains_key(&p.name) {
            return Err(SimError::Config(format!(
                "duplicate point name {:?}",
                p.name
            )));
        }
        let name = object_name(
            Some(&domain),
            &Identifier::new(&p.name).map_err(|e| SimError::Config(e.to_string()))?,
        );
        let value = initial_value(p.kind, &p.initial)?;
        point_items.insert(p.name.clone(), name.clone());
        points.insert(
            crate::provider::object_key(&name),
            (name.clone(), p.kind, value),
        );
        point_kinds.insert(p.name.clone(), p.kind);
    }

    // ---- datasets ---------------------------------------------------------
    let mut data_sets: HashMap<String, DataSet> = HashMap::new();
    for d in &cfg.datasets {
        if data_sets.contains_key(&d.name) {
            return Err(SimError::Config(format!(
                "duplicate dataset name {:?}",
                d.name
            )));
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
        data_sets.insert(
            crate::provider::object_key(&ds_name),
            DataSet::with_object_name(ds_name, members),
        );
    }

    // ---- version + features ------------------------------------------------
    let version = (
        cfg.tase2_version.major as u64,
        cfg.tase2_version.minor as u64,
    );
    let features =
        mms_proto::ber::BitString::from_bits(&Feature::bit_vector(&cfg.supported_features));

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
            return Err(SimError::Config(format!(
                "access override references unknown point {point:?}"
            )));
        }
    }

    // ---- provider ----------------------------------------------------------
    let provider: std::sync::Arc<crate::provider::SimProvider> = std::sync::Arc::new(
        crate::provider::SimProvider::new(points, data_sets, version, features),
    );

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

/// Build a mutation step value for `point` from a JSON value. Uses the
/// immutable startup-side map rather than the provider's async lock (which
/// would panic when called from a tokio worker thread). Returns `None` only
/// when the point name is unknown; a value that does not fit the point kind
/// is a configuration error (mutation values are validated at startup, so
/// this is normally unreachable).
pub fn mutation_value(
    model: &SimModel,
    point_name: &str,
    raw: &serde_json::Value,
) -> Result<Option<PointValue>, SimError> {
    let Some(kind) = model.point_kinds.get(point_name) else {
        return Ok(None);
    };
    Ok(Some(initial_value(*kind, raw)?))
}

/// Validate every mutation value against its point's kind at startup so a bad
/// test configuration fails immediately instead of being skipped at runtime.
pub fn validate_mutation_values(cfg: &SimConfig) -> Result<(), SimError> {
    // Point name → kind, from the config itself (no provider needed).
    let kinds: HashMap<&str, PointKind> = cfg
        .points
        .iter()
        .map(|p| (p.name.as_str(), p.kind))
        .collect();
    for mp in &cfg.mutation.points {
        let Some(kind) = kinds.get(mp.name.as_str()) else {
            return Err(SimError::Config(format!(
                "mutation point {:?} is not a configured point",
                mp.name
            )));
        };
        for (i, v) in mp.values.iter().enumerate() {
            initial_value(*kind, v).map_err(|e| {
                SimError::Config(format!(
                    "mutation point {:?} value[{}] {}: {e}",
                    mp.name,
                    i,
                    describe_value(v)
                ))
            })?;
        }
    }
    Ok(())
}
