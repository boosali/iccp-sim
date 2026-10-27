//! Configuration for the [`MmsConnection`](super::state::MmsConnection)
//! association state machine.

use std::time::Duration;

use crate::ber::ObjectIdentifier;
use crate::cotp::params::TpduSize;
use crate::cotp::reassembly::CotpReassembler;
use crate::mms::initiate::InitiateRequest;

/// Connection configuration for an MMS association.
///
/// All address fields (TSAP/SSEL/PSEL selectors and the ACSE AP-title /
/// AE-qualifier) default to the libIEC61850 client values so that a default
/// `AssocConfig` interoperates out of the box.
#[derive(Debug, Clone)]
pub struct AssocConfig {
    /// Local (calling) transport selector — COTP source TSAP.
    pub local_tsap: Vec<u8>,
    /// Remote (called) transport selector — COTP destination TSAP.
    pub remote_tsap: Vec<u8>,
    /// Local presentation selector (calling-presentation-selector).
    pub local_psel: Option<Vec<u8>>,
    /// Remote presentation selector (called-presentation-selector).
    pub remote_psel: Option<Vec<u8>>,
    /// Local session selector (calling-session-selector).
    pub local_ssel: Option<Vec<u8>>,
    /// Remote session selector (called-session-selector).
    pub remote_ssel: Option<Vec<u8>>,
    /// Local ACSE AP-title (calling for a client, responding for a server).
    pub local_ap_title: Option<ObjectIdentifier>,
    /// Local ACSE AE-qualifier.
    pub local_ae_qualifier: Option<i64>,
    /// Remote ACSE AP-title (called).
    pub remote_ap_title: Option<ObjectIdentifier>,
    /// Remote ACSE AE-qualifier.
    pub remote_ae_qualifier: Option<i64>,
    /// Maximum COTP TPDU size we propose.
    pub tpdu_size: TpduSize,
    /// Deadline for the full Associate → Associated handshake.
    pub setup_timeout: Duration,
    /// Deadline for the graceful Release → Closed exchange.
    pub release_timeout: Duration,
    /// Maximum reassembled TSDU size (the COTP DT reassembly cap).
    pub max_reassembly: usize,
    /// The MMS `Initiate-RequestPDU` the client sends (and the parameters a
    /// server negotiates against).
    pub initiate: InitiateRequest,
}

impl Default for AssocConfig {
    fn default() -> Self {
        AssocConfig {
            local_tsap: vec![0x00, 0x01],
            remote_tsap: vec![0x00, 0x01],
            local_psel: Some(vec![0, 0, 0, 1]),
            remote_psel: Some(vec![0, 0, 0, 1]),
            local_ssel: Some(vec![0, 1]),
            remote_ssel: Some(vec![0, 1]),
            local_ap_title: None,
            local_ae_qualifier: None,
            remote_ap_title: None,
            remote_ae_qualifier: None,
            tpdu_size: TpduSize::SIZE_1024,
            setup_timeout: Duration::from_secs(10),
            release_timeout: Duration::from_secs(10),
            max_reassembly: CotpReassembler::DEFAULT_MAX,
            initiate: InitiateRequest::default(),
        }
    }
}
