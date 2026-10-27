//! ISO 8327-1 Session layer (binary TLV, *not* BER).
//!
//! # SPDU framing
//!
//! Every SPDU starts with an SI (SPDU Identifier) octet and an LI (Length
//! Indicator). The LI gives the number of parameter octets that follow. Within
//! those parameters sit PGI (Parameter Group Identifier) and PI (Parameter
//! Identifier) units, each `code(1) len(1) value(len)`; a PGI may nest PIs.
//!
//! ## Length encoding (LI and PI/PGI lengths)
//!
//! Per ISO 8327-1 a length of `0..=254` is a single octet. A length of
//! `255..=65535` is encoded as `0xFF` followed by a big-endian `u16`. The MMS
//! profile's handshake SPDUs are normally short, but the CONNECT/ACCEPT
//! session-user-data carries the entire presentation CP/CPA, which can exceed
//! 254 bytes — so this module emits and accepts the extended form for the SPDU
//! LI and for the `0xC1` user-data length.
//!
//! Note: libIEC61850's `iso_session.c` uses only single-octet lengths and
//! therefore cannot represent a handshake whose parameters exceed 255 octets.
//! We are a strict superset on encode (we only use the long form when forced)
//! and tolerant on decode (we accept both forms).
//!
//! # Tolerant decode
//!
//! [`Session::decode`] walks the real parameter structure, picks out the
//! session selectors and the user data, and skips every other PGI/PI. It never
//! compares the incoming bytes against the template [`Session::encode`] emits.

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// SPDU identifiers (SI) and parameter codes (const tables)
// ---------------------------------------------------------------------------

/// GIVE-TOKENS SPDU identifier (also the DATA-TRANSFER SI; disambiguated by
/// position within the two-SPDU data prefix).
const SI_GIVE_TOKENS: u8 = 1;
/// FINISH SPDU.
const SI_FINISH: u8 = 9;
/// DISCONNECT SPDU.
const SI_DISCONNECT: u8 = 10;
/// REFUSE SPDU.
const SI_REFUSE: u8 = 12;
/// CONNECT SPDU.
const SI_CONNECT: u8 = 13;
/// ACCEPT SPDU.
const SI_ACCEPT: u8 = 14;
/// ABORT SPDU.
const SI_ABORT: u8 = 25;

/// Connect/Accept Item PGI.
const PGI_CONNECT_ACCEPT: u8 = 5;
/// Protocol Options PI (inside the Connect/Accept Item).
const PI_PROTOCOL_OPTIONS: u8 = 19;
/// Session User Requirements PI.
const PI_SESSION_REQUIREMENT: u8 = 20;
/// Version Number PI (inside the Connect/Accept Item).
const PI_VERSION_NUMBER: u8 = 22;
/// Calling Session Selector PI.
const PI_CALLING_SELECTOR: u8 = 51;
/// Called Session Selector PI.
const PI_CALLED_SELECTOR: u8 = 52;
/// Session User Data PGI.
const PGI_USER_DATA: u8 = 0xC1;

/// The two-SPDU data prefix: GIVE-TOKENS (SI=1, LI=0) + DATA-TRANSFER
/// (SI=1, LI=0). User data follows.
const DATA_PREFIX: [u8; 4] = [0x01, 0x00, 0x01, 0x00];

/// Maximum session-selector length (octets) accepted on decode, per ISO 8327.
const MAX_SELECTOR_LEN: usize = 16;

/// Duplex functional unit — the only session requirement the MMS profile uses.
const SESSION_REQUIREMENT_DUPLEX: u16 = 0x0002;

/// Protocol Options value emitted in the Connect/Accept Item (no options).
const PROTOCOL_OPTIONS_NONE: u8 = 0x00;

/// Version Number value emitted in the Connect/Accept Item (version 2).
const VERSION_NUMBER_2: u8 = 0x02;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A decoded (or to-be-encoded) Session SPDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionPdu {
    /// CONNECT (CN) SPDU.
    Connect(SessionConnect),
    /// ACCEPT (AC) SPDU.
    Accept(SessionConnect),
    /// REFUSE (RF) SPDU.
    Refuse {
        /// Reason code, if a Reason Code PI was present.
        reason: Option<u8>,
    },
    /// FINISH (FN) SPDU; may carry user data.
    Finish {
        /// Session user data (presentation bytes), empty if absent.
        user_data: Vec<u8>,
    },
    /// DISCONNECT (DN) SPDU; may carry user data.
    Disconnect {
        /// Session user data, empty if absent.
        user_data: Vec<u8>,
    },
    /// ABORT (AB) SPDU; may carry user data.
    Abort {
        /// Session user data, empty if absent.
        user_data: Vec<u8>,
    },
    /// DATA-TRANSFER (the GIVE-TOKENS + DATA-TRANSFER pair) carrying the
    /// presentation-layer payload.
    Data(Vec<u8>),
}

/// Parameters carried by a CONNECT or ACCEPT SPDU that the MMS profile cares
/// about.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionConnect {
    /// Calling Session Selector (PI 51), if present.
    pub calling_selector: Option<Vec<u8>>,
    /// Called Session Selector (PI 52), if present.
    pub called_selector: Option<Vec<u8>>,
    /// Session user data (PGI 0xC1) — the presentation CP/CPA bytes.
    pub user_data: Vec<u8>,
}

/// ISO 8327-1 Session codec (stateless).
#[derive(Debug)]
pub struct Session;

impl Session {
    /// Encode `pdu` and append the SPDU octets to `out`.
    ///
    /// CONNECT/ACCEPT emit the fixed MMS-profile parameter set (Connect/Accept
    /// Item, duplex Session Requirement, selectors when `Some`, and the `0xC1`
    /// session-user-data PGI). DATA emits the `01 00 01 00` prefix followed by
    /// the payload.
    pub fn encode(pdu: &SessionPdu, out: &mut Vec<u8>) -> Result<()> {
        match pdu {
            SessionPdu::Connect(c) => encode_connect_accept(SI_CONNECT, c, out),
            SessionPdu::Accept(c) => encode_connect_accept(SI_ACCEPT, c, out),
            SessionPdu::Refuse { reason } => {
                // REFUSE with an optional Reason Code PI (code 50).
                let mut params = Vec::new();
                if let Some(r) = reason {
                    params.push(50);
                    params.push(1);
                    params.push(*r);
                }
                encode_simple_spdu(SI_REFUSE, &params, out)
            }
            SessionPdu::Finish { user_data } => encode_user_data_spdu(SI_FINISH, user_data, out),
            SessionPdu::Disconnect { user_data } => {
                encode_user_data_spdu(SI_DISCONNECT, user_data, out)
            }
            SessionPdu::Abort { user_data } => {
                // ABORT: transport-disconnect PI (17) + user-data PGI.
                let mut params = Vec::new();
                params.push(17);
                params.push(1);
                params.push(11); // transport-connection-released | user-abort
                push_pgi_user_data(&mut params, user_data);
                encode_simple_spdu(SI_ABORT, &params, out)
            }
            SessionPdu::Data(payload) => {
                out.extend_from_slice(&DATA_PREFIX);
                out.extend_from_slice(payload);
                Ok(())
            }
        }
    }

    /// Decode a single SPDU from `buf` (tolerant structural parse).
    ///
    /// Unknown PGIs/PIs are skipped; the selectors and user data are extracted
    /// where present. Returns [`Error::SessionUnknownSpdu`] for an unrecognised
    /// SI, [`Error::SessionTruncated`] for a short buffer, and
    /// [`Error::SessionRefused`] for a REFUSE SPDU.
    pub fn decode(buf: &[u8]) -> Result<SessionPdu> {
        // The DATA prefix shares SI=1 with GIVE-TOKENS; check it first because
        // a lone GIVE-TOKENS is not a complete user message in this profile.
        if buf.len() >= 2 && buf[0] == SI_GIVE_TOKENS {
            return decode_data(buf);
        }

        if buf.len() < 2 {
            return Err(Error::SessionTruncated);
        }
        let si = buf[0];

        // Read the SPDU length (LI), which may be the extended form.
        let (li, hdr) = decode_length(&buf[1..]).ok_or(Error::SessionTruncated)?;
        let params_start = 1 + hdr;
        let params_end = params_start
            .checked_add(li)
            .filter(|&e| e <= buf.len())
            .ok_or(Error::SessionTruncated)?;
        let params = &buf[params_start..params_end];

        match si {
            SI_CONNECT => Ok(SessionPdu::Connect(parse_connect_params(params)?)),
            SI_ACCEPT => Ok(SessionPdu::Accept(parse_connect_params(params)?)),
            SI_REFUSE => Err(Error::SessionRefused),
            SI_FINISH => Ok(SessionPdu::Finish {
                user_data: extract_user_data(params),
            }),
            SI_DISCONNECT => Ok(SessionPdu::Disconnect {
                user_data: extract_user_data(params),
            }),
            SI_ABORT => Ok(SessionPdu::Abort {
                user_data: extract_user_data(params),
            }),
            other => Err(Error::SessionUnknownSpdu { si: other }),
        }
    }
}

// ---------------------------------------------------------------------------
// Length codec (ISO 8327-1)
// ---------------------------------------------------------------------------

/// Encode an ISO 8327 length: short form for `0..=254`, else `0xFF` + `u16`.
fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len <= 254 {
        out.push(len as u8);
    } else {
        out.push(0xFF);
        let v = len as u16; // caller guarantees len <= u16::MAX
        out.push((v >> 8) as u8);
        out.push((v & 0xFF) as u8);
    }
}

/// Decode an ISO 8327 length at the start of `buf`.
///
/// Returns `Some((length, header_octets))`, or `None` if `buf` is too short to
/// hold the declared length header.
fn decode_length(buf: &[u8]) -> Option<(usize, usize)> {
    let first = *buf.first()?;
    if first != 0xFF {
        Some((first as usize, 1))
    } else {
        // Extended form: 0xFF followed by a big-endian u16.
        let hi = *buf.get(1)?;
        let lo = *buf.get(2)?;
        Some((u16::from_be_bytes([hi, lo]) as usize, 3))
    }
}

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

/// Append a PI/PGI unit with a short-form length. Used only for the small
/// fixed parameters (all <= 254 bytes), so the short form always applies.
fn push_short_param(out: &mut Vec<u8>, code: u8, value: &[u8]) {
    out.push(code);
    out.push(value.len() as u8);
    out.extend_from_slice(value);
}

/// Append the `0xC1` user-data PGI with an ISO 8327 length (extended if
/// needed).
fn push_pgi_user_data(out: &mut Vec<u8>, user_data: &[u8]) {
    out.push(PGI_USER_DATA);
    encode_length(user_data.len(), out);
    out.extend_from_slice(user_data);
}

/// Encode a CONNECT or ACCEPT SPDU with the fixed MMS-profile parameter set.
fn encode_connect_accept(si: u8, c: &SessionConnect, out: &mut Vec<u8>) -> Result<()> {
    let mut params = Vec::new();

    // Connect/Accept Item (PGI 5) containing Protocol Options + Version Number.
    let mut cai = Vec::new();
    push_short_param(&mut cai, PI_PROTOCOL_OPTIONS, &[PROTOCOL_OPTIONS_NONE]);
    push_short_param(&mut cai, PI_VERSION_NUMBER, &[VERSION_NUMBER_2]);
    push_short_param(&mut params, PGI_CONNECT_ACCEPT, &cai);

    // Session Requirement (PI 20): duplex.
    push_short_param(
        &mut params,
        PI_SESSION_REQUIREMENT,
        &SESSION_REQUIREMENT_DUPLEX.to_be_bytes(),
    );

    // Calling / Called Session Selector, when present.
    if let Some(sel) = &c.calling_selector {
        if sel.len() > MAX_SELECTOR_LEN {
            return Err(Error::SessionInvalidParameter {
                code: PI_CALLING_SELECTOR,
            });
        }
        push_short_param(&mut params, PI_CALLING_SELECTOR, sel);
    }
    if let Some(sel) = &c.called_selector {
        if sel.len() > MAX_SELECTOR_LEN {
            return Err(Error::SessionInvalidParameter {
                code: PI_CALLED_SELECTOR,
            });
        }
        push_short_param(&mut params, PI_CALLED_SELECTOR, sel);
    }

    // Session user data PGI (carries the presentation CP/CPA).
    push_pgi_user_data(&mut params, &c.user_data);

    encode_simple_spdu(si, &params, out)
}

/// Encode an SPDU that carries only the `0xC1` user-data PGI (FINISH /
/// DISCONNECT).
fn encode_user_data_spdu(si: u8, user_data: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let mut params = Vec::new();
    push_pgi_user_data(&mut params, user_data);
    encode_simple_spdu(si, &params, out)
}

/// Encode `si` + LI + the already-assembled parameter octets.
fn encode_simple_spdu(si: u8, params: &[u8], out: &mut Vec<u8>) -> Result<()> {
    if params.len() > u16::MAX as usize {
        return Err(Error::SessionInvalidParameter { code: si });
    }
    out.push(si);
    encode_length(params.len(), out);
    out.extend_from_slice(params);
    Ok(())
}

// ---------------------------------------------------------------------------
// Decode helpers (tolerant structural walk)
// ---------------------------------------------------------------------------

/// Decode the GIVE-TOKENS + DATA-TRANSFER pair. Tolerant: any payload whose
/// first four bytes are `01 00 01 00` is treated as session data (matching
/// libIEC61850, which checks exactly those four bytes). The remaining bytes are
/// the user data.
fn decode_data(buf: &[u8]) -> Result<SessionPdu> {
    if buf.len() < DATA_PREFIX.len() {
        return Err(Error::SessionTruncated);
    }
    if buf[..DATA_PREFIX.len()] != DATA_PREFIX {
        // SI was 1 but it is not the data prefix — not a recognised SPDU.
        return Err(Error::SessionUnknownSpdu { si: buf[0] });
    }
    Ok(SessionPdu::Data(buf[DATA_PREFIX.len()..].to_vec()))
}

/// Walk a CONNECT/ACCEPT parameter block, extracting selectors and user data.
///
/// Unknown PGIs/PIs are skipped. A length that runs past the end of the block
/// is a [`Error::SessionInvalidParameter`].
fn parse_connect_params(params: &[u8]) -> Result<SessionConnect> {
    let mut out = SessionConnect::default();
    let mut pos = 0usize;

    while pos < params.len() {
        let code = params[pos];
        pos += 1;
        let (len, hdr) =
            decode_length(&params[pos..]).ok_or(Error::SessionInvalidParameter { code })?;
        pos += hdr;
        let end = pos
            .checked_add(len)
            .filter(|&e| e <= params.len())
            .ok_or(Error::SessionInvalidParameter { code })?;
        let value = &params[pos..end];

        match code {
            PI_CALLING_SELECTOR if value.len() <= MAX_SELECTOR_LEN => {
                out.calling_selector = Some(value.to_vec());
            }
            PI_CALLED_SELECTOR if value.len() <= MAX_SELECTOR_LEN => {
                out.called_selector = Some(value.to_vec());
            }
            PGI_USER_DATA => {
                out.user_data = value.to_vec();
            }
            // Connect/Accept Item, Session Requirement, Connection Identifier,
            // and anything else are not needed by the profile — skip.
            _ => {}
        }

        pos = end;
    }

    Ok(out)
}

/// Extract the `0xC1` user-data PGI value from a parameter block, walking
/// tolerantly past any preceding PIs (e.g. ABORT's transport-disconnect).
/// Returns an empty vector if no user-data PGI is present.
fn extract_user_data(params: &[u8]) -> Vec<u8> {
    let mut pos = 0usize;
    while pos < params.len() {
        let code = params[pos];
        pos += 1;
        let Some((len, hdr)) = decode_length(&params[pos..]) else {
            break;
        };
        pos += hdr;
        let Some(end) = pos.checked_add(len).filter(|&e| e <= params.len()) else {
            break;
        };
        if code == PGI_USER_DATA {
            return params[pos..end].to_vec();
        }
        pos = end;
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(pdu: &SessionPdu) -> SessionPdu {
        let mut buf = Vec::new();
        Session::encode(pdu, &mut buf).expect("encode");
        Session::decode(&buf).expect("decode")
    }

    #[test]
    fn connect_roundtrip_with_selectors() {
        let pdu = SessionPdu::Connect(SessionConnect {
            calling_selector: Some(vec![0x00, 0x01]),
            called_selector: Some(vec![0x00, 0x01]),
            user_data: vec![0xAA, 0xBB, 0xCC],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn accept_roundtrip_with_selectors() {
        let pdu = SessionPdu::Accept(SessionConnect {
            calling_selector: None,
            called_selector: Some(vec![0x00, 0x01]),
            user_data: vec![0x01, 0x02],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn connect_no_selectors_roundtrip() {
        let pdu = SessionPdu::Connect(SessionConnect {
            calling_selector: None,
            called_selector: None,
            user_data: vec![0x10; 5],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn connect_max_length_selectors() {
        let sel = vec![0x7Eu8; MAX_SELECTOR_LEN];
        let pdu = SessionPdu::Connect(SessionConnect {
            calling_selector: Some(sel.clone()),
            called_selector: Some(sel),
            user_data: vec![0x01],
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn encode_rejects_oversized_selector() {
        let pdu = SessionPdu::Connect(SessionConnect {
            calling_selector: Some(vec![0u8; 17]),
            called_selector: None,
            user_data: vec![],
        });
        let mut buf = Vec::new();
        assert!(matches!(
            Session::encode(&pdu, &mut buf),
            Err(Error::SessionInvalidParameter { code: 51 })
        ));
    }

    #[test]
    fn user_data_length_boundaries() {
        for n in [0usize, 1, 254, 255, 256, 1000] {
            let pdu = SessionPdu::Connect(SessionConnect {
                calling_selector: Some(vec![0x00, 0x01]),
                called_selector: Some(vec![0x00, 0x01]),
                user_data: vec![0x5A; n],
            });
            assert_eq!(roundtrip(&pdu), pdu, "user_data len {n}");
        }
    }

    #[test]
    fn extended_length_path_used_for_large_user_data() {
        // 300 bytes forces the SPDU LI and the 0xC1 length into extended form.
        let pdu = SessionPdu::Connect(SessionConnect {
            calling_selector: Some(vec![0x00, 0x01]),
            called_selector: Some(vec![0x00, 0x01]),
            user_data: vec![0xC3; 300],
        });
        let mut buf = Vec::new();
        Session::encode(&pdu, &mut buf).unwrap();
        // SI then 0xFF extended SPDU length.
        assert_eq!(buf[0], SI_CONNECT);
        assert_eq!(buf[1], 0xFF);
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn finish_disconnect_abort_roundtrip() {
        for pdu in [
            SessionPdu::Finish {
                user_data: vec![0x01, 0x02],
            },
            SessionPdu::Finish { user_data: vec![] },
            SessionPdu::Disconnect {
                user_data: vec![0xAA],
            },
            SessionPdu::Abort {
                user_data: vec![0x33, 0x44, 0x55],
            },
            SessionPdu::Abort { user_data: vec![] },
        ] {
            assert_eq!(roundtrip(&pdu), pdu);
        }
    }

    #[test]
    fn refuse_decodes_to_session_refused() {
        let mut buf = Vec::new();
        Session::encode(&SessionPdu::Refuse { reason: Some(1) }, &mut buf).unwrap();
        assert!(matches!(Session::decode(&buf), Err(Error::SessionRefused)));
    }

    #[test]
    fn data_roundtrip_and_empty() {
        for payload in [vec![], vec![0xDE, 0xAD, 0xBE, 0xEF]] {
            let pdu = SessionPdu::Data(payload.clone());
            let mut buf = Vec::new();
            Session::encode(&pdu, &mut buf).unwrap();
            assert_eq!(&buf[..4], &DATA_PREFIX);
            assert_eq!(Session::decode(&buf).unwrap(), pdu);
        }
    }

    #[test]
    fn data_prefix_empty_payload_decodes() {
        let pdu = Session::decode(&DATA_PREFIX).unwrap();
        assert_eq!(pdu, SessionPdu::Data(vec![]));
    }

    #[test]
    fn connect_skips_unknown_pgi_pi() {
        // Build a CONNECT, then splice an unknown PGI (code 0x49, len 2) and an
        // unknown PI before the user data; the decoder must skip both.
        let base = SessionConnect {
            calling_selector: Some(vec![0x00, 0x01]),
            called_selector: Some(vec![0x00, 0x02]),
            user_data: vec![0x11, 0x22],
        };
        // Assemble params manually with the unknown units injected.
        let mut params = Vec::new();
        // unknown PGI 0x49
        push_short_param(&mut params, 0x49, &[0xAB, 0xCD]);
        // Connect/Accept Item
        let mut cai = Vec::new();
        push_short_param(&mut cai, PI_PROTOCOL_OPTIONS, &[0]);
        push_short_param(&mut cai, PI_VERSION_NUMBER, &[2]);
        push_short_param(&mut params, PGI_CONNECT_ACCEPT, &cai);
        push_short_param(&mut params, PI_CALLING_SELECTOR, &[0x00, 0x01]);
        // unknown PI 0x60
        push_short_param(&mut params, 0x60, &[0x99]);
        push_short_param(&mut params, PI_CALLED_SELECTOR, &[0x00, 0x02]);
        push_pgi_user_data(&mut params, &base.user_data);

        let mut buf = Vec::new();
        encode_simple_spdu(SI_CONNECT, &params, &mut buf).unwrap();

        let decoded = Session::decode(&buf).unwrap();
        assert_eq!(decoded, SessionPdu::Connect(base));
    }

    #[test]
    fn garbage_si_is_unknown_spdu() {
        let buf = [0x7Fu8, 0x00];
        assert!(matches!(
            Session::decode(&buf),
            Err(Error::SessionUnknownSpdu { si: 0x7F })
        ));
    }

    #[test]
    fn si_one_but_not_data_prefix_is_unknown() {
        // SI=1 but the following bytes are not 01 00 01 00.
        let buf = [0x01u8, 0x00, 0x02, 0x00];
        assert!(matches!(
            Session::decode(&buf),
            Err(Error::SessionUnknownSpdu { si: 1 })
        ));
    }

    #[test]
    fn truncation_sweep_connect() {
        let pdu = SessionPdu::Connect(SessionConnect {
            calling_selector: Some(vec![0x00, 0x01]),
            called_selector: Some(vec![0x00, 0x01]),
            user_data: vec![0x42; 300],
        });
        let mut buf = Vec::new();
        Session::encode(&pdu, &mut buf).unwrap();
        for len in 0..buf.len() {
            // Must never panic; any error is acceptable.
            let _ = Session::decode(&buf[..len]);
        }
    }

    #[test]
    fn empty_and_one_byte_are_truncated() {
        assert!(matches!(Session::decode(&[]), Err(Error::SessionTruncated)));
        assert!(matches!(
            Session::decode(&[SI_CONNECT]),
            Err(Error::SessionTruncated)
        ));
    }

    #[test]
    fn param_length_past_end_is_invalid() {
        // CONNECT, LI=4, then a PI claiming length 10 (runs past end).
        let buf = [SI_CONNECT, 0x04, PI_CALLING_SELECTOR, 0x0A, 0x00, 0x00];
        assert!(matches!(
            Session::decode(&buf),
            Err(Error::SessionInvalidParameter { .. })
        ));
    }
}
