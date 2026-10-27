//! COTP TPDU encoder/decoder (ISO 8073 class 0).
//!
//! The codec operates on *complete slices* — the TPKT layer above is
//! responsible for buffering a complete TPKT payload before the COTP layer
//! is invoked.  Therefore none of the functions here return `Ok(None)` for
//! incomplete input; truncation is always an error.
//!
//! # Wire format summary (class 0, RFC 1006)
//!
//! Each TPDU starts with:
//!
//! ```text
//! Offset  Field
//! ------  -----
//! 0       LI   — Length Indicator: number of bytes that follow in the TPDU
//!               header, NOT counting the LI octet itself and NOT counting
//!               user data (for DT).
//! 1       Code — high nibble identifies the TPDU type; low nibble is credit
//!               (class 0 ignores this, but tolerates non-zero values on CR).
//! ...     fixed fields per TPDU type
//! ...     variable part (CR/CC: optional params; ER: optional params)
//! ```
//!
//! User data (DT only) follows the header and is NOT counted in LI.

use super::params::CotpParams;
use super::pdu::{ConnectionPdu, CotpPdu, CODE_CC, CODE_CR, CODE_DR, CODE_DT, CODE_ER};
use crate::cotp::params::TpduSize;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Fixed header sizes (not counting the LI byte itself, matching the LI field)
// ---------------------------------------------------------------------------

/// Minimum LI for CR/CC: code(1) + dst_ref(2) + src_ref(2) + class(1) = 6 bytes
/// after LI; the variable part adds `LI - 6` further bytes.
const LI_CR_CC_FIXED: u8 = 6;

/// LI for a DT header: code(1) + TPDU-NR/EOT(1) = 2 bytes after LI.
const LI_DT: u8 = 2;

/// LI for a DR header: code(1) + dst_ref(2) + src_ref(2) + reason(1) = 6 bytes after LI.
const LI_DR: u8 = 6;

/// LI for a minimal ER header: code(1) + dst_ref(2) + reject_cause(1) = 4 bytes after LI.
const LI_ER_MIN: u8 = 4;

// ---------------------------------------------------------------------------
// CotpCodec
// ---------------------------------------------------------------------------

/// Stateless COTP TPDU codec for ISO 8073 class 0.
#[derive(Debug)]
pub struct CotpCodec;

impl CotpCodec {
    // ---- Decode -------------------------------------------------------

    /// Decode one TPDU from a complete TPKT payload slice.
    ///
    /// The slice must contain exactly one TPDU (possible with trailing user
    /// data for DT); any leftover bytes are the DT payload for `Code::DT`,
    /// and other TPDU types silently ignore trailing bytes beyond their
    /// declared LI.
    pub fn decode(buf: &[u8]) -> Result<CotpPdu> {
        // Need at least LI + code.
        if buf.len() < 2 {
            return Err(Error::CotpTruncated);
        }

        let li = buf[0];
        let li_usize = li as usize;

        // LI must cover at least the code byte (1 byte).
        if li < 1 {
            return Err(Error::CotpInvalidLengthIndicator { li });
        }

        // The total header region is 1 (LI byte) + LI bytes.
        // The buffer must be at least 1 + LI bytes long.
        if buf.len() < 1 + li_usize {
            return Err(Error::CotpTruncated);
        }

        // The header slice (excluding the LI byte itself, LI bytes long).
        // Invariant: `header.len() == li as usize` exactly — every decode_*
        // helper relies on this, so they need no further length re-checks.
        let header = &buf[1..1 + li_usize];
        debug_assert_eq!(header.len(), li_usize);

        // TPDU code is the first byte of the header (= buf[1]).
        // High nibble identifies the type; low nibble is credit/ignored.
        // Safety: li >= 1 and header.len() == li_usize >= 1, so this is safe.
        let code_raw = header[0];
        let code = code_raw & 0xF0; // mask the credit nibble

        match code {
            CODE_CR => decode_cr_cc(li, header, false),
            CODE_CC => decode_cr_cc(li, header, true),
            CODE_DR => decode_dr(li, header),
            CODE_DT => {
                // User data is everything after the header region.
                let user_data = &buf[1 + li_usize..];
                decode_dt(li, header, user_data)
            }
            CODE_ER => decode_er(li, header),
            _ => Err(Error::CotpUnknownTpduCode { code: code_raw }),
        }
    }

    // ---- Encode -------------------------------------------------------

    /// Encode a single TPDU (CR/CC/DR/ER) into `out`.
    ///
    /// DT fragmentation is handled by [`encode_data`](Self::encode_data);
    /// calling this with a `CotpPdu::Data` still works but is intended only
    /// for explicit control of EOT and payload.
    ///
    /// Returns `Err` only for CR/CC TPDUs whose variable part cannot be
    /// encoded: a TSAP selector longer than
    /// [`MAX_TSAP_LEN`](crate::cotp::params::MAX_TSAP_LEN)
    /// ([`CotpInvalidParameter`](Error::CotpInvalidParameter)) or a total
    /// variable part that would overflow the single-octet LI field
    /// ([`CotpInvalidLengthIndicator`](Error::CotpInvalidLengthIndicator)).
    /// DR/DT/ER have fixed-size headers and never fail. On error `out` is left
    /// unchanged.
    pub fn encode(pdu: &CotpPdu, out: &mut Vec<u8>) -> Result<()> {
        match pdu {
            CotpPdu::ConnectionRequest(conn) => encode_cr_cc(CODE_CR, conn, out),
            CotpPdu::ConnectionConfirm(conn) => encode_cr_cc(CODE_CC, conn, out),
            CotpPdu::DisconnectRequest {
                dst_ref,
                src_ref,
                reason,
            } => {
                encode_dr(*dst_ref, *src_ref, *reason, out);
                Ok(())
            }
            CotpPdu::Data { eot, payload } => {
                encode_dt(*eot, payload, out);
                Ok(())
            }
            CotpPdu::ErrorTpdu {
                dst_ref,
                reject_cause,
            } => {
                encode_er(*dst_ref, *reject_cause, out);
                Ok(())
            }
        }
    }

    /// Fragment `payload` into DT TPDUs of at most `tpdu_size` user bytes
    /// each.  EOT is set only on the last fragment.
    ///
    /// If `payload` is empty, exactly one DT with EOT set and an empty payload
    /// is returned.
    ///
    /// Each returned `Vec<u8>` is a complete encoded DT TPDU ready for TPKT
    /// framing.
    #[must_use = "the encoded DT TPDUs are the only output of this call"]
    pub fn encode_data(payload: &[u8], tpdu_size: TpduSize) -> Vec<Vec<u8>> {
        let chunk_size = tpdu_size.bytes();
        let mut result = Vec::new();

        if payload.is_empty() {
            // One empty DT with EOT.
            let mut buf = Vec::new();
            encode_dt(true, &[], &mut buf);
            result.push(buf);
            return result;
        }

        let chunks: Vec<&[u8]> = payload.chunks(chunk_size).collect();
        let last_idx = chunks.len() - 1;
        for (i, chunk) in chunks.iter().enumerate() {
            let eot = i == last_idx;
            let mut buf = Vec::new();
            encode_dt(eot, chunk, &mut buf);
            result.push(buf);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Decode helpers
// ---------------------------------------------------------------------------

fn decode_cr_cc(li: u8, header: &[u8], is_cc: bool) -> Result<CotpPdu> {
    // CR/CC fixed part: code(1) + dst_ref(2) + src_ref(2) + class(1) = 6 bytes.
    // So LI must be >= LI_CR_CC_FIXED (= 6). Since header.len() == li, that
    // check alone guarantees header[0..6] is in bounds.
    if li < LI_CR_CC_FIXED {
        return Err(Error::CotpInvalidLengthIndicator { li });
    }

    // header[0] = code, [1..2] = dst_ref, [3..4] = src_ref, [5] = class.
    let dst_ref = u16::from_be_bytes([header[1], header[2]]);
    let src_ref = u16::from_be_bytes([header[3], header[4]]);
    let class_octet = header[5];

    // Class 0 only: high nibble of class octet must be 0.
    let class_nibble = (class_octet >> 4) & 0x0F;
    if class_nibble != 0 {
        return Err(Error::CotpUnsupportedClass {
            class: class_nibble,
        });
    }

    // Variable part: everything after the 6 fixed bytes in the header.
    let variable = &header[6..];
    let params = CotpParams::decode(variable)?;

    let conn = ConnectionPdu {
        dst_ref,
        src_ref,
        class: class_octet,
        params,
    };

    if is_cc {
        Ok(CotpPdu::ConnectionConfirm(conn))
    } else {
        Ok(CotpPdu::ConnectionRequest(conn))
    }
}

fn decode_dr(li: u8, header: &[u8]) -> Result<CotpPdu> {
    // DR fixed part: code(1) + dst_ref(2) + src_ref(2) + reason(1) = 6 bytes.
    // header.len() == li, so this check also bounds header[0..6].
    if li < LI_DR {
        return Err(Error::CotpInvalidLengthIndicator { li });
    }

    let dst_ref = u16::from_be_bytes([header[1], header[2]]);
    let src_ref = u16::from_be_bytes([header[3], header[4]]);
    let reason = header[5];

    Ok(CotpPdu::DisconnectRequest {
        dst_ref,
        src_ref,
        reason,
    })
}

fn decode_dt(li: u8, header: &[u8], user_data: &[u8]) -> Result<CotpPdu> {
    // DT fixed part: code(1) + TPDU-NR/EOT(1) = 2 bytes.
    // header.len() == li, so this check also bounds header[0..2].
    if li < LI_DT {
        return Err(Error::CotpInvalidLengthIndicator { li });
    }

    // TPDU-NR/EOT byte: bit7 = EOT, low 7 bits = sequence number (ignored in
    // class 0, but we read tolerantly).
    let nr_eot = header[1];
    let eot = (nr_eot & 0x80) != 0;

    Ok(CotpPdu::Data {
        eot,
        payload: user_data.to_vec(),
    })
}

fn decode_er(li: u8, header: &[u8]) -> Result<CotpPdu> {
    // ER fixed part: code(1) + dst_ref(2) + reject_cause(1) = 4 bytes.
    // header.len() == li, so this check also bounds header[0..4].
    if li < LI_ER_MIN {
        return Err(Error::CotpInvalidLengthIndicator { li });
    }

    let dst_ref = u16::from_be_bytes([header[1], header[2]]);
    let reject_cause = header[3];

    // Variable part (if any) is silently skipped — tolerant per spec.

    Ok(CotpPdu::ErrorTpdu {
        dst_ref,
        reject_cause,
    })
}

// ---------------------------------------------------------------------------
// Encode helpers
// ---------------------------------------------------------------------------

fn encode_cr_cc(code: u8, conn: &ConnectionPdu, out: &mut Vec<u8>) -> Result<()> {
    // Encode params into a scratch buffer first (validating TSAP lengths) so we
    // know the variable-part length before touching `out`.
    let mut params_buf = Vec::new();
    conn.params.encode(&mut params_buf)?;

    // LI = 1 (code) + 2 (dst_ref) + 2 (src_ref) + 1 (class) + params.len().
    // The variable part must fit so that LI stays within a single octet: the
    // fixed part is 6, so the variable part may be at most 255 - 6 = 249 bytes.
    let li = (LI_CR_CC_FIXED as usize)
        .checked_add(params_buf.len())
        .filter(|&li| li <= u8::MAX as usize)
        .ok_or(Error::CotpInvalidLengthIndicator { li: u8::MAX })? as u8;

    out.push(li);
    out.push(code);
    out.extend_from_slice(&conn.dst_ref.to_be_bytes());
    out.extend_from_slice(&conn.src_ref.to_be_bytes());
    out.push(conn.class);
    out.extend_from_slice(&params_buf);
    Ok(())
}

fn encode_dr(dst_ref: u16, src_ref: u16, reason: u8, out: &mut Vec<u8>) {
    // LI = 1 (code) + 2 (dst_ref) + 2 (src_ref) + 1 (reason) = 6
    out.push(LI_DR);
    out.push(CODE_DR);
    out.extend_from_slice(&dst_ref.to_be_bytes());
    out.extend_from_slice(&src_ref.to_be_bytes());
    out.push(reason);
}

fn encode_dt(eot: bool, payload: &[u8], out: &mut Vec<u8>) {
    // LI = 1 (code) + 1 (TPDU-NR/EOT) = 2
    out.push(LI_DT);
    out.push(CODE_DT);
    // TPDU-NR/EOT: bit7 = EOT; sequence number is always 0 in class 0.
    let nr_eot: u8 = if eot { 0x80 } else { 0x00 };
    out.push(nr_eot);
    out.extend_from_slice(payload);
}

fn encode_er(dst_ref: u16, reject_cause: u8, out: &mut Vec<u8>) {
    // LI = 1 (code) + 2 (dst_ref) + 1 (reject_cause) = 4
    out.push(LI_ER_MIN);
    out.push(CODE_ER);
    out.extend_from_slice(&dst_ref.to_be_bytes());
    out.push(reject_cause);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cotp::params::{CotpParams, TpduSize};
    use crate::cotp::pdu::ConnectionPdu;
    use crate::cotp::reassembly::CotpReassembler;
    use crate::Error;

    // Helper: encode a PDU and decode it back.
    fn roundtrip(pdu: &CotpPdu) -> CotpPdu {
        let mut buf = Vec::new();
        CotpCodec::encode(pdu, &mut buf).expect("encode");
        CotpCodec::decode(&buf).unwrap()
    }

    fn make_cr(params: CotpParams) -> CotpPdu {
        CotpPdu::ConnectionRequest(ConnectionPdu {
            dst_ref: 0x0000,
            src_ref: 0x0001,
            class: 0x00,
            params,
        })
    }

    fn make_cc(params: CotpParams) -> CotpPdu {
        CotpPdu::ConnectionConfirm(ConnectionPdu {
            dst_ref: 0x0001,
            src_ref: 0x0002,
            class: 0x00,
            params,
        })
    }

    // ---- CR/CC round-trips -------------------------------------------------

    #[test]
    fn cr_no_params_roundtrip() {
        let pdu = make_cr(CotpParams::default());
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn cc_no_params_roundtrip() {
        let pdu = make_cc(CotpParams::default());
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn cr_all_params_roundtrip() {
        let pdu = make_cr(CotpParams {
            tpdu_size: Some(TpduSize::SIZE_1024),
            src_tsap: Some(vec![0x00, 0x01]),
            dst_tsap: Some(vec![0x00, 0x02]),
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn cc_all_params_roundtrip() {
        let pdu = make_cc(CotpParams {
            tpdu_size: Some(TpduSize::new(9).unwrap()),
            src_tsap: Some(vec![0xAB]),
            dst_tsap: Some(vec![0xCD]),
        });
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn cr_credit_nibble_tolerated() {
        // Manually craft a CR with a non-zero credit nibble (low nibble of code byte).
        // The mask should make it decode as a CR anyway.
        let mut buf = Vec::new();
        CotpCodec::encode(&make_cr(CotpParams::default()), &mut buf).unwrap();
        // buf[1] is the code byte (0xE0); set low nibble to 3.
        buf[1] = 0xE3;
        let pdu = CotpCodec::decode(&buf).unwrap();
        assert!(matches!(pdu, CotpPdu::ConnectionRequest(_)));
    }

    #[test]
    fn cr_class_1_is_unsupported_class_error() {
        let mut buf = Vec::new();
        CotpCodec::encode(&make_cr(CotpParams::default()), &mut buf).unwrap();
        // class/options byte is buf[6]; set high nibble to 1 (class 1).
        buf[6] = 0x10;
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpUnsupportedClass { class: 1 }),
            "got {err:?}"
        );
    }

    #[test]
    fn unknown_param_skipped_in_cr() {
        let mut buf = Vec::new();
        CotpCodec::encode(&make_cr(CotpParams::default()), &mut buf).unwrap();
        // Append an unknown parameter (code 0xDE, len 2, val [0x01, 0x02]).
        // We need to also update the LI byte.
        let extra = [0xDEu8, 0x02, 0x01, 0x02];
        let old_li = buf[0];
        buf[0] = old_li + 4; // extend LI by 4
        buf.extend_from_slice(&extra);
        // Must decode OK and ignore the unknown param.
        let pdu = CotpCodec::decode(&buf).unwrap();
        assert!(
            matches!(pdu, CotpPdu::ConnectionRequest(conn) if conn.params == CotpParams::default())
        );
    }

    #[test]
    fn oversized_tsap_in_cr_is_error() {
        // Build a CR with a 33-byte called TSAP (> MAX_TSAP_LEN = 32).
        let too_long_tsap = vec![0xAAu8; 33];
        let mut var = Vec::new();
        var.push(0xC2u8); // DST_TSAP code
        var.push(33u8);
        var.extend_from_slice(&too_long_tsap);

        // Build a minimal CR with this bad variable part.
        let li = 6u8 + 35; // 6 fixed + 2 (code+len) + 33 (value)
        let mut buf = vec![li, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00];
        buf.extend_from_slice(&var);
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpInvalidParameter { code: 0xC2 }),
            "got {err:?}"
        );
    }

    #[test]
    fn encode_cr_oversized_tsap_is_error() {
        // A 33-byte called TSAP exceeds MAX_TSAP_LEN and must be rejected on
        // encode rather than silently truncating the length octet.
        let pdu = make_cr(CotpParams {
            tpdu_size: None,
            src_tsap: None,
            dst_tsap: Some(vec![0xAAu8; 33]),
        });
        let mut buf = Vec::new();
        let err = CotpCodec::encode(&pdu, &mut buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpInvalidParameter { code: 0xC2 }),
            "got {err:?}"
        );
        // On error the output buffer must be untouched.
        assert!(buf.is_empty());
    }

    #[test]
    fn truncated_cr_at_each_cut_point() {
        let mut buf = Vec::new();
        CotpCodec::encode(&make_cr(CotpParams::default()), &mut buf).unwrap();
        for len in 0..buf.len() {
            let err = CotpCodec::decode(&buf[..len]).unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::CotpTruncated
                        | Error::CotpInvalidLengthIndicator { .. }
                        | Error::CotpUnsupportedClass { .. }
                ),
                "at len={len} got {err:?}"
            );
        }
    }

    // ---- DT round-trips ----------------------------------------------------

    #[test]
    fn dt_with_eot() {
        let pdu = CotpPdu::Data {
            eot: true,
            payload: vec![0x01, 0x02, 0x03],
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn dt_without_eot() {
        let pdu = CotpPdu::Data {
            eot: false,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn dt_empty_payload_with_eot() {
        let pdu = CotpPdu::Data {
            eot: true,
            payload: vec![],
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn dt_sequence_bits_ignored() {
        // Manually craft a DT with non-zero sequence number bits (low 7 of TPDU-NR).
        let mut buf = Vec::new();
        CotpCodec::encode(
            &CotpPdu::Data {
                eot: true,
                payload: vec![0xAA],
            },
            &mut buf,
        )
        .unwrap();
        // buf[2] is the TPDU-NR/EOT byte; low 7 bits are sequence number (ignored).
        buf[2] = 0x81; // bit7=EOT set, low bits=1 (non-zero sequence)
        let pdu = CotpCodec::decode(&buf).unwrap();
        assert_eq!(
            pdu,
            CotpPdu::Data {
                eot: true,
                payload: vec![0xAA]
            }
        );
    }

    #[test]
    fn truncated_dt_at_each_cut_point() {
        let mut buf = Vec::new();
        CotpCodec::encode(
            &CotpPdu::Data {
                eot: true,
                payload: vec![0xAA, 0xBB],
            },
            &mut buf,
        )
        .unwrap();
        // DT header is 3 bytes (LI + code + NR/EOT); payload follows.
        // Truncation within the 3-byte header should produce errors.
        for len in 0..3 {
            let err = CotpCodec::decode(&buf[..len]).unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::CotpTruncated | Error::CotpInvalidLengthIndicator { .. }
                ),
                "at len={len} got {err:?}"
            );
        }
    }

    // ---- DR round-trip -----------------------------------------------------

    #[test]
    fn dr_roundtrip() {
        let pdu = CotpPdu::DisconnectRequest {
            dst_ref: 0x0001,
            src_ref: 0x0002,
            reason: 0x03,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn truncated_dr() {
        let mut buf = Vec::new();
        CotpCodec::encode(
            &CotpPdu::DisconnectRequest {
                dst_ref: 1,
                src_ref: 2,
                reason: 0,
            },
            &mut buf,
        )
        .unwrap();
        for len in 0..buf.len() {
            let err = CotpCodec::decode(&buf[..len]).unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::CotpTruncated | Error::CotpInvalidLengthIndicator { .. }
                ),
                "at len={len} got {err:?}"
            );
        }
    }

    // ---- ER round-trip -----------------------------------------------------

    #[test]
    fn er_roundtrip() {
        let pdu = CotpPdu::ErrorTpdu {
            dst_ref: 0x1234,
            reject_cause: 0x01,
        };
        assert_eq!(roundtrip(&pdu), pdu);
    }

    #[test]
    fn er_with_variable_part_skipped() {
        // Manually craft an ER with extra variable part bytes.
        // ER fixed: LI=4, code=0x70, dst_ref[2], reject_cause.
        // Add 3 extra bytes in the header (LI = 7).
        let buf = [0x07u8, 0x70, 0x12, 0x34, 0x01, 0xAA, 0xBB, 0xCC];
        let pdu = CotpCodec::decode(&buf).unwrap();
        assert_eq!(
            pdu,
            CotpPdu::ErrorTpdu {
                dst_ref: 0x1234,
                reject_cause: 0x01,
            }
        );
    }

    #[test]
    fn truncated_er() {
        let mut buf = Vec::new();
        CotpCodec::encode(
            &CotpPdu::ErrorTpdu {
                dst_ref: 1,
                reject_cause: 0,
            },
            &mut buf,
        )
        .unwrap();
        for len in 0..buf.len() {
            let err = CotpCodec::decode(&buf[..len]).unwrap_err();
            assert!(
                matches!(
                    err,
                    Error::CotpTruncated | Error::CotpInvalidLengthIndicator { .. }
                ),
                "at len={len} got {err:?}"
            );
        }
    }

    // ---- Unknown TPDU code -------------------------------------------------

    #[test]
    fn unknown_code_is_error() {
        // LI=2 (to satisfy minimal length check), code=0x50 (unknown), dummy bytes.
        let buf = [0x02u8, 0x50, 0x00, 0x00];
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpUnknownTpduCode { code: 0x50 }),
            "got {err:?}"
        );
    }

    // ---- LI inconsistencies ------------------------------------------------

    #[test]
    fn li_zero_is_error() {
        // LI=0 means no code byte at all, which is always invalid.
        let buf = [0x00u8, 0x00];
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpInvalidLengthIndicator { li: 0 }),
            "got {err:?}"
        );
    }

    #[test]
    fn dt_li_too_small_is_error() {
        // LI=1 for DT; minimum is 2.
        let buf = [0x01u8, 0xF0, 0x80];
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpInvalidLengthIndicator { li: 1 }),
            "got {err:?}"
        );
    }

    #[test]
    fn cr_li_too_small_is_error() {
        // LI=5 for CR; minimum is 6.
        let buf = [0x05u8, 0xE0, 0x00, 0x00, 0x00, 0x01];
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(
            matches!(err, Error::CotpInvalidLengthIndicator { li: 5 }),
            "got {err:?}"
        );
    }

    #[test]
    fn li_larger_than_buffer_is_truncated() {
        // LI=10 but buffer is only 5 bytes.
        let buf = [0x0Au8, 0xF0, 0x80, 0x00, 0x00];
        let err = CotpCodec::decode(&buf).unwrap_err();
        assert!(matches!(err, Error::CotpTruncated), "got {err:?}");
    }

    // ---- encode_data + reassembly integration ------------------------------

    #[test]
    fn encode_data_empty_payload_gives_one_dt_with_eot() {
        let frags = CotpCodec::encode_data(&[], TpduSize::SIZE_1024);
        assert_eq!(frags.len(), 1);
        let pdu = CotpCodec::decode(&frags[0]).unwrap();
        assert_eq!(
            pdu,
            CotpPdu::Data {
                eot: true,
                payload: vec![]
            }
        );
    }

    #[test]
    fn encode_data_exact_fit_gives_one_dt() {
        let tpdu_size = TpduSize::SIZE_1024;
        let payload = vec![0xAAu8; tpdu_size.bytes()];
        let frags = CotpCodec::encode_data(&payload, tpdu_size);
        assert_eq!(frags.len(), 1);
        let pdu = CotpCodec::decode(&frags[0]).unwrap();
        match pdu {
            CotpPdu::Data { eot, payload: p } => {
                assert!(eot);
                assert_eq!(p.len(), tpdu_size.bytes());
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn encode_data_one_over_gives_two_dts() {
        let tpdu_size = TpduSize::SIZE_1024;
        let payload = vec![0xBBu8; tpdu_size.bytes() + 1];
        let frags = CotpCodec::encode_data(&payload, tpdu_size);
        assert_eq!(frags.len(), 2);

        // First fragment: no EOT.
        let pdu0 = CotpCodec::decode(&frags[0]).unwrap();
        match pdu0 {
            CotpPdu::Data { eot, payload: p } => {
                assert!(!eot);
                assert_eq!(p.len(), tpdu_size.bytes());
            }
            _ => panic!("expected Data"),
        }

        // Second fragment: EOT.
        let pdu1 = CotpCodec::decode(&frags[1]).unwrap();
        match pdu1 {
            CotpPdu::Data { eot, payload: p } => {
                assert!(eot);
                assert_eq!(p.len(), 1);
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn encode_data_each_fragment_within_size() {
        let tpdu_size = TpduSize::new(8).unwrap(); // 256 bytes
        let payload = vec![0xCCu8; 1000];
        let frags = CotpCodec::encode_data(&payload, tpdu_size);
        for frag in &frags {
            let pdu = CotpCodec::decode(frag).unwrap();
            match pdu {
                CotpPdu::Data { payload: p, .. } => {
                    assert!(p.len() <= tpdu_size.bytes());
                }
                _ => panic!("expected Data"),
            }
        }
    }

    #[test]
    fn encode_data_eot_only_on_last() {
        let tpdu_size = TpduSize::new(7).unwrap(); // 128 bytes
        let payload = vec![0xDDu8; 300];
        let frags = CotpCodec::encode_data(&payload, tpdu_size);
        assert!(frags.len() > 1);
        let last_idx = frags.len() - 1;
        for (i, frag) in frags.iter().enumerate() {
            let pdu = CotpCodec::decode(frag).unwrap();
            match pdu {
                CotpPdu::Data { eot, .. } => {
                    if i == last_idx {
                        assert!(eot, "last fragment must have EOT");
                    } else {
                        assert!(!eot, "non-last fragment must not have EOT");
                    }
                }
                _ => panic!("expected Data"),
            }
        }
    }

    #[test]
    fn encode_data_reassembly_round_trip() {
        for exp in 7u8..=13 {
            let tpdu_size = TpduSize::new(exp).unwrap();
            // Use a payload that forces fragmentation.
            let payload: Vec<u8> = (0u8..=255)
                .cycle()
                .take(tpdu_size.bytes() * 3 + 17)
                .collect();
            let frags = CotpCodec::encode_data(&payload, tpdu_size);
            let mut reassembler = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
            let mut result = None;
            for frag in &frags {
                let pdu = CotpCodec::decode(frag).unwrap();
                match pdu {
                    CotpPdu::Data { eot, payload: p } => {
                        result = reassembler.push(&p, eot).unwrap();
                    }
                    _ => panic!("expected Data"),
                }
            }
            assert_eq!(result, Some(payload), "round-trip failed for exp={exp}");
        }
    }
}
