//! COTP variable-part parameter types.
//!
//! ISO 8073 defines a set of optional parameters that may appear in the
//! variable part of CR (Connection Request) and CC (Connection Confirm) TPDUs.
//! Each parameter is encoded as a 1-byte code, 1-byte length, and value
//! octets.
//!
//! # Codes used by class 0 over RFC 1006
//!
//! | Code | Name            |
//! |------|-----------------|
//! | 0xC0 | TPDU size       |
//! | 0xC1 | Calling TSAP    |
//! | 0xC2 | Called TSAP     |
//!
//! Unknown codes are skipped tolerantly (read code+len, skip value) to allow
//! forward-compatible interop with peers that send additional parameters.

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Parameter codes
// ---------------------------------------------------------------------------

/// Parameter code: maximum TPDU size (1 byte value: 2^n octets).
pub const PARAM_TPDU_SIZE: u8 = 0xC0;
/// Parameter code: calling TSAP selector (src_tsap / calling-TSAP).
pub const PARAM_SRC_TSAP: u8 = 0xC1;
/// Parameter code: called TSAP selector (dst_tsap / called-TSAP).
pub const PARAM_DST_TSAP: u8 = 0xC2;

/// Maximum TSAP selector length accepted on read (arbitrary; class-0 stacks
/// use 2 bytes in practice but the standard doesn't impose a small limit).
pub const MAX_TSAP_LEN: usize = 32;

// ---------------------------------------------------------------------------
// TpduSize
// ---------------------------------------------------------------------------

/// Maximum TPDU size, expressed as a power-of-two exponent.
///
/// The actual maximum user-data bytes per DT TPDU is `1 << exponent`.
/// ISO 8073 class 0 defines valid exponents in the range 7 (128 B) through
/// 13 (8 192 B).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpduSize(u8);

impl TpduSize {
    /// Minimum exponent (128-byte TPDU).
    pub const MIN_EXPONENT: u8 = 7;
    /// Maximum exponent (8192-byte TPDU).
    pub const MAX_EXPONENT: u8 = 13;

    /// Common default: 1024 bytes.
    pub const SIZE_1024: TpduSize = TpduSize(10);

    /// Construct a `TpduSize` from an exponent value.
    ///
    /// Returns `Err(CotpInvalidTpduSize)` if `exponent` is outside `7..=13`.
    pub fn new(exponent: u8) -> Result<Self> {
        if !(Self::MIN_EXPONENT..=Self::MAX_EXPONENT).contains(&exponent) {
            return Err(Error::CotpInvalidTpduSize { exponent });
        }
        Ok(TpduSize(exponent))
    }

    /// The maximum user-data bytes per DT TPDU: `1 << exponent`.
    #[must_use]
    pub fn bytes(self) -> usize {
        1usize << self.0
    }

    /// The raw exponent value.
    #[must_use]
    pub fn exponent(self) -> u8 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// CotpParams
// ---------------------------------------------------------------------------

/// Optional parameters from the variable part of a CR or CC TPDU.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CotpParams {
    /// Maximum TPDU size (parameter code 0xC0).
    pub tpdu_size: Option<TpduSize>,
    /// Calling TSAP selector (parameter code 0xC1).
    pub src_tsap: Option<Vec<u8>>,
    /// Called TSAP selector (parameter code 0xC2).
    pub dst_tsap: Option<Vec<u8>>,
}

impl CotpParams {
    /// Decode the variable part of a CR/CC TPDU from a byte slice.
    ///
    /// Unknown parameter codes are skipped tolerantly. Truncation or
    /// malformed lengths produce typed errors; oversized TSAP selectors are
    /// rejected with `CotpInvalidParameter`.
    pub fn decode(mut buf: &[u8]) -> Result<Self> {
        let mut params = CotpParams::default();

        while !buf.is_empty() {
            // Need at least code (1) + length (1).
            if buf.len() < 2 {
                return Err(Error::CotpTruncated);
            }
            let code = buf[0];
            let value_len = buf[1] as usize;
            buf = &buf[2..];

            if buf.len() < value_len {
                return Err(Error::CotpTruncated);
            }
            let value = &buf[..value_len];
            buf = &buf[value_len..];

            match code {
                PARAM_TPDU_SIZE => {
                    if value_len != 1 {
                        return Err(Error::CotpInvalidParameter { code });
                    }
                    let exponent = value[0];
                    let size = TpduSize::new(exponent)
                        .map_err(|_| Error::CotpInvalidParameter { code })?;
                    params.tpdu_size = Some(size);
                }
                PARAM_SRC_TSAP => {
                    if value_len > MAX_TSAP_LEN {
                        return Err(Error::CotpInvalidParameter { code });
                    }
                    params.src_tsap = Some(value.to_vec());
                }
                PARAM_DST_TSAP => {
                    if value_len > MAX_TSAP_LEN {
                        return Err(Error::CotpInvalidParameter { code });
                    }
                    params.dst_tsap = Some(value.to_vec());
                }
                _ => {
                    // Unknown parameter — skip tolerantly.
                }
            }
        }
        Ok(params)
    }

    /// Encode the parameters into `out`.
    ///
    /// Each present parameter is written as code (1 B) + length (1 B) + value.
    ///
    /// Returns `Err(CotpInvalidParameter)` if a TSAP selector exceeds
    /// [`MAX_TSAP_LEN`] (the per-parameter length field is a single octet and
    /// the decoder rejects oversized selectors symmetrically). On error `out`
    /// may have been partially written; callers that need atomicity should
    /// encode into a scratch buffer.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if let Some(size) = self.tpdu_size {
            out.push(PARAM_TPDU_SIZE);
            out.push(1);
            out.push(size.exponent());
        }
        if let Some(tsap) = &self.src_tsap {
            if tsap.len() > MAX_TSAP_LEN {
                return Err(Error::CotpInvalidParameter {
                    code: PARAM_SRC_TSAP,
                });
            }
            out.push(PARAM_SRC_TSAP);
            out.push(tsap.len() as u8);
            out.extend_from_slice(tsap);
        }
        if let Some(tsap) = &self.dst_tsap {
            if tsap.len() > MAX_TSAP_LEN {
                return Err(Error::CotpInvalidParameter {
                    code: PARAM_DST_TSAP,
                });
            }
            out.push(PARAM_DST_TSAP);
            out.push(tsap.len() as u8);
            out.extend_from_slice(tsap);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpdu_size_valid_range() {
        for exp in 7u8..=13 {
            let ts = TpduSize::new(exp).unwrap();
            assert_eq!(ts.exponent(), exp);
            assert_eq!(ts.bytes(), 1usize << exp);
        }
    }

    #[test]
    fn tpdu_size_below_min_is_error() {
        assert!(matches!(
            TpduSize::new(6),
            Err(Error::CotpInvalidTpduSize { exponent: 6 })
        ));
    }

    #[test]
    fn tpdu_size_above_max_is_error() {
        assert!(matches!(
            TpduSize::new(14),
            Err(Error::CotpInvalidTpduSize { exponent: 14 })
        ));
    }

    #[test]
    fn tpdu_size_zero_is_error() {
        assert!(matches!(
            TpduSize::new(0),
            Err(Error::CotpInvalidTpduSize { exponent: 0 })
        ));
    }

    #[test]
    fn size_1024_constant() {
        assert_eq!(TpduSize::SIZE_1024.exponent(), 10);
        assert_eq!(TpduSize::SIZE_1024.bytes(), 1024);
    }

    // ---- CotpParams encode/decode round-trip --------------------------------

    fn roundtrip(params: &CotpParams) -> CotpParams {
        let mut buf = Vec::new();
        params.encode(&mut buf).unwrap();
        CotpParams::decode(&buf).unwrap()
    }

    #[test]
    fn params_empty_roundtrip() {
        let params = CotpParams::default();
        assert_eq!(roundtrip(&params), params);
    }

    #[test]
    fn params_all_fields_roundtrip() {
        let params = CotpParams {
            tpdu_size: Some(TpduSize::SIZE_1024),
            src_tsap: Some(vec![0x00, 0x01]),
            dst_tsap: Some(vec![0x00, 0x02]),
        };
        assert_eq!(roundtrip(&params), params);
    }

    #[test]
    fn params_only_tpdu_size_roundtrip() {
        let params = CotpParams {
            tpdu_size: Some(TpduSize::new(8).unwrap()),
            src_tsap: None,
            dst_tsap: None,
        };
        assert_eq!(roundtrip(&params), params);
    }

    #[test]
    fn params_only_tsap_selectors_roundtrip() {
        let params = CotpParams {
            tpdu_size: None,
            src_tsap: Some(vec![0x00, 0x03]),
            dst_tsap: Some(vec![0x00, 0x04]),
        };
        assert_eq!(roundtrip(&params), params);
    }

    #[test]
    fn params_empty_tsap_selectors_roundtrip() {
        let params = CotpParams {
            tpdu_size: None,
            src_tsap: Some(vec![]),
            dst_tsap: Some(vec![]),
        };
        assert_eq!(roundtrip(&params), params);
    }

    #[test]
    fn params_max_tsap_len_accepted() {
        let tsap = vec![0xAAu8; MAX_TSAP_LEN];
        let buf = {
            let mut b = Vec::new();
            b.push(PARAM_SRC_TSAP);
            b.push(MAX_TSAP_LEN as u8);
            b.extend_from_slice(&tsap);
            b
        };
        let params = CotpParams::decode(&buf).unwrap();
        assert_eq!(params.src_tsap.unwrap(), tsap);
    }

    #[test]
    fn params_encode_oversized_src_tsap_rejected() {
        let params = CotpParams {
            tpdu_size: None,
            src_tsap: Some(vec![0xAAu8; MAX_TSAP_LEN + 1]),
            dst_tsap: None,
        };
        let mut buf = Vec::new();
        assert!(matches!(
            params.encode(&mut buf),
            Err(Error::CotpInvalidParameter { code: 0xC1 })
        ));
    }

    #[test]
    fn params_encode_oversized_dst_tsap_rejected() {
        let params = CotpParams {
            tpdu_size: None,
            src_tsap: None,
            dst_tsap: Some(vec![0xBBu8; MAX_TSAP_LEN + 1]),
        };
        let mut buf = Vec::new();
        assert!(matches!(
            params.encode(&mut buf),
            Err(Error::CotpInvalidParameter { code: 0xC2 })
        ));
    }

    #[test]
    fn params_encode_max_tsap_len_ok() {
        let params = CotpParams {
            tpdu_size: None,
            src_tsap: Some(vec![0xAAu8; MAX_TSAP_LEN]),
            dst_tsap: Some(vec![0xBBu8; MAX_TSAP_LEN]),
        };
        assert_eq!(roundtrip(&params), params);
    }

    #[test]
    fn params_oversized_tsap_rejected() {
        let too_long = vec![0xAAu8; MAX_TSAP_LEN + 1];
        let buf = {
            let mut b = Vec::new();
            b.push(PARAM_SRC_TSAP);
            b.push((MAX_TSAP_LEN + 1) as u8);
            b.extend_from_slice(&too_long);
            b
        };
        assert!(matches!(
            CotpParams::decode(&buf),
            Err(Error::CotpInvalidParameter { code: 0xC1 })
        ));
    }

    #[test]
    fn params_unknown_code_skipped() {
        // Insert an unknown parameter (code 0xDE, len 2, value [0x01, 0x02])
        // followed by a known TPDU-size parameter.
        let buf = [0xDEu8, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A];
        let params = CotpParams::decode(&buf).unwrap();
        assert_eq!(params.tpdu_size, Some(TpduSize::SIZE_1024));
        assert_eq!(params.src_tsap, None);
    }

    #[test]
    fn params_truncated_mid_code_length() {
        // Only the code byte, no length.
        let buf = [0xC0u8];
        assert!(matches!(
            CotpParams::decode(&buf),
            Err(Error::CotpTruncated)
        ));
    }

    #[test]
    fn params_truncated_mid_value() {
        // code 0xC0, length 1, but no value byte.
        let buf = [0xC0u8, 0x01];
        assert!(matches!(
            CotpParams::decode(&buf),
            Err(Error::CotpTruncated)
        ));
    }

    #[test]
    fn params_tpdu_size_wrong_value_length_is_error() {
        // code 0xC0, length 2 (should be 1), value [0x0A, 0x00].
        let buf = [0xC0u8, 0x02, 0x0A, 0x00];
        assert!(matches!(
            CotpParams::decode(&buf),
            Err(Error::CotpInvalidParameter { code: 0xC0 })
        ));
    }

    #[test]
    fn params_tpdu_size_invalid_exponent_is_error() {
        // code 0xC0, length 1, exponent 6 (< MIN_EXPONENT).
        let buf = [0xC0u8, 0x01, 0x06];
        assert!(matches!(
            CotpParams::decode(&buf),
            Err(Error::CotpInvalidParameter { code: 0xC0 })
        ));
    }
}
