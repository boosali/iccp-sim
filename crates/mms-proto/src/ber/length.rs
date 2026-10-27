//! BER definite/indefinite length encoding and decoding.
//!
//! # Encoding rules produced by this module
//! - Values 0..=127: short form, single octet.
//! - Values >= 128: long form, minimal number of octets.
//!   First octet is `0x80 | n_octets`, then `n_octets` big-endian.
//!
//! # Decoding rules
//! - 0x80: indefinite length (the caller decides whether it is legal).
//! - 0xFF: reserved — returns `BerInvalidTag`.
//! - Long form with more than 4 length octets (>32-bit length) returns
//!   `BerLengthOverflow`.
//! - Non-minimal long-form encodings are accepted on read (tolerant).

use crate::{Error, Result};

/// Outcome of decoding a length field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthForm {
    /// A definite length `n`.
    Definite(usize),
    /// Indefinite length (content extends to end-of-contents `00 00`).
    Indefinite,
}

/// Encode a definite length and append it to `out`.
pub fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        // How many octets does `len` need?
        let n_octets = length_octets_needed(len);
        out.push(0x80 | n_octets as u8);
        // Big-endian, minimal.
        for shift in (0..n_octets).rev() {
            out.push((len >> (shift * 8)) as u8);
        }
    }
}

/// Decode the length field starting at `buf[0]`.
///
/// Returns `Ok(Some((form, bytes_consumed)))` on success or
/// `Ok(None)` if `buf` is empty (caller should treat as truncated).
///
/// Returns `Err` for reserved or overflowing encodings.
pub fn decode_length(buf: &[u8]) -> Result<Option<(LengthForm, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let first = buf[0];

    if first == 0xFF {
        // Reserved by BER/DER.
        return Err(Error::BerInvalidTag);
    }

    if first == 0x80 {
        return Ok(Some((LengthForm::Indefinite, 1)));
    }

    if (first & 0x80) == 0 {
        // Short form: 0x00..=0x7F.
        return Ok(Some((LengthForm::Definite(first as usize), 1)));
    }

    // Long form: low 7 bits = number of length octets.
    let n = (first & 0x7F) as usize;
    if n > 4 {
        // More than 4 octets of length = value > u32::MAX, refuse.
        return Err(Error::BerLengthOverflow { len: n as u64 });
    }
    if buf.len() < 1 + n {
        return Err(Error::BerTruncated {
            needed: 1 + n,
            have: buf.len(),
        });
    }

    let mut len: u64 = 0;
    for &b in &buf[1..=n] {
        len = (len << 8) | b as u64;
    }

    // Convert to usize (on 32-bit targets usize may be 32 bits).
    let len_usize = usize::try_from(len).map_err(|_| Error::BerLengthOverflow { len })?;

    Ok(Some((LengthForm::Definite(len_usize), 1 + n)))
}

/// Minimum number of big-endian octets needed to represent `len`.
fn length_octets_needed(len: usize) -> usize {
    if len <= 0xFF {
        1
    } else if len <= 0xFFFF {
        2
    } else if len <= 0xFF_FFFF {
        3
    } else if len <= 0xFFFF_FFFF {
        4
    } else {
        // usize is wider than u32 on 64-bit; use 8 octets max.
        // In practice BER encoders rarely produce lengths > 4 GiB.
        8
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let mut buf = Vec::new();
        encode_length(len, &mut buf);
        let (form, consumed) = decode_length(&buf).expect("decode ok").expect("not empty");
        assert_eq!(
            consumed,
            buf.len(),
            "should consume all bytes for len={len}"
        );
        assert_eq!(
            form,
            LengthForm::Definite(len),
            "roundtrip failed for len={len}"
        );
    }

    #[test]
    fn short_form_boundaries() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(127);
    }

    #[test]
    fn long_form_boundaries() {
        roundtrip(128);
        roundtrip(255);
        roundtrip(256);
        roundtrip(65535);
        roundtrip(65536);
    }

    #[test]
    fn non_minimal_long_form_accepted() {
        // 0x82 0x00 0x05 encodes 5 using 2 length octets (non-minimal, should be 0x05).
        let buf = [0x82u8, 0x00, 0x05];
        let (form, consumed) = decode_length(&buf).unwrap().unwrap();
        assert_eq!(form, LengthForm::Definite(5));
        assert_eq!(consumed, 3);
    }

    #[test]
    fn indefinite_length() {
        let buf = [0x80u8];
        let (form, consumed) = decode_length(&buf).unwrap().unwrap();
        assert_eq!(form, LengthForm::Indefinite);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn reserved_0xff_rejected() {
        assert!(matches!(decode_length(&[0xFF]), Err(Error::BerInvalidTag)));
    }

    #[test]
    fn more_than_4_length_octets_rejected() {
        // 0x85 = 5 length octets follow.
        let buf = [0x85u8, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(matches!(
            decode_length(&buf),
            Err(Error::BerLengthOverflow { .. })
        ));
    }

    #[test]
    fn truncated_long_form() {
        // Claims 2 octets but provides only 1.
        let buf = [0x82u8, 0x01];
        assert!(matches!(
            decode_length(&buf),
            Err(Error::BerTruncated { .. })
        ));
    }

    #[test]
    fn empty_returns_none() {
        assert_eq!(decode_length(&[]).unwrap(), None);
    }
}
