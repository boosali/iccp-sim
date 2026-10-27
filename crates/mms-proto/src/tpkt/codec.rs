//! Stateless TPKT encoder/decoder.
//!
//! `decode_slice` is the only re-entrant streaming framer in the stack: it
//! returns `Ok(None)` when the buffer does not yet hold a complete TPKT
//! packet, allowing callers to accumulate bytes and retry without any internal
//! state.

use super::{TPKT_HEADER_LEN, TPKT_MAX_PAYLOAD, TPKT_VERSION};
use crate::{Error, Result};

/// RFC 1006 TPKT framing: stateless encode/decode.
#[derive(Debug)]
pub struct Tpkt;

impl Tpkt {
    /// Attempt to decode one TPKT packet from `buf`.
    ///
    /// Returns:
    /// * `Ok(None)` — the buffer does not yet contain a complete TPKT packet
    ///   (fewer than 4 bytes, or declared length not yet fully received).
    /// * `Ok(Some((payload, consumed)))` — `payload` is the TPKT body (the
    ///   COTP TPDU), and `consumed` is the number of bytes from the start of
    ///   `buf` that belong to this TPKT packet (i.e. the total packet length).
    /// * `Err(_)` — the header is malformed (wrong version or invalid length
    ///   field); the stream is irrecoverably desynchronised.
    ///
    /// This function never panics on any input.
    pub fn decode_slice(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
        // Need at least the 4-byte header.
        if buf.len() < TPKT_HEADER_LEN {
            return Ok(None);
        }

        // byte 0: version
        let version = buf[0];
        if version != TPKT_VERSION {
            return Err(Error::TpktInvalidVersion { got: version });
        }

        // byte 1: reserved — ignored on read.

        // bytes 2-3: total length (big-endian u16, includes the 4-byte header).
        let total_len = u16::from_be_bytes([buf[2], buf[3]]);

        // RFC 1006 minimum: 4-byte header + 3-byte minimum COTP header = 7.
        if total_len < 7 {
            return Err(Error::TpktInvalidLength { len: total_len });
        }

        let total_usize = total_len as usize;

        // Not enough bytes yet — buffer more data and retry.
        if buf.len() < total_usize {
            return Ok(None);
        }

        // Extract the payload slice (everything after the 4-byte header).
        let payload = buf[TPKT_HEADER_LEN..total_usize].to_vec();
        Ok(Some((payload, total_usize)))
    }

    /// Frame `payload` with a 4-byte TPKT header and append the result to
    /// `out`.
    ///
    /// Returns `Err(TpktPayloadTooLong)` if `payload` exceeds the maximum
    /// encodable size (`65_531` bytes, i.e. `65_535 − 4`). On error `out` is
    /// left unchanged.
    pub fn encode(payload: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if payload.len() > TPKT_MAX_PAYLOAD {
            return Err(Error::TpktPayloadTooLong { len: payload.len() });
        }

        // total_len is u16 and fits because we checked payload.len() above.
        let total_len = (TPKT_HEADER_LEN + payload.len()) as u16;
        out.push(TPKT_VERSION);
        out.push(0x00); // reserved
        out.push((total_len >> 8) as u8);
        out.push(total_len as u8);
        out.extend_from_slice(payload);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // Helper: encode a payload and return the resulting bytes.
    fn encode(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        Tpkt::encode(payload, &mut out).expect("encode");
        out
    }

    // ---- decode_slice: incomplete inputs -----------------------------------

    #[test]
    fn decode_slice_empty_returns_none() {
        assert_eq!(Tpkt::decode_slice(&[]).unwrap(), None);
    }

    #[test]
    fn decode_slice_one_byte_returns_none() {
        assert_eq!(Tpkt::decode_slice(&[0x03]).unwrap(), None);
    }

    #[test]
    fn decode_slice_two_bytes_returns_none() {
        assert_eq!(Tpkt::decode_slice(&[0x03, 0x00]).unwrap(), None);
    }

    #[test]
    fn decode_slice_three_bytes_returns_none() {
        assert_eq!(Tpkt::decode_slice(&[0x03, 0x00, 0x00]).unwrap(), None);
    }

    // ---- decode_slice: minimal valid frame (length = 7) --------------------

    #[test]
    fn decode_slice_minimal_valid_frame() {
        // length = 7: header (4) + 3 payload bytes
        let buf = [0x03u8, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC];
        let (payload, consumed) = Tpkt::decode_slice(&buf).unwrap().unwrap();
        assert_eq!(payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(consumed, 7);
    }

    // ---- decode_slice: body not yet available ------------------------------

    #[test]
    fn decode_slice_header_complete_body_missing_returns_none() {
        // Declare length = 10, only supply 7 bytes.
        let buf = [0x03u8, 0x00, 0x00, 0x0A, 0xAA, 0xBB, 0xCC];
        assert_eq!(Tpkt::decode_slice(&buf).unwrap(), None);
    }

    // ---- decode_slice: no over-consume with trailing bytes -----------------

    #[test]
    fn decode_slice_does_not_overconsume() {
        // Two back-to-back TPKT frames; first is 7 bytes, second is 8 bytes.
        let mut buf = Vec::new();
        Tpkt::encode(&[0x01, 0x02, 0x03], &mut buf).unwrap(); // 7 bytes
        Tpkt::encode(&[0x04, 0x05, 0x06, 0x07], &mut buf).unwrap(); // 8 bytes

        let (payload1, consumed1) = Tpkt::decode_slice(&buf).unwrap().unwrap();
        assert_eq!(consumed1, 7);
        assert_eq!(payload1, vec![0x01, 0x02, 0x03]);

        let (payload2, consumed2) = Tpkt::decode_slice(&buf[consumed1..]).unwrap().unwrap();
        assert_eq!(consumed2, 8);
        assert_eq!(payload2, vec![0x04, 0x05, 0x06, 0x07]);
    }

    // ---- decode_slice: drain loop over back-to-back frames -----------------

    #[test]
    fn decode_slice_drain_loop_back_to_back() {
        let payloads: &[&[u8]] = &[
            &[0xAA, 0xBB, 0xCC],
            &[0x11, 0x22, 0x33, 0x44],
            &[0xDE, 0xAD, 0xBE],
        ];

        let mut stream = Vec::new();
        for p in payloads {
            Tpkt::encode(p, &mut stream).unwrap();
        }

        let mut pos = 0usize;
        let mut decoded = Vec::new();
        loop {
            match Tpkt::decode_slice(&stream[pos..]).unwrap() {
                None => break,
                Some((payload, consumed)) => {
                    assert!(consumed > 0, "consumed must be > 0 to avoid infinite loop");
                    decoded.push(payload);
                    pos += consumed;
                }
            }
        }
        assert_eq!(pos, stream.len());
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], &[0xAA, 0xBB, 0xCC]);
        assert_eq!(decoded[1], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(decoded[2], &[0xDE, 0xAD, 0xBE]);
    }

    // ---- decode_slice: error cases -----------------------------------------

    #[test]
    fn decode_slice_wrong_version_is_error() {
        let buf = [0x04u8, 0x00, 0x00, 0x07, 0xAA, 0xBB, 0xCC];
        assert!(matches!(
            Tpkt::decode_slice(&buf),
            Err(Error::TpktInvalidVersion { got: 4 })
        ));
    }

    #[test]
    fn decode_slice_length_6_is_error() {
        let buf = [0x03u8, 0x00, 0x00, 0x06, 0xAA, 0xBB];
        assert!(matches!(
            Tpkt::decode_slice(&buf),
            Err(Error::TpktInvalidLength { len: 6 })
        ));
    }

    #[test]
    fn decode_slice_length_zero_is_error() {
        let buf = [0x03u8, 0x00, 0x00, 0x00];
        assert!(matches!(
            Tpkt::decode_slice(&buf),
            Err(Error::TpktInvalidLength { len: 0 })
        ));
    }

    // ---- decode_slice: max length ------------------------------------------

    #[test]
    fn decode_slice_max_length_65535() {
        // Total 65535 bytes: header (4) + 65531-byte payload.
        let payload = vec![0xABu8; 65_531];
        let frame = encode(&payload);
        assert_eq!(frame.len(), 65_535);

        let (decoded_payload, consumed) = Tpkt::decode_slice(&frame).unwrap().unwrap();
        assert_eq!(consumed, 65_535);
        assert_eq!(decoded_payload, payload);
    }

    // ---- encode: overflow rejected -----------------------------------------

    #[test]
    fn encode_payload_too_long_is_error() {
        let huge = vec![0u8; 65_532]; // 65_535 - 4 + 1 = too large
        let mut out = Vec::new();
        let result = Tpkt::encode(&huge, &mut out);
        assert!(
            matches!(result, Err(Error::TpktPayloadTooLong { len: 65_532 })),
            "got {result:?}"
        );
        // out must be unchanged on error.
        assert!(out.is_empty());
    }

    // ---- encode → decode identity ------------------------------------------

    #[test]
    fn encode_decode_identity_typical() {
        let payload = b"hello COTP";
        let frame = encode(payload);
        let (decoded, consumed) = Tpkt::decode_slice(&frame).unwrap().unwrap();
        assert_eq!(consumed, frame.len());
        assert_eq!(decoded, payload);
    }

    /// Document the asymmetry: encode allows small payloads (< 3 bytes) that
    /// would fail the strict RFC minimum of 7 if decoded. Callers at the COTP
    /// layer always produce at least a 3-byte TPDU, so this is fine in practice.
    ///
    /// A payload of 2 bytes → total_len = 6, which decode_slice rejects with
    /// TpktInvalidLength. A payload of 3 bytes → total_len = 7, which is the
    /// minimum valid length.
    #[test]
    fn encode_two_byte_payload_gives_length_6_which_decode_rejects() {
        let payload = &[0xAA, 0xBB];
        let frame = encode(payload);
        // The frame starts with 03 00 00 06 (length = 6).
        assert_eq!(frame[2], 0x00);
        assert_eq!(frame[3], 0x06);
        // decode_slice rejects it.
        assert!(matches!(
            Tpkt::decode_slice(&frame),
            Err(Error::TpktInvalidLength { len: 6 })
        ));
    }

    #[test]
    fn encode_three_byte_payload_gives_length_7_which_decode_accepts() {
        let payload = &[0xAA, 0xBB, 0xCC];
        let frame = encode(payload);
        assert_eq!(frame[3], 0x07);
        let (decoded, _) = Tpkt::decode_slice(&frame).unwrap().unwrap();
        assert_eq!(decoded, payload);
    }

    // ---- encode: reserved byte is 0x00 -------------------------------------

    #[test]
    fn encode_reserved_byte_is_zero() {
        let frame = encode(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(frame[1], 0x00);
    }

    // ---- decode_slice: reserved byte is ignored on read --------------------

    #[test]
    fn decode_slice_reserved_byte_nonzero_is_ignored() {
        // Same as minimal valid frame but with byte 1 = 0xFF.
        let buf = [0x03u8, 0xFF, 0x00, 0x07, 0xAA, 0xBB, 0xCC];
        let (payload, consumed) = Tpkt::decode_slice(&buf).unwrap().unwrap();
        assert_eq!(payload, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(consumed, 7);
    }
}
