//! COTP DT-TPDU reassembly buffer.
//!
//! ISO 8073 class 0 allows a single TSDU (Transport Service Data Unit) to be
//! split across multiple DT TPDUs.  The last (or only) DT sets the EOT
//! (End-Of-TSDU) bit in its TPDU-NR/EOT octet.  This module provides a simple
//! stateful helper that accumulates user data from successive DT TPDUs and
//! returns the complete TSDU once EOT is seen.

use crate::{Error, Result};

/// Stateful reassembler for COTP DT-TPDU streams.
///
/// The reassembler accumulates user data across multiple DT TPDUs, returning
/// the complete TSDU when the DT with EOT set is received.
///
/// On [`CotpReassemblyOverflow`](Error::CotpReassemblyOverflow) the internal
/// buffer is automatically reset, preventing unbounded growth.
#[derive(Debug)]
pub struct CotpReassembler {
    buf: Vec<u8>,
    max: usize,
}

impl CotpReassembler {
    /// Default maximum TSDU size: 256 KiB.
    pub const DEFAULT_MAX: usize = 262_144;

    /// Create a new reassembler that will reject TSDUs larger than `max` bytes.
    pub fn new(max: usize) -> Self {
        CotpReassembler {
            buf: Vec::new(),
            max,
        }
    }

    /// Append the user data from one DT TPDU.
    ///
    /// Returns `Ok(Some(tsdu))` when `eot` is `true`, indicating that the
    /// TSDU is complete.  The internal buffer is reset after a successful
    /// completion so the reassembler is ready for the next TSDU.
    ///
    /// Returns `Ok(None)` when `eot` is `false` — more fragments are expected.
    ///
    /// Returns `Err(CotpReassemblyOverflow)` if the accumulated size would
    /// exceed `max`.  The internal buffer is reset on overflow.
    pub fn push(&mut self, payload: &[u8], eot: bool) -> Result<Option<Vec<u8>>> {
        // Overflow check before any mutation.
        let new_len = self.buf.len().saturating_add(payload.len());
        if new_len > self.max {
            self.buf.clear();
            return Err(Error::CotpReassemblyOverflow { max: self.max });
        }

        self.buf.extend_from_slice(payload);

        if eot {
            let tsdu = core::mem::take(&mut self.buf);
            Ok(Some(tsdu))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` if no data has been accumulated yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Reset the internal buffer, discarding any partially-reassembled TSDU.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_fragment_with_eot() {
        let mut r = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
        let result = r.push(b"hello", true).unwrap();
        assert_eq!(result, Some(b"hello".to_vec()));
        assert!(r.is_empty());
    }

    #[test]
    fn multiple_fragments_reassembled() {
        let mut r = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
        assert_eq!(r.push(b"foo", false).unwrap(), None);
        assert!(!r.is_empty());
        assert_eq!(r.push(b"bar", false).unwrap(), None);
        let result = r.push(b"baz", true).unwrap();
        assert_eq!(result, Some(b"foobarbaz".to_vec()));
        assert!(r.is_empty());
    }

    #[test]
    fn empty_payload_with_eot() {
        let mut r = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
        let result = r.push(b"", true).unwrap();
        assert_eq!(result, Some(vec![]));
        assert!(r.is_empty());
    }

    #[test]
    fn overflow_at_boundary_exactly_max_ok() {
        let max = 10usize;
        let mut r = CotpReassembler::new(max);
        // Exactly max bytes: OK.
        let data = vec![0xAAu8; max];
        let result = r.push(&data, true).unwrap();
        assert_eq!(result, Some(data));
        assert!(r.is_empty());
    }

    #[test]
    fn overflow_one_over_max_is_error() {
        let max = 10usize;
        let mut r = CotpReassembler::new(max);
        let data = vec![0xAAu8; max + 1];
        let err = r.push(&data, false).unwrap_err();
        assert!(
            matches!(err, Error::CotpReassemblyOverflow { max: 10 }),
            "got {err:?}"
        );
        // Buffer must be reset after overflow.
        assert!(r.is_empty());
    }

    #[test]
    fn overflow_accumulation_triggers_error() {
        let max = 10usize;
        let mut r = CotpReassembler::new(max);
        // Push 6 bytes (within limit).
        assert_eq!(r.push(b"abcdef", false).unwrap(), None);
        // Push 5 more bytes: total 11 > 10.
        let err = r.push(b"12345", false).unwrap_err();
        assert!(matches!(err, Error::CotpReassemblyOverflow { max: 10 }));
        // State is reset: can start a new TSDU.
        assert!(r.is_empty());
        let result = r.push(b"new", true).unwrap();
        assert_eq!(result, Some(b"new".to_vec()));
    }

    #[test]
    fn clear_resets_state() {
        let mut r = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
        r.push(b"partial", false).unwrap();
        assert!(!r.is_empty());
        r.clear();
        assert!(r.is_empty());
        // Can start fresh.
        let result = r.push(b"fresh", true).unwrap();
        assert_eq!(result, Some(b"fresh".to_vec()));
    }

    #[test]
    fn is_empty_initially() {
        let r = CotpReassembler::new(CotpReassembler::DEFAULT_MAX);
        assert!(r.is_empty());
    }
}
