//! TASE.2 `DataFlags` quality octet and its MMS `BitString` mapping.
//!
//! # Ground truth
//! The numeric layout of the DataFlags octet is taken from libtase2's
//! `Tase2_DataFlags` enum
//! (<https://support.mz-automation.de/doc/libtase2/c/latest/group__tase2__point__value.html>):
//!
//! | Field          | Bits  | Values (octet contribution)                       |
//! |----------------|-------|---------------------------------------------------|
//! | (state, unused)| 0..=1 | used only by `Data_State*`; otherwise zero        |
//! | validity       | 2..=3 | VALID=0, SUSPECT=4, HELD=8, NOTVALID=12           |
//! | current source | 4..=5 | TELEMETERED=0, ENTERED=16, CALCULATED=32, ESTIM.=48|
//! | normal value   | 6     | NORMAL_VALUE=64                                   |
//! | timestamp qual.| 7     | TIME_STAMP_QUALITY=128                            |
//!
//! So the *octet value* equals the OR of those constants: e.g. an octet of
//! `0x44` = 64 (normal) | 4 (suspect) means normal-value set, validity=suspect.
//!
//! # Octet ↔ MMS BitString bit order
//! On the wire the octet is carried as an MMS `BitString` of 8 bits. MMS
//! `BitString` is **MSB-first**: bit index 0 is the most-significant bit
//! (`0x80`). The libtase2 numbering above is **LSB-aligned** (its "bit n" has
//! numeric weight `1 << n`). The two are mirror images: octet bit `n`
//! (weight `1<<n`) lands at MMS BitString index `7 - n`.
//!
//! Concretely, the MMS `BitString` produced by [`Quality::to_bit_string`] has
//! the same 8 raw bits as the octet itself (`data = [octet]`), because
//! [`mms_proto::ber::primitives::BitString::from_bits`] also packs MSB-first.
//! We therefore build the bit-string directly from the octet's bits with index
//! 0 = MSB, which is bit-exact with the octet. This is asserted in the tests.

use mms_proto::ber::primitives::BitString;

use crate::{Error, Result};

// Octet masks, matching libtase2 `Tase2_DataFlags`. Bits 0..=1 are the
// "unused" quality bits, reused by `Data_State*` for the 2-bit state value.
const MASK_VALIDITY: u8 = 0b0000_1100; // bits 2..=3
const MASK_SOURCE: u8 = 0b0011_0000; // bits 4..=5
const MASK_NORMAL_VALUE: u8 = 0b0100_0000; // bit 6
const MASK_TIMESTAMP_QUALITY: u8 = 0b1000_0000; // bit 7

/// Validity of a data value (DataFlags bits 2..=3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Validity {
    /// `VALID` (0).
    #[default]
    Valid,
    /// `HELD` (8) — value is frozen / not currently updated.
    Held,
    /// `SUSPECT` (4) — value may be unreliable.
    Suspect,
    /// `NOTVALID` (12).
    NotValid,
}

impl Validity {
    fn from_octet(o: u8) -> Self {
        match o & MASK_VALIDITY {
            0 => Validity::Valid,
            4 => Validity::Suspect,
            8 => Validity::Held,
            _ => Validity::NotValid, // 12
        }
    }

    fn to_octet(self) -> u8 {
        match self {
            Validity::Valid => 0,
            Validity::Suspect => 4,
            Validity::Held => 8,
            Validity::NotValid => 12,
        }
    }
}

/// Current source of a data value (DataFlags bits 4..=5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Source {
    /// `TELEMETERED` (0).
    #[default]
    Telemetered,
    /// `CALCULATED` (32).
    Calculated,
    /// `ENTERED` (16).
    Entered,
    /// `ESTIMATED` (48).
    Estimated,
}

impl Source {
    fn from_octet(o: u8) -> Self {
        match o & MASK_SOURCE {
            0 => Source::Telemetered,
            16 => Source::Entered,
            32 => Source::Calculated,
            _ => Source::Estimated, // 48
        }
    }

    fn to_octet(self) -> u8 {
        match self {
            Source::Telemetered => 0,
            Source::Entered => 16,
            Source::Calculated => 32,
            Source::Estimated => 48,
        }
    }
}

/// The TASE.2 `DataFlags` quality descriptor.
///
/// Maps to/from the single DataFlags octet and the MMS `BitString(8)` carried
/// on the wire. The two low bits (0..=1) are not represented here: they are
/// "unused" for quality and reused by `Data_State*` to carry the state value
/// (see [`crate::StateValue`]). [`Quality::pack`] always emits them as zero;
/// the state value is layered on separately by the value codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quality {
    /// Validity (bits 2..=3).
    pub validity: Validity,
    /// Current source (bits 4..=5).
    pub source: Source,
    /// Normal-value flag (bit 6): the value equals its configured normal value.
    pub normal_value: bool,
    /// Timestamp-quality flag (bit 7): the associated timestamp is good.
    pub timestamp_quality_good: bool,
}

impl Default for Quality {
    /// A "good" default: VALID, TELEMETERED, normal-value set, timestamp good.
    fn default() -> Self {
        Quality {
            validity: Validity::Valid,
            source: Source::Telemetered,
            normal_value: true,
            timestamp_quality_good: true,
        }
    }
}

impl Quality {
    /// Pack into the DataFlags octet (bits 0..=1 left zero).
    #[must_use]
    pub fn pack(self) -> u8 {
        let mut o = 0u8;
        o |= self.validity.to_octet();
        o |= self.source.to_octet();
        if self.normal_value {
            o |= MASK_NORMAL_VALUE;
        }
        if self.timestamp_quality_good {
            o |= MASK_TIMESTAMP_QUALITY;
        }
        o
    }

    /// Unpack from a DataFlags octet, ignoring the two low (state/unused) bits.
    #[must_use]
    pub fn unpack(octet: u8) -> Self {
        Quality {
            validity: Validity::from_octet(octet),
            source: Source::from_octet(octet),
            normal_value: octet & MASK_NORMAL_VALUE != 0,
            timestamp_quality_good: octet & MASK_TIMESTAMP_QUALITY != 0,
        }
    }

    /// Encode the DataFlags octet `o` as an MMS `BitString` of 8 bits,
    /// MSB-first (bit index 0 = `0x80`).
    #[must_use]
    pub fn octet_to_bit_string(o: u8) -> BitString {
        // MSB-first: index 0 carries 0x80 ... index 7 carries 0x01. This is
        // exactly the octet's own bit layout, so the resulting `data` is `[o]`.
        let bits: [bool; 8] = core::array::from_fn(|i| (o >> (7 - i)) & 1 == 1);
        BitString::from_bits(&bits)
    }

    /// Decode a DataFlags octet from an MMS `BitString` of (up to) 8 bits.
    ///
    /// Reads the first 8 bits MSB-first; missing trailing bits read as zero.
    /// Returns [`Error::InvalidFlags`] if the bit-string carries more than 8
    /// significant bits.
    pub fn octet_from_bit_string(bs: &BitString) -> Result<u8> {
        if bs.bit_len() > 8 {
            return Err(Error::InvalidFlags);
        }
        let mut o = 0u8;
        for i in 0..8 {
            if bs.bit(i) {
                o |= 1 << (7 - i);
            }
        }
        Ok(o)
    }

    /// Encode this quality as the MMS `BitString(8)` DataFlags value (state bits
    /// zero).
    #[must_use]
    pub fn to_bit_string(self) -> BitString {
        Self::octet_to_bit_string(self.pack())
    }

    /// Decode quality from an MMS DataFlags `BitString`.
    pub fn from_bit_string(bs: &BitString) -> Result<Self> {
        Ok(Self::unpack(Self::octet_from_bit_string(bs)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_good() {
        let q = Quality::default();
        assert_eq!(q.validity, Validity::Valid);
        assert_eq!(q.source, Source::Telemetered);
        assert!(q.normal_value);
        assert!(q.timestamp_quality_good);
        // VALID(0)|TELEMETERED(0)|NORMAL(64)|TSQ(128) = 192.
        assert_eq!(q.pack(), 0b1100_0000);
    }

    #[test]
    fn known_octets_decode_correctly() {
        // 0x44 = 64 (normal) | 4 (suspect).
        let q = Quality::unpack(0x44);
        assert_eq!(q.validity, Validity::Suspect);
        assert_eq!(q.source, Source::Telemetered);
        assert!(q.normal_value);
        assert!(!q.timestamp_quality_good);

        // ESTIMATED(48) | HELD(8) | TSQ(128) = 0xB8.
        let q = Quality::unpack(0xB8);
        assert_eq!(q.validity, Validity::Held);
        assert_eq!(q.source, Source::Estimated);
        assert!(!q.normal_value);
        assert!(q.timestamp_quality_good);
    }

    #[test]
    fn bit_string_is_bit_exact_with_octet() {
        // The MMS BitString of a DataFlags octet has `data == [octet]`.
        for o in 0u8..=255 {
            let bs = Quality::octet_to_bit_string(o);
            assert_eq!(bs.unused_bits, 0);
            assert_eq!(bs.data, vec![o], "octet {o:#04x}");
            assert_eq!(Quality::octet_from_bit_string(&bs).unwrap(), o);
        }
    }

    #[test]
    fn bit7_is_msb_in_bit_string() {
        // TIME_STAMP_QUALITY = 128 = octet bit 7 → MMS BitString index 0 (MSB).
        let bs = Quality::octet_to_bit_string(0x80);
        assert!(bs.bit(0), "octet bit 7 must be MMS BitString index 0");
        for i in 1..8 {
            assert!(!bs.bit(i));
        }
        // SUSPECT = 4 = octet bit 2 → MMS BitString index 5.
        let bs = Quality::octet_to_bit_string(0x04);
        assert!(bs.bit(5), "octet bit 2 must be MMS BitString index 5");
    }

    #[test]
    fn over_wide_bit_string_rejected() {
        let bs = BitString::from_bits(&[true; 9]);
        assert_eq!(
            Quality::octet_from_bit_string(&bs),
            Err(Error::InvalidFlags)
        );
    }
}
