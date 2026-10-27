//! ASN.1 BER tag encoding and decoding.
//!
//! Tags are encoded as one or more octets. When the low five bits of the
//! first octet are all set (`0b11111 = 31`), the actual tag number follows
//! in base-128 continuation octets (MSB = 1 means more octets follow).
//!
//! This module supports tag numbers up to `u32::MAX`.

use crate::{Error, Result};

// ---------------------------------------------------------------------------
// Tag class
// ---------------------------------------------------------------------------

/// The class of an ASN.1 tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl TagClass {
    /// Encode the class into the top two bits of the first tag octet.
    pub(crate) const fn bits(self) -> u8 {
        match self {
            TagClass::Universal => 0b0000_0000,
            TagClass::Application => 0b0100_0000,
            TagClass::ContextSpecific => 0b1000_0000,
            TagClass::Private => 0b1100_0000,
        }
    }

    pub(crate) fn from_bits(b: u8) -> Self {
        match b & 0b1100_0000 {
            0b0000_0000 => TagClass::Universal,
            0b0100_0000 => TagClass::Application,
            0b1000_0000 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        }
    }
}

// ---------------------------------------------------------------------------
// Tag
// ---------------------------------------------------------------------------

/// A fully qualified ASN.1 tag (class, constructed flag, tag number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub number: u32,
}

impl Tag {
    // --- Constructors -------------------------------------------------------

    /// Universal primitive tag with the given number.
    #[must_use]
    pub const fn universal(n: u32) -> Self {
        Tag {
            class: TagClass::Universal,
            constructed: false,
            number: n,
        }
    }

    /// Context-specific primitive tag.
    #[must_use]
    pub const fn context(n: u32) -> Self {
        Tag {
            class: TagClass::ContextSpecific,
            constructed: false,
            number: n,
        }
    }

    /// Context-specific constructed tag.
    #[must_use]
    pub const fn context_constructed(n: u32) -> Self {
        Tag {
            class: TagClass::ContextSpecific,
            constructed: true,
            number: n,
        }
    }

    /// Application primitive tag.
    #[must_use]
    pub const fn application(n: u32) -> Self {
        Tag {
            class: TagClass::Application,
            constructed: false,
            number: n,
        }
    }

    /// Application constructed tag.
    #[must_use]
    pub const fn application_constructed(n: u32) -> Self {
        Tag {
            class: TagClass::Application,
            constructed: true,
            number: n,
        }
    }

    // --- Universal constants ------------------------------------------------

    /// BOOLEAN (Universal 1, primitive).
    pub const BOOLEAN: Tag = Tag::universal(1);
    /// INTEGER (Universal 2, primitive).
    pub const INTEGER: Tag = Tag::universal(2);
    /// BIT STRING (Universal 3, primitive).
    pub const BIT_STRING: Tag = Tag::universal(3);
    /// OCTET STRING (Universal 4, primitive).
    pub const OCTET_STRING: Tag = Tag::universal(4);
    /// NULL (Universal 5, primitive).
    pub const NULL: Tag = Tag::universal(5);
    /// OBJECT IDENTIFIER (Universal 6, primitive).
    pub const OID: Tag = Tag::universal(6);
    /// EXTERNAL (Universal 8, constructed).
    pub const EXTERNAL: Tag = Tag {
        class: TagClass::Universal,
        constructed: true,
        number: 8,
    };
    /// SEQUENCE / SEQUENCE OF (Universal 16, constructed).
    pub const SEQUENCE: Tag = Tag {
        class: TagClass::Universal,
        constructed: true,
        number: 16,
    };
    /// GeneralizedTime (Universal 24, primitive).
    pub const GENERALIZED_TIME: Tag = Tag::universal(24);
    /// VisibleString (Universal 26, primitive).
    pub const VISIBLE_STRING: Tag = Tag::universal(26);

    // --- Wire encoding/decoding ---------------------------------------------

    /// Encode this tag and append the octets to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        let class_bits = self.class.bits();
        let constructed_bit: u8 = if self.constructed { 0b0010_0000 } else { 0 };

        if self.number < 31 {
            // Short form: single octet.
            out.push(class_bits | constructed_bit | self.number as u8);
        } else {
            // Long form: first octet has low-5 bits set to 0b11111, followed by
            // base-128 continuation octets (big-endian, MSB = 1 = more follow).
            out.push(class_bits | constructed_bit | 0b0001_1111u8);
            encode_base128_u32(self.number, out);
        }
    }

    /// Decode a tag from `buf`. Returns `(tag, bytes_consumed)`.
    ///
    /// Returns `Error::BerTruncated` if `buf` ends mid-tag, and
    /// `Error::BerInvalidTag` if the tag number would overflow `u32`.
    pub fn decode(buf: &[u8]) -> Result<(Tag, usize)> {
        if buf.is_empty() {
            return Err(Error::BerTruncated { needed: 1, have: 0 });
        }

        let first = buf[0];
        let class = TagClass::from_bits(first);
        let constructed = (first & 0b0010_0000) != 0;
        let low5 = first & 0b0001_1111;

        if low5 < 31 {
            // Short form.
            return Ok((
                Tag {
                    class,
                    constructed,
                    number: low5 as u32,
                },
                1,
            ));
        }

        // Long form: read base-128 continuation octets.
        // Accumulate into u64 so we can detect u32 overflow at the end.
        let mut number: u64 = 0;
        let mut pos = 1usize;
        loop {
            if pos >= buf.len() {
                return Err(Error::BerTruncated {
                    needed: pos + 1,
                    have: buf.len(),
                });
            }
            let b = buf[pos];
            pos += 1;
            let fragment = (b & 0x7F) as u64;
            // Checked shift + add; if this overflows u64 the encoding is
            // pathologically long, which we also reject.
            number = number
                .checked_shl(7)
                .and_then(|n| n.checked_add(fragment))
                .ok_or(Error::BerInvalidTag)?;
            if (b & 0x80) == 0 {
                // Last octet.
                break;
            }
        }
        // Reject values that overflow u32.
        let number = u32::try_from(number).map_err(|_| Error::BerInvalidTag)?;

        // BER requires the tag number in long form to be >= 31.
        // We don't enforce the "no leading zero octet" rule (tolerant reader).
        Ok((
            Tag {
                class,
                constructed,
                number,
            },
            pos,
        ))
    }
}

impl core::fmt::Display for TagClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            TagClass::Universal => "UNIVERSAL",
            TagClass::Application => "APPLICATION",
            TagClass::ContextSpecific => "CONTEXT",
            TagClass::Private => "PRIVATE",
        };
        f.write_str(s)
    }
}

impl core::fmt::Display for Tag {
    /// Human-readable form, e.g. `[CONTEXT 3 constructed]`.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = if self.constructed {
            "constructed"
        } else {
            "primitive"
        };
        write!(f, "[{} {} {}]", self.class, self.number, kind)
    }
}

/// Encode `n` into base-128 big-endian octets (used for long-form tag numbers).
fn encode_base128_u32(n: u32, out: &mut Vec<u8>) {
    if n == 0 {
        out.push(0);
        return;
    }
    // Build the octets in reverse, then reverse.
    let start = out.len();
    let mut v = n;
    while v > 0 {
        out.push((v & 0x7F) as u8);
        v >>= 7;
    }
    // Reverse the fragment we just pushed.
    out[start..].reverse();
    // Set the continuation bit on all but the last.
    let end = out.len();
    for b in out[start..end - 1].iter_mut() {
        *b |= 0x80;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(tag: Tag) {
        let mut buf = Vec::new();
        tag.encode(&mut buf);
        let (decoded, consumed) = Tag::decode(&buf).expect("decode");
        assert_eq!(
            consumed,
            buf.len(),
            "should consume all bytes for tag {tag:?}"
        );
        assert_eq!(decoded, tag, "roundtrip failed for tag {tag:?}");
    }

    #[test]
    fn short_form_tags() {
        roundtrip(Tag::BOOLEAN);
        roundtrip(Tag::INTEGER);
        roundtrip(Tag::SEQUENCE);
        roundtrip(Tag::context(0));
        roundtrip(Tag::context(30));
        roundtrip(Tag::application(0));
    }

    #[test]
    fn long_form_tag_31() {
        roundtrip(Tag::context(31));
    }

    #[test]
    fn long_form_tag_127() {
        roundtrip(Tag::context(127));
    }

    #[test]
    fn long_form_tag_128() {
        roundtrip(Tag::context(128));
    }

    #[test]
    fn long_form_tag_16383() {
        roundtrip(Tag::context(16383));
    }

    #[test]
    fn long_form_tag_u32_max() {
        roundtrip(Tag::context(u32::MAX));
    }

    #[test]
    fn all_classes_roundtrip() {
        for n in [0u32, 15, 30, 31, 127, 128] {
            roundtrip(Tag {
                class: TagClass::Universal,
                constructed: false,
                number: n,
            });
            roundtrip(Tag {
                class: TagClass::Application,
                constructed: false,
                number: n,
            });
            roundtrip(Tag {
                class: TagClass::ContextSpecific,
                constructed: true,
                number: n,
            });
            roundtrip(Tag {
                class: TagClass::Private,
                constructed: true,
                number: n,
            });
        }
    }

    #[test]
    fn truncated_tag_error() {
        // Empty buffer.
        assert!(matches!(Tag::decode(&[]), Err(Error::BerTruncated { .. })));
        // Long-form start but no continuation.
        assert!(matches!(
            Tag::decode(&[0x1F]),
            Err(Error::BerTruncated { .. })
        ));
        // Long-form start with continuation bit set but no following octet.
        assert!(matches!(
            Tag::decode(&[0x1F, 0x81]),
            Err(Error::BerTruncated { .. })
        ));
    }

    #[test]
    fn overflow_tag_rejected() {
        // 5 base-128 octets encoding a value > u32::MAX.
        // u32::MAX in base-128 is [0x8F, 0xFF, 0xFF, 0xFF, 0x7F] (5 bytes).
        // One more step overflows.
        let buf: &[u8] = &[0x1F, 0x90, 0x80, 0x80, 0x80, 0x00];
        assert!(matches!(Tag::decode(buf), Err(Error::BerInvalidTag)));
    }
}
