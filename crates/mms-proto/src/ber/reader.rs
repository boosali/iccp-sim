//! Zero-copy BER cursor over a borrowed byte slice.
//!
//! The reader advances through the slice one TLV at a time. For constructed
//! TLVs the caller obtains the raw content slice and recursively constructs a
//! new `BerReader` over it — there is no internal recursion stack here.
//!
//! # Indefinite length
//! When a *constructed* TLV carries indefinite length (length octet `0x80`),
//! the reader scans forward in a single flat pass to locate the matching
//! end-of-contents octets (`0x00 0x00`), tracking nesting with a depth counter
//! rather than recursion. Depth is capped at [`MAX_DEPTH`] to bound work and
//! prevent stack abuse. Indefinite length on a *primitive* tag is rejected with
//! [`Error::BerInvalidTag`]. See [`BerReader::read_tlv`] for the per-message
//! cost bound.

use super::length::{decode_length, LengthForm};
use super::tag::Tag;
use crate::{Error, Result};

/// Maximum indefinite-length nesting depth the scanner will tolerate.
pub const MAX_DEPTH: usize = 32;

/// Zero-copy BER cursor.
#[derive(Debug)]
pub struct BerReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BerReader<'a> {
    /// Create a new reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        BerReader { buf, pos: 0 }
    }

    /// Read one TLV. Returns `(tag, content_slice)`.
    ///
    /// For definite-length TLVs the content slice is the raw value bytes.
    /// For indefinite-length constructed TLVs the content slice *excludes*
    /// the end-of-contents octets, which are consumed here.
    ///
    /// # Cost of indefinite-length content
    /// Locating the matching end-of-contents for an indefinite-length TLV is a
    /// single flat forward scan over its content (`find_eoc`); it does *not*
    /// recurse to validate the interior, so each octet of an indefinite body is
    /// visited exactly once by that scan. When the caller then descends into
    /// the returned content with a fresh `BerReader`, the inner indefinite
    /// children are scanned again — so across `MAX_DEPTH` levels of nesting any
    /// given byte is visited at most `MAX_DEPTH` times in total. Upper framing
    /// layers (TPKT) cap a message at 64 KiB, so total scan work per message is
    /// bounded by `64 KiB * MAX_DEPTH`.
    pub fn read_tlv(&mut self) -> Result<(Tag, &'a [u8])> {
        // Decode tag.
        let remaining = &self.buf[self.pos..];
        let (tag, tag_len) = Tag::decode(remaining)?;
        self.pos += tag_len;

        // Decode length.
        let remaining = &self.buf[self.pos..];
        let (length_form, len_hdr) =
            decode_length(remaining)?.ok_or(Error::BerTruncated { needed: 1, have: 0 })?;
        self.pos += len_hdr;

        match length_form {
            LengthForm::Definite(content_len) => {
                // Guard against length exceeding available bytes.
                let available = self.buf.len() - self.pos;
                if content_len > available {
                    return Err(Error::BerTruncated {
                        needed: content_len,
                        have: available,
                    });
                }
                let content = &self.buf[self.pos..self.pos + content_len];
                self.pos += content_len;
                Ok((tag, content))
            }
            LengthForm::Indefinite => {
                // Indefinite length is only valid for constructed tags.
                if !tag.constructed {
                    return Err(Error::BerInvalidTag);
                }
                // Scan forward to find the matching EOC.
                let content_start = self.pos;
                let eoc_pos = find_eoc(&self.buf[self.pos..])?;
                let content = &self.buf[content_start..content_start + eoc_pos];
                // Consume content + EOC (2 bytes: 0x00 0x00).
                self.pos = content_start + eoc_pos + 2;
                Ok((tag, content))
            }
        }
    }

    /// Read one TLV and require its tag to match `expected`, returning the
    /// content slice. Returns [`Error::BerUnexpectedTag`] on mismatch.
    pub fn read_expected(&mut self, expected: Tag) -> Result<&'a [u8]> {
        let saved_pos = self.pos;
        let (tag, content) = self.read_tlv()?;
        if tag != expected {
            // Rewind so the caller can re-read if they want.
            self.pos = saved_pos;
            return Err(Error::BerUnexpectedTag { expected, got: tag });
        }
        Ok(content)
    }

    /// Peek at the next tag without consuming any bytes.
    ///
    /// Returns `Ok(None)` at end of buffer.
    #[must_use = "peeking the tag has no effect unless the result is inspected"]
    pub fn peek_tag(&self) -> Result<Option<Tag>> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let (tag, _) = Tag::decode(&self.buf[self.pos..])?;
        Ok(Some(tag))
    }

    /// Returns `true` if all bytes have been consumed.
    #[must_use]
    pub fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// The bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Returns `Ok(())` if [`done`](Self::done), else
    /// [`Error::BerTrailingBytes`].
    pub fn expect_done(&self) -> Result<()> {
        if self.done() {
            Ok(())
        } else {
            Err(Error::BerTrailingBytes {
                count: self.buf.len() - self.pos,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// EOC scanner
// ---------------------------------------------------------------------------

/// Scan `buf` from offset 0 to find the end-of-contents (`0x00 0x00`) that
/// closes the *outermost* indefinite-length level (the one `read_tlv` is
/// currently resolving).
///
/// This is a single flat forward pass: a `depth` counter starts at 1 for the
/// level we are closing. Each TLV header is examined exactly once —
/// definite-length TLVs are skipped wholesale via their length, while
/// indefinite-length constructed TLVs increment `depth` *without* recursing
/// into their interior (their own closing EOC will decrement it again). The
/// interior is therefore never re-validated here; that happens later if the
/// caller descends into the returned content with a fresh reader.
///
/// `depth` is capped at [`MAX_DEPTH`]; exceeding it yields
/// [`Error::BerDepthExceeded`].
///
/// All offsets in returned [`Error::BerTruncated`] values are relative to the
/// start of `buf` (the indefinite content region), matching the local-slice
/// convention used elsewhere in the reader.
///
/// Returns the byte offset of the *first* `0x00` of the matching EOC pair (so
/// `buf[0..offset]` is the content, and `buf[offset..offset+2]` is the EOC).
fn find_eoc(buf: &[u8]) -> Result<usize> {
    let mut pos = 0usize;
    let mut depth = 1usize;

    loop {
        // Need at least one byte for the next tag / EOC.
        if pos >= buf.len() {
            return Err(Error::BerTruncated {
                needed: pos + 1,
                have: buf.len(),
            });
        }

        // Check for an end-of-contents marker: tag=0x00, length=0x00.
        if buf[pos] == 0x00 {
            if pos + 1 >= buf.len() {
                return Err(Error::BerTruncated {
                    needed: pos + 2,
                    have: buf.len(),
                });
            }
            if buf[pos + 1] == 0x00 {
                depth -= 1;
                if depth == 0 {
                    // EOC for the level we are resolving.
                    return Ok(pos);
                }
                // EOC for a nested indefinite TLV: consume it and continue.
                pos += 2;
                continue;
            }
            // A 0x00 tag with non-zero length is unusual but not an EOC; fall
            // through and decode it as a normal (UNIVERSAL 0) TLV.
        }

        // Decode the next TLV header.
        let (tag, tag_len) = Tag::decode(&buf[pos..]).map_err(|e| match e {
            Error::BerTruncated { have, .. } => Error::BerTruncated {
                needed: pos + 1,
                have,
            },
            other => other,
        })?;
        pos += tag_len;

        if pos >= buf.len() {
            return Err(Error::BerTruncated {
                needed: pos + 1,
                have: buf.len(),
            });
        }

        let (length_form, len_hdr) = decode_length(&buf[pos..])?.ok_or(Error::BerTruncated {
            needed: pos + 1,
            have: buf.len(),
        })?;
        pos += len_hdr;

        match length_form {
            LengthForm::Definite(n) => {
                // Skip the content wholesale.
                if pos + n > buf.len() {
                    return Err(Error::BerTruncated {
                        needed: pos + n,
                        have: buf.len(),
                    });
                }
                pos += n;
            }
            LengthForm::Indefinite => {
                // Indefinite length is only valid for constructed tags.
                if !tag.constructed {
                    return Err(Error::BerInvalidTag);
                }
                // Enter one more indefinite level; do NOT recurse — its closing
                // EOC will bring `depth` back down on a later iteration.
                depth += 1;
                if depth > MAX_DEPTH {
                    return Err(Error::BerDepthExceeded { max: MAX_DEPTH });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ber::tag::TagClass;
    use crate::ber::writer::BerWriter;

    #[test]
    fn read_simple_primitive() {
        let mut w = BerWriter::new();
        w.write_bool(Tag::BOOLEAN, true);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let (tag, content) = r.read_tlv().unwrap();
        assert_eq!(tag, Tag::BOOLEAN);
        assert_eq!(content, &[0xFF]);
        assert!(r.done());
    }

    #[test]
    fn peek_tag() {
        let mut w = BerWriter::new();
        w.write_bool(Tag::BOOLEAN, false);
        let bytes = w.into_bytes();
        let r = BerReader::new(&bytes);
        assert_eq!(r.peek_tag().unwrap(), Some(Tag::BOOLEAN));
        assert!(!r.done());
    }

    #[test]
    fn peek_tag_at_end_returns_none() {
        let r = BerReader::new(&[]);
        assert_eq!(r.peek_tag().unwrap(), None);
        assert!(r.done());
    }

    #[test]
    fn expect_done_trailing_bytes() {
        let bytes = &[0x01, 0x01, 0xFF]; // BOOLEAN TRUE
        let r = BerReader::new(bytes);
        // Didn't read anything — trailing bytes present.
        assert!(matches!(
            r.expect_done(),
            Err(Error::BerTrailingBytes { count: 3 })
        ));
    }

    #[test]
    fn read_expected_tag_mismatch() {
        let mut w = BerWriter::new();
        w.write_bool(Tag::BOOLEAN, true);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let err = r.read_expected(Tag::INTEGER).unwrap_err();
        // The error must carry the real tags, not a lossy id.
        assert_eq!(
            err,
            Error::BerUnexpectedTag {
                expected: Tag::INTEGER,
                got: Tag::BOOLEAN,
            }
        );
        // Reader should have rewound.
        assert!(!r.done());
    }

    #[test]
    fn nested_constructed_descent() {
        // Build SEQUENCE { BOOLEAN TRUE }
        let mut w = BerWriter::new();
        w.write_tlv(Tag::SEQUENCE, |inner| {
            inner.write_bool(Tag::BOOLEAN, true);
        });
        let bytes = w.into_bytes();
        let mut outer = BerReader::new(&bytes);
        let (tag, content) = outer.read_tlv().unwrap();
        assert_eq!(tag, Tag::SEQUENCE);
        assert!(outer.done());

        let mut inner = BerReader::new(content);
        let (tag2, c2) = inner.read_tlv().unwrap();
        assert_eq!(tag2, Tag::BOOLEAN);
        assert_eq!(c2, &[0xFF]);
        assert!(inner.done());
    }

    #[test]
    fn truncated_at_every_cut_point() {
        // Build a known TLV encoding.
        let mut w = BerWriter::new();
        w.write_octet_string(Tag::OCTET_STRING, b"hello");
        let bytes = w.into_bytes();
        // Every strict prefix should return BerTruncated.
        for len in 0..bytes.len() {
            let mut r = BerReader::new(&bytes[..len]);
            assert!(
                matches!(r.read_tlv(), Err(Error::BerTruncated { .. })),
                "expected BerTruncated at len={len}"
            );
        }
    }

    #[test]
    fn indefinite_length_simple() {
        // Manually craft: SEQUENCE (indefinite) { BOOLEAN TRUE } EOC
        // 0x30 0x80  [BOOLEAN TRUE: 01 01 FF]  00 00
        let bytes: &[u8] = &[0x30, 0x80, 0x01, 0x01, 0xFF, 0x00, 0x00];
        let mut r = BerReader::new(bytes);
        let (tag, content) = r.read_tlv().unwrap();
        assert_eq!(tag, Tag::SEQUENCE);
        // Content should NOT include the EOC.
        assert_eq!(content, &[0x01, 0x01, 0xFF]);
        assert!(r.done());
    }

    #[test]
    fn indefinite_nested() {
        // Outer SEQUENCE (indefinite) { inner SEQUENCE (indefinite) { NULL } } EOC EOC
        // outer: 0x30 0x80
        //   inner: 0x30 0x80
        //     NULL: 0x05 0x00
        //   inner EOC: 0x00 0x00
        // outer EOC: 0x00 0x00
        let bytes: &[u8] = &[
            0x30, 0x80, // outer SEQUENCE indefinite
            0x30, 0x80, // inner SEQUENCE indefinite
            0x05, 0x00, // NULL
            0x00, 0x00, // inner EOC
            0x00, 0x00, // outer EOC
        ];
        let mut r = BerReader::new(bytes);
        let (tag, outer_content) = r.read_tlv().unwrap();
        assert_eq!(tag, Tag::SEQUENCE);
        assert!(r.done());

        let mut inner_r = BerReader::new(outer_content);
        let (inner_tag, inner_content) = inner_r.read_tlv().unwrap();
        assert_eq!(inner_tag, Tag::SEQUENCE);
        assert!(inner_r.done());

        let mut null_r = BerReader::new(inner_content);
        let (null_tag, null_content) = null_r.read_tlv().unwrap();
        assert_eq!(null_tag, Tag::NULL);
        assert!(null_content.is_empty());
        assert!(null_r.done());
    }

    #[test]
    fn indefinite_missing_eoc_error() {
        // SEQUENCE indefinite, no EOC.
        let bytes: &[u8] = &[0x30, 0x80, 0x01, 0x01, 0xFF];
        let mut r = BerReader::new(bytes);
        assert!(matches!(r.read_tlv(), Err(Error::BerTruncated { .. })));
    }

    #[test]
    fn indefinite_on_primitive_rejected() {
        // BOOLEAN with indefinite length: invalid.
        let bytes: &[u8] = &[0x01, 0x80, 0xFF, 0x00, 0x00];
        let mut r = BerReader::new(bytes);
        assert!(matches!(r.read_tlv(), Err(Error::BerInvalidTag)));
    }

    #[test]
    fn indefinite_depth_exceeded() {
        // Build 33 nested indefinite-length SEQUENCEs plus terminator.
        // depth cap is MAX_DEPTH = 32; 33 nested levels should exceed it.
        let mut bytes = Vec::new();
        for _ in 0..33 {
            bytes.push(0x30); // SEQUENCE
            bytes.push(0x80); // indefinite
        }
        bytes.push(0x05); // NULL
        bytes.push(0x00);
        // Close each level.
        for _ in 0..33 {
            bytes.push(0x00);
            bytes.push(0x00);
        }
        let mut r = BerReader::new(&bytes);
        assert!(matches!(r.read_tlv(), Err(Error::BerDepthExceeded { .. })));
    }

    #[test]
    fn many_sibling_indefinite_not_depth_exceeded() {
        // 100 sibling indefinite-length SEQUENCEs (each immediately closed)
        // nested inside one outer indefinite SEQUENCE. The depth counter must
        // rise to only 2 and fall back, so this is well within MAX_DEPTH and
        // must NOT trip BerDepthExceeded — proving the flat scan decrements.
        let mut bytes = vec![0x30, 0x80]; // outer SEQUENCE indefinite
        for _ in 0..100 {
            bytes.push(0x30); // sibling SEQUENCE
            bytes.push(0x80); // indefinite
            bytes.push(0x00); // its EOC
            bytes.push(0x00);
        }
        bytes.push(0x00); // outer EOC
        bytes.push(0x00);

        let mut r = BerReader::new(&bytes);
        let (tag, content) = r.read_tlv().unwrap();
        assert_eq!(tag, Tag::SEQUENCE);
        assert!(r.done());
        // Content holds the 100 empty siblings (4 bytes each).
        assert_eq!(content.len(), 400);
    }

    #[test]
    fn high_tag_number_roundtrip() {
        let tag = Tag {
            class: TagClass::ContextSpecific,
            constructed: false,
            number: 16383,
        };
        let mut w = BerWriter::new();
        w.write_primitive(tag, b"test");
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let (decoded_tag, content) = r.read_tlv().unwrap();
        assert_eq!(decoded_tag, tag);
        assert_eq!(content, b"test");
    }
}
