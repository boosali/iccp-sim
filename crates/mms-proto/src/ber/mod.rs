//! ASN.1 BER primitive layer: tag/length/value encoding and decoding.
//!
//! # Module layout
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`tag`] | Tag class, `Tag` struct, encode/decode |
//! | [`length`] | Length encode/decode, `LengthForm` |
//! | [`primitives`] | Content-slice decoders/encoders, `BitString`, `ObjectIdentifier` |
//! | [`reader`] | Zero-copy `BerReader` cursor |
//! | [`writer`] | `BerWriter` encoder |

pub mod length;
pub mod primitives;
pub mod reader;
pub mod tag;
pub mod writer;

#[cfg(test)]
mod proptests;

// Re-export the most common types at the `ber` crate level.
pub use length::LengthForm;
pub use primitives::{
    decode_bit_string, decode_bool, decode_integer_i64, decode_oid, decode_unsigned_u64,
    decode_visible_string, encode_bit_string, encode_bool, encode_integer_i64, encode_oid,
    encode_unsigned_u64, BitString, ObjectIdentifier,
};
pub use reader::{BerReader, MAX_DEPTH};
pub use tag::{Tag, TagClass};
pub use writer::BerWriter;
