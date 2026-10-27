//! MMS variable-naming types: `Identifier`, `ObjectName`,
//! `VariableSpecification`, and `VariableAccessSpecification`.
//!
//! # Identifier rules
//! An MMS `Identifier` is an ASN.1 `VisibleString` constrained (ISO 9506-2,
//! `BasicIdentifier`) to 1..=32 characters drawn from
//! `[A-Za-z_$][A-Za-z0-9_$]*` (a leading letter, underscore, or dollar sign,
//! then alphanumerics, underscores or dollar signs). libiec61850 internally
//! uses a larger buffer, but the standard caps `BasicIdentifier` at `SIZE(1..32)`
//! — we enforce the standard.
//!
//! # ObjectName tags (ISO 9506-2)
//! `vmd-specific [0] Identifier`, `domain-specific [1] SEQUENCE { domainID,
//! itemID }`, `aa-specific [2] Identifier`. All IMPLICIT.
//!
//! # VariableSpecification / VariableAccessSpecification
//! `VariableSpecification ::= CHOICE { name [0] ObjectName, ... }` — we only
//! produce/consume the `name` form; other alternatives decode to
//! [`VariableSpecification::Unknown`] preserving the raw tag and bytes.
//! `VariableAccessSpecification ::= CHOICE { listOfVariable [0] VariableDefs,
//! variableListName [1] ObjectName }`, where `VariableDefs ::= SEQUENCE OF
//! SEQUENCE { variableSpecification, alternateAccess [5] OPTIONAL }`.

use crate::ber::reader::BerReader;
use crate::ber::tag::{Tag, TagClass};
use crate::ber::writer::BerWriter;
use crate::{Error, Result};

/// Maximum length of an MMS `Identifier`.
///
/// ISO 9506-2 `BasicIdentifier` is `SIZE(1..32)`, but IEC 61850-8-1 maps item
/// ids like `GGIO1$CO$SPCSO3$Oper$origin$orIdent` (35 chars) onto MMS
/// identifiers, and real stacks (libiec61850) emit them. Since this crate is
/// the shared MMS base for TASE.2 *and* IEC 61850, the cap is 64 — IEC
/// 61850-7-2's object-name component limit — rather than the historical 32.
pub const MAX_IDENTIFIER_LEN: usize = 64;

// --- ObjectName tags --------------------------------------------------------

const TAG_VMD_SPECIFIC: Tag = Tag::context(0);
const TAG_DOMAIN_SPECIFIC: Tag = Tag::context_constructed(1);
const TAG_AA_SPECIFIC: Tag = Tag::context(2);

// --- VariableSpecification / VariableAccessSpecification tags ---------------

const TAG_VARSPEC_NAME: Tag = Tag::context_constructed(0);
const TAG_VAS_LIST_OF_VARIABLE: Tag = Tag::context_constructed(0);
const TAG_VAS_VARIABLE_LIST_NAME: Tag = Tag::context_constructed(1);

// ---------------------------------------------------------------------------
// Identifier
// ---------------------------------------------------------------------------

/// A validated MMS `Identifier` (ISO 9506-2 `BasicIdentifier`).
///
/// Construct with [`Identifier::new`], which enforces the length and character
/// rules. The inner string is never exposed mutably so the invariant holds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identifier(String);

impl Identifier {
    /// Validate and wrap a string as an `Identifier`.
    ///
    /// Returns [`Error::MmsInvalidIdentifier`] if `s` is empty, longer than
    /// [`MAX_IDENTIFIER_LEN`], or contains a character outside the permitted
    /// set.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        Self::validate(&s)?;
        Ok(Identifier(s))
    }

    fn validate(s: &str) -> Result<()> {
        if s.is_empty() || s.len() > MAX_IDENTIFIER_LEN {
            return Err(Error::MmsInvalidIdentifier);
        }
        let mut chars = s.chars();
        // First character: letter, underscore, or dollar.
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
            _ => return Err(Error::MmsInvalidIdentifier),
        }
        for c in chars {
            if !(c.is_ascii_alphanumeric() || c == '_' || c == '$') {
                return Err(Error::MmsInvalidIdentifier);
            }
        }
        Ok(())
    }

    /// The identifier as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decode an `Identifier` from VisibleString content bytes.
    pub(crate) fn decode(content: &[u8]) -> Result<Self> {
        let s = core::str::from_utf8(content).map_err(|_| Error::MmsInvalidIdentifier)?;
        Identifier::new(s)
    }

    /// Encode this `Identifier` under the given (IMPLICIT VisibleString) tag.
    pub(crate) fn encode(&self, w: &mut BerWriter, tag: Tag) {
        w.write_visible_string(tag, &self.0);
    }
}

impl core::fmt::Display for Identifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for Identifier {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        Identifier::new(s)
    }
}

impl core::str::FromStr for Identifier {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Identifier::new(s)
    }
}

// ---------------------------------------------------------------------------
// ObjectName
// ---------------------------------------------------------------------------

/// An MMS `ObjectName` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectName {
    /// `vmd-specific [0] Identifier`.
    VmdSpecific(Identifier),
    /// `domain-specific [1] SEQUENCE { domainID, itemID }`.
    DomainSpecific {
        /// `domainID` Identifier.
        domain: Identifier,
        /// `itemID` Identifier.
        item: Identifier,
    },
    /// `aa-specific [2] Identifier`.
    AaSpecific(Identifier),
}

impl ObjectName {
    /// Encode this `ObjectName` (one CHOICE alternative) into `w`.
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        match self {
            ObjectName::VmdSpecific(id) => id.encode(w, TAG_VMD_SPECIFIC),
            ObjectName::AaSpecific(id) => id.encode(w, TAG_AA_SPECIFIC),
            ObjectName::DomainSpecific { domain, item } => {
                w.write_tlv(TAG_DOMAIN_SPECIFIC, |seq| {
                    // domainID and itemID are untagged VisibleStrings inside the
                    // SEQUENCE.
                    domain.encode(seq, Tag::VISIBLE_STRING);
                    item.encode(seq, Tag::VISIBLE_STRING);
                });
            }
        }
    }

    /// Decode an `ObjectName` from a `(tag, content)` pair already read from the
    /// stream.
    pub(crate) fn decode_from(tag: Tag, content: &[u8]) -> Result<Self> {
        if tag == TAG_VMD_SPECIFIC {
            Ok(ObjectName::VmdSpecific(Identifier::decode(content)?))
        } else if tag == TAG_AA_SPECIFIC {
            Ok(ObjectName::AaSpecific(Identifier::decode(content)?))
        } else if tag == TAG_DOMAIN_SPECIFIC {
            let mut r = BerReader::new(content);
            let dom = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            let it = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
            Ok(ObjectName::DomainSpecific {
                domain: Identifier::decode(dom.1)?,
                item: Identifier::decode(it.1)?,
            })
        } else {
            Err(Error::MmsInvalidPdu)
        }
    }

    /// Read one `ObjectName` TLV from `r`.
    pub(crate) fn decode(r: &mut BerReader<'_>) -> Result<Self> {
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        Self::decode_from(tag, content)
    }
}

// ---------------------------------------------------------------------------
// VariableSpecification
// ---------------------------------------------------------------------------

/// An MMS `VariableSpecification` CHOICE.
///
/// Only the `name [0]` form is produced by this crate. Other alternatives
/// (e.g. address- or scattered-access forms) decode to [`Self::Unknown`],
/// preserving the raw context tag number and content bytes so the value
/// re-encodes identically and the state machine can reject unsupported forms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VariableSpecification {
    /// `name [0] ObjectName`.
    Name(ObjectName),
    /// Any other CHOICE alternative, preserved verbatim.
    Unknown {
        /// The context tag number of the unhandled alternative.
        tag: u32,
        /// Whether the unhandled alternative was constructed.
        constructed: bool,
        /// The raw content bytes.
        bytes: Vec<u8>,
    },
}

impl VariableSpecification {
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        match self {
            VariableSpecification::Name(name) => {
                w.write_tlv(TAG_VARSPEC_NAME, |inner| name.encode(inner));
            }
            VariableSpecification::Unknown {
                tag,
                constructed,
                bytes,
            } => {
                let t = Tag {
                    class: TagClass::ContextSpecific,
                    constructed: *constructed,
                    number: *tag,
                };
                w.write_primitive(t, bytes);
            }
        }
    }

    pub(crate) fn decode(r: &mut BerReader<'_>) -> Result<Self> {
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag == TAG_VARSPEC_NAME {
            let mut inner = BerReader::new(content);
            Ok(VariableSpecification::Name(ObjectName::decode(&mut inner)?))
        } else {
            Ok(VariableSpecification::Unknown {
                tag: tag.number,
                constructed: tag.constructed,
                bytes: content.to_vec(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// VariableAccessSpecification
// ---------------------------------------------------------------------------

/// An MMS `VariableAccessSpecification` CHOICE.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VariableAccessSpecification {
    /// `listOfVariable [0] VariableDefs` — a list of variable specifications.
    ListOfVariable(Vec<VariableSpecification>),
    /// `variableListName [1] ObjectName` — a named variable list.
    VariableListName(ObjectName),
}

impl VariableAccessSpecification {
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        match self {
            VariableAccessSpecification::ListOfVariable(vars) => {
                // listOfVariable [0] IMPLICIT SEQUENCE OF SEQUENCE {
                //   variableSpecification, alternateAccess [5] OPTIONAL }
                w.write_tlv(TAG_VAS_LIST_OF_VARIABLE, |list| {
                    for v in vars {
                        list.write_tlv(Tag::SEQUENCE, |item| v.encode(item));
                    }
                });
            }
            VariableAccessSpecification::VariableListName(name) => {
                // variableListName [1] ObjectName (EXPLICIT: the [1] wraps the
                // ObjectName CHOICE).
                w.write_tlv(TAG_VAS_VARIABLE_LIST_NAME, |inner| name.encode(inner));
            }
        }
    }

    pub(crate) fn decode_from(tag: Tag, content: &[u8]) -> Result<Self> {
        if tag == TAG_VAS_LIST_OF_VARIABLE {
            let mut r = BerReader::new(content);
            let mut vars = Vec::new();
            while !r.done() {
                // Each item is a SEQUENCE { variableSpecification,
                // alternateAccess [5] OPTIONAL }.
                let (item_tag, item) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                if item_tag != Tag::SEQUENCE {
                    return Err(Error::MmsInvalidPdu);
                }
                let mut ir = BerReader::new(item);
                vars.push(VariableSpecification::decode(&mut ir)?);
                // Ignore any trailing alternateAccess [5] etc.
            }
            Ok(VariableAccessSpecification::ListOfVariable(vars))
        } else if tag == TAG_VAS_VARIABLE_LIST_NAME {
            let mut r = BerReader::new(content);
            Ok(VariableAccessSpecification::VariableListName(
                ObjectName::decode(&mut r)?,
            ))
        } else {
            Err(Error::MmsInvalidPdu)
        }
    }

    pub(crate) fn decode(r: &mut BerReader<'_>) -> Result<Self> {
        let (tag, content) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        Self::decode_from(tag, content)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_valid() {
        assert!(Identifier::new("Foo").is_ok());
        assert!(Identifier::new("_bar9").is_ok());
        assert!(Identifier::new("$x").is_ok());
        assert!(Identifier::new("a").is_ok());
        assert!(Identifier::new("A".repeat(32)).is_ok());
        // IEC 61850-8-1 item ids routinely exceed ISO 9506's historical 32
        // (observed live from libiec61850's server example, 35 chars):
        assert!(Identifier::new("GGIO1$CO$SPCSO3$Oper$origin$orIdent").is_ok());
        assert!(Identifier::new("A".repeat(MAX_IDENTIFIER_LEN)).is_ok());
        assert!(Identifier::new("A".repeat(MAX_IDENTIFIER_LEN + 1)).is_err());
    }

    #[test]
    fn identifier_conversions() {
        use core::str::FromStr;
        assert_eq!(
            Identifier::try_from("Foo").unwrap(),
            Identifier::new("Foo").unwrap()
        );
        assert_eq!(
            Identifier::from_str("Bar").unwrap(),
            Identifier::new("Bar").unwrap()
        );
        assert!(Identifier::try_from("9bad").is_err());
        assert!("9bad".parse::<Identifier>().is_err());
    }

    #[test]
    fn identifier_invalid() {
        assert!(matches!(
            Identifier::new(""),
            Err(Error::MmsInvalidIdentifier)
        ));
        assert!(matches!(
            Identifier::new("A".repeat(MAX_IDENTIFIER_LEN + 1)),
            Err(Error::MmsInvalidIdentifier)
        ));
        assert!(matches!(
            Identifier::new("9leading"),
            Err(Error::MmsInvalidIdentifier)
        ));
        assert!(matches!(
            Identifier::new("has space"),
            Err(Error::MmsInvalidIdentifier)
        ));
        assert!(matches!(
            Identifier::new("dot.name"),
            Err(Error::MmsInvalidIdentifier)
        ));
    }

    fn roundtrip_name(name: &ObjectName) -> ObjectName {
        let mut w = BerWriter::new();
        name.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        ObjectName::decode(&mut r).unwrap()
    }

    #[test]
    fn object_name_vmd() {
        let n = ObjectName::VmdSpecific(Identifier::new("Var1").unwrap());
        assert_eq!(roundtrip_name(&n), n);
    }

    #[test]
    fn object_name_aa() {
        let n = ObjectName::AaSpecific(Identifier::new("Assoc").unwrap());
        assert_eq!(roundtrip_name(&n), n);
    }

    #[test]
    fn object_name_domain() {
        let n = ObjectName::DomainSpecific {
            domain: Identifier::new("DomA").unwrap(),
            item: Identifier::new("ItemB").unwrap(),
        };
        assert_eq!(roundtrip_name(&n), n);
    }

    #[test]
    fn vas_list_of_variable_roundtrip() {
        let vas = VariableAccessSpecification::ListOfVariable(vec![
            VariableSpecification::Name(ObjectName::VmdSpecific(Identifier::new("A").unwrap())),
            VariableSpecification::Name(ObjectName::DomainSpecific {
                domain: Identifier::new("D").unwrap(),
                item: Identifier::new("I").unwrap(),
            }),
        ]);
        let mut w = BerWriter::new();
        vas.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        assert_eq!(VariableAccessSpecification::decode(&mut r).unwrap(), vas);
    }

    #[test]
    fn vas_variable_list_name_roundtrip() {
        let vas = VariableAccessSpecification::VariableListName(ObjectName::DomainSpecific {
            domain: Identifier::new("D").unwrap(),
            item: Identifier::new("List").unwrap(),
        });
        let mut w = BerWriter::new();
        vas.encode(&mut w);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        assert_eq!(VariableAccessSpecification::decode(&mut r).unwrap(), vas);
    }

    #[test]
    fn variable_specification_unknown_passthrough() {
        // CHOICE alternative [3] (not name [0]) with arbitrary content.
        let mut w = BerWriter::new();
        w.write_primitive(Tag::context(3), &[0xDE, 0xAD]);
        let bytes = w.into_bytes();
        let mut r = BerReader::new(&bytes);
        let spec = VariableSpecification::decode(&mut r).unwrap();
        assert_eq!(
            spec,
            VariableSpecification::Unknown {
                tag: 3,
                constructed: false,
                bytes: vec![0xDE, 0xAD],
            }
        );
        // Re-encode reproduces the input.
        let mut w2 = BerWriter::new();
        spec.encode(&mut w2);
        assert_eq!(w2.into_bytes(), bytes);
    }
}
