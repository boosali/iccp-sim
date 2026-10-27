//! TASE.2 naming newtypes over the MMS [`Identifier`].
//!
//! TASE.2 names are MMS `Identifier`s used in specific roles: a *domain*
//! (a.k.a. "data set transfer set" / VCC or ICC scope), a *point* (a data
//! value name) and a *data set* name. These newtypes carry the role in the type
//! system while delegating validation to the underlying MMS identifier rules
//! (ISO 9506-2 `BasicIdentifier`, `SIZE(1..32)`).

use mms_proto::mms::{Identifier, ObjectName};

/// A TASE.2 domain (bilateral table / VCC) name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainName(Identifier);

/// A TASE.2 data-point name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PointName(Identifier);

/// A TASE.2 data-set name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataSetName(Identifier);

macro_rules! ident_newtype {
    ($t:ty) => {
        impl $t {
            /// Borrow the inner MMS [`Identifier`].
            #[must_use]
            pub fn identifier(&self) -> &Identifier {
                &self.0
            }

            /// The name as a `&str`.
            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }

            /// Consume self and return the inner [`Identifier`].
            #[must_use]
            pub fn into_identifier(self) -> Identifier {
                self.0
            }
        }

        impl From<Identifier> for $t {
            fn from(id: Identifier) -> Self {
                Self(id)
            }
        }

        impl From<$t> for Identifier {
            fn from(n: $t) -> Identifier {
                n.0
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

ident_newtype!(DomainName);
ident_newtype!(PointName);
ident_newtype!(DataSetName);

/// Build an MMS [`ObjectName`] for an item, scoped to `domain` if given.
///
/// With a domain, this is a `domain-specific` name (`{ domainID, itemID }`);
/// without one, a `vmd-specific` name. TASE.2 points and data sets are usually
/// domain-specific (the domain is the bilateral table / ICC), while a handful
/// of VMD-scoped special variables (see [`crate::names`]) are vmd-specific.
#[must_use]
pub fn object_name(domain: Option<&DomainName>, item: &Identifier) -> ObjectName {
    match domain {
        Some(d) => ObjectName::DomainSpecific {
            domain: d.0.clone(),
            item: item.clone(),
        },
        None => ObjectName::VmdSpecific(item.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newtype_roundtrip_and_display() {
        let id = Identifier::new("Point1").unwrap();
        let p = PointName::from(id.clone());
        assert_eq!(p.as_str(), "Point1");
        assert_eq!(p.to_string(), "Point1");
        assert_eq!(p.identifier(), &id);
        assert_eq!(Identifier::from(p), id);
    }

    #[test]
    fn object_name_scoping() {
        let item = Identifier::new("MeasFlt").unwrap();
        let dom = DomainName::from(Identifier::new("ICC1").unwrap());
        assert_eq!(
            object_name(Some(&dom), &item),
            ObjectName::DomainSpecific {
                domain: Identifier::new("ICC1").unwrap(),
                item: item.clone(),
            }
        );
        assert_eq!(
            object_name(None, &item),
            ObjectName::VmdSpecific(item.clone())
        );
    }
}
