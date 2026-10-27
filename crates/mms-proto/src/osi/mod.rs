//! OSI upper layers between COTP framing and the MMS PDUs.
//!
//! These three layers carry the MMS profile's association handshake and data
//! phase over an established COTP class-0 connection:
//!
//! | Module           | Standard      | Encoding                              |
//! |------------------|---------------|---------------------------------------|
//! | [`session`]      | ISO 8327-1    | binary TLV (PGI/PI units, not BER)    |
//! | [`presentation`] | ISO 8823      | BER                                   |
//! | [`acse`]         | ISO 8650      | BER                                   |
//!
//! # Encode vs decode asymmetry
//!
//! For the MMS profile, the Session and Presentation layers carry a *nearly
//! static* set of parameters. The encoders here therefore emit a fixed,
//! parameterised template (only selectors and the carried payload vary).
//!
//! Decoding, however, is deliberately **tolerant structural parsing**: the
//! decoders walk the actual parameter / TLV structure, extract only the fields
//! the profile keys on, and skip everything else. They never byte-compare an
//! incoming PDU against the template we would have produced — other conforming
//! implementations legitimately encode these layers differently (different
//! selector values, parameter ordering, extra contexts, long vs short length
//! forms), and the stack must interoperate with them.
//!
//! ACSE is a genuine (small) BER codec because its fields really do vary from
//! message to message.

pub mod acse;
pub mod presentation;
pub mod session;

#[cfg(test)]
mod proptests;

pub use acse::{Aare, Aarq, Acse, AcsePdu, MMS_APP_CONTEXT_ARCS};
pub use presentation::{CpaResult, Presentation, PresentationContexts};
pub use session::{Session, SessionConnect, SessionPdu};
