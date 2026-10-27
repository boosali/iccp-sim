//! TASE.2 indication-point values and their MMS `Data` mapping.
//!
//! # Point types (libtase2 / IEC 60870-6-802 §9.1)
//! Verified against the libtase2 developer guide type table
//! (<https://support.mz-automation.de/doc/libtase2/manual/latest/tase2_developer_guide.html>):
//! the value classes are `Real`, `Discrete`, `State`, `StateSupplemental`
//! (Block-1 implements the first three) crossed with quality/timestamp/COV:
//!
//! * plain (`Data_Real`, `Data_Discrete`, `Data_State`)
//! * `…Q` — adds DataFlags
//! * `…QTimeTag` — adds DataFlags + GMTBasedS timestamp (seconds)
//! * `…Extended` — adds DataFlags + COV + GMTBasedS timestamp
//! * `…QTimeTagExtended` — adds DataFlags + TimeStampExtended (seconds+millis) + COV
//!
//! # Wire shapes
//! * plain `Real` → `Data::Float`; `Discrete` → `Data::Integer`;
//!   `State` → `Data::BitString(8)` (the DataFlags octet with the 2-bit state in
//!   bits 0..=1, all other bits zero).
//! * `…Q` → `Structure { <value>, DataFlags:BitString(8) }`.
//! * `…QTimeTag` → `Structure { <value>, DataFlags, TimeStamp }`.
//! * `…Extended` → `Structure { <value>, DataFlags, COV:Integer, TimeStamp }`.
//! * `…QTimeTagExtended` → `Structure { <value>, DataFlags, TimeStampExtended, COV:Integer }`.
//!
//! where:
//! * `TimeStamp` = `Data::Integer(seconds)` (GMTBasedS; UTC seconds since the
//!   epoch). For `State` values the "value" element is the state BitString.
//! * `TimeStampExtended` = `Structure { Integer(seconds), Integer(millis) }`.
//!
//! ## Field order rationale
//! IEC 60870-6-802 orders the structured types **value-first**, then quality,
//! then timestamp/COV. The exact placement of COV vs. timestamp for the two
//! "Extended" families is the one ambiguous point across public references; the
//! single source of truth for the order lives in the `to_mms` / `from_mms`
//! bodies below so it can be adjusted in one place if a conformance test
//! disagrees. Encode/decode are each other's inverse (proptested), which is
//! what matters for interop with our own peer regardless of the chosen order.

use mms_proto::mms::Data;

use crate::quality::Quality;
use crate::{Error, Result};

/// Two-bit logical state of a `Data_State*` point (DataFlags bits 0..=1).
///
/// Codes per libtase2 `Tase2_DataState`: `BETWEEN`=0, `CLOSED`/`ON`=1,
/// `OFF`/`TRIPPED`=2, `INVALID`=3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum StateValue {
    /// `BETWEEN` (0) — intermediate / transit.
    #[default]
    Between,
    /// `CLOSED` / `ON` (1).
    Closed,
    /// `OFF` / `TRIPPED` (2).
    TrippedOpen,
    /// `INVALID` (3).
    Invalid,
}

impl StateValue {
    /// The 2-bit code (`0..=3`).
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            StateValue::Between => 0,
            StateValue::Closed => 1,
            StateValue::TrippedOpen => 2,
            StateValue::Invalid => 3,
        }
    }

    /// Decode from a 2-bit code; anything outside `0..=3` is rejected.
    pub fn from_code(code: u8) -> Result<Self> {
        Ok(match code {
            0 => StateValue::Between,
            1 => StateValue::Closed,
            2 => StateValue::TrippedOpen,
            3 => StateValue::Invalid,
            _ => return Err(Error::InvalidStateValue),
        })
    }
}

/// A TASE.2 timestamp.
///
/// `seconds` is `GMTBasedS` — UTC seconds since the Unix epoch (the standard
/// type is 32-bit, so values stay within `i32` range in practice). `millis` is
/// `Some` only for the `…QTimeTagExtended` (TimeStampExtended) family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeStamp {
    /// `GMTBasedS` seconds since the Unix epoch.
    pub seconds: i64,
    /// Optional milliseconds (present for `TimeStampExtended`).
    pub millis: Option<u16>,
}

impl TimeStamp {
    /// A second-resolution timestamp.
    #[must_use]
    pub fn from_seconds(seconds: i64) -> Self {
        TimeStamp {
            seconds,
            millis: None,
        }
    }
}

/// The kind of a point value — mirrors the [`PointValue`] variants so a decoder
/// knows which wire shape to expect (a bare `Structure` is otherwise
/// ambiguous).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PointKind {
    /// `Data_Real`.
    Real,
    /// `Data_Discrete`.
    Discrete,
    /// `Data_State`.
    State,
    /// `Data_RealQ`.
    RealQ,
    /// `Data_DiscreteQ`.
    DiscreteQ,
    /// `Data_StateQ`.
    StateQ,
    /// `Data_RealQTimeTag`.
    RealQTimeTag,
    /// `Data_DiscreteQTimeTag`.
    DiscreteQTimeTag,
    /// `Data_StateQTimeTag`.
    StateQTimeTag,
    /// `Data_RealExtended` (Q + COV + TimeTag).
    RealExtended,
    /// `Data_DiscreteExtended`.
    DiscreteExtended,
    /// `Data_StateExtended`.
    StateExtended,
    /// `Data_RealQTimeTagExtended` (Q + TimeStampExtended + COV).
    RealQTimeTagExtended,
    /// `Data_DiscreteQTimeTagExtended`.
    DiscreteQTimeTagExtended,
    /// `Data_StateQTimeTagExtended`.
    StateQTimeTagExtended,
}

/// A TASE.2 indication-point value.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum PointValue {
    /// `Data_Real`.
    Real(f32),
    /// `Data_Discrete`.
    Discrete(i32),
    /// `Data_State`.
    State(StateValue),

    /// `Data_RealQ`.
    RealQ { value: f32, quality: Quality },
    /// `Data_DiscreteQ`.
    DiscreteQ { value: i32, quality: Quality },
    /// `Data_StateQ`.
    StateQ { value: StateValue, quality: Quality },

    /// `Data_RealQTimeTag`.
    RealQTimeTag {
        value: f32,
        quality: Quality,
        timestamp: TimeStamp,
    },
    /// `Data_DiscreteQTimeTag`.
    DiscreteQTimeTag {
        value: i32,
        quality: Quality,
        timestamp: TimeStamp,
    },
    /// `Data_StateQTimeTag`.
    StateQTimeTag {
        value: StateValue,
        quality: Quality,
        timestamp: TimeStamp,
    },

    // --- Extended family ---------------------------------------------------
    // The `…Extended` and `…QTimeTagExtended` families have *identical Rust
    // field sets* (value, quality, timestamp, cov) but DIFFERENT wire layouts.
    // This is an easy trap, so the wire order is spelled out on each:
    //
    //   …Extended         → Structure { value, flags, cov:Integer, ts-seconds:Integer }
    //                       (second-resolution timestamp; `timestamp.millis`
    //                       MUST be `None` — `to_mms` debug-asserts this).
    //   …QTimeTagExtended → Structure { value, flags, ts-extended:Structure{secs,ms}, cov:Integer }
    //                       (`timestamp.millis` is always emitted; a `None`
    //                       there encodes as `0`).
    /// `Data_RealExtended` — wire `Structure { value, flags, cov, ts-seconds }`.
    /// `timestamp.millis` must be `None` (second resolution).
    RealExtended {
        value: f32,
        quality: Quality,
        timestamp: TimeStamp,
        cov: u16,
    },
    /// `Data_DiscreteExtended` — wire `Structure { value, flags, cov, ts-seconds }`.
    /// `timestamp.millis` must be `None` (second resolution).
    DiscreteExtended {
        value: i32,
        quality: Quality,
        timestamp: TimeStamp,
        cov: u16,
    },
    /// `Data_StateExtended` — wire `Structure { state-flags, cov, ts-seconds }`.
    /// `timestamp.millis` must be `None` (second resolution).
    StateExtended {
        value: StateValue,
        quality: Quality,
        timestamp: TimeStamp,
        cov: u16,
    },

    /// `Data_RealQTimeTagExtended` — wire
    /// `Structure { value, flags, ts-extended{secs,ms}, cov }` (millisecond
    /// timestamp always emitted).
    RealQTimeTagExtended {
        value: f32,
        quality: Quality,
        timestamp: TimeStamp,
        cov: u16,
    },
    /// `Data_DiscreteQTimeTagExtended` — wire
    /// `Structure { value, flags, ts-extended{secs,ms}, cov }`.
    DiscreteQTimeTagExtended {
        value: i32,
        quality: Quality,
        timestamp: TimeStamp,
        cov: u16,
    },
    /// `Data_StateQTimeTagExtended` — wire
    /// `Structure { state-flags, ts-extended{secs,ms}, cov }`.
    StateQTimeTagExtended {
        value: StateValue,
        quality: Quality,
        timestamp: TimeStamp,
        cov: u16,
    },
}

// --- helpers ----------------------------------------------------------------

/// The DataFlags BitString for a non-state value (state bits zero).
fn flags_data(q: Quality) -> Data {
    Data::BitString(q.to_bit_string())
}

/// The DataFlags BitString for a state value: quality in the upper bits, the
/// 2-bit state value OR-ed into bits 0..=1.
fn state_flags_data(state: StateValue, q: Quality) -> Data {
    let octet = q.pack() | state.code();
    Data::BitString(Quality::octet_to_bit_string(octet))
}

/// `TimeStamp` → `Data` (Integer seconds, or Structure{seconds, millis}).
fn timestamp_data(ts: TimeStamp) -> Data {
    match ts.millis {
        None => Data::Integer(ts.seconds),
        Some(ms) => Data::Structure(vec![
            Data::Integer(ts.seconds),
            Data::Integer(i64::from(ms)),
        ]),
    }
}

/// COV counter → `Data::Integer`.
fn cov_data(cov: u16) -> Data {
    Data::Integer(i64::from(cov))
}

fn real_data(v: f32) -> Data {
    Data::Float(v)
}

fn discrete_data(v: i32) -> Data {
    Data::Integer(i64::from(v))
}

// `expected` strings distinguish a *shape* failure (wrong `Data` variant) from
// a *range* failure (right variant, value out of the target integer range), so
// diagnostics make the cause unambiguous.
const EXP_REAL: &str = "Real (Float)";
const EXP_DISCRETE: &str = "Discrete (Integer)";
const EXP_DISCRETE_RANGE: &str = "Discrete (Integer in i32 range)";
const EXP_STATE: &str = "State (BitString)";
const EXP_STRUCT: &str = "Structure";
const EXP_COV: &str = "COV (Integer)";
const EXP_COV_RANGE: &str = "COV (Unsigned in u16 range)";
const EXP_TS_SECONDS: &str = "TimeStamp (Integer seconds)";
const EXP_TSX: &str = "TimeStampExtended (Structure{seconds, millis})";
const EXP_TSX_SECONDS: &str = "TimeStampExtended.seconds (Integer)";
const EXP_TSX_MILLIS: &str = "TimeStampExtended.millis (Integer)";
const EXP_TSX_MILLIS_RANGE: &str = "TimeStampExtended.millis (Integer in u16 range)";

fn as_real(d: &Data) -> Result<f32> {
    match d {
        Data::Float(v) => Ok(*v),
        _ => Err(Error::UnexpectedDataShape { expected: EXP_REAL }),
    }
}

fn as_discrete(d: &Data) -> Result<i32> {
    match d {
        Data::Integer(v) => i32::try_from(*v).map_err(|_| Error::UnexpectedDataShape {
            expected: EXP_DISCRETE_RANGE,
        }),
        _ => Err(Error::UnexpectedDataShape {
            expected: EXP_DISCRETE,
        }),
    }
}

/// Read the DataFlags octet from a BitString `Data`.
fn as_flags_octet(d: &Data) -> Result<u8> {
    match d {
        Data::BitString(bs) => Quality::octet_from_bit_string(bs),
        _ => Err(Error::UnexpectedDataShape {
            expected: EXP_STATE,
        }),
    }
}

fn as_quality(d: &Data) -> Result<Quality> {
    Ok(Quality::unpack(as_flags_octet(d)?))
}

/// Read (quality, state) from a state DataFlags BitString.
fn as_state_and_quality(d: &Data) -> Result<(StateValue, Quality)> {
    let octet = as_flags_octet(d)?;
    let state = StateValue::from_code(octet & 0b11)?;
    Ok((state, Quality::unpack(octet)))
}

fn as_cov(d: &Data) -> Result<u16> {
    match d {
        Data::Integer(v) => u16::try_from(*v).map_err(|_| Error::UnexpectedDataShape {
            expected: EXP_COV_RANGE,
        }),
        _ => Err(Error::UnexpectedDataShape { expected: EXP_COV }),
    }
}

fn as_timestamp(d: &Data, extended: bool) -> Result<TimeStamp> {
    if extended {
        match d {
            Data::Structure(elems) if elems.len() == 2 => {
                let seconds = match &elems[0] {
                    Data::Integer(s) => *s,
                    _ => {
                        return Err(Error::UnexpectedDataShape {
                            expected: EXP_TSX_SECONDS,
                        })
                    }
                };
                let millis = match &elems[1] {
                    Data::Integer(ms) => {
                        u16::try_from(*ms).map_err(|_| Error::UnexpectedDataShape {
                            expected: EXP_TSX_MILLIS_RANGE,
                        })?
                    }
                    _ => {
                        return Err(Error::UnexpectedDataShape {
                            expected: EXP_TSX_MILLIS,
                        })
                    }
                };
                Ok(TimeStamp {
                    seconds,
                    millis: Some(millis),
                })
            }
            _ => Err(Error::UnexpectedDataShape { expected: EXP_TSX }),
        }
    } else {
        match d {
            Data::Integer(s) => Ok(TimeStamp::from_seconds(*s)),
            _ => Err(Error::UnexpectedDataShape {
                expected: EXP_TS_SECONDS,
            }),
        }
    }
}

/// Borrow the elements of a `Structure`, checking the exact arity.
fn struct_elems(d: &Data, arity: usize) -> Result<&[Data]> {
    match d {
        Data::Structure(elems) if elems.len() == arity => Ok(elems),
        _ => Err(Error::UnexpectedDataShape {
            expected: EXP_STRUCT,
        }),
    }
}

impl PointValue {
    /// The [`PointKind`] of this value.
    #[must_use]
    pub fn kind(&self) -> PointKind {
        match self {
            PointValue::Real(_) => PointKind::Real,
            PointValue::Discrete(_) => PointKind::Discrete,
            PointValue::State(_) => PointKind::State,
            PointValue::RealQ { .. } => PointKind::RealQ,
            PointValue::DiscreteQ { .. } => PointKind::DiscreteQ,
            PointValue::StateQ { .. } => PointKind::StateQ,
            PointValue::RealQTimeTag { .. } => PointKind::RealQTimeTag,
            PointValue::DiscreteQTimeTag { .. } => PointKind::DiscreteQTimeTag,
            PointValue::StateQTimeTag { .. } => PointKind::StateQTimeTag,
            PointValue::RealExtended { .. } => PointKind::RealExtended,
            PointValue::DiscreteExtended { .. } => PointKind::DiscreteExtended,
            PointValue::StateExtended { .. } => PointKind::StateExtended,
            PointValue::RealQTimeTagExtended { .. } => PointKind::RealQTimeTagExtended,
            PointValue::DiscreteQTimeTagExtended { .. } => PointKind::DiscreteQTimeTagExtended,
            PointValue::StateQTimeTagExtended { .. } => PointKind::StateQTimeTagExtended,
        }
    }

    /// Encode to MMS `Data`.
    #[must_use]
    pub fn to_mms(&self) -> Data {
        match *self {
            // Plain.
            PointValue::Real(v) => real_data(v),
            PointValue::Discrete(v) => discrete_data(v),
            PointValue::State(s) => state_flags_data(s, Quality::default_state_quality()),

            // Q.
            PointValue::RealQ { value, quality } => {
                Data::Structure(vec![real_data(value), flags_data(quality)])
            }
            PointValue::DiscreteQ { value, quality } => {
                Data::Structure(vec![discrete_data(value), flags_data(quality)])
            }
            PointValue::StateQ { value, quality } => {
                // The state lives inside the DataFlags; a StateQ is therefore a
                // single BitString carrying both, like plain State but with
                // explicit quality.
                state_flags_data(value, quality)
            }

            // QTimeTag.
            PointValue::RealQTimeTag {
                value,
                quality,
                timestamp,
            } => Data::Structure(vec![
                real_data(value),
                flags_data(quality),
                timestamp_data(timestamp),
            ]),
            PointValue::DiscreteQTimeTag {
                value,
                quality,
                timestamp,
            } => Data::Structure(vec![
                discrete_data(value),
                flags_data(quality),
                timestamp_data(timestamp),
            ]),
            PointValue::StateQTimeTag {
                value,
                quality,
                timestamp,
            } => Data::Structure(vec![
                state_flags_data(value, quality),
                timestamp_data(timestamp),
            ]),

            // Extended (Q + COV + second timestamp). The timestamp is
            // second-resolution: `millis` must be `None`, or the value has been
            // confused with a `…QTimeTagExtended`.
            PointValue::RealExtended {
                value,
                quality,
                timestamp,
                cov,
            } => {
                debug_assert!(
                    timestamp.millis.is_none(),
                    "RealExtended uses a second-resolution timestamp (millis must be None)"
                );
                Data::Structure(vec![
                    real_data(value),
                    flags_data(quality),
                    cov_data(cov),
                    timestamp_data(timestamp),
                ])
            }
            PointValue::DiscreteExtended {
                value,
                quality,
                timestamp,
                cov,
            } => {
                debug_assert!(
                    timestamp.millis.is_none(),
                    "DiscreteExtended uses a second-resolution timestamp (millis must be None)"
                );
                Data::Structure(vec![
                    discrete_data(value),
                    flags_data(quality),
                    cov_data(cov),
                    timestamp_data(timestamp),
                ])
            }
            PointValue::StateExtended {
                value,
                quality,
                timestamp,
                cov,
            } => {
                debug_assert!(
                    timestamp.millis.is_none(),
                    "StateExtended uses a second-resolution timestamp (millis must be None)"
                );
                Data::Structure(vec![
                    state_flags_data(value, quality),
                    cov_data(cov),
                    timestamp_data(timestamp),
                ])
            }

            // QTimeTagExtended (Q + millisecond timestamp + COV).
            PointValue::RealQTimeTagExtended {
                value,
                quality,
                timestamp,
                cov,
            } => Data::Structure(vec![
                real_data(value),
                flags_data(quality),
                timestamp_data(force_millis(timestamp)),
                cov_data(cov),
            ]),
            PointValue::DiscreteQTimeTagExtended {
                value,
                quality,
                timestamp,
                cov,
            } => Data::Structure(vec![
                discrete_data(value),
                flags_data(quality),
                timestamp_data(force_millis(timestamp)),
                cov_data(cov),
            ]),
            PointValue::StateQTimeTagExtended {
                value,
                quality,
                timestamp,
                cov,
            } => Data::Structure(vec![
                state_flags_data(value, quality),
                timestamp_data(force_millis(timestamp)),
                cov_data(cov),
            ]),
        }
    }

    /// Decode from MMS `Data`, directed by the expected [`PointKind`].
    ///
    /// The wire shape alone is ambiguous (everything but the plain types is a
    /// `Structure`), so the caller must say which kind it expects (from the
    /// bilateral-table / point configuration). A mismatch yields
    /// [`Error::UnexpectedDataShape`].
    pub fn from_mms(kind: PointKind, data: &Data) -> Result<PointValue> {
        match kind {
            // Plain.
            PointKind::Real => Ok(PointValue::Real(as_real(data)?)),
            PointKind::Discrete => Ok(PointValue::Discrete(as_discrete(data)?)),
            PointKind::State => {
                let (value, _q) = as_state_and_quality(data)?;
                Ok(PointValue::State(value))
            }

            // Q.
            PointKind::RealQ => {
                let e = struct_elems(data, 2)?;
                Ok(PointValue::RealQ {
                    value: as_real(&e[0])?,
                    quality: as_quality(&e[1])?,
                })
            }
            PointKind::DiscreteQ => {
                let e = struct_elems(data, 2)?;
                Ok(PointValue::DiscreteQ {
                    value: as_discrete(&e[0])?,
                    quality: as_quality(&e[1])?,
                })
            }
            PointKind::StateQ => {
                let (value, quality) = as_state_and_quality(data)?;
                Ok(PointValue::StateQ { value, quality })
            }

            // QTimeTag.
            PointKind::RealQTimeTag => {
                let e = struct_elems(data, 3)?;
                Ok(PointValue::RealQTimeTag {
                    value: as_real(&e[0])?,
                    quality: as_quality(&e[1])?,
                    timestamp: as_timestamp(&e[2], false)?,
                })
            }
            PointKind::DiscreteQTimeTag => {
                let e = struct_elems(data, 3)?;
                Ok(PointValue::DiscreteQTimeTag {
                    value: as_discrete(&e[0])?,
                    quality: as_quality(&e[1])?,
                    timestamp: as_timestamp(&e[2], false)?,
                })
            }
            PointKind::StateQTimeTag => {
                let e = struct_elems(data, 2)?;
                let (value, quality) = as_state_and_quality(&e[0])?;
                Ok(PointValue::StateQTimeTag {
                    value,
                    quality,
                    timestamp: as_timestamp(&e[1], false)?,
                })
            }

            // Extended.
            PointKind::RealExtended => {
                let e = struct_elems(data, 4)?;
                Ok(PointValue::RealExtended {
                    value: as_real(&e[0])?,
                    quality: as_quality(&e[1])?,
                    cov: as_cov(&e[2])?,
                    timestamp: as_timestamp(&e[3], false)?,
                })
            }
            PointKind::DiscreteExtended => {
                let e = struct_elems(data, 4)?;
                Ok(PointValue::DiscreteExtended {
                    value: as_discrete(&e[0])?,
                    quality: as_quality(&e[1])?,
                    cov: as_cov(&e[2])?,
                    timestamp: as_timestamp(&e[3], false)?,
                })
            }
            PointKind::StateExtended => {
                let e = struct_elems(data, 3)?;
                let (value, quality) = as_state_and_quality(&e[0])?;
                Ok(PointValue::StateExtended {
                    value,
                    quality,
                    cov: as_cov(&e[1])?,
                    timestamp: as_timestamp(&e[2], false)?,
                })
            }

            // QTimeTagExtended.
            PointKind::RealQTimeTagExtended => {
                let e = struct_elems(data, 4)?;
                Ok(PointValue::RealQTimeTagExtended {
                    value: as_real(&e[0])?,
                    quality: as_quality(&e[1])?,
                    timestamp: as_timestamp(&e[2], true)?,
                    cov: as_cov(&e[3])?,
                })
            }
            PointKind::DiscreteQTimeTagExtended => {
                let e = struct_elems(data, 4)?;
                Ok(PointValue::DiscreteQTimeTagExtended {
                    value: as_discrete(&e[0])?,
                    quality: as_quality(&e[1])?,
                    timestamp: as_timestamp(&e[2], true)?,
                    cov: as_cov(&e[3])?,
                })
            }
            PointKind::StateQTimeTagExtended => {
                let e = struct_elems(data, 3)?;
                let (value, quality) = as_state_and_quality(&e[0])?;
                Ok(PointValue::StateQTimeTagExtended {
                    value,
                    quality,
                    timestamp: as_timestamp(&e[1], true)?,
                    cov: as_cov(&e[2])?,
                })
            }
        }
    }
}

/// Ensure a timestamp encodes as `TimeStampExtended` (millis present).
fn force_millis(ts: TimeStamp) -> TimeStamp {
    TimeStamp {
        seconds: ts.seconds,
        millis: Some(ts.millis.unwrap_or(0)),
    }
}

impl Quality {
    /// The quality used for a plain `Data_State` (no explicit quality on the
    /// wire): the default "good" quality, whose octet OR-ed with the 2-bit
    /// state forms the BitString.
    fn default_state_quality() -> Quality {
        Quality::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mms_proto::ber::primitives::BitString;

    #[test]
    fn state_packs_into_low_bits() {
        // State value occupies bits 0..=1; default quality octet is 0xC0.
        let d = PointValue::State(StateValue::TrippedOpen).to_mms();
        match d {
            Data::BitString(bs) => {
                let octet = Quality::octet_from_bit_string(&bs).unwrap();
                assert_eq!(octet & 0b11, 2, "TrippedOpen code");
                assert_eq!(octet & !0b11, 0xC0, "default quality in upper bits");
            }
            other => panic!("expected BitString, got {other:?}"),
        }
    }

    #[test]
    fn state_q_carries_quality_and_state() {
        let v = PointValue::StateQ {
            value: StateValue::Closed,
            quality: Quality {
                validity: crate::Validity::Suspect,
                ..Quality::default()
            },
        };
        let d = v.to_mms();
        let back = PointValue::from_mms(PointKind::StateQ, &d).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn extended_timestamp_shape() {
        let v = PointValue::RealQTimeTagExtended {
            value: 1.5,
            quality: Quality::default(),
            timestamp: TimeStamp {
                seconds: 1_700_000_000,
                millis: Some(123),
            },
            cov: 7,
        };
        match v.to_mms() {
            Data::Structure(e) => {
                assert_eq!(e.len(), 4);
                assert_eq!(e[0], Data::Float(1.5));
                assert!(matches!(e[2], Data::Structure(ref s) if s.len() == 2));
                assert_eq!(e[3], Data::Integer(7));
            }
            other => panic!("expected Structure, got {other:?}"),
        }
    }

    #[test]
    fn wrong_kind_is_unexpected_shape() {
        let d = PointValue::Real(2.0).to_mms(); // a bare Float
        let err = PointValue::from_mms(PointKind::RealQ, &d).unwrap_err();
        assert!(matches!(err, Error::UnexpectedDataShape { .. }));
    }

    #[test]
    fn invalid_state_code_rejected() {
        // BitString octet with state bits = 3 is INVALID (valid), but a
        // structurally wrong (too wide) flags string is rejected.
        let bs = BitString::from_bits(&[true; 9]);
        let err = PointValue::from_mms(PointKind::State, &Data::BitString(bs)).unwrap_err();
        assert!(matches!(err, Error::InvalidFlags));
    }
}
