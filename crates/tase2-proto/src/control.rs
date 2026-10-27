//! TASE.2 Block-5 device control: commands, setpoints, SBO selection and tags.
//!
//! # Verified wire / model facts (sources cited)
//!
//! Block 5 ("Device Control") lets a client request the operation of a *device*
//! (a control point). TASE.2 does not directly drive the device; it conveys the
//! client's request to the server, which actuates it (libtase2 developer guide,
//! <https://support.mz-automation.de/doc/libtase2/manual/latest/tase2_developer_guide.html>).
//!
//! Three control-point kinds, verified against the libtase2 C client API
//! (<https://support.mz-automation.de/doc/libtase2/c/latest/group__tase2__client.html>):
//!
//! * **Command** — `Tase2_Client_sendCommand(.., int16_t commandValue)` → MMS
//!   `Data::Integer` (Integer16 range; the trip/close semantics are
//!   application-level).
//! * **SetPointDiscrete** — `Tase2_Client_sendDiscreteSetPoint(.., int16_t)` →
//!   `Data::Integer` (Integer16 range). The libtase2 C API uses `int16_t` for
//!   discrete setpoints, so this crate models it as `i16` (not the wider
//!   Integer32 some texts suggest).
//! * **SetPointReal** — `Tase2_Client_sendRealSetPoint(.., float)` →
//!   `Data::Float`.
//!
//! Two control models (libtase2 `Tase2_DeviceClass`): **Direct** (operate is a
//! plain write of the device variable) and **SBO** select-before-operate (the
//! client first *selects* the device, then *operates* before the select
//! timeout).
//!
//! ## Select (SBO)
//! Selection is performed by **reading** the device's reserved `<dev>_SBO`
//! companion variable (the `_SBO` suffix is reserved for "protocol internal
//! variables", libtase2 developer guide §naming). The libtase2 client
//! `Tase2_Client_selectDevice` returns an **integer** "check back name value"
//! on success, so this crate encodes the select response as `Data::Integer`
//! (the *checkback id*). A non-positive / failure value indicates selection was
//! refused.
//!
//! ## Tags
//! A device may carry a persistent tag inhibiting operations. Tag values are
//! verified against the libtase2 `Tase2_TagValue` enum
//! (<https://support.mz-automation.de/doc/libtase2/c/latest/group__tase2__common.html>):
//! `NO_TAG=0`, `OPEN_AND_CLOSE_INHIBIT=1`, `CLOSE_ONLY_INHIBIT=2`, `INVALID=3`.
//! Tags are read/written via the reserved `<dev>_TAG` companion variable.
//!
//! **Wire-shape uncertainty (documented, isolated):** the exact MMS encoding of
//! the `_TAG` structure is not publicly specified in the IEC 60870-6-802 text
//! or the libtase2 docs available at authoring time. The libtase2 client tag
//! API (`Tase2_Client_getTag` / `setTag`) exposes a `Tase2_TagValue`, an
//! `isArmed` boolean and a `reason` string. This crate implements a **minimal**
//! `Structure { tag: Integer, reason: VisibleString }` and isolates the whole
//! codec in [`DeviceTag::to_mms`] / [`DeviceTag::from_mms`] so it can be
//! adjusted in one place if a conformance test disagrees. The `isArmed` flag is
//! derived from `tag != NoTag` rather than carried separately.

use mms_proto::mms::{Data, Identifier};

use crate::{Error, Result};

/// The reserved companion-variable suffix for select-before-operate.
const SBO_SUFFIX: &str = "_SBO";
/// The reserved companion-variable suffix for device tags.
const TAG_SUFFIX: &str = "_TAG";

/// The kind of a device (control point) — selects the operate value's wire
/// shape and the [`CommandValue`] variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeviceKind {
    /// A command device. Operate value is an `int16` (`Data::Integer`).
    Command,
    /// A real (floating-point) setpoint. Operate value is an `f32`
    /// (`Data::Float`).
    SetPointReal,
    /// A discrete (integer) setpoint. Operate value is an `int16`
    /// (`Data::Integer`).
    SetPointDiscrete,
}

/// The control model of a device: direct operate vs. select-before-operate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ControlModel {
    /// Direct operate: a single write of the device variable.
    Direct,
    /// Select-before-operate: the client must read `<dev>_SBO` to select, then
    /// write the device variable to operate before the select timeout.
    Sbo,
}

/// A device tag value (libtase2 `Tase2_TagValue`).
///
/// Codes verified against the libtase2 common API: `NO_TAG=0`,
/// `OPEN_AND_CLOSE_INHIBIT=1`, `CLOSE_ONLY_INHIBIT=2`, `INVALID=3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum TagValue {
    /// `TASE2_TAG_NO_TAG` (0) — no tag present; operations are not inhibited.
    #[default]
    NoTag,
    /// `TASE2_TAG_OPEN_AND_CLOSE_INHIBIT` (1) — all operations inhibited.
    OpenAndCloseInhibit,
    /// `TASE2_TAG_CLOSE_ONLY_INHIBIT` (2) — close inhibited, open allowed.
    CloseOnlyInhibit,
    /// `TASE2_TAG_INVALID` (3) — the device has an invalid tag.
    Invalid,
}

impl TagValue {
    /// The integer code (`0..=3`).
    #[must_use]
    pub fn code(self) -> i64 {
        match self {
            TagValue::NoTag => 0,
            TagValue::OpenAndCloseInhibit => 1,
            TagValue::CloseOnlyInhibit => 2,
            TagValue::Invalid => 3,
        }
    }

    /// Decode from an integer code; anything outside `0..=3` is rejected.
    pub fn from_code(code: i64) -> Result<Self> {
        Ok(match code {
            0 => TagValue::NoTag,
            1 => TagValue::OpenAndCloseInhibit,
            2 => TagValue::CloseOnlyInhibit,
            3 => TagValue::Invalid,
            _ => {
                return Err(Error::InvalidControl {
                    reason: "TagValue code out of range 0..=3",
                })
            }
        })
    }

    /// Whether this tag inhibits a `close` (or, for setpoints/commands, any
    /// non-open operation). `OPEN_AND_CLOSE_INHIBIT`, `CLOSE_ONLY_INHIBIT` and
    /// `INVALID` all block; `NO_TAG` permits.
    ///
    /// TASE.2 tags are oriented at switchgear (open/close). For command and
    /// setpoint devices, which have no open/close polarity on the wire, this
    /// server treats *any* inhibiting tag (anything but `NoTag`) as blocking the
    /// operate. The finer open-vs-close distinction is left to the host's
    /// [`operate`](crate) logic if it has device polarity context.
    #[must_use]
    pub fn inhibits_operate(self) -> bool {
        !matches!(self, TagValue::NoTag)
    }
}

/// A device tag: a [`TagValue`] plus a free-text reason.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DeviceTag {
    /// The tag value.
    pub tag: TagValue,
    /// A free-text reason for the tag (may be empty).
    pub reason: String,
}

impl DeviceTag {
    /// A tag with the given value and reason. The canonical constructor (the
    /// struct is `#[non_exhaustive]`, so it cannot be built with a literal from
    /// other crates).
    #[must_use]
    pub fn new(tag: TagValue, reason: impl Into<String>) -> Self {
        DeviceTag {
            tag,
            reason: reason.into(),
        }
    }

    /// A tag with no inhibit and an empty reason.
    #[must_use]
    pub fn none() -> Self {
        DeviceTag::default()
    }

    /// Whether this tag inhibits operating the device (see
    /// [`TagValue::inhibits_operate`]).
    #[must_use]
    pub fn inhibits_operate(&self) -> bool {
        self.tag.inhibits_operate()
    }

    /// Encode the tag to its MMS `Data` wire form.
    ///
    /// **Wire shape (uncertain — see module docs):**
    /// `Structure { tag: Integer, reason: VisibleString }`. This is the single
    /// source of truth for the tag codec.
    #[must_use]
    pub fn to_mms(&self) -> Data {
        Data::Structure(vec![
            Data::Integer(self.tag.code()),
            Data::VisibleString(self.reason.clone()),
        ])
    }

    /// Decode a tag from its MMS `Data` wire form.
    ///
    /// Accepts the `Structure { Integer, VisibleString }` produced by
    /// [`to_mms`](Self::to_mms). A bare `Integer` (tag value with no reason) is
    /// also accepted as a lenient fallback, since some peers may omit the
    /// reason.
    pub fn from_mms(data: &Data) -> Result<Self> {
        match data {
            Data::Structure(elems) if elems.len() == 2 => {
                let tag = match &elems[0] {
                    Data::Integer(code) => TagValue::from_code(*code)?,
                    _ => {
                        return Err(Error::InvalidControl {
                            reason: "DeviceTag.tag must be an Integer",
                        })
                    }
                };
                let reason = match &elems[1] {
                    Data::VisibleString(s) => s.clone(),
                    _ => {
                        return Err(Error::InvalidControl {
                            reason: "DeviceTag.reason must be a VisibleString",
                        })
                    }
                };
                Ok(DeviceTag { tag, reason })
            }
            // Lenient fallback: a bare tag code with no reason.
            Data::Integer(code) => Ok(DeviceTag {
                tag: TagValue::from_code(*code)?,
                reason: String::new(),
            }),
            _ => Err(Error::InvalidControl {
                reason: "DeviceTag must be Structure{Integer, VisibleString}",
            }),
        }
    }
}

/// A device operate value, carrying the value and (via its variant) the kind.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum CommandValue {
    /// A command value (`int16`).
    Command(i16),
    /// A real setpoint value (`f32`).
    SetPointReal(f32),
    /// A discrete setpoint value (`int16`).
    SetPointDiscrete(i16),
}

impl CommandValue {
    /// The [`DeviceKind`] this value operates.
    #[must_use]
    pub fn kind(&self) -> DeviceKind {
        match self {
            CommandValue::Command(_) => DeviceKind::Command,
            CommandValue::SetPointReal(_) => DeviceKind::SetPointReal,
            CommandValue::SetPointDiscrete(_) => DeviceKind::SetPointDiscrete,
        }
    }

    /// Encode the operate value to MMS `Data`.
    ///
    /// Command / discrete setpoint → `Data::Integer`; real setpoint →
    /// `Data::Float` (libtase2 `sendCommand`/`sendDiscreteSetPoint` use
    /// `int16_t`, `sendRealSetPoint` uses `float`).
    #[must_use]
    pub fn to_mms(&self) -> Data {
        match *self {
            CommandValue::Command(v) | CommandValue::SetPointDiscrete(v) => {
                Data::Integer(i64::from(v))
            }
            CommandValue::SetPointReal(v) => Data::Float(v),
        }
    }

    /// Decode an operate value from MMS `Data`, directed by the device's
    /// [`DeviceKind`] (the wire type alone cannot distinguish a command from a
    /// discrete setpoint).
    ///
    /// An integer outside the `i16` range, or a `Data` variant that does not
    /// match the kind, is [`Error::InvalidControl`].
    pub fn from_mms(kind: DeviceKind, data: &Data) -> Result<Self> {
        match kind {
            DeviceKind::Command | DeviceKind::SetPointDiscrete => {
                let v = match data {
                    Data::Integer(v) => i16::try_from(*v).map_err(|_| Error::InvalidControl {
                        reason: "command/discrete-setpoint value out of i16 range",
                    })?,
                    _ => {
                        return Err(Error::InvalidControl {
                            reason: "command/discrete-setpoint operate value must be an Integer",
                        })
                    }
                };
                Ok(match kind {
                    DeviceKind::Command => CommandValue::Command(v),
                    _ => CommandValue::SetPointDiscrete(v),
                })
            }
            DeviceKind::SetPointReal => match data {
                Data::Float(v) => Ok(CommandValue::SetPointReal(*v)),
                _ => Err(Error::InvalidControl {
                    reason: "real-setpoint operate value must be a Float",
                }),
            },
        }
    }
}

/// Derive the SBO companion identifier `<device>_SBO` for a device name.
///
/// Returns [`Error::DeviceNameTooLong`] if appending `_SBO` would exceed the
/// MMS `Identifier` length cap ([`mms_proto::mms::MAX_IDENTIFIER_LEN`]).
pub fn sbo_name(device: &Identifier) -> Result<Identifier> {
    suffixed(device, SBO_SUFFIX)
}

/// Derive the TAG companion identifier `<device>_TAG` for a device name.
///
/// Returns [`Error::DeviceNameTooLong`] if appending `_TAG` would exceed the
/// MMS `Identifier` length cap ([`mms_proto::mms::MAX_IDENTIFIER_LEN`]).
pub fn tag_name(device: &Identifier) -> Result<Identifier> {
    suffixed(device, TAG_SUFFIX)
}

/// Whether `companion` equals `<device><suffix>` for a known suffix. Used by the
/// server to recognise a `_SBO` / `_TAG` companion and recover the base device
/// name.
#[must_use]
pub fn strip_sbo_suffix(companion: &str) -> Option<&str> {
    companion.strip_suffix(SBO_SUFFIX)
}

/// As [`strip_sbo_suffix`], for the `_TAG` suffix.
#[must_use]
pub fn strip_tag_suffix(companion: &str) -> Option<&str> {
    companion.strip_suffix(TAG_SUFFIX)
}

fn suffixed(device: &Identifier, suffix: &'static str) -> Result<Identifier> {
    let combined = format!("{}{suffix}", device.as_str());
    Identifier::new(combined).map_err(|_| Error::DeviceNameTooLong {
        name: device.as_str().to_owned(),
        suffix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> Identifier {
        Identifier::new(s).unwrap()
    }

    #[test]
    fn tag_value_codes_round_trip() {
        for tv in [
            TagValue::NoTag,
            TagValue::OpenAndCloseInhibit,
            TagValue::CloseOnlyInhibit,
            TagValue::Invalid,
        ] {
            assert_eq!(TagValue::from_code(tv.code()).unwrap(), tv);
        }
        assert_eq!(TagValue::NoTag.code(), 0);
        assert_eq!(TagValue::OpenAndCloseInhibit.code(), 1);
        assert_eq!(TagValue::CloseOnlyInhibit.code(), 2);
        assert_eq!(TagValue::Invalid.code(), 3);
    }

    #[test]
    fn tag_value_out_of_range_rejected() {
        assert!(matches!(
            TagValue::from_code(4),
            Err(Error::InvalidControl { .. })
        ));
        assert!(matches!(
            TagValue::from_code(-1),
            Err(Error::InvalidControl { .. })
        ));
    }

    #[test]
    fn tag_inhibits_only_when_set() {
        assert!(!TagValue::NoTag.inhibits_operate());
        assert!(TagValue::OpenAndCloseInhibit.inhibits_operate());
        assert!(TagValue::CloseOnlyInhibit.inhibits_operate());
        assert!(TagValue::Invalid.inhibits_operate());
    }

    #[test]
    fn device_tag_round_trip() {
        let t = DeviceTag {
            tag: TagValue::OpenAndCloseInhibit,
            reason: "maintenance".to_owned(),
        };
        let back = DeviceTag::from_mms(&t.to_mms()).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn device_tag_bare_integer_fallback() {
        let back = DeviceTag::from_mms(&Data::Integer(2)).unwrap();
        assert_eq!(back.tag, TagValue::CloseOnlyInhibit);
        assert!(back.reason.is_empty());
    }

    #[test]
    fn device_tag_wrong_shape_rejected() {
        assert!(matches!(
            DeviceTag::from_mms(&Data::Float(1.0)),
            Err(Error::InvalidControl { .. })
        ));
        // Structure with wrong inner types.
        let bad = Data::Structure(vec![Data::Float(1.0), Data::VisibleString(String::new())]);
        assert!(matches!(
            DeviceTag::from_mms(&bad),
            Err(Error::InvalidControl { .. })
        ));
    }

    #[test]
    fn command_value_round_trips_by_kind() {
        let c = CommandValue::Command(-5);
        assert_eq!(
            CommandValue::from_mms(DeviceKind::Command, &c.to_mms()).unwrap(),
            c
        );
        let d = CommandValue::SetPointDiscrete(1234);
        assert_eq!(
            CommandValue::from_mms(DeviceKind::SetPointDiscrete, &d.to_mms()).unwrap(),
            d
        );
        let r = CommandValue::SetPointReal(3.5);
        assert_eq!(
            CommandValue::from_mms(DeviceKind::SetPointReal, &r.to_mms()).unwrap(),
            r
        );
    }

    #[test]
    fn command_value_wrong_kind_rejected() {
        // A real value decoded as a command is a shape error.
        let r = CommandValue::SetPointReal(1.0).to_mms();
        assert!(matches!(
            CommandValue::from_mms(DeviceKind::Command, &r),
            Err(Error::InvalidControl { .. })
        ));
        // An integer decoded as a real is a shape error.
        let c = CommandValue::Command(1).to_mms();
        assert!(matches!(
            CommandValue::from_mms(DeviceKind::SetPointReal, &c),
            Err(Error::InvalidControl { .. })
        ));
        // A float decoded as a discrete setpoint is a shape error.
        let f = CommandValue::SetPointReal(1.0).to_mms();
        assert!(matches!(
            CommandValue::from_mms(DeviceKind::SetPointDiscrete, &f),
            Err(Error::InvalidControl { .. })
        ));
    }

    #[test]
    fn command_value_out_of_i16_range_rejected() {
        let too_big = Data::Integer(i64::from(i16::MAX) + 1);
        assert!(matches!(
            CommandValue::from_mms(DeviceKind::Command, &too_big),
            Err(Error::InvalidControl { .. })
        ));
    }

    #[test]
    fn name_helpers_suffix() {
        assert_eq!(sbo_name(&id("Dev1")).unwrap().as_str(), "Dev1_SBO");
        assert_eq!(tag_name(&id("Dev1")).unwrap().as_str(), "Dev1_TAG");
        assert_eq!(strip_sbo_suffix("Dev1_SBO"), Some("Dev1"));
        assert_eq!(strip_tag_suffix("Dev1_TAG"), Some("Dev1"));
        assert_eq!(strip_sbo_suffix("Dev1"), None);
    }

    #[test]
    fn name_helper_overflow_errors() {
        use mms_proto::mms::MAX_IDENTIFIER_LEN;
        // (cap-2)-char device name + "_SBO" (4) = cap+2 → DeviceNameTooLong.
        let long = "D".repeat(MAX_IDENTIFIER_LEN - 2);
        let dev = id(&long);
        assert!(matches!(
            sbo_name(&dev),
            Err(Error::DeviceNameTooLong { suffix: "_SBO", .. })
        ));
        assert!(matches!(
            tag_name(&dev),
            Err(Error::DeviceNameTooLong { suffix: "_TAG", .. })
        ));
        // (cap-4)-char name + 4 = cap exactly → OK.
        let ok = id(&"D".repeat(MAX_IDENTIFIER_LEN - 4));
        assert_eq!(sbo_name(&ok).unwrap().as_str().len(), MAX_IDENTIFIER_LEN);
    }
}
