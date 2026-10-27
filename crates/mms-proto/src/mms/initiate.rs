//! MMS Initiate request/response PDUs (association negotiation).
//!
//! ```asn1
//! Initiate-RequestPDU ::= SEQUENCE {
//!     localDetailCalling                  [0] IMPLICIT Integer32 OPTIONAL,
//!     proposedMaxServOutstandingCalling   [1] IMPLICIT Integer16,
//!     proposedMaxServOutstandingCalled    [2] IMPLICIT Integer16,
//!     proposedDataStructureNestingLevel   [3] IMPLICIT Integer8 OPTIONAL,
//!     initRequestDetail                   [4] IMPLICIT SEQUENCE {
//!         proposedVersionNumber       [0] IMPLICIT Integer16,
//!         proposedParameterCBB        [1] IMPLICIT BIT STRING,
//!         servicesSupportedCalling    [2] IMPLICIT BIT STRING } }
//! ```
//!
//! `Initiate-ResponsePDU` mirrors this with `negotiated*` field names and
//! `servicesSupportedCalled` in the detail.
//!
//! # Default field values
//! The [`InitiateRequest::default`] / [`InitiateResponse::default`] values
//! mirror what the libiec61850 MMS client emits in `mms_client_initiate.c`:
//! * `localDetailCalling` = 65000 (proposed max PDU size)
//! * outstanding calling / called = 10 / 10
//! * data-structure nesting level = 5
//! * `proposedVersionNumber` = 1
//! * `proposedParameterCBB` BIT STRING = `f1 00` (11 bits: str1, str2, vnam,
//!   valt, vadr off, vsca off ... — encoded content `05 f1 00`)
//! * `servicesSupportedCalling` BIT STRING = `ee 1c 00 00 04 08 00 00 79 ef 18`
//!   (85 bits, encoded content `03 ee 1c 00 00 04 08 00 00 79 ef 18`)

use crate::ber::primitives::BitString;
use crate::ber::reader::BerReader;
use crate::ber::tag::Tag;
use crate::ber::writer::BerWriter;
use crate::ber::{decode_bit_string, decode_integer_i64};
use crate::{Error, Result};

const TAG_LOCAL_DETAIL: Tag = Tag::context(0);
const TAG_OUTSTANDING_CALLING: Tag = Tag::context(1);
const TAG_OUTSTANDING_CALLED: Tag = Tag::context(2);
const TAG_NESTING_LEVEL: Tag = Tag::context(3);
const TAG_INIT_DETAIL: Tag = Tag::context_constructed(4);
const TAG_VERSION: Tag = Tag::context(0);
const TAG_PARAMETER_CBB: Tag = Tag::context(1);
const TAG_SERVICES_SUPPORTED: Tag = Tag::context(2);

/// Default proposed max PDU size (libiec61850 client default).
const DEFAULT_LOCAL_DETAIL: i64 = 65000;
/// Default max outstanding service requests.
const DEFAULT_OUTSTANDING: i64 = 10;
/// Default data-structure nesting level.
const DEFAULT_NESTING_LEVEL: i64 = 5;
/// Default proposed MMS version number.
const DEFAULT_VERSION: i64 = 1;

/// The libiec61850 default `parameterCBB` BIT STRING data bytes (`f1 00`),
/// representing 11 significant bits (str1, str2, vnam, valt, vlis...).
const DEFAULT_PARAMETER_CBB: &[u8] = &[0xf1, 0x00];
/// Unused trailing bits in [`DEFAULT_PARAMETER_CBB`] (16 - 11 = 5).
const DEFAULT_PARAMETER_CBB_UNUSED: u8 = 5;

/// The libiec61850 default `servicesSupported` BIT STRING data bytes.
const DEFAULT_SERVICES_SUPPORTED: &[u8] = &[
    0xee, 0x1c, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xef, 0x18,
];
/// Unused trailing bits in [`DEFAULT_SERVICES_SUPPORTED`] (88 - 85 = 3).
const DEFAULT_SERVICES_SUPPORTED_UNUSED: u8 = 3;

fn default_parameter_cbb() -> BitString {
    BitString {
        unused_bits: DEFAULT_PARAMETER_CBB_UNUSED,
        data: DEFAULT_PARAMETER_CBB.to_vec(),
    }
}

fn default_services_supported() -> BitString {
    BitString {
        unused_bits: DEFAULT_SERVICES_SUPPORTED_UNUSED,
        data: DEFAULT_SERVICES_SUPPORTED.to_vec(),
    }
}

/// An MMS `Initiate-RequestPDU`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateRequest {
    /// `localDetailCalling` — proposed max PDU size.
    pub local_detail: Option<i64>,
    /// `proposedMaxServOutstandingCalling`.
    pub max_outstanding_calling: i64,
    /// `proposedMaxServOutstandingCalled`.
    pub max_outstanding_called: i64,
    /// `proposedDataStructureNestingLevel`.
    pub nesting_level: Option<i64>,
    /// `proposedVersionNumber`.
    pub version: i64,
    /// `proposedParameterCBB`.
    pub parameter_cbb: BitString,
    /// `servicesSupportedCalling`.
    pub services_supported: BitString,
}

impl Default for InitiateRequest {
    fn default() -> Self {
        InitiateRequest {
            local_detail: Some(DEFAULT_LOCAL_DETAIL),
            max_outstanding_calling: DEFAULT_OUTSTANDING,
            max_outstanding_called: DEFAULT_OUTSTANDING,
            nesting_level: Some(DEFAULT_NESTING_LEVEL),
            version: DEFAULT_VERSION,
            parameter_cbb: default_parameter_cbb(),
            services_supported: default_services_supported(),
        }
    }
}

/// An MMS `Initiate-ResponsePDU`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitiateResponse {
    /// `localDetailCalled`.
    pub local_detail: Option<i64>,
    /// `negotiatedMaxServOutstandingCalling`.
    pub max_outstanding_calling: i64,
    /// `negotiatedMaxServOutstandingCalled`.
    pub max_outstanding_called: i64,
    /// `negotiatedDataStructureNestingLevel`.
    pub nesting_level: Option<i64>,
    /// `negotiatedVersionNumber`.
    pub version: i64,
    /// `negotiatedParameterCBB`.
    pub parameter_cbb: BitString,
    /// `servicesSupportedCalled`.
    pub services_supported: BitString,
}

impl Default for InitiateResponse {
    fn default() -> Self {
        InitiateResponse {
            local_detail: Some(DEFAULT_LOCAL_DETAIL),
            max_outstanding_calling: DEFAULT_OUTSTANDING,
            max_outstanding_called: DEFAULT_OUTSTANDING,
            nesting_level: Some(DEFAULT_NESTING_LEVEL),
            version: DEFAULT_VERSION,
            parameter_cbb: default_parameter_cbb(),
            services_supported: default_services_supported(),
        }
    }
}

/// Shared field layout for request and response (the wire shape is identical;
/// only field names differ in the standard).
struct InitiateFields {
    local_detail: Option<i64>,
    max_outstanding_calling: i64,
    max_outstanding_called: i64,
    nesting_level: Option<i64>,
    version: i64,
    parameter_cbb: BitString,
    services_supported: BitString,
}

fn encode_fields(f: &InitiateFields, w: &mut BerWriter) {
    if let Some(ld) = f.local_detail {
        w.write_integer(TAG_LOCAL_DETAIL, ld);
    }
    w.write_integer(TAG_OUTSTANDING_CALLING, f.max_outstanding_calling);
    w.write_integer(TAG_OUTSTANDING_CALLED, f.max_outstanding_called);
    if let Some(nl) = f.nesting_level {
        w.write_integer(TAG_NESTING_LEVEL, nl);
    }
    w.write_tlv(TAG_INIT_DETAIL, |detail| {
        detail.write_integer(TAG_VERSION, f.version);
        detail.write_bit_string(TAG_PARAMETER_CBB, &f.parameter_cbb);
        detail.write_bit_string(TAG_SERVICES_SUPPORTED, &f.services_supported);
    });
}

fn decode_fields(content: &[u8]) -> Result<InitiateFields> {
    let mut r = BerReader::new(content);
    let mut local_detail = None;
    let mut max_outstanding_calling = None;
    let mut max_outstanding_called = None;
    let mut nesting_level = None;
    let mut version = None;
    let mut parameter_cbb = None;
    let mut services_supported = None;

    while !r.done() {
        let (tag, c) = r.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
        if tag == TAG_LOCAL_DETAIL {
            local_detail = Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
        } else if tag == TAG_OUTSTANDING_CALLING {
            max_outstanding_calling =
                Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
        } else if tag == TAG_OUTSTANDING_CALLED {
            max_outstanding_called = Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
        } else if tag == TAG_NESTING_LEVEL {
            nesting_level = Some(decode_integer_i64(c).map_err(|_| Error::MmsInvalidPdu)?);
        } else if tag == TAG_INIT_DETAIL {
            let mut dr = BerReader::new(c);
            while !dr.done() {
                let (dt, dc) = dr.read_tlv().map_err(|_| Error::MmsInvalidPdu)?;
                if dt == TAG_VERSION {
                    version = Some(decode_integer_i64(dc).map_err(|_| Error::MmsInvalidPdu)?);
                } else if dt == TAG_PARAMETER_CBB {
                    parameter_cbb = Some(decode_bit_string(dc).map_err(|_| Error::MmsInvalidPdu)?);
                } else if dt == TAG_SERVICES_SUPPORTED {
                    services_supported =
                        Some(decode_bit_string(dc).map_err(|_| Error::MmsInvalidPdu)?);
                }
            }
        }
        // Unknown trailing fields: skip (tolerant).
    }

    Ok(InitiateFields {
        local_detail,
        max_outstanding_calling: max_outstanding_calling.ok_or(Error::MmsInvalidPdu)?,
        max_outstanding_called: max_outstanding_called.ok_or(Error::MmsInvalidPdu)?,
        nesting_level,
        version: version.ok_or(Error::MmsInvalidPdu)?,
        parameter_cbb: parameter_cbb.ok_or(Error::MmsInvalidPdu)?,
        services_supported: services_supported.ok_or(Error::MmsInvalidPdu)?,
    })
}

impl InitiateRequest {
    /// Encode the body of the `initiate-RequestPDU [8]` (the wrapper tag is
    /// supplied by [`crate::mms::pdu::MmsPdu`]).
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        encode_fields(
            &InitiateFields {
                local_detail: self.local_detail,
                max_outstanding_calling: self.max_outstanding_calling,
                max_outstanding_called: self.max_outstanding_called,
                nesting_level: self.nesting_level,
                version: self.version,
                parameter_cbb: self.parameter_cbb.clone(),
                services_supported: self.services_supported.clone(),
            },
            w,
        );
    }

    pub(crate) fn decode(content: &[u8]) -> Result<Self> {
        let f = decode_fields(content)?;
        Ok(InitiateRequest {
            local_detail: f.local_detail,
            max_outstanding_calling: f.max_outstanding_calling,
            max_outstanding_called: f.max_outstanding_called,
            nesting_level: f.nesting_level,
            version: f.version,
            parameter_cbb: f.parameter_cbb,
            services_supported: f.services_supported,
        })
    }
}

impl InitiateResponse {
    /// Encode the body of the `initiate-ResponsePDU [9]`.
    pub(crate) fn encode(&self, w: &mut BerWriter) {
        encode_fields(
            &InitiateFields {
                local_detail: self.local_detail,
                max_outstanding_calling: self.max_outstanding_calling,
                max_outstanding_called: self.max_outstanding_called,
                nesting_level: self.nesting_level,
                version: self.version,
                parameter_cbb: self.parameter_cbb.clone(),
                services_supported: self.services_supported.clone(),
            },
            w,
        );
    }

    pub(crate) fn decode(content: &[u8]) -> Result<Self> {
        let f = decode_fields(content)?;
        Ok(InitiateResponse {
            local_detail: f.local_detail,
            max_outstanding_calling: f.max_outstanding_calling,
            max_outstanding_called: f.max_outstanding_called,
            nesting_level: f.nesting_level,
            version: f.version,
            parameter_cbb: f.parameter_cbb,
            services_supported: f.services_supported,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_default_roundtrip() {
        let req = InitiateRequest::default();
        let mut w = BerWriter::new();
        req.encode(&mut w);
        assert_eq!(InitiateRequest::decode(&w.into_bytes()).unwrap(), req);
    }

    #[test]
    fn request_optionals_absent() {
        let req = InitiateRequest {
            local_detail: None,
            max_outstanding_calling: 1,
            max_outstanding_called: 1,
            nesting_level: None,
            version: 1,
            parameter_cbb: default_parameter_cbb(),
            services_supported: default_services_supported(),
        };
        let mut w = BerWriter::new();
        req.encode(&mut w);
        assert_eq!(InitiateRequest::decode(&w.into_bytes()).unwrap(), req);
    }

    #[test]
    fn response_default_roundtrip() {
        let resp = InitiateResponse::default();
        let mut w = BerWriter::new();
        resp.encode(&mut w);
        assert_eq!(InitiateResponse::decode(&w.into_bytes()).unwrap(), resp);
    }

    #[test]
    fn request_default_exact_bytes() {
        // Exact-byte assertion for a known-good Initiate-RequestPDU body, derived
        // from the libiec61850 client defaults (mms_client_initiate.c):
        //   localDetailCalling [0] = 65000 (0xFDE8 -> 03 00 FD E8 with sign pad)
        //   outstanding calling [1] = 10
        //   outstanding called  [2] = 10
        //   nesting level       [3] = 5
        //   initRequestDetail   [4] { version [0]=1, parameterCBB [1]=05 f1 00,
        //                             services [2]=03 ee 1c 00 00 04 08 00 00 79 ef 18 }
        let req = InitiateRequest::default();
        let mut w = BerWriter::new();
        req.encode(&mut w);
        let got = w.into_bytes();

        let expected: &[u8] = &[
            // localDetailCalling [0] INTEGER 65000 -> 00 FD E8 (leading 00 keeps
            // it positive since 0xFD has the high bit set)
            0x80, 0x03, 0x00, 0xFD, 0xE8,
            // proposedMaxServOutstandingCalling [1] INTEGER 10
            0x81, 0x01, 0x0A, // proposedMaxServOutstandingCalled [2] INTEGER 10
            0x82, 0x01, 0x0A, // proposedDataStructureNestingLevel [3] INTEGER 5
            0x83, 0x01, 0x05, // initRequestDetail [4] (constructed) length 0x16 = 22
            0xA4, 0x16, //   proposedVersionNumber [0] INTEGER 1
            0x80, 0x01, 0x01, //   proposedParameterCBB [1] BIT STRING 05 f1 00
            0x81, 0x03, 0x05, 0xF1, 0x00,
            //   servicesSupportedCalling [2] BIT STRING 03 ee 1c ...
            0x82, 0x0C, 0x03, 0xEE, 0x1C, 0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x79, 0xEF, 0x18,
        ];
        assert_eq!(got, expected, "Initiate-RequestPDU default bytes");
    }
}
