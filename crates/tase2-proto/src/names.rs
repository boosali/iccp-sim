//! Names of the Block-1-relevant TASE.2 special VMD-scoped variables.
//!
//! Spellings verified against the FreeTase2 client
//! (<https://github.com/aklira/FreeTase2>, `tase2/client/client.py`, which reads
//! `Bilateral_Table_ID`, `TASE2_Version` as `{major, minor}` and
//! `Supported_Features` as a BitString) and the libtase2 developer guide.
//!
//! The Block-2 transfer-set special names below are verified against the
//! FreeTase2 client/common sources (`tase2/client/client.py`,
//! `tase2/common/iccpcommon.py` — which reference the variables
//! `Transfer_Set_Name`, `Transfer_Set_Time_Stamp`, `DSConditions_Detected` and
//! `Next_DSTransfer_Set`) and the libtase2 developer guide §8.6 / Table 1,
//! which lists the special data-set members `Transfer_Set_Name`,
//! `Transfer_Set_Time_Stamp`, `DSConditions_Detected`, `Event_Code_Detected`.

/// `Bilateral_Table_ID` — the negotiated bilateral table identifier
/// (VisibleString).
pub const BILATERAL_TABLE_ID: &str = "Bilateral_Table_ID";

/// `TASE2_Version` — the supported protocol version, a structure of
/// `{ major: Unsigned, minor: Unsigned }`.
pub const TASE2_VERSION: &str = "TASE2_Version";

/// `Supported_Features` — a BitString advertising the conformance blocks /
/// optional features the peer supports.
pub const SUPPORTED_FEATURES: &str = "Supported_Features";

// --- Block 2: DS transfer sets ---------------------------------------------

/// `Next_DSTransfer_Set` — the VMD/domain-scoped special variable a client
/// reads to claim an unused DS-transfer-set instance. The server answers with
/// the [`ObjectName`](mms_proto::mms::ObjectName) of a free transfer set.
///
/// libtase2 names the C-side instances `DSTransferSet`/`DSTransferSetN`; the
/// FreeTase2 stub reads `Next_DSTransfer_Set` (no trailing `_Name`). We follow
/// FreeTase2's spelling for the special variable name.
pub const NEXT_DSTRANSFER_SET_NAME: &str = "Next_DSTransfer_Set";

/// `Transfer_Set_Name` — special data-set member carrying the reporting
/// transfer set's name (an MMS `ObjectName` structure).
pub const TRANSFER_SET_NAME: &str = "Transfer_Set_Name";

/// `Transfer_Set_Time_Stamp` — special data-set member carrying the report
/// timestamp (`GMTBasedS`, an `Integer` of UTC seconds).
pub const TRANSFER_SET_TIME_STAMP: &str = "Transfer_Set_Time_Stamp";

/// `DSConditions_Detected` — special data-set member carrying the
/// [`DsConditions`](crate::transfer_set::DsConditions) that triggered the
/// report (a `BitString(5)`).
pub const DSCONDITIONS_DETECTED: &str = "DSConditions_Detected";

/// `Event_Code_Detected` — special data-set member carrying the external event
/// code (`Integer`, i16 range) for the report.
pub const EVENT_CODE_DETECTED: &str = "Event_Code_Detected";
