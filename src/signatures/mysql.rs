use crate::signatures::common::{CONFIDENCE_LOW, SignatureError, SignatureResult};

/// Human readable descriptions
pub const FRM_DESCRIPTION: &str = "MySQL table definition file";
pub const MISAM_INDEX_DESCRIPTION: &str = "MySQL MISAM index file";
pub const MISAM_DATA_DESCRIPTION: &str = "MySQL MISAM compressed data file";
pub const ISAM_INDEX_DESCRIPTION: &str = "MySQL ISAM index file";
pub const ISAM_DATA_DESCRIPTION: &str = "MySQL ISAM compressed data file";

/// A table definition file starts with this
pub fn frm_magic() -> Vec<Vec<u8>> {
    vec![b"\xFE\x01".to_vec()]
}

/// The index and data files of the two storage engines each start with their own byte
pub fn misam_index_magic() -> Vec<Vec<u8>> {
    vec![b"\xFE\xFE\x03".to_vec()]
}

pub fn misam_data_magic() -> Vec<Vec<u8>> {
    vec![b"\xFE\xFE\x07".to_vec()]
}

pub fn isam_index_magic() -> Vec<Vec<u8>> {
    vec![b"\xFE\xFE\x05".to_vec()]
}

pub fn isam_data_magic() -> Vec<Vec<u8>> {
    vec![b"\xFE\xFE\x06".to_vec()]
}

/// None of these files describes its own length, and their magics are two and three bytes, so all
/// of them are matched only at the start of a file and none of them reports a size.
fn describe(offset: usize, description: &str) -> Result<SignatureResult, SignatureError> {
    Ok(SignatureResult {
        offset,
        description: description.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    })
}

pub fn frm_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    describe(offset, FRM_DESCRIPTION)
}

pub fn misam_index_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    describe(offset, MISAM_INDEX_DESCRIPTION)
}

pub fn misam_data_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    describe(offset, MISAM_DATA_DESCRIPTION)
}

pub fn isam_index_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    describe(offset, ISAM_INDEX_DESCRIPTION)
}

pub fn isam_data_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    describe(offset, ISAM_DATA_DESCRIPTION)
}
