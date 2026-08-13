use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};

/// Human readable descriptions
pub const STANDARD_DESCRIPTION: &str = "Base64 standard index table";
pub const SERCOMM_DESCRIPTION: &str = "Base64 SerComm index table";

/// The index table of a standard Base64 implementation
pub fn standard_table_magic() -> Vec<Vec<u8>> {
    vec![b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec()]
}

/// The scrambled index table that SerComm firmware uses in place of it
pub fn sercomm_table_magic() -> Vec<Vec<u8>> {
    vec![b"ACEGIKMOQSUWYBDFHJLNPRTVXZacegikmoqsuwybdfhjlnprtvxz0246813579=+/".to_vec()]
}

/// Validate a standard Base64 index table signature
pub fn standard_table_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    Ok(index_table(offset, STANDARD_DESCRIPTION))
}

/// Validate a SerComm Base64 index table signature
pub fn sercomm_table_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    Ok(index_table(offset, SERCOMM_DESCRIPTION))
}

/// Both tables are sixty four bytes of constant, which is the whole of the signature
fn index_table(offset: usize, description: &str) -> SignatureResult {
    const TABLE_SIZE: usize = 64;

    SignatureResult {
        offset,
        size: TABLE_SIZE,
        description: description.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    }
}
