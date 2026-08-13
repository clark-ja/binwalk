use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};

/// Human readable descriptions
pub const PC1_DESCRIPTION: &str = "DES PC1 permutation table";
pub const PC2_DESCRIPTION: &str = "DES PC2 permutation table";
pub const SP1_DESCRIPTION: &str = "DES SP1 table";
pub const SP2_DESCRIPTION: &str = "DES SP2 table";

/*
 * The tables below are constants of the algorithm, so each of them is the whole of its
 * signature and its length is the size reported for it. The SP tables are indexed as words,
 * so they appear in one of two byte orders; the permutation tables are indexed as bytes and
 * so read the same either way.
 */

/// DES PC1 permutation table
pub fn des_pc1_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x38\x30\x28\x20\x18\x10\x08\x00\x39\x31\x29\x21\x19\x11\x09\x01\x3A\x32\x2A\x22\x1A\x12\x0A\x02\x3B\x33\x2B\x23\x3E\x36\x2E\x26\x1E\x16\x0E\x06\x3D\x35\x2D\x25\x1D\x15\x0D\x05\x3C\x34\x2C\x24\x1C\x14\x0C\x04\x1B\x13\x0B\x03".to_vec(),
    ]
}

/// DES PC2 permutation table
pub fn des_pc2_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x0D\x10\x0A\x17\x00\x04\x02\x1B\x0E\x05\x14\x09\x16\x12\x0B\x03\x19\x07\x0F\x06\x1A\x13\x0C\x01\x28\x33\x1E\x24\x2E\x36\x1D\x27\x32\x2C\x20\x2F\x2B\x30\x26\x37\x21\x34\x2D\x29\x31\x23\x1C\x1F".to_vec(),
    ]
}

/// DES SP1 table
pub fn des_sp1_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x01\x01\x04\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01\x01\x04\x04\x01\x01\x00\x04\x00\x01\x04\x04\x00\x00\x00\x04\x00\x01\x00\x00".to_vec(),  // big endian
        b"\x00\x04\x01\x01\x00\x00\x00\x00\x00\x00\x01\x00\x04\x04\x01\x01\x04\x00\x01\x01\x04\x04\x01\x00\x04\x00\x00\x00\x00\x00\x01\x00".to_vec(),  // little endian
    ]
}

/// DES SP2 table
pub fn des_sp2_magic() -> Vec<Vec<u8>> {
    vec![
        b"\x80\x10\x80\x20\x80\x00\x80\x00\x00\x00\x80\x00\x00\x10\x80\x20\x00\x10\x00\x00\x00\x00\x00\x20\x80\x10\x00\x20\x80\x00\x80\x20".to_vec(),  // big endian
        b"\x20\x80\x10\x80\x00\x80\x00\x80\x00\x80\x00\x00\x20\x80\x10\x00\x00\x00\x10\x00\x20\x00\x00\x00\x20\x00\x10\x80\x20\x80\x00\x80".to_vec(),  // little endian
    ]
}

/// Validate a DES PC1 permutation table signature
pub fn des_pc1_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(des_table(offset, PC1_DESCRIPTION, 56))
}

/// Validate a DES PC2 permutation table signature
pub fn des_pc2_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(des_table(offset, PC2_DESCRIPTION, 48))
}

/// Validate a DES SP1 table signature
pub fn des_sp1_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(des_table(offset, SP1_DESCRIPTION, 32))
}

/// Validate a DES SP2 table signature
pub fn des_sp2_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(des_table(offset, SP2_DESCRIPTION, 32))
}

/// A table is a constant, so a match on it is the table itself
fn des_table(offset: usize, description: &str, size: usize) -> SignatureResult {
    SignatureResult {
        offset,
        size,
        description: description.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    }
}
