use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::rzip::parse_rzip_header;

/// Human readable description
pub const DESCRIPTION: &str = "rzip compressed data";

/// rzip files start with these magic bytes
pub fn rzip_magic() -> Vec<Vec<u8>> {
    vec![b"RZIP".to_vec()]
}

/// Validate an rzip signature
pub fn rzip_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    /*
     * The header describes the size of the data before it was compressed, not the size of the
     * compressed data, so the size of the file itself is left unknown.
     */
    if let Ok(rzip_header) = parse_rzip_header(&file_data[offset..]) {
        result.description = format!(
            "{}, version: {}.{}, uncompressed size: {} bytes",
            result.description,
            rzip_header.major_version,
            rzip_header.minor_version,
            rzip_header.uncompressed_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
