use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::pe::parse_pe_header;

/// Human readable description
pub const DESCRIPTION: &str = "Windows PE binary";

/// PE file magic
pub fn pe_magic() -> Vec<Vec<u8>> {
    /*
     * Only the two bytes that begin the DOS header are matched here; the rest of the header varies
     * between linkers and DOS stubs. What makes a match a PE binary is checked by the parser: the
     * reserved fields of the DOS header must be zero, and the offset it holds must point at a PE
     * header with a known machine type.
     */
    vec![b"MZ".to_vec()]
}

/// Validate a PE header
pub fn pe_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Parse the PE header
    if let Ok(pe_header) = parse_pe_header(&file_data[offset..]) {
        result.description = format!(
            "{}, machine type: {}",
            result.description, pe_header.machine
        );
        return Ok(result);
    }

    Err(SignatureError)
}
