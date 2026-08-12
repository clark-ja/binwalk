use crate::signatures::common::{CONFIDENCE_LOW, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "AFX compressed data";

/// The signature sits this many bytes into the file
pub const MAGIC_OFFSET: usize = 2;

/// AFX compressed files carry this signature
pub fn afx_magic() -> Vec<Vec<u8>> {
    vec![b"-afx".to_vec()]
}

/// Validate an AFX signature
pub fn afx_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    // The file starts before the signature
    if offset < MAGIC_OFFSET {
        return Err(SignatureError);
    }

    result.offset = offset - MAGIC_OFFSET;

    /*
     * There is nothing else here to validate, and no description of the format available, so this
     * signature is only matched at the start of a file and reports no size.
     */
    if file_data.get(result.offset..offset).is_none() {
        return Err(SignatureError);
    }

    Ok(result)
}
