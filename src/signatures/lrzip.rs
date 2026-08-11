use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "lrzip compressed data";

/// lrzip files start with these magic bytes
pub fn lrzip_magic() -> Vec<Vec<u8>> {
    vec![b"LRZI".to_vec()]
}

/// Validate an lrzip signature
pub fn lrzip_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const MAJOR_VERSION_OFFSET: usize = 4;
    const MINOR_VERSION_OFFSET: usize = 5;

    // No release has ever carried a version outside of these
    const MAX_MAJOR_VERSION: u8 = 1;
    const MAX_MINOR_VERSION: u8 = 20;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let major_version = match file_data.get(offset + MAJOR_VERSION_OFFSET) {
        Some(major_version) => *major_version,
        None => return Err(SignatureError),
    };

    let minor_version = match file_data.get(offset + MINOR_VERSION_OFFSET) {
        Some(minor_version) => *minor_version,
        None => return Err(SignatureError),
    };

    /*
     * There is nothing else in the header that can be checked without knowing which version wrote
     * it, and what follows the version differs between them, so the size is left unknown.
     */
    if major_version > MAX_MAJOR_VERSION || minor_version > MAX_MINOR_VERSION {
        return Err(SignatureError);
    }

    result.description = format!(
        "{}, version: {}.{}",
        result.description, major_version, minor_version
    );

    Ok(result)
}
