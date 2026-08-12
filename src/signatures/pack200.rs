use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "JAR archive compressed with pack200";

/// pack200 archives start with these magic bytes
pub fn pack200_magic() -> Vec<Vec<u8>> {
    vec![b"\xCA\xFE\xD0\x0D".to_vec()]
}

/// Validate a pack200 signature
pub fn pack200_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    /*
     * The archive version follows the magic, encoded with the variable length integer coding that
     * the format uses throughout. For every version ever released, minor then major, that coding
     * puts the two values in a byte each.
     */
    const MINOR_VERSION_OFFSET: usize = 4;
    const MAJOR_VERSION_OFFSET: usize = 5;

    const MAJOR_VERSION: u8 = 150;
    const MAX_MINOR_VERSION: u8 = 7;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let minor_version = match file_data.get(offset + MINOR_VERSION_OFFSET) {
        Some(minor_version) => *minor_version,
        None => return Err(SignatureError),
    };

    let major_version = match file_data.get(offset + MAJOR_VERSION_OFFSET) {
        Some(major_version) => *major_version,
        None => return Err(SignatureError),
    };

    if major_version != MAJOR_VERSION || minor_version > MAX_MINOR_VERSION {
        return Err(SignatureError);
    }

    /*
     * What follows the version is a series of compressed bands whose lengths are themselves
     * encoded, so the size of the archive cannot be had without unpacking it.
     */
    result.description = format!(
        "{}, version: {}.{}",
        result.description, major_version, minor_version
    );

    Ok(result)
}
