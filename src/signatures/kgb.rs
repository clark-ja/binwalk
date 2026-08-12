use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "KGB archive";

/// KGB archives start with this string
pub fn kgb_magic() -> Vec<Vec<u8>> {
    vec![b"KGB_arch -".to_vec()]
}

/// Validate a KGB archive signature
pub fn kgb_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The magic is followed by the version of the archiver that wrote the archive
    const VERSION_OFFSET: usize = 10;
    const MAX_VERSION_SIZE: usize = 16;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let version_start = offset + VERSION_OFFSET;
    let version_end = std::cmp::min(version_start + MAX_VERSION_SIZE, file_data.len());

    // The version is printable text; anything else is not a KGB archive
    let version: String = match file_data.get(version_start..version_end) {
        Some(version_data) => version_data
            .iter()
            .take_while(|b| b.is_ascii_graphic() || **b == b' ')
            .map(|b| *b as char)
            .collect(),
        None => return Err(SignatureError),
    };

    if version.trim().is_empty() {
        return Err(SignatureError);
    }

    /*
     * The archive header does not describe the length of the archive, so the size is left unknown.
     */
    result.description = format!("{}, version: {}", result.description, version.trim());

    Ok(result)
}
