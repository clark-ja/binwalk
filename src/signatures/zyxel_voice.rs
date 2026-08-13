use crate::signatures::common::{CONFIDENCE_LOW, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "ZyXEL voice data";

/// ZyXEL voice data starts with this
pub fn zyxel_voice_magic() -> Vec<Vec<u8>> {
    vec![b"ZyXEL\x02".to_vec()]
}

/// Validate a ZyXEL voice data signature
pub fn zyxel_voice_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    /*
     * Nothing after the magic is documented, and it does not describe the length of the data, so
     * there is nothing to validate and no size to report.
     */
    Ok(SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    })
}
