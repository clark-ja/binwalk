use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "Windows Script encoded data";

/// Encoded scripts start with this marker
pub fn screnc_magic() -> Vec<Vec<u8>> {
    vec![b"#@~^".to_vec()]
}

/// Validate a Windows Script encoded data signature
pub fn screnc_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    /*
     * The marker is followed by the length of the encoded script, as six characters of base64, and
     * then by two more characters that close the header.
     */
    const LENGTH_OFFSET: usize = 4;
    const LENGTH_SIZE: usize = 6;
    const HEADER_TERMINATOR: &[u8; 2] = b"==";

    let result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let length_start = offset + LENGTH_OFFSET;
    let length_end = length_start + LENGTH_SIZE;

    let length = match file_data.get(length_start..length_end) {
        Some(length) => length,
        None => return Err(SignatureError),
    };

    // The length is base64, so every character of it has to be one
    if !length
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    {
        return Err(SignatureError);
    }

    if file_data.get(length_end..length_end + HEADER_TERMINATOR.len()) != Some(HEADER_TERMINATOR) {
        return Err(SignatureError);
    }

    /*
     * The length is encoded with the same substitution table as the script itself, which is not
     * worth reproducing here just to report a size.
     */
    Ok(result)
}
