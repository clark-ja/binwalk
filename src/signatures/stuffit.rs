use crate::signatures::common::{
    CONFIDENCE_HIGH, CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};
use crate::structures::stuffit::parse_stuffit_header;

/// Human readable descriptions
pub const DESCRIPTION: &str = "StuffIt archive";
pub const SEGMENT_DESCRIPTION: &str = "StuffIt Deluxe segment";

/// Classic StuffIt archives, and the text banner that StuffIt 5 archives begin with
pub fn stuffit_magic() -> Vec<Vec<u8>> {
    vec![b"SIT!".to_vec(), b"SITD".to_vec(), b"StuffIt".to_vec()]
}

/// StuffIt Deluxe segments start with this, and nothing else identifies them
pub fn stuffit_segment_magic() -> Vec<Vec<u8>> {
    vec![b"Sef".to_vec()]
}

/// Validate a StuffIt archive signature
pub fn stuffit_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // StuffIt 5 archives begin with a text banner rather than with a binary header
    const BANNER_MAGIC: &[u8; 7] = b"StuffIt";

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if file_data.get(offset..offset + BANNER_MAGIC.len()) == Some(BANNER_MAGIC) {
        result.description = format!("{}, version 5", result.description);
        return Ok(result);
    }

    /*
     * Classic archives carry their own total size, and a second signature after the file count
     * that confirms the match.
     */
    if let Ok(stuffit_header) = parse_stuffit_header(&file_data[offset..]) {
        let available_data = file_data.len() - offset;

        if stuffit_header.total_size <= available_data {
            result.confidence = CONFIDENCE_HIGH;
            result.size = stuffit_header.total_size;
            result.description = format!(
                "{}, file count: {}, total size: {} bytes",
                result.description, stuffit_header.file_count, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validate a StuffIt Deluxe segment signature
pub fn stuffit_segment_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    /*
     * There is nothing here to validate: the magic is three bytes and no description of what
     * follows it is available, so this signature is only matched at the start of a file.
     */
    Ok(SignatureResult {
        offset,
        description: SEGMENT_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    })
}
