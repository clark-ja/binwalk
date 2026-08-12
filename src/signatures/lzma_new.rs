use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "LZMA compressed data, alternative header";

/// The alternative LZMA header starts with these magic bytes
pub fn lzma_new_magic() -> Vec<Vec<u8>> {
    vec![b"\xFFLZMA\x00".to_vec()]
}

/// Validate an alternative LZMA header signature
pub fn lzma_new_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The properties byte that follows the magic encodes lc, lp and pb as ((pb * 5) + lp) * 9 + lc
    const PROPERTIES_OFFSET: usize = 6;
    const MAX_PROPERTIES: u8 = 224;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let properties = match file_data.get(offset + PROPERTIES_OFFSET) {
        Some(properties) => *properties,
        None => return Err(SignatureError),
    };

    if properties > MAX_PROPERTIES {
        return Err(SignatureError);
    }

    /*
     * Nothing in this header describes the length of the stream that follows it, so the size is
     * left unknown.
     */
    result.description = format!("{}, properties: {:#04X}", result.description, properties);

    Ok(result)
}
