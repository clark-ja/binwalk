use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::samsung_toc::parse_samsung_toc;

/// Human readable description
pub const DESCRIPTION: &str = "Samsung modem TOC index";

/// The first entry of the index describes the index itself, and is named for it
pub fn samsung_toc_magic() -> Vec<Vec<u8>> {
    vec![b"TOC\x00\x00\x00\x00".to_vec()]
}

/// Validate a Samsung modem TOC index signature
pub fn samsung_toc_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data = file_data.len() - offset;

    if let Ok(toc) = parse_samsung_toc(&file_data[offset..]) {
        // The first entry describes the whole image, which is what gives the size
        if toc.image_size <= available_data {
            result.size = toc.image_size;
        }

        result.description = format!(
            "{}, entry count: {}, total size: {} bytes",
            result.description, toc.entry_count, toc.image_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
