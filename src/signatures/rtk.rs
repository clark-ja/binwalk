use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::rtk::{parse_rome_header, parse_rtk_header};

/// Human readable descriptions
pub const DESCRIPTION: &str = "RTK firmware header";
pub const ROME_DESCRIPTION: &str = "Realtek ROME bootloader firmware header";

/// ROME bootloader magic bytes; these are specific to each product that uses the bootloader
pub fn rome_magic() -> Vec<Vec<u8>> {
    vec![
        // Netgear KWGR614
        b"G614".to_vec(),
        // Linksys WRT54GX
        b"\x59\xA0\xE8\x42".to_vec(),
    ]
}

/// RTK firmware images always start with these bytes
pub fn rtk_magic() -> Vec<Vec<u8>> {
    vec![b"RTK0".to_vec()]
}

/// Validates the RTK header
pub fn rtk_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // Note: magic.rs enforces short=true for this signature, so offset will always be 0
    let available_data = file_data.len() - offset;

    if let Ok(rtk_header) = parse_rtk_header(&file_data[offset..]) {
        // This firmware header is expected to encompass the entirety of the remaining file data
        if rtk_header.image_size == available_data {
            result.size = rtk_header.header_size;
            result.description = format!(
                "{}, header size: {} bytes, image size: {}",
                result.description, rtk_header.header_size, rtk_header.image_size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validates a ROME bootloader firmware header
pub fn rome_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: ROME_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(rome_header) = parse_rome_header(&file_data[offset..]) {
        /*
         * Only the header itself is reported, so that whatever the image contains is scanned for
         * signatures of its own.
         */
        result.size = rome_header.header_size;
        result.description = format!(
            "{}, image type: {}, header version: {}, created: {}, image size: {} bytes",
            result.description,
            rome_header.image_type,
            rome_header.header_version,
            rome_header.creation_date,
            rome_header.image_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
