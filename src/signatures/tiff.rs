use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::tiff::parse_tiff_header;

/// Human readable description
pub const DESCRIPTION: &str = "TIFF image data";

/// TIFF images start with a byte order mark and the version of the format
pub fn tiff_magic() -> Vec<Vec<u8>> {
    vec![b"MM\x00\x2A".to_vec(), b"II\x2A\x00".to_vec()]
}

/// Validate a TIFF signature
pub fn tiff_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    if let Ok(tiff_header) = parse_tiff_header(&file_data[offset..]) {
        /*
         * The image is a chain of directories, each pointing at the next and at data that may be
         * anywhere in the file, so its length is only known by following all of them; the size is
         * left unknown.
         */
        result.description = format!(
            "{}, {} endian, first directory: {} entries at offset {}",
            result.description,
            tiff_header.endianness,
            tiff_header.entry_count,
            tiff_header.directory_offset
        );
        return Ok(result);
    }

    Err(SignatureError)
}
