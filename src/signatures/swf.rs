use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::swf::parse_swf_header;

/// Human readable description
pub const DESCRIPTION: &str = "Adobe Flash SWF file";

/// SWF files start with one of these, according to how the body is compressed
pub fn swf_magic() -> Vec<Vec<u8>> {
    vec![b"FWS".to_vec(), b"CWS".to_vec(), b"ZWS".to_vec()]
}

/// Validate an SWF signature
pub fn swf_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data = file_data.len() - offset;

    if let Ok(swf_header) = parse_swf_header(&file_data[offset..]) {
        // The header carries the length of the whole file, decompressed
        if swf_header.compression == "uncompressed" && swf_header.file_size > available_data {
            return Err(SignatureError);
        }

        result.size = match swf_header.compression.as_str() {
            "uncompressed" => swf_header.file_size,
            // A compressed body is smaller than the length the header reports
            _ => 0,
        };

        result.description = format!(
            "{}, version: {}, {}, file size: {} bytes",
            result.description, swf_header.version, swf_header.compression, swf_header.file_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
