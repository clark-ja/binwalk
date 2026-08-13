use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::ebml::parse_ebml_header;

/// Human readable description
pub const DESCRIPTION: &str = "EBML data";

/// Every EBML document starts with the ID of its header element
pub fn ebml_magic() -> Vec<Vec<u8>> {
    vec![b"\x1A\x45\xDF\xA3".to_vec()]
}

/// Validate an EBML signature
pub fn ebml_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    if let Ok(ebml_header) = parse_ebml_header(&file_data[offset..]) {
        /*
         * The header describes only itself. What follows it is a segment whose own length may be
         * unknown even to a reader of the file, so no size is reported.
         */
        result.description = format!(
            "{}, doc type: \"{}\", header size: {} bytes",
            result.description, ebml_header.doc_type, ebml_header.header_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
