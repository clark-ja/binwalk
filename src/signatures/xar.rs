use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::xar::parse_xar_header;

/// Human readable description
pub const DESCRIPTION: &str = "XAR archive";

/// XAR archives start with these magic bytes
pub fn xar_magic() -> Vec<Vec<u8>> {
    vec![b"xar!".to_vec()]
}

/// Validate a XAR archive signature
pub fn xar_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    if let Ok(xar_header) = parse_xar_header(&file_data[offset..]) {
        /*
         * The header describes the table of contents but not the heap of file data that follows
         * it, whose length is only described by the table of contents itself, so the size reported
         * here covers the header and the table of contents alone.
         */
        result.size = xar_header.header_size + xar_header.toc_compressed_size;
        result.description = format!(
            "{}, version: {}, checksum algorithm: {}, table of contents: {} bytes compressed, {} bytes uncompressed",
            result.description,
            xar_header.version,
            xar_header.checksum_algorithm,
            xar_header.toc_compressed_size,
            xar_header.toc_uncompressed_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
