use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::psx::parse_psx_header;

/// Human readable description
pub const DESCRIPTION: &str = "Sony PlayStation executable";

/// PlayStation executables start with this
pub fn psx_magic() -> Vec<Vec<u8>> {
    vec![b"PS-X EXE".to_vec()]
}

/// Validate a PlayStation executable signature
pub fn psx_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let available_data = file_data.len() - offset;

    if let Ok(psx_header) = parse_psx_header(&file_data[offset..]) {
        // The header is one sector, and the text section follows it
        let total_size = psx_header.header_size + psx_header.text_size;

        if total_size <= available_data {
            result.size = total_size;
        }

        result.description = format!(
            "{}, entry point: {:#X}, load address: {:#X}, total size: {} bytes",
            result.description, psx_header.entry_point, psx_header.text_address, total_size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
