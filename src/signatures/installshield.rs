use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::installshield::parse_installshield_header;

/// Human readable description
pub const DESCRIPTION: &str = "InstallShield cabinet archive";

/// InstallShield cabinets start with these magic bytes
pub fn installshield_magic() -> Vec<Vec<u8>> {
    vec![b"ISc(".to_vec()]
}

/// Validate an InstallShield cabinet signature
pub fn installshield_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let available_data = file_data.len() - offset;

    if let Ok(cabinet_header) = parse_installshield_header(&file_data[offset..]) {
        /*
         * The descriptor sits at the end of the cabinet, so where it ends is where the cabinet
         * ends; a descriptor that runs past the available data is a false positive.
         */
        let cabinet_size = cabinet_header.descriptor_offset + cabinet_header.descriptor_size;

        if cabinet_size <= available_data {
            result.size = cabinet_size;
            result.description = format!(
                "{}, version: {:#X}, total size: {} bytes",
                result.description, cabinet_header.version, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}
