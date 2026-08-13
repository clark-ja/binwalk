use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "Xen saved domain file";

/// A saved domain starts with this
pub fn xen_magic() -> Vec<Vec<u8>> {
    vec![b"LinuxGuestRecord".to_vec()]
}

/// Validate a Xen saved domain signature
pub fn xen_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    /*
     * The magic is sixteen bytes of text, which is the whole of what identifies the format; what
     * follows it is the saved state of the domain, of no described length.
     */
    Ok(SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    })
}
