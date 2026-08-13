use crate::signatures::common::{CONFIDENCE_LOW, SignatureError, SignatureResult};

/// Human readable descriptions
pub const PK_DESCRIPTION: &str = "Nagra PK";
pub const CONSTANT_KEY_DESCRIPTION: &str = "Nagra Constant_KEY";

/// The Nagra PK constant
pub fn nagra_pk_magic() -> Vec<Vec<u8>> {
    vec![b"\x00\x00\x01\x6C".to_vec()]
}

/// The Nagra Constant_KEY constant
pub fn nagra_constant_key_magic() -> Vec<Vec<u8>> {
    vec![b"\x10\x19\x24\x31".to_vec()]
}

/// Validate a Nagra PK signature
pub fn nagra_pk_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    Ok(nagra_key(offset, PK_DESCRIPTION))
}

/// Validate a Nagra Constant_KEY signature
pub fn nagra_constant_key_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    Ok(nagra_key(offset, CONSTANT_KEY_DESCRIPTION))
}

/// Both of these are four byte constants with nothing around them to check, so both are only
/// matched at the start of a file and neither reports a size.
fn nagra_key(offset: usize, description: &str) -> SignatureResult {
    SignatureResult {
        offset,
        description: description.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    }
}
