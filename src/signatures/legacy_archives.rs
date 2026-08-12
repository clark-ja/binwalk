use crate::signatures::common::{
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};

/// Human readable descriptions
pub const HPACK_DESCRIPTION: &str = "HPACK archive";
pub const JAM_DESCRIPTION: &str = "JAM archive";
pub const PARITY_DESCRIPTION: &str = "PARity archive";
pub const BORG_DESCRIPTION: &str = "Borg backup archive segment";
pub const BSA_DESCRIPTION: &str = "BSA archive";
pub const LBR_DESCRIPTION: &str = "LBR archive";

/// HPACK archives start with this
pub fn hpack_magic() -> Vec<Vec<u8>> {
    vec![b"HPAK".to_vec()]
}

/// JAM archives start with this
pub fn jam_magic() -> Vec<Vec<u8>> {
    vec![b"\xE9\x2C\x01JAM".to_vec()]
}

/// PARity archives start with this
pub fn parity_magic() -> Vec<Vec<u8>> {
    vec![b"PAR\x00".to_vec()]
}

/// Borg backup segments start with this
pub fn borg_magic() -> Vec<Vec<u8>> {
    vec![b"BORG_SEG".to_vec()]
}

/// BSA archives start with the magic and the version, of which two are known
pub fn bsa_magic() -> Vec<Vec<u8>> {
    vec![
        b"BSA\x00\x67\x00\x00\x00".to_vec(),
        b"BSA\x00\x68\x00\x00\x00".to_vec(),
    ]
}

/// The first directory entry of an LBR archive names the directory itself, with a status byte of
/// zero and a blank file name
pub fn lbr_magic() -> Vec<Vec<u8>> {
    vec![b"\x00           ".to_vec()]
}

/// None of these headers describes the length of the archive, so none of these parsers reports a
/// size; they exist to report the format, and to name the version where the header carries one.
fn describe(offset: usize, description: &str, confidence: u8) -> SignatureResult {
    SignatureResult {
        offset,
        description: description.to_string(),
        confidence,
        ..Default::default()
    }
}

/// Validate an HPACK archive signature
pub fn hpack_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(describe(offset, HPACK_DESCRIPTION, CONFIDENCE_LOW))
}

/// Validate a JAM archive signature
pub fn jam_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(describe(offset, JAM_DESCRIPTION, CONFIDENCE_MEDIUM))
}

/// Validate a PARity archive signature
pub fn parity_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(describe(offset, PARITY_DESCRIPTION, CONFIDENCE_LOW))
}

/// Validate a Borg backup segment signature
pub fn borg_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(describe(offset, BORG_DESCRIPTION, CONFIDENCE_MEDIUM))
}

/// Validate a BSA archive signature
pub fn bsa_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The version follows the magic bytes
    const VERSION_OFFSET: usize = 4;

    let version = match file_data.get(offset + VERSION_OFFSET) {
        Some(version) => *version,
        None => return Err(SignatureError),
    };

    let mut result = describe(offset, BSA_DESCRIPTION, CONFIDENCE_MEDIUM);
    result.description = format!("{}, version: {}", result.description, version);

    Ok(result)
}

/// Validate an LBR archive signature
pub fn lbr_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(describe(offset, LBR_DESCRIPTION, CONFIDENCE_LOW))
}
