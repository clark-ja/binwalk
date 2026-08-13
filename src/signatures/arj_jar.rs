use crate::signatures::common::{
    CONFIDENCE_LOW, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};

/// Human readable description
pub const DESCRIPTION: &str = "JAR archive (ARJ Software)";

/// The signature of an archive sits this far into its first local header
pub const HEADER_MAGIC_OFFSET: usize = 14;

/// Archives carry this signature inside their first local header
pub fn arj_jar_magic() -> Vec<Vec<u8>> {
    vec![b"\x1AJar\x1B".to_vec()]
}

/// Self extracting archives start with this instead
pub fn arj_jar_sfx_magic() -> Vec<Vec<u8>> {
    vec![b"JARCS".to_vec()]
}

/// Validate a JAR archive signature
pub fn arj_jar_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // The archive starts before the signature, at the start of the local header that holds it
    if offset < HEADER_MAGIC_OFFSET {
        return Err(SignatureError);
    }

    result.offset = offset - HEADER_MAGIC_OFFSET;

    /*
     * Nothing else in the header is documented, and it does not describe the length of the
     * archive, so no size is reported.
     */
    Ok(result)
}

/// Validate a self extracting JAR archive signature
pub fn arj_jar_sfx_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    Ok(SignatureResult {
        offset,
        description: format!("{DESCRIPTION}, self extracting"),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    })
}
