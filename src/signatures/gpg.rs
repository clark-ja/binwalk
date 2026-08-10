use crate::extractors::gpg::gpg_decompress;
use crate::signatures::common::{
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};
use crate::structures::gpg::parse_gpg_trustdb_version_record;

/// Human readable descriptions
pub const GPG_SIGNED_DESCRIPTION: &str = "GPG signed file";
pub const GPG_TRUSTDB_DESCRIPTION: &str = "GPG key trust database";

/// GPG key trust databases start with a version record, which starts with these bytes
pub fn gpg_trustdb_magic() -> Vec<Vec<u8>> {
    vec![b"\x01gpg".to_vec()]
}

/// GPG signed files start with these two bytes
pub fn gpg_signed_magic() -> Vec<Vec<u8>> {
    vec![b"\xA3\x01".to_vec()]
}

/// Validates GPG signatures
pub fn gpg_signed_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Success result; confidence is high since this signature is only reported what it starts at the beginning of a file
    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_HIGH,
        description: GPG_SIGNED_DESCRIPTION.to_string(),
        ..Default::default()
    };

    /*
     * GPG signed files are just zlib compressed files with the zlib magic bytes replaced with the GPG magic bytes.
     * Decompress the signed file; no output directory specified, dry run only.
     */
    let decompression_dry_run = gpg_decompress(file_data, offset, None);

    // If the decompression dry run was a success, this signature is almost certianly valid
    if decompression_dry_run.success
        && let Some(total_size) = decompression_dry_run.size
    {
        result.size = total_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Validates GPG key trust databases
pub fn gpg_trustdb_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_MEDIUM,
        description: GPG_TRUSTDB_DESCRIPTION.to_string(),
        ..Default::default()
    };

    /*
     * A trust database is a series of fixed size records, and does not describe how many of them
     * there are, so the size is left unknown; only the version record at the start of it is parsed.
     */
    if let Ok(version_record) = parse_gpg_trustdb_version_record(&file_data[offset..]) {
        result.description = format!(
            "{}, version: {}, trust model: {}",
            result.description, version_record.version, version_record.trust_model
        );
        return Ok(result);
    }

    Err(SignatureError)
}
