use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "lzip compressed data";

/// lzip members start with these magic bytes
pub fn lzip_magic() -> Vec<Vec<u8>> {
    vec![b"LZIP".to_vec()]
}

/// Validate an lzip signature
pub fn lzip_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Only one version of the format has been defined
    const SUPPORTED_VERSION: u8 = 1;

    const VERSION_OFFSET: usize = 4;
    const DICTIONARY_SIZE_OFFSET: usize = 5;

    // The base of the dictionary size is a power of two in this range
    const MIN_DICTIONARY_BASE: u32 = 12;
    const MAX_DICTIONARY_BASE: u32 = 29;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let version = match file_data.get(offset + VERSION_OFFSET) {
        Some(version) => *version,
        None => return Err(SignatureError),
    };

    let coded_dictionary_size = match file_data.get(offset + DICTIONARY_SIZE_OFFSET) {
        Some(coded_dictionary_size) => *coded_dictionary_size,
        None => return Err(SignatureError),
    };

    /*
     * The dictionary size is a power of two, less a fraction in sixteenths of that power of two;
     * the exponent is in the low five bits of the field and the numerator of the fraction is in
     * the high three.
     */
    let dictionary_base = (coded_dictionary_size & 0x1F) as u32;
    let dictionary_fraction = ((coded_dictionary_size >> 5) & 0x07) as usize;

    if version != SUPPORTED_VERSION
        || !(MIN_DICTIONARY_BASE..=MAX_DICTIONARY_BASE).contains(&dictionary_base)
    {
        return Err(SignatureError);
    }

    let base_size: usize = 1 << dictionary_base;
    let dictionary_size = base_size - ((base_size / 16) * dictionary_fraction);

    /*
     * The size of a member is only recorded in the trailer that ends it, which cannot be located
     * without decompressing the member, so the size is left unknown.
     */
    result.description = format!(
        "{}, version: {}, dictionary size: {} bytes",
        result.description, version, dictionary_size
    );

    Ok(result)
}
