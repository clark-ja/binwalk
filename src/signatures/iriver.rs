use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "iRiver database file";

/// iRiver database files start with this
pub fn iriver_magic() -> Vec<Vec<u8>> {
    vec![b"iRivDB".to_vec()]
}

/// Validate an iRiver database signature
pub fn iriver_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    /*
     * The magic is followed by the name of the database, as printable text; the layout of the rest
     * of the header is not documented, and it does not describe the length of the file.
     */
    const NAME_OFFSET: usize = 6;
    const MAX_NAME_SIZE: usize = 32;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let name_start = offset + NAME_OFFSET;
    let name_end = std::cmp::min(name_start + MAX_NAME_SIZE, file_data.len());

    let name: String = match file_data.get(name_start..name_end) {
        Some(name_data) => name_data
            .iter()
            .take_while(|b| b.is_ascii_graphic() || **b == b' ')
            .map(|b| *b as char)
            .collect(),
        None => return Err(SignatureError),
    };

    if name.trim().is_empty() {
        return Err(SignatureError);
    }

    result.description = format!("{}, name: \"{}\"", result.description, name.trim());

    Ok(result)
}
