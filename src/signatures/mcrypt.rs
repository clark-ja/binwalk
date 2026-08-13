use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};

/// Human readable descriptions
pub const V25_DESCRIPTION: &str = "mcrypt 2.5 encrypted data";
pub const V22_DESCRIPTION: &str = "mcrypt 2.2 encrypted data";

/// Files written by mcrypt 2.5 start with this
pub fn mcrypt25_magic() -> Vec<Vec<u8>> {
    vec![b"\x00m\x03".to_vec()]
}

/// Files written by mcrypt 2.2 start with this
pub fn mcrypt22_magic() -> Vec<Vec<u8>> {
    vec![b"\x00m\x02".to_vec()]
}

/// Validate an mcrypt 2.5 signature
pub fn mcrypt25_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    /*
     * A flag byte follows the magic, and the name of the algorithm follows that as a length
     * prefixed string; the name is what makes the match worth reporting.
     */
    const FLAGS_OFFSET: usize = 3;
    const NAME_LENGTH_OFFSET: usize = 4;
    const MAX_NAME_LENGTH: usize = 32;

    let mut result = SignatureResult {
        offset,
        description: V25_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let name_length = match file_data.get(offset + NAME_LENGTH_OFFSET) {
        Some(name_length) => *name_length as usize,
        None => return Err(SignatureError),
    };

    if name_length == 0 || name_length > MAX_NAME_LENGTH {
        return Err(SignatureError);
    }

    let name_start = offset + NAME_LENGTH_OFFSET + 1;

    let algorithm = match file_data.get(name_start..name_start + name_length) {
        Some(name) if name.iter().all(|b| b.is_ascii_graphic()) => {
            name.iter().map(|b| *b as char).collect::<String>()
        }
        _ => return Err(SignatureError),
    };

    // The flag byte only has its low bits defined
    let flags = match file_data.get(offset + FLAGS_OFFSET) {
        Some(flags) => *flags,
        None => return Err(SignatureError),
    };

    if flags > 1 {
        return Err(SignatureError);
    }

    /*
     * The header does not describe how much encrypted data follows it, so no size is reported.
     */
    result.description = format!("{}, algorithm: \"{}\"", result.description, algorithm);

    Ok(result)
}

/// Validate an mcrypt 2.2 signature
pub fn mcrypt22_parser(
    _file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    /*
     * The 2.2 header names its algorithm by number rather than by name, and the numbering is only
     * meaningful to that release, so there is nothing here worth reporting beyond the format
     * itself; the magic is three bytes, so it is only matched at the start of a file.
     */
    Ok(SignatureResult {
        offset,
        description: V22_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    })
}
