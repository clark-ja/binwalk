use crate::common::get_cstring;
use crate::signatures::common::{CONFIDENCE_LOW, SignatureError, SignatureResult};

/// Human readable descriptions
pub const EXCEPTION_HANDLER_DESCRIPTION: &str = "eCos kernel exception handler";
pub const STRING_REFERENCE_DESCRIPTION: &str = "eCos RTOS string reference";

/// Strings that reference eCos
pub fn string_reference_magic() -> Vec<Vec<u8>> {
    vec![b"ecos".to_vec(), b"eCos".to_vec(), b"ECOS".to_vec()]
}

/// Big and little endian magic byte signatures for eCos kernel exception handlers (MIPS only)
pub fn exception_handler_magic() -> Vec<Vec<u8>> {
    /*
     * eCos kernel exception handlers
     *
     * mfc0    $k0, Cause       # Cause of last exception
     * nop                      # Some versions of eCos omit the nop
     * andi    $k0, 0x7F
     * li      $k1, 0xXXXXXXXX
     * add     $k1, $k0
     * lw      $k1, 0($k1)
     * jr      $k1
     * nop
     */
    vec![
        b"\x00\x68\x1A\x40\x00\x00\x00\x00\x7F\x00\x5A\x33".to_vec(),
        b"\x00\x68\x1A\x40\x7F\x00\x5A\x33".to_vec(),
        b"\x40\x1A\x68\x00\x00\x00\x00\x00\x33\x5A\x00\x7F".to_vec(),
        b"\x40\x1A\x68\x00\x33\x5A\x00\x7F".to_vec(),
    ]
}

/// Parses the eCos exception handler signature
pub fn exception_handler_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: EXCEPTION_HANDLER_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    let mut endianness: &str = "big";

    // Detect endianess
    if file_data[offset] == 0 {
        endianness = "little";
    }

    result.description = format!("{}, MIPS {} endian", result.description, endianness);
    Ok(result)
}

/// Parses eCos string references
pub fn string_reference_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Size of the magic bytes
    const MAGIC_SIZE: usize = 4;

    // Only this much of a string is of interest; it also bounds the search for the terminator
    const MAX_STRING_SIZE: usize = 128;

    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: STRING_REFERENCE_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    /*
     * The magic bytes have to be a word of their own to be a reference to eCos, else every
     * "ecosystem" in a file would match.
     */
    if offset > 0 && file_data[offset - 1].is_ascii_alphanumeric() {
        return Err(SignatureError);
    }

    let string_end = std::cmp::min(offset + MAX_STRING_SIZE, file_data.len());
    let ecos_string = get_cstring(&file_data[offset..string_end]);

    /*
     * A string that has no terminator inside the window, or that contains anything unprintable, is
     * not a string reference.
     */
    if ecos_string.len() < MAX_STRING_SIZE
        && ecos_string
            .chars()
            .all(|c| c.is_ascii_graphic() || c == ' ')
        && !ecos_string
            .chars()
            .nth(MAGIC_SIZE)
            .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        result.size = ecos_string.len();
        result.description = format!("{}: \"{}\"", result.description, ecos_string);
        return Ok(result);
    }

    Err(SignatureError)
}
