use crate::common::get_cstring;
use crate::extractors::vxworks::extract_symbol_table;
use crate::signatures::common::{CONFIDENCE_HIGH, CONFIDENCE_LOW, SignatureError, SignatureResult};

/// Human readable descriptions
pub const SYMTAB_DESCRIPTION: &str = "VxWorks symbol table";
pub const WIND_KERNEL_DESCRIPTION: &str = "VxWorks WIND kernel version";
pub const OS_VERSION_DESCRIPTION: &str = "VxWorks operating system version";

/// VxWorks operating system version banner magic
pub fn os_version_magic() -> Vec<Vec<u8>> {
    // The magic bytes are the NULL terminated runtime name that starts the version banner
    vec![b"VxWorks\x00".to_vec()]
}

/// WIND kernel version magic
pub fn wind_kernel_magic() -> Vec<Vec<u8>> {
    // Magic version string for WIND kernels
    vec![b"WIND version ".to_vec()]
}

/// VxWorks symbol table magic bytes
pub fn symbol_table_magic() -> Vec<Vec<u8>> {
    // These magic bytes match the type and group fields in the VxWorks symbol table, for both big and little endian targets
    vec![
        b"\x00\x00\x05\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x00\x07\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x00\x09\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x05\x00\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x07\x00\x00\x00\x00\x00\x00".to_vec(),
        b"\x00\x09\x00\x00\x00\x00\x00\x00".to_vec(),
    ]
}

/// Validates WIND kernel version signatures
pub fn wind_kernel_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Length of the magic signatures bytes
    const MAGIC_SIZE: usize = 13;

    let mut result = SignatureResult {
        offset,
        description: WIND_KERNEL_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_LOW,
        ..Default::default()
    };

    // Want the string that proceeds the magic bytes
    let version_offset: usize = offset + MAGIC_SIZE;

    if let Some(version_bytes) = file_data.get(version_offset..) {
        // The wind kernel magic bytes should be followed by a string containing the wind kernel version
        let version_string = get_cstring(version_bytes);

        // Make sure we got a string
        if !version_string.is_empty() {
            result.size = MAGIC_SIZE + version_string.len();
            result.description = format!("{} {}", result.description, version_string);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validates VxWorks symbol table signatures
pub fn symbol_table_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // The magic bytes start at this offset from the beginning of the symbol table
    const MAGIC_OFFSET: usize = 8;

    let mut result = SignatureResult {
        description: SYMTAB_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // The magic bytes are not at the beginning of the VxWorks symbol table; sanity check the specified offset
    if offset >= MAGIC_OFFSET {
        // Actual start of the symbol table
        let symtab_start: usize = offset - MAGIC_OFFSET;

        // Do a dry-run extraction of the symbol table
        let dry_run = extract_symbol_table(file_data, symtab_start, None);

        // If dry run was a success, this is very likely a valid symbol table
        if dry_run.success {
            // Get the size of the symbol table from the dry-run
            if let Some(symtab_size) = dry_run.size {
                result.size = symtab_size;
                result.offset = symtab_start;
                result.description =
                    format!("{}, total size: {} bytes", result.description, result.size);

                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Validates VxWorks operating system version signatures
pub fn os_version_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    /*
     * The version banner is a series of fixed size fields: the runtime name, which is the magic,
     * the version string, the runtime name again, and then the date the image was built.
     */
    const VERSION_OFFSET: usize = 8;
    const RUNTIME_NAME_OFFSET: usize = 16;
    const CREATION_DATE_OFFSET: usize = 32;

    const RUNTIME_NAME: &[u8; 7] = b"VxWorks";

    // The version has to fit in the field that follows the magic bytes
    const MAX_VERSION_SIZE: usize = RUNTIME_NAME_OFFSET - VERSION_OFFSET;

    // Sane limit on the length of the creation date string
    const MAX_CREATION_DATE_SIZE: usize = 64;

    let mut result = SignatureResult {
        offset,
        description: OS_VERSION_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let banner_data = &file_data[offset..];

    // The runtime name appears a second time, after the version string
    let runtime_name_end = RUNTIME_NAME_OFFSET + RUNTIME_NAME.len();

    if banner_data.get(RUNTIME_NAME_OFFSET..runtime_name_end) != Some(RUNTIME_NAME) {
        return Err(SignatureError);
    }

    // A banner with no version string in it is of no use
    let version = match banner_data.get(VERSION_OFFSET..RUNTIME_NAME_OFFSET) {
        Some(version_data) => get_cstring(version_data),
        None => return Err(SignatureError),
    };

    if version.is_empty() || version.len() >= MAX_VERSION_SIZE {
        return Err(SignatureError);
    }

    result.size = CREATION_DATE_OFFSET;
    result.description = format!("{}: \"{}\"", result.description, version);

    // The creation date is optional
    let creation_date_end = std::cmp::min(
        CREATION_DATE_OFFSET + MAX_CREATION_DATE_SIZE,
        banner_data.len(),
    );

    if let Some(creation_date_data) = banner_data.get(CREATION_DATE_OFFSET..creation_date_end) {
        let creation_date = get_cstring(creation_date_data);

        if !creation_date.is_empty() && creation_date.len() < MAX_CREATION_DATE_SIZE {
            result.size += creation_date.len();
            result.description = format!("{}, compiled: \"{}\"", result.description, creation_date);
        }
    }

    Ok(result)
}
