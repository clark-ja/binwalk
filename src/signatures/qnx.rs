use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::qnx::{parse_ifs_header, parse_qnx4_root_dir, parse_qnx6_super_block};

/// Human readable descriptions
pub const IFS_DESCRIPTION: &str = "QNX IFS image";
pub const QNX4_DESCRIPTION: &str = "QNX4 file system";
pub const QNX6_DESCRIPTION: &str = "QNX6 file system";

/// QNX IFS magic bytes
pub fn qnx_ifs_magic() -> Vec<Vec<u8>> {
    /*
     * Assumes little endian.
     * Includes the magic bytes (u32) and version number (u16), which must be 1.
     */
    vec![b"\xEB\x7E\xFF\x00\x01\x00".to_vec()]
}

/// QNX4 boot block magic bytes
pub fn qnx4_magic() -> Vec<Vec<u8>> {
    // This is just an x86 jump instruction; the root directory entry is what validates the match
    vec![b"\xEB\x10\x90\x00".to_vec()]
}

/// QNX6 super block magic bytes, little and big endian
pub fn qnx6_magic() -> Vec<Vec<u8>> {
    vec![b"\x68\x19\x11\x22".to_vec(), b"\x22\x11\x19\x68".to_vec()]
}

/// Validate a QNX IFS signature
pub fn qnx_ifs_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: IFS_DESCRIPTION.to_string(),
        ..Default::default()
    };

    let available_data: usize = file_data.len() - offset;

    if let Ok(ifs_header) = parse_ifs_header(&file_data[offset..]) {
        // Set the total size of this signature
        result.size = ifs_header.total_size;

        // Sanity check that the total size doesn't exceed the available data size
        if result.size <= available_data {
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validate a QNX4 boot block signature
pub fn qnx4_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: QNX4_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    /*
     * The size of the file system is not described anywhere in the boot block, so the size is left
     * unknown; only the root directory entry is available to validate the match.
     */
    if let Ok(root_dir) = parse_qnx4_root_dir(&file_data[offset..]) {
        result.description = format!(
            "{}, root directory size: {} bytes",
            result.description, root_dir.size
        );
        return Ok(result);
    }

    Err(SignatureError)
}

/// Validate a QNX6 super block signature
pub fn qnx6_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The magic value is 0x22111968, so a little endian image starts with the low byte of it
    const LITTLE_ENDIAN_MAGIC: &[u8; 4] = b"\x68\x19\x11\x22";

    // Success return value
    let mut result = SignatureResult {
        offset,
        description: QNX6_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let endianness = match file_data.get(offset..offset + LITTLE_ENDIAN_MAGIC.len()) {
        Some(magic) if magic == LITTLE_ENDIAN_MAGIC => "little",
        _ => "big",
    };

    /*
     * The super block describes the number of file system blocks, but not how much of the image
     * precedes it, nor the size of the super block area, so the size is left unknown.
     */
    if let Ok(super_block) = parse_qnx6_super_block(&file_data[offset..], endianness) {
        result.description = format!(
            "{}, {} endian, block size: {} bytes, block count: {}",
            result.description,
            super_block.endianness,
            super_block.block_size,
            super_block.block_count
        );
        return Ok(result);
    }

    Err(SignatureError)
}
