use crate::common::is_offset_safe;
use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::lz4::{
    parse_lz4_block_header, parse_lz4_file_header, parse_lz4_legacy_block_header,
};

/// Human readable descriptions
pub const DESCRIPTION: &str = "LZ4 compressed data";
pub const LEGACY_DESCRIPTION: &str = "LZ4 compressed data, legacy frame";

/// LZ4 files start with these magic bytes
pub fn lz4_magic() -> Vec<Vec<u8>> {
    vec![b"\x04\x22\x4D\x18".to_vec()]
}

/// LZ4 legacy frames start with these magic bytes
pub fn lz4_legacy_magic() -> Vec<Vec<u8>> {
    vec![b"\x02\x21\x4C\x18".to_vec()]
}

/// Validate a LZ4 signature
pub fn lz4_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Checksums are 4 bytes in length
    const CONTENT_CHECKSUM_LEN: usize = 4;

    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_MEDIUM,
        description: DESCRIPTION.to_string(),
        ..Default::default()
    };

    // Sanity check the size of available data
    if let Ok(lz4_file_header) = parse_lz4_file_header(&file_data[offset..]) {
        // LZ4 data starts immediately after the LZ4 header
        if let Some(lz4_data) = file_data.get(offset + lz4_file_header.header_size..) {
            // Determine the size of the actual LZ4 data by processing the data blocks that immediately follow the file header
            if let Ok(lz4_data_size) =
                get_lz4_data_size(lz4_data, lz4_file_header.block_checksum_present)
            {
                // Set the size of the header and the LZ4 data
                result.size = lz4_file_header.header_size + lz4_data_size;

                // If this flag is set, an additional 4-byte checksum will be present at the end of the LZ4 data
                if lz4_file_header.content_checksum_present {
                    result.size += CONTENT_CHECKSUM_LEN;
                }

                // Update description
                result.description =
                    format!("{}, total size: {} bytes", result.description, result.size);

                return Ok(result);
            }
        }
    }

    Err(SignatureError)
}

/// Validate an LZ4 legacy frame signature
pub fn lz4_legacy_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // A legacy frame header is just the magic bytes; data blocks follow immediately
    const MAGIC_SIZE: usize = 4;

    let mut result = SignatureResult {
        offset,
        confidence: CONFIDENCE_MEDIUM,
        description: LEGACY_DESCRIPTION.to_string(),
        ..Default::default()
    };

    // LZ4 data starts immediately after the magic bytes
    if let Some(lz4_data) = file_data.get(offset + MAGIC_SIZE..) {
        // Determine the size of the LZ4 data by processing the data blocks
        if let Ok(lz4_data_size) = get_lz4_legacy_data_size(lz4_data) {
            result.size = MAGIC_SIZE + lz4_data_size;
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Processes the data blocks of an LZ4 legacy frame and returns the size of the block data
fn get_lz4_legacy_data_size(lz4_data: &[u8]) -> Result<usize, SignatureError> {
    let mut lz4_data_size: usize = 0;
    let mut last_lz4_data_size = None;
    let available_data = lz4_data.len();

    // Loop while there is still data and while the offsets are sane
    while is_offset_safe(available_data, lz4_data_size, last_lz4_data_size) {
        // Get the next block's data
        match lz4_data.get(lz4_data_size..) {
            None => {
                break;
            }
            Some(lz4_block_data) => {
                // Parse the next block's data; this fails once the data no longer looks like a
                // block header, which is how the end of a legacy frame is identified
                match parse_lz4_legacy_block_header(lz4_block_data) {
                    Err(_) => {
                        break;
                    }
                    Ok(block_header) => {
                        let block_total_size = block_header.header_size + block_header.data_size;

                        // Don't include a truncated block in the reported size
                        if (lz4_data_size + block_total_size) > available_data {
                            break;
                        }

                        // Update offsets
                        last_lz4_data_size = Some(lz4_data_size);
                        lz4_data_size += block_total_size;
                    }
                }
            }
        }
    }

    // At least one complete block is required; the 4 magic bytes alone are too short to trust
    if lz4_data_size > 0 {
        return Ok(lz4_data_size);
    }

    Err(SignatureError)
}

/// Processes the LZ4 data blocks and returns the size of the raw LZ4 data
fn get_lz4_data_size(lz4_data: &[u8], checksum_present: bool) -> Result<usize, SignatureError> {
    let mut lz4_data_size: usize = 0;
    let mut last_lz4_data_size = None;
    let available_data = lz4_data.len();

    // Loop while there is still data and while the offsets are sane
    while is_offset_safe(available_data, lz4_data_size, last_lz4_data_size) {
        // Get the next block's data
        match lz4_data.get(lz4_data_size..) {
            None => {
                break;
            }
            Some(lz4_block_data) => {
                // Parse the next block's data
                match parse_lz4_block_header(lz4_block_data, checksum_present) {
                    Err(_) => {
                        break;
                    }
                    Ok(block_header) => {
                        // Update offsets
                        last_lz4_data_size = Some(lz4_data_size);
                        lz4_data_size += block_header.header_size
                            + block_header.data_size
                            + block_header.checksum_size;

                        // Only return success if a last block header is found
                        if block_header.last_block {
                            return Ok(lz4_data_size);
                        }
                    }
                }
            }
        }
    }

    Err(SignatureError)
}
