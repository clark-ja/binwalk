use crate::extractors::wince::wince_dump;
use crate::signatures::common::{
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};
use crate::structures::wince::{
    parse_wince_header, parse_wince_installer_header, parse_wince_memory_segment_header,
};

/// Human readable descriptions
pub const DESCRIPTION: &str = "Windows CE binary image";
pub const INSTALLER_DESCRIPTION: &str = "Microsoft WinCE installer";
pub const MEMORY_SEGMENT_DESCRIPTION: &str = "Windows CE memory segment header";

/// Windows CE magic bytes
pub fn wince_magic() -> Vec<Vec<u8>> {
    vec![b"B000FF\n".to_vec()]
}

/// Windows CE installer magic bytes
pub fn wince_installer_magic() -> Vec<Vec<u8>> {
    vec![b"MSCE\x00\x00\x00\x00".to_vec()]
}

/// Windows CE memory segment magic bytes; the signature is preceded by a NULL byte
pub fn wince_memory_segment_magic() -> Vec<Vec<u8>> {
    vec![b"\x00ECEC".to_vec()]
}

/// Validates the Windows CE header
pub fn wince_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry-run
    let dry_run = wince_dump(file_data, offset, None);

    if dry_run.success
        && let Some(total_size) = dry_run.size
    {
        result.size = total_size;

        // Parse the WinCE header to get some useful info to display
        if let Ok(wince_header) = parse_wince_header(&file_data[offset..]) {
            result.description = format!(
                "{}, base address: {:#X}, image size: {} bytes, file size: {} bytes",
                result.description, wince_header.base_address, wince_header.image_size, result.size
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validate a Windows CE installer header
pub fn wince_installer_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: INSTALLER_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    /*
     * The documentation available for this header does not agree on which field holds the length
     * of the installer, so the size is left unknown, as it was in binwalk v2.
     */
    if let Ok(installer_header) = parse_wince_installer_header(&file_data[offset..]) {
        result.description = format!(
            "{}, {}, file count: {}, registry entry count: {}",
            result.description,
            installer_header.architecture,
            installer_header.file_count,
            installer_header.registry_entry_count
        );
        return Ok(result);
    }

    Err(SignatureError)
}

/// Validate a Windows CE memory segment header
pub fn wince_memory_segment_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // The signature is at a fixed offset from the start of the ROM image
    const SIGNATURE_OFFSET: usize = 63;

    // Successful return value
    let mut result = SignatureResult {
        description: MEMORY_SEGMENT_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    // We need at least SIGNATURE_OFFSET bytes to exist before the magic match offset
    if offset >= SIGNATURE_OFFSET {
        // The ROM image starts before the signature
        result.offset = offset - SIGNATURE_OFFSET;

        /*
         * The table of contents is described by an address rather than by an offset into the image,
         * so it says nothing about how large the image is; the size is left unknown.
         */
        if let Ok(segment_header) = parse_wince_memory_segment_header(&file_data[offset..]) {
            result.description = format!(
                "{}, TOC address: {:#X}",
                result.description, segment_header.toc_address
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}
