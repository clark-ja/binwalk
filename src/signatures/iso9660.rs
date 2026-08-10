use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::iso9660::{
    DESCRIPTOR_SET_OFFSET, SECTOR_SIZE, find_primary_volume_descriptor, is_iso_descriptor,
    parse_iso_boot_record, parse_iso_header,
};

/// Human readable descriptions
pub const DESCRIPTION: &str = "ISO9660 primary volume";
pub const BOOT_RECORD_DESCRIPTION: &str = "ISO9660 boot record";

/// ISOs start with these magic bytes
pub fn iso_magic() -> Vec<Vec<u8>> {
    vec![b"\x01CD001\x01\x00".to_vec()]
}

/// Boot record volume descriptors start with these magic bytes
pub fn iso_boot_record_magic() -> Vec<Vec<u8>> {
    vec![b"\x00CD001\x01".to_vec()]
}

/// Validate ISO signatures
pub fn iso_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // We need at least DESCRIPTOR_SET_OFFSET bytes to exist before the magic match offset
    if offset >= DESCRIPTOR_SET_OFFSET {
        // Calculate the actual starting offset of the ISO
        result.offset = offset - DESCRIPTOR_SET_OFFSET;

        // Parse the header, if parsing succeeds assume it's valid
        if let Ok(iso_header) = parse_iso_header(&file_data[result.offset..], DESCRIPTOR_SET_OFFSET)
        {
            result.size = iso_header.image_size;
            result.description =
                format!("{}, total size: {} bytes", result.description, result.size);
            return Ok(result);
        }
    }

    Err(SignatureError)
}

/// Validate ISO boot record signatures
pub fn iso_boot_record_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        description: BOOT_RECORD_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // We need at least DESCRIPTOR_SET_OFFSET bytes to exist before the magic match offset
    if offset < DESCRIPTOR_SET_OFFSET {
        return Err(SignatureError);
    }

    // Calculate the assumed starting offset of the ISO
    result.offset = offset - DESCRIPTOR_SET_OFFSET;
    let iso_data = &file_data[result.offset..];

    /*
     * A boot record is only the start of the volume descriptor set if the preceding sector is not
     * itself a volume descriptor. Boot records that follow a primary volume descriptor, which is
     * the usual El Torito layout, belong to an ISO that starts a sector earlier and are reported
     * as part of that image instead.
     */
    if DESCRIPTOR_SET_OFFSET >= SECTOR_SIZE
        && is_iso_descriptor(iso_data, DESCRIPTOR_SET_OFFSET - SECTOR_SIZE)
    {
        return Err(SignatureError);
    }

    // Report the boot system identifier, which is what identifies an El Torito bootable image
    let boot_record = match parse_iso_boot_record(iso_data) {
        Ok(boot_record) => boot_record,
        Err(_) => return Err(SignatureError),
    };

    if !boot_record.boot_system_identifier.is_empty() {
        result.description = format!(
            "{}, boot system identifier: \"{}\"",
            result.description, boot_record.boot_system_identifier
        );
    }

    /*
     * The size of the image is only described by the primary volume descriptor, which is somewhere
     * further along in the descriptor set. Without it the size is left unknown.
     */
    if let Some(descriptor_offset) = find_primary_volume_descriptor(iso_data)
        && let Ok(iso_header) = parse_iso_header(iso_data, descriptor_offset)
    {
        result.size = iso_header.image_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
    }

    Ok(result)
}
