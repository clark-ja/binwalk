use crate::common::get_cstring;
use crate::structures::common::{self, StructureError};

/// Volume descriptors are one logical sector each, starting at this offset into the image
pub const DESCRIPTOR_SET_OFFSET: usize = 32768;
pub const SECTOR_SIZE: usize = 2048;

/// Every ISO9660 volume descriptor carries this standard identifier
const STANDARD_IDENTIFIER: &[u8; 5] = b"CD001";
const STANDARD_IDENTIFIER_OFFSET: usize = 1;

/// Volume descriptor types of interest
const DESCRIPTOR_TYPE_PRIMARY_VOLUME: u8 = 1;
const DESCRIPTOR_TYPE_TERMINATOR: u8 = 255;

/// Struct to store useful ISO info
#[derive(Debug, Default, Clone)]
pub struct ISOHeader {
    pub image_size: usize,
}

/// Returns true if there is an ISO9660 volume descriptor at the specified offset
pub fn is_iso_descriptor(iso_data: &[u8], descriptor_offset: usize) -> bool {
    let identifier_start = descriptor_offset + STANDARD_IDENTIFIER_OFFSET;
    let identifier_end = identifier_start + STANDARD_IDENTIFIER.len();

    match iso_data.get(identifier_start..identifier_end) {
        Some(identifier) => identifier == STANDARD_IDENTIFIER,
        None => false,
    }
}

/// Walks the volume descriptor set and returns the offset of the primary volume descriptor
pub fn find_primary_volume_descriptor(iso_data: &[u8]) -> Option<usize> {
    let mut descriptor_offset = DESCRIPTOR_SET_OFFSET;

    while is_iso_descriptor(iso_data, descriptor_offset) {
        match iso_data.get(descriptor_offset) {
            None => break,
            Some(&descriptor_type) => {
                if descriptor_type == DESCRIPTOR_TYPE_PRIMARY_VOLUME {
                    return Some(descriptor_offset);
                }

                // The descriptor set ends at the terminating descriptor
                if descriptor_type == DESCRIPTOR_TYPE_TERMINATOR {
                    break;
                }
            }
        }

        descriptor_offset += SECTOR_SIZE;
    }

    None
}

/// Struct to store useful ISO boot record info
#[derive(Debug, Default, Clone)]
pub struct ISOBootRecord {
    pub boot_system_identifier: String,
}

/// Parses the boot record volume descriptor at the start of the volume descriptor set
pub fn parse_iso_boot_record(iso_data: &[u8]) -> Result<ISOBootRecord, StructureError> {
    // The boot system identifier is a 32 byte string that follows the type, identifier and version fields
    const BOOT_SYSTEM_IDENTIFIER_OFFSET: usize = DESCRIPTOR_SET_OFFSET + 7;
    const BOOT_SYSTEM_IDENTIFIER_SIZE: usize = 32;

    if let Some(identifier_data) = iso_data.get(
        BOOT_SYSTEM_IDENTIFIER_OFFSET..BOOT_SYSTEM_IDENTIFIER_OFFSET + BOOT_SYSTEM_IDENTIFIER_SIZE,
    ) {
        // Identifiers are space padded, and may be unset
        let identifier = get_cstring(identifier_data).trim_end().to_string();

        return Ok(ISOBootRecord {
            boot_system_identifier: identifier,
        });
    }

    Err(StructureError)
}

/// Partially parses an ISO header
pub fn parse_iso_header(
    iso_data: &[u8],
    descriptor_offset: usize,
) -> Result<ISOHeader, StructureError> {
    // The volume size fields follow the type, identifier, version, unused, system ID and volume ID fields
    let iso_struct_start: usize = descriptor_offset + 72;

    // Partial ISO header structure, enough to reasonably validate that this is not a false positive and to calculate the total ISO size
    let iso_structure = vec![
        ("unused1", "u64"),
        ("volume_size_lsb", "u32"),
        ("volume_size_msb", "u32"),
        ("unused2", "u64"),
        ("unused3", "u64"),
        ("unused4", "u64"),
        ("unused5", "u64"),
        ("set_size_lsb", "u16"),
        ("set_size_msb", "u16"),
        ("sequence_number_lsb", "u16"),
        ("sequence_number_msb", "u16"),
        ("block_size_lsb", "u16"),
        ("block_size_msb", "u16"),
        ("path_table_size_lsb", "u32"),
        ("path_table_size_msb", "u32"),
    ];

    let mut iso_info = ISOHeader {
        ..Default::default()
    };

    if let Some(iso_header_data) = iso_data.get(iso_struct_start..) {
        // Parse the ISO header
        if let Ok(iso_header) = common::parse(iso_header_data, &iso_structure, "little") {
            // Make sure all the unused fields are, in fact, unused
            if iso_header["unused1"] == 0
                && iso_header["unused2"] == 0
                && iso_header["unused3"] == 0
                && iso_header["unused4"] == 0
                && iso_header["unused5"] == 0
            {
                /*
                 * Make sure all the identical, but byte-swapped, fields agree.
                 * NOTE: The to_be() conversions probably won't work on big-endian hosts.
                 */
                if iso_header["set_size_lsb"]
                    == (iso_header["set_size_msb"] as u16).to_be() as usize
                    && iso_header["block_size_lsb"]
                        == (iso_header["block_size_msb"] as u16).to_be() as usize
                    && iso_header["volume_size_lsb"]
                        == (iso_header["volume_size_msb"] as u32).to_be() as usize
                    && iso_header["sequence_number_lsb"]
                        == (iso_header["sequence_number_msb"] as u16).to_be() as usize
                    && iso_header["path_table_size_lsb"]
                        == (iso_header["path_table_size_msb"] as u32).to_be() as usize
                {
                    iso_info.image_size =
                        iso_header["volume_size_lsb"] * iso_header["block_size_lsb"];
                    return Ok(iso_info);
                }
            }
        }
    }

    Err(StructureError)
}
