use crate::structures::common::{self, StructureError};
use std::collections::HashMap;

/// Struct to store RTK firmware header info
#[derive(Debug, Default, Clone)]
pub struct RTKHeader {
    pub image_size: usize,
    pub header_size: usize,
}

/// Parses a RTK header
pub fn parse_rtk_header(rtk_data: &[u8]) -> Result<RTKHeader, StructureError> {
    const MAGIC_SIZE: usize = 4;

    let rtk_structure = vec![
        ("magic", "u32"),
        ("image_size", "u32"),
        ("checksum", "u32"),
        ("unknown1", "u32"),
        ("header_size", "u32"),
        ("unknown2", "u32"),
        ("unknown3", "u32"),
        ("identifier", "u32"),
    ];

    let mut result = RTKHeader {
        ..Default::default()
    };

    // Parse the header
    if let Ok(rtk_header) = common::parse(rtk_data, &rtk_structure, "little") {
        result.image_size = rtk_header["image_size"];
        result.header_size = rtk_header["header_size"] + MAGIC_SIZE;
        return Ok(result);
    }

    Err(StructureError)
}

/// Struct to store ROME bootloader firmware header info
#[derive(Debug, Default, Clone)]
pub struct ROMEHeader {
    pub header_size: usize,
    pub image_type: String,
    pub header_version: usize,
    pub creation_date: String,
    pub image_size: usize,
}

/// Parses a ROME bootloader firmware header
pub fn parse_rome_header(rome_data: &[u8]) -> Result<ROMEHeader, StructureError> {
    // The header runs through the two checksum bytes that end it
    const HEADER_SIZE: usize = 24;

    // Sane limits on the reported creation date
    const MAX_YEAR: usize = 3000;
    const MAX_MONTH: usize = 12;
    const MAX_DAY: usize = 31;

    // Image types, as reported by the image type field
    let image_types = HashMap::from([
        (0xd92f, "KFS"),
        (0xb162, "RDIR"),
        (0xea43, "BOOT"),
        (0x8dc9, "RUN"),
        (0x2a05, "CCFG"),
        (0x6ce8, "DCFG"),
        (0xc371, "LOG"),
    ]);

    let rome_structure = vec![
        ("magic", "u32"),
        ("image_type", "u16"),
        ("header_version", "u8"),
        ("unknown_1", "u8"),
        ("year", "u16"),
        ("month", "u8"),
        ("unknown_2", "u8"),
        ("day", "u8"),
        ("unknown_3", "u8"),
        ("unknown_4", "u16"),
        ("image_size", "u32"),
        ("unknown_5", "u32"),
        ("body_checksum", "u8"),
        ("header_checksum", "u8"),
    ];

    if let Ok(rome_header) = common::parse(rome_data, &rome_structure, "big") {
        // The image type is the strongest indication that this is a real header
        if let Some(image_type) = image_types.get(&rome_header["image_type"]) {
            // Sanity check the creation date and the size of the image that follows the header
            if rome_header["year"] <= MAX_YEAR
                && (1..=MAX_MONTH).contains(&rome_header["month"])
                && (1..=MAX_DAY).contains(&rome_header["day"])
                && rome_header["image_size"] > 0
            {
                return Ok(ROMEHeader {
                    header_size: HEADER_SIZE,
                    image_type: image_type.to_string(),
                    header_version: rome_header["header_version"],
                    creation_date: format!(
                        "{}/{}/{}",
                        rome_header["month"], rome_header["day"], rome_header["year"]
                    ),
                    image_size: rome_header["image_size"],
                });
            }
        }
    }

    Err(StructureError)
}
