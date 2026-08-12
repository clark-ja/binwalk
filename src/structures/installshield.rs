use crate::structures::common::{self, StructureError};

/// Stores info about an InstallShield cabinet header
#[derive(Debug, Default, Clone)]
pub struct InstallShieldHeader {
    pub version: usize,
    pub descriptor_offset: usize,
    pub descriptor_size: usize,
}

/// Parse an InstallShield cabinet header
pub fn parse_installshield_header(
    cabinet_data: &[u8],
) -> Result<InstallShieldHeader, StructureError> {
    // The version field is the release that wrote the cabinet, shifted into the high half
    const MIN_VERSION: usize = 0x01000000;
    const MAX_VERSION: usize = 0x10000000;

    let cabinet_structure = vec![
        ("magic", "u32"),
        ("version", "u32"),
        ("volume_info", "u32"),
        ("descriptor_offset", "u32"),
        ("descriptor_size", "u32"),
    ];

    if let Ok(cabinet_header) = common::parse(cabinet_data, &cabinet_structure, "little")
        && (MIN_VERSION..=MAX_VERSION).contains(&cabinet_header["version"])
        // The descriptor follows the header, and describes the contents of the cabinet
        && cabinet_header["descriptor_offset"] >= common::size(&cabinet_structure)
        && cabinet_header["descriptor_size"] > 0
    {
        return Ok(InstallShieldHeader {
            version: cabinet_header["version"],
            descriptor_offset: cabinet_header["descriptor_offset"],
            descriptor_size: cabinet_header["descriptor_size"],
        });
    }

    Err(StructureError)
}
