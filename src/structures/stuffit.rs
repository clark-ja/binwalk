use crate::structures::common::{self, StructureError};

/// Stores info about a classic StuffIt archive header
#[derive(Debug, Default, Clone)]
pub struct StuffItHeader {
    pub file_count: usize,
    pub total_size: usize,
}

/// Parse a classic StuffIt archive header
pub fn parse_stuffit_header(stuffit_data: &[u8]) -> Result<StuffItHeader, StructureError> {
    // The header ends with a second signature, which is what confirms the match
    const SECOND_MAGIC: usize = 0x724C6175;

    let stuffit_structure = vec![
        ("magic", "u32"),
        ("file_count", "u16"),
        ("total_size", "u32"),
        ("second_magic", "u32"),
    ];

    if let Ok(stuffit_header) = common::parse(stuffit_data, &stuffit_structure, "big")
        && stuffit_header["second_magic"] == SECOND_MAGIC
        && stuffit_header["total_size"] >= common::size(&stuffit_structure)
    {
        return Ok(StuffItHeader {
            file_count: stuffit_header["file_count"],
            total_size: stuffit_header["total_size"],
        });
    }

    Err(StructureError)
}
