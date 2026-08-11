use crate::structures::common::{self, StructureError};

/// Stores info about an rzip header
#[derive(Debug, Default, Clone)]
pub struct RzipHeader {
    pub major_version: usize,
    pub minor_version: usize,
    pub uncompressed_size: usize,
}

/// Parse an rzip header
pub fn parse_rzip_header(rzip_data: &[u8]) -> Result<RzipHeader, StructureError> {
    // Only versions 1 and 2 of the format exist
    const MIN_MAJOR_VERSION: usize = 1;
    const MAX_MAJOR_VERSION: usize = 2;

    let rzip_structure = vec![
        ("magic", "u32"),
        ("major_version", "u8"),
        ("minor_version", "u8"),
        ("uncompressed_size", "u32"),
    ];

    if let Ok(rzip_header) = common::parse(rzip_data, &rzip_structure, "big")
        && (MIN_MAJOR_VERSION..=MAX_MAJOR_VERSION).contains(&rzip_header["major_version"])
        && rzip_header["uncompressed_size"] > 0
    {
        return Ok(RzipHeader {
            major_version: rzip_header["major_version"],
            minor_version: rzip_header["minor_version"],
            uncompressed_size: rzip_header["uncompressed_size"],
        });
    }

    Err(StructureError)
}
