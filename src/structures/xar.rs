use crate::structures::common::{self, StructureError};

/// Stores info about a XAR archive header
#[derive(Debug, Default, Clone)]
pub struct XarHeader {
    pub header_size: usize,
    pub version: usize,
    pub checksum_algorithm: String,
    pub toc_compressed_size: usize,
    pub toc_uncompressed_size: usize,
}

/// Parse a XAR archive header
pub fn parse_xar_header(xar_data: &[u8]) -> Result<XarHeader, StructureError> {
    // Only one version of the format has been defined
    const SUPPORTED_VERSION: usize = 1;

    // The header has only ever been this long, but the field allows for it to grow
    const MIN_HEADER_SIZE: usize = 28;
    const MAX_HEADER_SIZE: usize = 1024;

    let xar_structure = vec![
        ("magic", "u32"),
        ("header_size", "u16"),
        ("version", "u16"),
        ("toc_compressed_size", "u64"),
        ("toc_uncompressed_size", "u64"),
        ("checksum_algorithm", "u32"),
    ];

    let checksum_algorithms = ["none", "SHA1", "MD5", "SHA256", "SHA512"];

    if let Ok(xar_header) = common::parse(xar_data, &xar_structure, "big")
        && xar_header["version"] == SUPPORTED_VERSION
        && (MIN_HEADER_SIZE..=MAX_HEADER_SIZE).contains(&xar_header["header_size"])
        && xar_header["checksum_algorithm"] < checksum_algorithms.len()
        // The table of contents is zlib compressed, so it can only shrink so far
        && xar_header["toc_compressed_size"] > 0
        && xar_header["toc_compressed_size"] <= xar_header["toc_uncompressed_size"]
    {
        return Ok(XarHeader {
            header_size: xar_header["header_size"],
            version: xar_header["version"],
            checksum_algorithm: checksum_algorithms[xar_header["checksum_algorithm"]].to_string(),
            toc_compressed_size: xar_header["toc_compressed_size"],
            toc_uncompressed_size: xar_header["toc_uncompressed_size"],
        });
    }

    Err(StructureError)
}
