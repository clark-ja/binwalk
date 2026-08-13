use crate::structures::common::{self, StructureError};

/// Stores info about an SWF header
#[derive(Debug, Default, Clone)]
pub struct SWFHeader {
    pub version: usize,
    pub compression: String,
    pub file_size: usize,
}

/// Parse an SWF header
pub fn parse_swf_header(swf_data: &[u8]) -> Result<SWFHeader, StructureError> {
    // The signature names how the body is compressed
    const UNCOMPRESSED: usize = 0x465753;
    const ZLIB: usize = 0x435753;
    const LZMA: usize = 0x5A5753;

    // Versions released run to the low thirties; a file size has to at least cover the header
    const MAX_VERSION: usize = 64;
    const MIN_FILE_SIZE: usize = 8;

    let swf_structure = vec![
        ("signature", "u24"),
        ("version", "u8"),
        ("file_size", "u32"),
    ];

    if let Ok(swf_header) = common::parse(swf_data, &swf_structure, "little") {
        // The signature is text, so it reads back in the opposite order to the rest of the header
        let compression = match swf_header["signature"].swap_bytes() >> 40 {
            UNCOMPRESSED => "uncompressed",
            ZLIB => "zlib compressed",
            LZMA => "LZMA compressed",
            _ => return Err(StructureError),
        };

        if swf_header["version"] > 0
            && swf_header["version"] <= MAX_VERSION
            && swf_header["file_size"] >= MIN_FILE_SIZE
        {
            return Ok(SWFHeader {
                version: swf_header["version"],
                compression: compression.to_string(),
                file_size: swf_header["file_size"],
            });
        }
    }

    Err(StructureError)
}
