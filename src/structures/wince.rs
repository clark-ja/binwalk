use crate::structures::common::{self, StructureError};
use std::collections::HashMap;

/// Struct to store WindowsCE header info
#[derive(Debug, Default, Clone)]
pub struct WinCEHeader {
    pub base_address: usize,
    pub image_size: usize,
    pub header_size: usize,
}

/// Parses a Windows CE header
pub fn parse_wince_header(wince_data: &[u8]) -> Result<WinCEHeader, StructureError> {
    let wince_header_structure = vec![
        ("magic_p1", "u32"),
        ("magic_p2", "u24"),
        ("image_start", "u32"),
        ("image_size", "u32"),
    ];

    // Parse the WinCE header
    if let Ok(wince_header) = common::parse(wince_data, &wince_header_structure, "little") {
        return Ok(WinCEHeader {
            base_address: wince_header["image_start"],
            image_size: wince_header["image_size"],
            header_size: common::size(&wince_header_structure),
        });
    }

    Err(StructureError)
}

/// Struct to store WindowsCE block info
#[derive(Debug, Default, Clone)]
pub struct WinCEBlock {
    pub address: usize,
    pub data_size: usize,
    pub header_size: usize,
}

/// Parse a WindowsCE block header
pub fn parse_wince_block_header(block_data: &[u8]) -> Result<WinCEBlock, StructureError> {
    let wince_block_structure = vec![("address", "u32"), ("size", "u32"), ("checksum", "u32")];

    if let Ok(block_header) = common::parse(block_data, &wince_block_structure, "little") {
        return Ok(WinCEBlock {
            address: block_header["address"],
            data_size: block_header["size"],
            header_size: common::size(&wince_block_structure),
        });
    }

    Err(StructureError)
}

/// Struct to store Windows CE installer header info
#[derive(Debug, Default, Clone)]
pub struct WinCEInstallerHeader {
    pub architecture: String,
    pub file_count: usize,
    pub registry_entry_count: usize,
}

/// Parse a Windows CE installer header
pub fn parse_wince_installer_header(
    installer_data: &[u8],
) -> Result<WinCEInstallerHeader, StructureError> {
    // Target architectures, as reported by the architecture field
    let architectures = HashMap::from([
        (0, "architecture independent"),
        (103, "Hitachi SH3"),
        (104, "Hitachi SH4"),
        (0xA11, "StrongARM"),
        (4000, "MIPS R4000"),
        (10003, "Hitachi SH3"),
        (10004, "Hitachi SH3E"),
        (10005, "Hitachi SH4"),
        (70001, "ARM 7TDMI"),
    ]);

    /*
     * Only the architecture and the entry counts are described consistently by the available
     * documentation for this header, so the other fields are left unnamed rather than guessed at.
     */
    let installer_structure = vec![
        ("magic_p1", "u32"),
        ("magic_p2", "u32"),
        ("unknown_1", "u32"),
        ("unknown_2", "u32"),
        ("unknown_3", "u32"),
        ("architecture", "u32"),
        ("min_ce_version", "u32"),
        ("max_ce_version", "u32"),
        ("min_build_number", "u32"),
        ("max_build_number", "u32"),
        ("unknown_4", "u32"),
        ("unknown_5", "u32"),
        ("unknown_6", "u32"),
        ("file_count", "u16"),
        ("unknown_7", "u16"),
        ("registry_entry_count", "u16"),
    ];

    if let Ok(installer_header) = common::parse(installer_data, &installer_structure, "little") {
        let architecture = match architectures.get(&installer_header["architecture"]) {
            Some(architecture) => architecture.to_string(),
            None => format!("unknown ({})", installer_header["architecture"]),
        };

        return Ok(WinCEInstallerHeader {
            architecture,
            file_count: installer_header["file_count"],
            registry_entry_count: installer_header["registry_entry_count"],
        });
    }

    Err(StructureError)
}

/// Struct to store Windows CE memory segment header info
#[derive(Debug, Default, Clone)]
pub struct WinCEMemorySegment {
    pub toc_address: usize,
}

/// Parse a Windows CE memory segment header
pub fn parse_wince_memory_segment_header(
    segment_data: &[u8],
) -> Result<WinCEMemorySegment, StructureError> {
    // The signature is preceded by a NULL byte, which is included in the magic bytes
    let segment_structure = vec![("null_byte", "u8"), ("signature", "u32"), ("toc", "u32")];

    if let Ok(segment_header) = common::parse(segment_data, &segment_structure, "little") {
        // A ROM image with no table of contents is of no use to anyone
        if segment_header["toc"] != 0 {
            return Ok(WinCEMemorySegment {
                toc_address: segment_header["toc"],
            });
        }
    }

    Err(StructureError)
}
