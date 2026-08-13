use crate::structures::common::{self, StructureError};

/// Stores info about a PlayStation executable header
#[derive(Debug, Default, Clone)]
pub struct PSXHeader {
    pub header_size: usize,
    pub entry_point: usize,
    pub text_address: usize,
    pub text_size: usize,
}

/// Parse a PlayStation executable header
pub fn parse_psx_header(psx_data: &[u8]) -> Result<PSXHeader, StructureError> {
    // The header is padded out to one sector of a disc
    const HEADER_SIZE: usize = 2048;

    // Text sections are loaded into main memory, which is mapped in these regions
    const KUSEG_BASE: usize = 0x00000000;
    const KSEG0_BASE: usize = 0x80000000;
    const KSEG1_BASE: usize = 0xA0000000;
    const MEMORY_SIZE: usize = 0x00800000;

    // A section is a whole number of words, and cannot be larger than memory
    const ALIGNMENT: usize = 2048;

    let psx_structure = vec![
        ("magic_p1", "u32"),
        ("magic_p2", "u32"),
        ("reserved_1", "u32"),
        ("reserved_2", "u32"),
        ("entry_point", "u32"),
        ("initial_gp", "u32"),
        ("text_address", "u32"),
        ("text_size", "u32"),
    ];

    if let Ok(psx_header) = common::parse(psx_data, &psx_structure, "little") {
        let in_memory = |address: usize| {
            [KUSEG_BASE, KSEG0_BASE, KSEG1_BASE]
                .iter()
                .any(|base| address >= *base && (address - base) < MEMORY_SIZE)
        };

        if psx_header["reserved_1"] == 0
            && psx_header["reserved_2"] == 0
            && psx_header["text_size"] > 0
            && psx_header["text_size"] < MEMORY_SIZE
            && (psx_header["text_size"] % ALIGNMENT) == 0
            && in_memory(psx_header["entry_point"])
            && in_memory(psx_header["text_address"])
        {
            return Ok(PSXHeader {
                header_size: HEADER_SIZE,
                entry_point: psx_header["entry_point"],
                text_address: psx_header["text_address"],
                text_size: psx_header["text_size"],
            });
        }
    }

    Err(StructureError)
}
