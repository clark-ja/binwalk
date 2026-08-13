use crate::structures::common::{self, StructureError};

/// Stores info about a TIFF header
#[derive(Debug, Default, Clone)]
pub struct TIFFHeader {
    pub endianness: String,
    pub directory_offset: usize,
    pub entry_count: usize,
}

/// Parse a TIFF header and the first image file directory it points at
pub fn parse_tiff_header(tiff_data: &[u8]) -> Result<TIFFHeader, StructureError> {
    // The byte order mark is the text "II" or "MM", which reads as one of these either way round
    const LITTLE_ENDIAN_MARK: usize = 0x4949;
    const BIG_ENDIAN_MARK: usize = 0x4D4D;

    // Every directory holds at least one entry, and no sane one holds this many
    const MAX_DIRECTORY_ENTRIES: usize = 4096;

    let tiff_structure = vec![
        ("byte_order", "u16"),
        ("version", "u16"),
        ("directory_offset", "u32"),
    ];

    let directory_structure = vec![("entry_count", "u16")];

    // The byte order mark reads the same whichever way it is taken, so it names the endianness
    let byte_order = common::parse(tiff_data, &tiff_structure, "big")?["byte_order"];

    let endianness = match byte_order {
        LITTLE_ENDIAN_MARK => "little",
        BIG_ENDIAN_MARK => "big",
        _ => return Err(StructureError),
    };

    let tiff_header = common::parse(tiff_data, &tiff_structure, endianness)?;

    // The first directory follows the header, and has to be inside the data available
    if tiff_header["directory_offset"] < common::size(&tiff_structure) {
        return Err(StructureError);
    }

    let directory_data = match tiff_data.get(tiff_header["directory_offset"]..) {
        Some(directory_data) => directory_data,
        None => return Err(StructureError),
    };

    let directory = common::parse(directory_data, &directory_structure, endianness)?;

    if directory["entry_count"] == 0 || directory["entry_count"] > MAX_DIRECTORY_ENTRIES {
        return Err(StructureError);
    }

    Ok(TIFFHeader {
        endianness: endianness.to_string(),
        directory_offset: tiff_header["directory_offset"],
        entry_count: directory["entry_count"],
    })
}
