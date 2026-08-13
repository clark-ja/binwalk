use crate::structures::common::{self, StructureError};

/// Stores info about a Samsung modem TOC index
#[derive(Debug, Default, Clone)]
pub struct SamsungTOC {
    pub entry_count: usize,
    pub image_size: usize,
}

/// Parse a Samsung modem TOC index
///
/// The index is a table of fixed size entries, each naming a section of the image and saying where
/// it lives. The first entry describes the index itself, so the size of the image is the end of
/// the section that reaches furthest into it.
pub fn parse_samsung_toc(toc_data: &[u8]) -> Result<SamsungTOC, StructureError> {
    const ENTRY_SIZE: usize = 32;
    const NAME_SIZE: usize = 12;

    // The table is small; a count beyond this is not an index
    const MAX_ENTRIES: usize = 64;

    let entry_structure = vec![
        ("name_p1", "u64"),
        ("name_p2", "u32"),
        ("offset", "u32"),
        ("load_address", "u32"),
        ("size", "u32"),
        ("crc", "u32"),
        ("entry_id", "u32"),
    ];

    // The first entry describes the index, which is at least one entry long
    let first_entry = common::parse(toc_data, &entry_structure, "little")?;

    if first_entry["size"] < ENTRY_SIZE {
        return Err(StructureError);
    }

    let mut image_size = first_entry["offset"] + first_entry["size"];

    /*
     * Count the entries that follow, each of which has to be named in printable text, until the
     * table runs into an unused entry or into the sections it describes.
     */
    let mut entry_count: usize = 1;

    while entry_count < MAX_ENTRIES {
        let entry_start = entry_count * ENTRY_SIZE;

        let name = match toc_data.get(entry_start..entry_start + NAME_SIZE) {
            Some(name) => name,
            None => break,
        };

        // An entry name is printable text, NULL padded
        if name[0] == 0 || !name.iter().all(|b| *b == 0 || b.is_ascii_graphic()) {
            break;
        }

        let entry = match common::parse(&toc_data[entry_start..], &entry_structure, "little") {
            Ok(entry) => entry,
            Err(_) => break,
        };

        // The image runs to the end of whichever section reaches furthest into it
        image_size = std::cmp::max(image_size, entry["offset"] + entry["size"]);
        entry_count += 1;
    }

    // An index of one entry describes nothing
    if entry_count < 2 {
        return Err(StructureError);
    }

    Ok(SamsungTOC {
        entry_count,
        image_size,
    })
}
