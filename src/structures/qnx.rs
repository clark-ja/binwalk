use crate::structures::common::{self, StructureError};

/// Stores info on a QNX IFS header
pub struct IFSHeader {
    pub total_size: usize,
}

/// Stores info on a QNX4 root directory entry
pub struct QNX4RootDir {
    pub size: usize,
}

/// Parse the root directory entry that follows a QNX4 boot block
///
/// The boot block magic is just an x86 jump instruction, so the root directory entry in the block
/// that follows it is what actually identifies the file system.
pub fn parse_qnx4_root_dir(qnx4_data: &[u8]) -> Result<QNX4RootDir, StructureError> {
    // The root directory entry lives in the block that follows the boot block
    const ROOT_DIR_OFFSET: usize = 512;

    // The root directory is always named "/"
    const ROOT_DIR_NAME: u8 = b'/';
    const FILE_NAME_LEN: usize = 16;

    let root_dir_structure = vec![
        ("size", "u32"),
        ("first_extent_block", "u32"),
        ("first_extent_size", "u32"),
        ("extent_block", "u32"),
        ("ftime", "u32"),
        ("mtime", "u32"),
        ("atime", "u32"),
        ("ctime", "u32"),
        ("extent_count", "u16"),
        ("mode", "u16"),
        ("uid", "u16"),
        ("gid", "u16"),
        ("link_count", "u16"),
        ("zero", "u32"),
    ];

    // The file name field is NULL padded, so the root directory's name is "/" followed by a NULL
    if let Some(name) = qnx4_data.get(ROOT_DIR_OFFSET..ROOT_DIR_OFFSET + 2)
        && name == [ROOT_DIR_NAME, 0]
        && let Some(entry_data) = qnx4_data.get(ROOT_DIR_OFFSET + FILE_NAME_LEN..)
        && let Ok(root_dir) = common::parse(entry_data, &root_dir_structure, "little")
        && root_dir["zero"] == 0
        && root_dir["extent_count"] > 0
    {
        return Ok(QNX4RootDir {
            size: root_dir["size"],
        });
    }

    Err(StructureError)
}

/// Stores info on a QNX6 super block
pub struct QNX6SuperBlock {
    pub endianness: String,
    pub block_size: usize,
    pub block_count: usize,
}

/// Parse a QNX6 super block
pub fn parse_qnx6_super_block(
    qnx6_data: &[u8],
    endianness: &str,
) -> Result<QNX6SuperBlock, StructureError> {
    // Sane limits on the reported block size, which must also be a power of two
    const MIN_BLOCK_SIZE: usize = 512;
    const MAX_BLOCK_SIZE: usize = 65536;

    let super_block_structure = vec![
        ("magic", "u32"),
        ("checksum", "u32"),
        ("serial", "u64"),
        ("ctime", "u32"),
        ("atime", "u32"),
        ("flags", "u32"),
        ("version1", "u16"),
        ("version2", "u16"),
        ("volumeid_p1", "u64"),
        ("volumeid_p2", "u64"),
        ("block_size", "u32"),
        ("inode_count", "u32"),
        ("free_inodes", "u32"),
        ("block_count", "u32"),
        ("free_blocks", "u32"),
    ];

    if let Ok(super_block) = common::parse(qnx6_data, &super_block_structure, endianness) {
        let block_size = super_block["block_size"];

        if (MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size)
            && block_size.is_power_of_two()
            && super_block["block_count"] > 0
            && super_block["free_blocks"] <= super_block["block_count"]
            && super_block["free_inodes"] <= super_block["inode_count"]
        {
            return Ok(QNX6SuperBlock {
                endianness: endianness.to_string(),
                block_size,
                block_count: super_block["block_count"],
            });
        }
    }

    Err(StructureError)
}

/// Parse a QNX IFS header
pub fn parse_ifs_header(ifs_data: &[u8]) -> Result<IFSHeader, StructureError> {
    // https://github.com/askac/dumpifs/blob/master/sys/startup.h
    let ifs_structure = vec![
        ("magic", "u32"),
        ("version", "u16"),
        ("flags1", "u8"),
        ("flags2", "u8"),
        ("header_size", "u16"),
        ("machine", "u16"),
        ("startup_vaddr", "u32"),
        ("paddr_bias", "u32"),
        ("image_paddr", "u32"),
        ("ram_paddr", "u32"),
        ("ram_size", "u32"),
        ("startup_size", "u32"),
        ("stored_size", "u32"),
        ("imagefs_paddr", "u32"),
        ("imagefs_size", "u32"),
        ("preboot_size", "u16"),
        ("zero_0", "u16"),
        ("zero_1", "u32"),
        ("zero_2", "u32"),
        ("zero_3", "u32"),
    ];

    // Parse the IFS header
    if let Ok(ifs_header) = common::parse(ifs_data, &ifs_structure, "little") {
        // The flags2 field is unused and should be 0
        if ifs_header["flags2"] == 0 {
            // Verify that all the zero fields are, in fact, zero
            if ifs_header["zero_0"] == 0
                && ifs_header["zero_1"] == 0
                && ifs_header["zero_2"] == 0
                && ifs_header["zero_3"] == 0
            {
                return Ok(IFSHeader {
                    total_size: ifs_header["stored_size"],
                });
            }
        }
    }

    Err(StructureError)
}
