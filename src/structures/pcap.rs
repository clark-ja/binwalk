use crate::structures::common::{self, StructureError};
use std::collections::HashMap;

/// Storage struct for Pcap block info
#[derive(Debug, Clone, Default)]
pub struct PcapBlock {
    pub block_type: usize,
    pub block_size: usize,
}

/// Parse a Pcap-ng block
pub fn parse_pcapng_block(
    block_data: &[u8],
    endianness: &str,
) -> Result<PcapBlock, StructureError> {
    // Reserved bit in block type field
    const BLOCK_TYPE_RESERVED_MASK: usize = 0x80000000;

    let block_header_structure = vec![("block_type", "u32"), ("block_size", "u32")];

    let block_footer_structure = vec![("block_size", "u32")];

    let mut result = PcapBlock {
        ..Default::default()
    };

    let footer_size = common::size(&block_footer_structure);

    // Parse the block header
    if let Ok(block_header) = common::parse(block_data, &block_header_structure, endianness) {
        // Populate the block type and size values
        result.block_type = block_header["block_type"];
        result.block_size = block_header["block_size"];

        // Make sure the reserved bit of the block type is not set
        if (result.block_type & BLOCK_TYPE_RESERVED_MASK) == 0 {
            // Calculate the block footer offsets
            let block_footer_start = result.block_size - footer_size;
            let block_footer_end = block_footer_start + footer_size;

            // Validate that the block size in the block footer matches the block size in the block header
            if let Some(block_footer_data) = block_data.get(block_footer_start..block_footer_end)
                && let Ok(block_footer) =
                    common::parse(block_footer_data, &block_footer_structure, endianness)
                && block_footer["block_size"] == result.block_size
            {
                return Ok(result);
            }
        }
    }

    Err(StructureError)
}

#[derive(Debug, Default, Clone)]
pub struct PcapSectionBlock {
    pub block_size: usize,
    pub endianness: String,
}

/// Parse a Pcap-ng section block
pub fn parse_pcapng_section_block(block_data: &[u8]) -> Result<PcapSectionBlock, StructureError> {
    // Section header block type (same value, regardless of endianness)
    const SECTION_HEADER_BLOCK_TYPE: usize = 0x0A0D0D0A;

    let section_header_structure = vec![
        ("block_type", "u32"),
        ("block_size", "u32"),
        ("endian_magic", "u32"),
        ("major_version", "u16"),
        ("minor_version", "u16"),
        ("section_length", "u32"),
    ];

    let endian_magics: HashMap<usize, &str> =
        HashMap::from([(0x1A2B3C4D, "little"), (0x4D3C2B1A, "big")]);

    let mut result = PcapSectionBlock {
        ..Default::default()
    };

    // Parse the section header structure; endianess doesn't matter (yet)
    if let Ok(section_header) = common::parse(block_data, &section_header_structure, "little") {
        // Determine the endianness based on the endian magic bytes
        if endian_magics.contains_key(&section_header["endian_magic"]) {
            result.endianness = endian_magics[&section_header["endian_magic"]].to_string();

            // Parse the section header block as a generic block to ensure it is valid
            if let Ok(block_header) = parse_pcapng_block(block_data, &result.endianness) {
                // Make sure the section header block type is the expected value
                if block_header.block_type == SECTION_HEADER_BLOCK_TYPE {
                    result.block_size = block_header.block_size;
                    return Ok(result);
                }
            }
        }
    }

    Err(StructureError)
}

/// Storage struct for libpcap file header info
#[derive(Debug, Clone, Default)]
pub struct LibpcapHeader {
    pub header_size: usize,
    pub endianness: String,
    pub timestamp_resolution: String,
    pub major_version: usize,
    pub minor_version: usize,
    pub snap_length: usize,
    pub link_type: usize,
}

/// Parse a libpcap file header
pub fn parse_libpcap_header(pcap_data: &[u8]) -> Result<LibpcapHeader, StructureError> {
    // Magic values, in host order; the nanosecond variants only differ in timestamp resolution
    const MICROSECOND_MAGIC: usize = 0xA1B2C3D4;
    const NANOSECOND_MAGIC: usize = 0xA1B23C4D;

    // Only version 2.4 has ever been released
    const MAJOR_VERSION: usize = 2;
    const MINOR_VERSION: usize = 4;

    // Sane limit on the snap length, which is the largest packet the capture can hold
    const MAX_SNAP_LENGTH: usize = 0x400000;

    // Link layer types are assigned by tcpdump.org and are nowhere near this large
    const MAX_LINK_TYPE: usize = 300;

    let libpcap_structure = vec![
        ("magic", "u32"),
        ("major_version", "u16"),
        ("minor_version", "u16"),
        ("time_zone_offset", "u32"),
        ("timestamp_accuracy", "u32"),
        ("snap_length", "u32"),
        ("link_type", "u32"),
    ];

    for endianness in ["little", "big"] {
        if let Ok(libpcap_header) = common::parse(pcap_data, &libpcap_structure, endianness) {
            let timestamp_resolution = match libpcap_header["magic"] {
                MICROSECOND_MAGIC => "microsecond",
                NANOSECOND_MAGIC => "nanosecond",
                _ => continue,
            };

            if libpcap_header["major_version"] == MAJOR_VERSION
                && libpcap_header["minor_version"] == MINOR_VERSION
                && libpcap_header["snap_length"] <= MAX_SNAP_LENGTH
                && libpcap_header["link_type"] <= MAX_LINK_TYPE
            {
                return Ok(LibpcapHeader {
                    header_size: common::size(&libpcap_structure),
                    endianness: endianness.to_string(),
                    timestamp_resolution: timestamp_resolution.to_string(),
                    major_version: libpcap_header["major_version"],
                    minor_version: libpcap_header["minor_version"],
                    snap_length: libpcap_header["snap_length"],
                    link_type: libpcap_header["link_type"],
                });
            }
        }
    }

    Err(StructureError)
}

/// Storage struct for libpcap packet record info
#[derive(Debug, Clone, Default)]
pub struct LibpcapRecord {
    pub header_size: usize,
    pub data_size: usize,
}

/// Parse a libpcap packet record header
pub fn parse_libpcap_record(
    record_data: &[u8],
    endianness: &str,
    snap_length: usize,
) -> Result<LibpcapRecord, StructureError> {
    let record_structure = vec![
        ("timestamp_seconds", "u32"),
        ("timestamp_fraction", "u32"),
        ("captured_length", "u32"),
        ("original_length", "u32"),
    ];

    if let Ok(record_header) = common::parse(record_data, &record_structure, endianness) {
        /*
         * A record can be shorter than the packet it came from, if the packet was truncated to the
         * snap length, but never longer, and never longer than the snap length itself. An empty
         * record is not a packet at all: rejecting it is what stops the walk from running on into
         * whatever follows the capture.
         */
        if record_header["captured_length"] > 0
            && record_header["captured_length"] <= record_header["original_length"]
            && record_header["captured_length"] <= snap_length
        {
            return Ok(LibpcapRecord {
                header_size: common::size(&record_structure),
                data_size: record_header["captured_length"],
            });
        }
    }

    Err(StructureError)
}
