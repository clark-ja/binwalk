use crate::structures::common::{self, StructureError};

/// Stores info about a chunk of a Snappy framed stream
#[derive(Debug, Default, Clone)]
pub struct SnappyChunk {
    pub header_size: usize,
    pub data_size: usize,
}

/// Parse a chunk header of a Snappy framed stream
pub fn parse_snappy_chunk(chunk_data: &[u8]) -> Result<SnappyChunk, StructureError> {
    // Chunk types that carry data, and the stream identifier that begins every stream
    const CHUNK_TYPE_COMPRESSED: usize = 0x00;
    const CHUNK_TYPE_UNCOMPRESSED: usize = 0x01;
    const CHUNK_TYPE_STREAM_IDENTIFIER: usize = 0xFF;

    // Chunk types reserved for future use, which a reader must reject rather than skip
    const RESERVED_UNSKIPPABLE: std::ops::RangeInclusive<usize> = 0x02..=0x7F;

    // Data chunks hold at most 64KB of data, plus a checksum and, when compressed, some overhead
    const MAX_DATA_CHUNK_SIZE: usize = 0x11000;

    // The stream identifier is a fixed size chunk holding the string "sNaPpY"
    const STREAM_IDENTIFIER_SIZE: usize = 6;

    let chunk_structure = vec![("chunk_type", "u8"), ("chunk_size", "u24")];

    if let Ok(chunk_header) = common::parse(chunk_data, &chunk_structure, "little") {
        let chunk_type = chunk_header["chunk_type"];
        let chunk_size = chunk_header["chunk_size"];

        if RESERVED_UNSKIPPABLE.contains(&chunk_type) {
            return Err(StructureError);
        }

        let size_is_valid = match chunk_type {
            CHUNK_TYPE_STREAM_IDENTIFIER => chunk_size == STREAM_IDENTIFIER_SIZE,
            CHUNK_TYPE_COMPRESSED | CHUNK_TYPE_UNCOMPRESSED => {
                chunk_size > 0 && chunk_size <= MAX_DATA_CHUNK_SIZE
            }
            // Padding and the skippable chunk types are only bounded by the size field itself
            _ => true,
        };

        if size_is_valid {
            return Ok(SnappyChunk {
                header_size: common::size(&chunk_structure),
                data_size: chunk_size,
            });
        }
    }

    Err(StructureError)
}
