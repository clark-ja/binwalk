use crate::common::is_offset_safe;
use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::snappy::parse_snappy_chunk;

/// Human readable description
pub const DESCRIPTION: &str = "Snappy compressed data";

/// Snappy framed streams start with a stream identifier chunk
pub fn snappy_magic() -> Vec<Vec<u8>> {
    vec![b"\xFF\x06\x00\x00sNaPpY".to_vec()]
}

/// Validate a Snappy framed stream signature
pub fn snappy_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    /*
     * A framed stream does not record its own length, but it is a series of length prefixed
     * chunks, so walking them gives both the size of the stream and confidence in the match.
     */
    let stream_data = &file_data[offset..];
    let mut stream_size: usize = 0;
    let mut previous_stream_size = None;
    let mut chunk_count: usize = 0;
    let available_data = stream_data.len();

    while is_offset_safe(available_data, stream_size, previous_stream_size) {
        match stream_data.get(stream_size..) {
            None => break,
            Some(chunk_data) => match parse_snappy_chunk(chunk_data) {
                Err(_) => break,
                Ok(chunk) => {
                    let chunk_size = chunk.header_size + chunk.data_size;

                    // Don't include a truncated chunk in the reported size
                    if (stream_size + chunk_size) > available_data {
                        break;
                    }

                    previous_stream_size = Some(stream_size);
                    stream_size += chunk_size;
                    chunk_count += 1;
                }
            },
        }
    }

    // The stream identifier itself is the first chunk; anything less is not a stream
    if chunk_count > 0 {
        result.size = stream_size;
        result.description = format!(
            "{}, chunk count: {}, total size: {} bytes",
            result.description, chunk_count, result.size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
