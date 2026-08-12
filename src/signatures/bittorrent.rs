use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::bencode::parse_bencoded_value;

/// Human readable description
pub const DESCRIPTION: &str = "BitTorrent file";

/// Torrent files are a bencoded dictionary whose first key is the tracker URL
pub fn bittorrent_magic() -> Vec<Vec<u8>> {
    vec![b"d8:announce".to_vec()]
}

/// Validate a BitTorrent file signature
pub fn bittorrent_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    /*
     * The whole file is one bencoded dictionary, so walking it both validates the match and gives
     * the size of the torrent.
     */
    if let Ok(torrent_size) = parse_bencoded_value(&file_data[offset..]) {
        result.size = torrent_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}
