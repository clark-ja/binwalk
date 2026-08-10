use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use aho_corasick::AhoCorasick;

/// Human readable description
pub const DESCRIPTION: &str = "PGP armored data";

/// All PGP armor headers start with this string
pub fn pgp_armor_magic() -> Vec<Vec<u8>> {
    vec![b"-----BEGIN PGP ".to_vec()]
}

/// Validate a PGP armored data signature
pub fn pgp_armor_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // Cleartext signatures are the one armor type whose tail marker is not the header's counterpart
    const CLEARTEXT_HEADER: &str = "PGP SIGNED MESSAGE";
    const CLEARTEXT_TAIL: &str = "PGP SIGNATURE";

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let armor_data = &file_data[offset..];

    // Identify which type of armored data this is
    let armor_type = get_armor_type(armor_data)?;

    // Build the tail marker that terminates this armored data
    let tail_type = match armor_type.as_str() {
        CLEARTEXT_HEADER => CLEARTEXT_TAIL,
        _ => &armor_type,
    };
    let tail_marker = format!("-----END {tail_type}-----");

    /*
     * Armored data must be terminated by its tail marker; requiring it both validates the match
     * and provides the size of the data.
     */
    result.size = find_armor_tail(armor_data, tail_marker.as_bytes())?;
    result.description = format!(
        "{}, type: \"{}\", total size: {} bytes",
        result.description, armor_type, result.size
    );

    Ok(result)
}

/// Returns the armor type of a PGP armor header, e.g. "PGP PUBLIC KEY BLOCK"
fn get_armor_type(armor_data: &[u8]) -> Result<String, SignatureError> {
    // "-----BEGIN " and the trailing "-----" that surround the armor type
    const HEADER_PREFIX: &str = "-----BEGIN ";
    const MARKER_SUFFIX: &str = "-----";

    // No armor type comes close to this long; multi part message types are the longest
    const MAX_ARMOR_TYPE_LEN: usize = 64;

    let header_end = std::cmp::min(
        HEADER_PREFIX.len() + MAX_ARMOR_TYPE_LEN + MARKER_SUFFIX.len(),
        armor_data.len(),
    );

    // Only the header line is of interest, and it must be terminated by the trailing "-----"
    if let Some(header_data) = armor_data.get(HEADER_PREFIX.len()..header_end)
        && let Ok(header_string) = String::from_utf8(header_data.to_vec())
        && let Some(suffix_index) = header_string.find(MARKER_SUFFIX)
    {
        let armor_type = &header_string[0..suffix_index];

        /*
         * Armor types are upper case ASCII; the comma, digits and forward slash are only used by
         * multi part messages, e.g. "PGP MESSAGE, PART 1/3". This also rejects any candidate whose
         * header line ends before the trailing "-----" is found.
         */
        if !armor_type.is_empty()
            && armor_type
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || " ,/".contains(c))
        {
            return Ok(armor_type.to_string());
        }
    }

    Err(SignatureError)
}

/// Returns the total size of the armored data, including its tail marker and any trailing newlines
fn find_armor_tail(armor_data: &[u8], tail_marker: &[u8]) -> Result<usize, SignatureError> {
    const NEWLINE_CHARS: [u8; 2] = [0x0D, 0x0A];

    let grep = AhoCorasick::new(vec![tail_marker]).unwrap();

    if let Some(tail_match) = grep.find_iter(armor_data).next() {
        let mut armor_size = tail_match.start() + tail_marker.len();

        // Include any trailing newline characters in the total size
        while let Some(next_byte) = armor_data.get(armor_size) {
            if !NEWLINE_CHARS.contains(next_byte) {
                break;
            }
            armor_size += 1;
        }

        return Ok(armor_size);
    }

    Err(SignatureError)
}
