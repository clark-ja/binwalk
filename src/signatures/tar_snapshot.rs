use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "GNU tar incremental snapshot";

/// Snapshot files start with this
pub fn tar_snapshot_magic() -> Vec<Vec<u8>> {
    vec![b"GNU tar-".to_vec()]
}

/// Validate a GNU tar incremental snapshot signature
pub fn tar_snapshot_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    /*
     * The first line of a snapshot names the version of tar that wrote it and the version of the
     * snapshot format, as in "GNU tar-1.35-2".
     */
    const MAX_HEADER_LINE: usize = 64;
    const MAX_SNAPSHOT_FORMAT: usize = 2;

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    let window_end = std::cmp::min(offset + MAX_HEADER_LINE, file_data.len());

    let window = match file_data.get(offset..window_end) {
        Some(window) => window,
        None => return Err(SignatureError),
    };

    // The line has to be terminated within the window, and to be printable text
    let line_length = match window.iter().position(|b| *b == b'\n') {
        Some(line_length) => line_length,
        None => return Err(SignatureError),
    };

    let header_line = match std::str::from_utf8(&window[0..line_length]) {
        Ok(header_line)
            if header_line
                .chars()
                .all(|c| c.is_ascii_graphic() || c == ' ') =>
        {
            header_line
        }
        _ => return Err(SignatureError),
    };

    // The snapshot format version is the last field of the line
    let (tar_version, snapshot_format) = match header_line.rsplit_once('-') {
        Some((tar_version, snapshot_format)) => (tar_version, snapshot_format),
        None => return Err(SignatureError),
    };

    let snapshot_format: usize = match snapshot_format.parse() {
        Ok(snapshot_format) => snapshot_format,
        Err(_) => return Err(SignatureError),
    };

    if snapshot_format > MAX_SNAPSHOT_FORMAT {
        return Err(SignatureError);
    }

    /*
     * What follows the first line is a list of the directories in the archive, whose length is not
     * described anywhere, so the size is left unknown.
     */
    result.description = format!(
        "{}, written by {}, snapshot format: {}",
        result.description, tar_version, snapshot_format
    );

    Ok(result)
}
