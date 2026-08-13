use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};

/// Human readable description
pub const DESCRIPTION: &str = "Xilinx Virtex/Spartan FPGA bitstream";

/// A bitstream is preceded by a run of dummy words and then the word that synchronises the device
pub fn xilinx_magic() -> Vec<Vec<u8>> {
    vec![b"\xFF\xFF\xFF\xFF\xAA\x99\x55\x66".to_vec()]
}

/// Validate a Xilinx bitstream signature
pub fn xilinx_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The dummy word that pads the bus before the sync word
    const DUMMY_WORD: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    /*
     * The sync word is preceded by a run of dummy words, so the bitstream starts at the first of
     * them rather than at the match.
     */
    let mut dummy_words: usize = 1;

    while offset >= dummy_words * DUMMY_WORD.len() {
        let word_start = offset - (dummy_words * DUMMY_WORD.len());

        match file_data.get(word_start..word_start + DUMMY_WORD.len()) {
            Some(word) if word == DUMMY_WORD => dummy_words += 1,
            _ => break,
        }
    }

    result.offset = offset - ((dummy_words - 1) * DUMMY_WORD.len());

    /*
     * What follows the sync word is a series of configuration commands whose total length is not
     * described anywhere in the stream, so no size is reported.
     */
    result.description = format!(
        "{}, {} dummy words before the sync word",
        result.description, dummy_words
    );

    Ok(result)
}
