use crate::extractors::lzma;
use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::lzma::parse_lzma_header;

/// Human readable description
pub const DESCRIPTION: &str = "LZMA compressed data";

/// Builds a list of common LZMA magic bytes (properties + dictionary sizes)
pub fn lzma_magic() -> Vec<Vec<u8>> {
    let mut magic_signatures: Vec<Vec<u8>> = vec![];

    /*
     * Known LZMA properties bytes.
     *
     * The properties byte encodes the lc, lp and pb values as ((pb * 5) + lp) * 9 + lc.
     * Only a subset of the possible combinations are ever produced by real encoders; this is the
     * list of values that have been observed in the wild.
     */
    let supported_properties: Vec<u8> = vec![
        0x51, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x63, 0x64, 0x65, 0x66, 0x6C, 0x6D, 0x6E, 0x75, 0x76,
        0x7E, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x90, 0x91, 0x92, 0x93, 0x99, 0x9A, 0x9B, 0xA2, 0xA3,
        0xAB, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xBD, 0xBE, 0xBF, 0xC0, 0xC6, 0xC7, 0xC8, 0xCF, 0xD0,
        0xD8,
    ];

    let supported_dictionary_sizes: Vec<u32> = vec![
        0x10_00_00_00,
        0x20_00_00_00,
        0x01_00_00_00,
        0x02_00_00_00,
        0x04_00_00_00,
        0x00_80_00_00,
        0x00_40_00_00,
        0x00_20_00_00,
        0x00_10_00_00,
        0x00_08_00_00,
        0x00_02_00_00,
        0x00_01_00_00,
    ];

    /*
     * Build a list of magic signatures to search for based on the supported property and dictionary values.
     * This means having a lot of LZMA signatures, but they are less prone to false positives than searching
     * for a more generic, but shorter, signature, such as b"\x5d\x00\x00". This results in less validation
     * of false positives, improving analysis times.
     */
    for property in supported_properties {
        for dictionary_size in &supported_dictionary_sizes {
            let mut magic: Vec<u8> = vec![property];
            magic.extend(dictionary_size.to_le_bytes().to_vec());
            magic_signatures.push(magic.to_vec());
        }
    }

    magic_signatures
}

/// Validate LZMA signatures
pub fn lzma_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Success return value
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Parse the LZMA header
    if let Ok(lzma_header) = parse_lzma_header(&file_data[offset..]) {
        /*
         * LZMA signatures are very prone to false positives, so do a dry-run extraction.
         * If it succeeds, we have high confidence that this signature is valid.
         * Else, assume this is a false positive.
         */
        let dry_run = lzma::lzma_decompress(file_data, offset, None);

        // Return success if dry run succeeded
        if dry_run.success
            && let Some(lzma_stream_size) = dry_run.size
        {
            result.size = lzma_stream_size;
            result.description = format!(
                "{}, properties: {:#04X}, dictionary size: {} bytes, compressed size: {} bytes, uncompressed size: {} bytes",
                result.description,
                lzma_header.properties,
                lzma_header.dictionary_size,
                result.size,
                lzma_header.decompressed_size as i64
            );
            return Ok(result);
        }
    }

    Err(SignatureError)
}
