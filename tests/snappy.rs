mod common;

/// The input file is a framed stream of four chunks: the stream identifier, two uncompressed data
/// chunks with real CRC32C checksums, and a padding chunk.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "snappy";
    const INPUT_FILE_NAME: &str = "snappy.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 260);
    assert!(results.file_map[0].description.contains("chunk count: 4"));
}
