mod common;

/// The input file is the alternative LZMA header, with a properties byte of 0x5D, followed by
/// filler; nothing in the header describes the stream that follows it.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lzma_new";
    const INPUT_FILE_NAME: &str = "lzma_new.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("properties: 0x5D"));
}
