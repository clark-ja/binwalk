mod common;

/// The input file is an uncompressed SWF, whose header records the length of the whole file.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "swf";
    const INPUT_FILE_NAME: &str = "swf.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 128);
    assert!(results.file_map[0].description.contains("version: 13"));
}
