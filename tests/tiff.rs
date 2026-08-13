mod common;

/// The input file is a little endian TIFF header whose first image file directory holds four
/// entries.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "tiff";
    const INPUT_FILE_NAME: &str = "tiff.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("little endian"));
    assert!(results.file_map[0].description.contains("4 entries"));
}
