mod common;

/// The input file is a TOC index of four entries: the one describing the image itself, and three
/// naming sections of it.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "samsung_toc";
    const INPUT_FILE_NAME: &str = "samsung_toc.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 4096);
    assert!(results.file_map[0].description.contains("entry count: 4"));
}
