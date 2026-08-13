mod common;

/// The input file is an encoded script header: the marker, the encoded length, and the two
/// characters that close the header.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "screnc";
    const INPUT_FILE_NAME: &str = "screnc.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
}
