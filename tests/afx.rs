mod common;

/// The input file carries the AFX signature at its usual offset of two bytes, so the match is
/// reported at the start of the file.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "afx";
    const INPUT_FILE_NAME: &str = "afx.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
}
