mod common;

/// The input file is the sixteen byte magic followed by filler.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "xen";
    const INPUT_FILE_NAME: &str = "xen.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
}
