mod common;

/// The input file is a trust database written by gnupg for a throwaway key.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "gpg_trustdb";
    const INPUT_FILE_NAME: &str = "gpg_trustdb.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("version: 3"));
}
