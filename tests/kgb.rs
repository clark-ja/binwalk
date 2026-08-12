mod common;

/// The input file is a KGB archive header naming version 1.2.1, followed by filler.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "kgb";
    const INPUT_FILE_NAME: &str = "kgb.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("version: 1.2.1"));
}
