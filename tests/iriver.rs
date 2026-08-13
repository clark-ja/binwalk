mod common;

/// The input file is an iRiver database header naming the database, followed by filler.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "iriver";
    const INPUT_FILE_NAME: &str = "iriver.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("PlayList"));
}
