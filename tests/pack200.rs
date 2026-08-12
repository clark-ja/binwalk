mod common;

/// The input file is a pack200 header of version 150.7, the version every release of the packer
/// wrote, followed by filler.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "pack200";
    const INPUT_FILE_NAME: &str = "pack200.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("version: 150.7"));
}
