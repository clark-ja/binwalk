mod common;

/// The input file is an InstallShield cabinet header whose descriptor sits at the end of the
/// cabinet, which is what gives the size reported for it.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "installshield";
    const INPUT_FILE_NAME: &str = "installshield.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 608);
}
