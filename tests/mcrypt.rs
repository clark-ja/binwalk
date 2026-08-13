mod common;

/// The 2.5 input names its algorithm in the header, which is what makes that version worth
/// matching anywhere. The 2.2 input is only its three byte magic, so it is matched at the start of
/// a file alone.
#[test]
fn integration_test() {
    let results = common::run_binwalk("mcrypt25", "mcrypt25.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(
        results.file_map[0]
            .description
            .contains("algorithm: \"rijndael-128\"")
    );

    let results = common::run_binwalk("mcrypt22", "mcrypt22.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
}
