mod common;

/// The input file is a PE binary whose DOS header matches neither of the two headers that used to
/// be hardcoded as the magic bytes, so it was previously missed entirely.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "pe";
    const INPUT_FILE_NAME: &str = "pe_dos_header.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(
        results.file_map[0]
            .description
            .contains("machine type: Intel x86")
    );
}
