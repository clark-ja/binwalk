mod common;

/// The input file is a PlayStation executable header, which is one sector long, followed by a text
/// section of four kilobytes.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "psx";
    const INPUT_FILE_NAME: &str = "psx.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 6144);
    assert!(
        results.file_map[0]
            .description
            .contains("entry point: 0x80010000")
    );
}
