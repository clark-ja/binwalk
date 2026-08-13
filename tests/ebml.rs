mod common;

/// The input file is an EBML header declaring a doc type of matroska, followed by the start of a
/// segment of unknown length.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ebml";
    const INPUT_FILE_NAME: &str = "ebml.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(
        results.file_map[0]
            .description
            .contains("doc type: \"matroska\"")
    );
}
