mod common;

/// The input file is the first line of a snapshot written by tar 1.35 in snapshot format 2,
/// followed by the start of the directory list.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "tar_snapshot";
    const INPUT_FILE_NAME: &str = "tar_snapshot.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(
        results.file_map[0]
            .description
            .contains("snapshot format: 2")
    );
}
