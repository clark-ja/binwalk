mod common;

/// The input file is a XAR header followed by a real zlib compressed table of contents and some
/// filler standing in for the heap.
///
/// The reported size covers the header and the table of contents: the length of the heap that
/// follows is only described inside the table of contents itself.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "xar";
    const INPUT_FILE_NAME: &str = "xar.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 122);
    assert!(
        results.file_map[0]
            .description
            .contains("checksum algorithm: SHA1")
    );
}
