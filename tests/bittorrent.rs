mod common;

/// The input file is a torrent for a three piece file, with an announce URL, an announce list, a
/// creation date and an info dictionary, so the walk covers strings, integers, lists and nested
/// dictionaries.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "bittorrent";
    const INPUT_FILE_NAME: &str = "bittorrent.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 287);
}
