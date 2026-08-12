mod common;

/// The classic input is a StuffIt archive header: the magic, a file count, the total size of the
/// archive and the second signature that confirms it. The other input is the text banner that a
/// StuffIt 5 archive begins with.
///
/// Deluxe segments are not covered here: their magic is three bytes with nothing to validate, so
/// that signature is only matched at the start of a file.
#[test]
fn integration_test() {
    let results = common::run_binwalk("stuffit", "stuffit.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 120);
    assert!(results.file_map[0].description.contains("file count: 3"));

    let results = common::run_binwalk("stuffit", "stuffit5.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("version 5"));
}
