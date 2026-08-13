mod common;

/// One input carries the archive signature inside its first local header, fourteen bytes in, so
/// the match is reported at the start of the header. The other is a self extracting archive,
/// which begins with its own signature and is only matched at the start of a file.
#[test]
fn integration_test() {
    let results = common::run_binwalk("arj_jar", "arj_jar.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);

    let results = common::run_binwalk("arj_jar_sfx", "arj_jar_sfx.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("self extracting"));
}
