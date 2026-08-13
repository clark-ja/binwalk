mod common;

/// The input file holds both index tables, each surrounded by filler.
#[test]
fn integration_test() {
    let results = common::run_binwalk("base64_table", "base64_tables.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 32);
    assert!(results.file_map[0].size == 64);

    let results = common::run_binwalk("base64_table_sercomm", "base64_tables.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 128);
    assert!(results.file_map[0].size == 64);
}
