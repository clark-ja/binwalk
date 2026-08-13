mod common;

/// Each input is one of the five file headers, followed by filler. All five are only matched at
/// the start of a file: their magics are two and three bytes, with nothing after them to check.
#[test]
fn integration_test() {
    for (signature, input) in [
        ("frm", "mysql_frm.bin"),
        ("misam_index", "mysql_misam_index.bin"),
        ("misam_data", "mysql_misam_data.bin"),
        ("isam_index", "mysql_isam_index.bin"),
        ("isam_data", "mysql_isam_data.bin"),
    ] {
        let results = common::run_binwalk(signature, input);
        assert!(results.file_map.len() == 1);
        assert!(results.file_map[0].offset == 0);
    }
}
