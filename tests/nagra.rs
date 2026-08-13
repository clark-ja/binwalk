mod common;

/// Each input is one of the two constants at the start of a file, which is the only place either
/// of them is matched: they are four bytes with nothing around them to check.
#[test]
fn integration_test() {
    for (signature, input) in [
        ("nagra_pk", "nagra_pk.bin"),
        ("nagra_constant_key", "nagra_constant_key.bin"),
    ] {
        let results = common::run_binwalk(signature, input);
        assert!(results.file_map.len() == 1);
        assert!(results.file_map[0].offset == 0);
    }
}
