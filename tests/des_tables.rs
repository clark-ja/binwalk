mod common;

/// The input file holds all six tables, each surrounded by filler: the two permutation tables, and
/// the two SP tables in both of the byte orders they are stored in.
#[test]
fn integration_test() {
    for (signature, offsets, size) in [
        ("des_pc1", vec![16], 56),
        ("des_pc2", vec![88], 48),
        ("des_sp1", vec![152, 200], 32),
        ("des_sp2", vec![248, 296], 32),
    ] {
        let results = common::run_binwalk(signature, "des_tables.bin");
        assert!(results.file_map.len() == offsets.len());

        for (result, offset) in results.file_map.iter().zip(offsets) {
            assert!(result.offset == offset);
            assert!(result.size == size);
        }
    }
}
