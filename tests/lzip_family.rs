mod common;

/// The lzip input is a complete member: header, a real LZMA stream that decompresses back to the
/// original data, and a trailer whose CRC and sizes match it.
///
/// The rzip and lrzip inputs are headers followed by filler, since neither header can be checked
/// against the compressed data that follows it.
///
/// None of the three formats records the size of its compressed data in the header, so no size is
/// asserted. Everything is checked from a single test because run_binwalk() shares one extraction
/// directory.
#[test]
fn integration_test() {
    let results = common::run_binwalk("lzip", "lzip.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(
        results.file_map[0]
            .description
            .contains("dictionary size: 8388608")
    );

    let results = common::run_binwalk("rzip", "rzip.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("version: 2.1"));
    assert!(
        results.file_map[0]
            .description
            .contains("uncompressed size: 1048576")
    );

    let results = common::run_binwalk("lrzip", "lrzip.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("version: 0.6"));
}
