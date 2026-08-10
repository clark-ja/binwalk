mod common;

/// The QNX4 input is a boot block followed by the block holding the root directory entry, which is
/// what validates the match: the boot block magic on its own is only an x86 jump instruction.
///
/// The QNX6 input is a little endian super block followed by a big endian one.
///
/// Neither file system describes its own total size, so no size is asserted. Everything is checked
/// from a single test because run_binwalk() shares one extraction directory.
#[test]
fn integration_test() {
    let results = common::run_binwalk("qnx4", "qnx4.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);

    let results = common::run_binwalk("qnx6", "qnx6.bin");
    assert!(results.file_map.len() == 2);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("little endian"));
    assert!(results.file_map[1].offset == 512);
    assert!(results.file_map[1].description.contains("big endian"));
}
