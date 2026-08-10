mod common;

/// Both input files are minimal ISO9660 volume descriptor sets of 19 sectors: a boot record, a
/// primary volume descriptor and a terminator, differing only in whether the boot record or the
/// primary volume descriptor comes first.
///
/// Extraction is not asserted because it needs an external utility. Everything is checked from a
/// single test because run_binwalk() shares one extraction directory.
#[test]
fn integration_test() {
    const IMAGE_SIZE: usize = 38912;

    // A boot record at the start of the descriptor set is the start of an ISO image
    let results = common::run_binwalk("iso9660_boot_record", "iso9660_boot_record.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == IMAGE_SIZE);

    // A boot record that follows another volume descriptor is part of that image, not its start
    let results = common::run_binwalk("iso9660_boot_record", "iso9660_boot_record_second.bin");
    assert!(results.file_map.is_empty());

    // The primary volume descriptor of that same image is still reported as usual
    let results = common::run_binwalk("iso9660", "iso9660_boot_record_second.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == IMAGE_SIZE);
}
