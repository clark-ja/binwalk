mod common;

/// The installer input is an MSCE header describing a StrongARM installer with three files and one
/// registry entry. The memory segment input is a ROM image with the signature at its usual offset
/// of 64 bytes, so the match is reported at the start of the image.
///
/// Neither header describes a size that can be relied on, so no size is asserted. Everything is
/// checked from a single test because run_binwalk() shares one extraction directory.
#[test]
fn integration_test() {
    let results = common::run_binwalk("wince_installer", "wince_installer.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("StrongARM"));
    assert!(results.file_map[0].description.contains("file count: 3"));

    let results = common::run_binwalk("wince_memory_segment", "wince_memory_segment.bin");
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("0x80200000"));
}
