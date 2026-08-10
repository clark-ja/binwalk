mod common;

/// The input file is a two entry ZIP archive preceded by the spanning marker, with the central
/// directory offsets adjusted for it, so that it is a valid single segment multi-volume archive.
///
/// Extraction is not asserted: it needs an external utility, and whether that utility accepts an
/// archive that begins with a spanning marker is its own business.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "zip_multi_volume";
    const INPUT_FILE_NAME: &str = "zip_multi_volume.bin";
    const ARCHIVE_SIZE: usize = 290;

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    // The spanning marker is part of the archive, so the result starts at it, not at the file entry
    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == ARCHIVE_SIZE);
}
