mod common;

/// The input file holds two ROME bootloader headers, one for each of the product specific magics:
/// a Netgear KWGR614 RUN image at offset 0 and a Linksys WRT54GX BOOT image at offset 88. The
/// second one is only reached because the first reports the size of its header rather than of the
/// whole image, so scanning continues into the image body.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "rome";
    const INPUT_FILE_NAME: &str = "rome.bin";
    const HEADER_SIZE: usize = 24;

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 2);

    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == HEADER_SIZE);
    assert!(results.file_map[0].description.contains("image type: RUN"));
    assert!(
        results.file_map[0]
            .description
            .contains("created: 3/10/2010")
    );

    assert!(results.file_map[1].offset == 88);
    assert!(results.file_map[1].size == HEADER_SIZE);
    assert!(results.file_map[1].description.contains("image type: BOOT"));
    assert!(results.file_map[1].description.contains("image size: 8192"));
}
