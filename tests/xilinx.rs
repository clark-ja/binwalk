mod common;

/// The input file is four dummy words followed by the sync word, so the match is reported at the
/// first dummy word rather than at the sync word itself.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "xilinx";
    const INPUT_FILE_NAME: &str = "xilinx.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 16);
    assert!(results.file_map[0].description.contains("4 dummy words"));
}
