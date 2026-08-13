mod common;

/// The input file is the magic followed by filler; nothing after it is documented.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "zyxel_voice";
    const INPUT_FILE_NAME: &str = "zyxel_voice.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
}
