mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "lz4_legacy";
    const INPUT_FILE_NAME: &str = "lz4_legacy.bin";
    common::integration_test(SIGNATURE_TYPE, INPUT_FILE_NAME);
}
