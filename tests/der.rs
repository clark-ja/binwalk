mod common;

/// The input file holds three structures written by openssl, one after the other: a PKCS#8 private
/// key, an x509 certificate and a PKCS#7 signature. All three begin with the same two bytes, and
/// are told apart by what the sequence holds first.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "der";
    const INPUT_FILE_NAME: &str = "der.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 3);

    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 1217);
    assert!(results.file_map[0].description.contains("PKCS#8"));

    assert!(results.file_map[1].offset == 1217);
    assert!(results.file_map[1].size == 795);
    assert!(results.file_map[1].description.contains("x509 v3"));

    assert!(results.file_map[2].offset == 2012);
    assert!(results.file_map[2].size == 842);
    assert!(results.file_map[2].description.contains("PKCS#7"));
}
