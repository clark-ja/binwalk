mod common;

#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "pem_certificate_request";
    const INPUT_FILE_NAME: &str = "pem_certificate_request.bin";

    let expected_signature_offsets: Vec<usize> = vec![0];
    // The signature spans the entire file, so extraction is declined
    let expected_extraction_offsets: Vec<usize> = vec![];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);
    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}
