mod common;

/// The input file holds five armored blobs, one after the other: a public key block, a cleartext
/// signed message, an encrypted message, a detached signature and a multi part message. The
/// cleartext signed message contains a nested signature block, which must not be reported
/// separately. No private key block is included, to keep key material out of the repository.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "pgp_armored";
    const INPUT_FILE_NAME: &str = "pgp_armored.bin";

    let expected_signature_offsets: Vec<usize> = vec![0, 640, 932, 1225, 1453];
    // Armored data is reported, not carved
    let expected_extraction_offsets: Vec<usize> = vec![];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);
    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}
