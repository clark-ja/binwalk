mod common;

/// Each input file holds three PEM blobs whose end markers were previously unknown to the PEM
/// carver, which meant the signatures were found and then discarded as false positives.
///
/// Only the RSA public key and the encrypted private key are openssl output; the other four blobs
/// are relabelled copies of them, since openssl writes SubjectPublicKeyInfo ("PUBLIC KEY") for DSA
/// and EC keys, "ANY PRIVATE KEY" is a read side wildcard rather than something openssl writes, and
/// TSS2 keys need tpm2 tooling. The parser does not care what the body decodes to, so the
/// relabelled blobs still exercise the end marker lookup for those labels.
///
/// Both files are checked from a single test because run_binwalk() shares one extraction
/// directory, which it removes before and after each run.
#[test]
fn integration_test() {
    // RSA PUBLIC KEY, DSA PUBLIC KEY, ECDSA PUBLIC KEY
    let public_key_offsets: Vec<usize> = vec![0, 426, 885];
    let results = common::run_binwalk("pem_public_key", "pem_public_keys.bin");
    common::assert_results_ok(results, public_key_offsets.clone(), public_key_offsets);

    // ANY PRIVATE KEY, ENCRYPTED PRIVATE KEY, TSS2 PRIVATE KEY
    let private_key_offsets: Vec<usize> = vec![0, 1874, 3760];
    let results = common::run_binwalk("pem_private_key", "pem_private_keys.bin");
    common::assert_results_ok(results, private_key_offsets.clone(), private_key_offsets);
}
