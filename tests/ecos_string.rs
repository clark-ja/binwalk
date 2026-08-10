mod common;

/// The input file is a series of NULL terminated strings, some of which reference eCos and some of
/// which only contain the magic bytes as part of a longer word:
///
/// ```text
///    0  eCos 3.0 kernel      match
///   16  ecosystem            no match
///   26  ECOS_VERSION=2.0     match
///   43  Pecos River          no match
///   55  libecos.so           no match
///   66  ecos                 match
///   71  eCos                 match
///   76  the ecos build       match at 80, reported from the magic bytes onwards
///   91  ECOSYSTEM            no match
/// ```
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "ecos_string";
    const INPUT_FILE_NAME: &str = "ecos_string.bin";

    let expected_signature_offsets: Vec<usize> = vec![0, 26, 66, 71, 80];
    // String references are reported, not carved
    let expected_extraction_offsets: Vec<usize> = vec![];

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);
    common::assert_results_ok(
        results,
        expected_signature_offsets,
        expected_extraction_offsets,
    );
}
