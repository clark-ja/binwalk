mod common;

/// The input file is a VxWorks version banner: the runtime name, the version string, the runtime
/// name a second time, and the date the image was built.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "vxworks_os_version";
    const INPUT_FILE_NAME: &str = "vxworks_os_version.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].description.contains("\"5.5.1\""));
    assert!(
        results.file_map[0]
            .description
            .contains("compiled: \"Mar 10 2010, 12:34:56\"")
    );
}
