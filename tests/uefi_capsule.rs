mod common;

/// Each input file is a minimal capsule header (header size 28, total size 128) followed by filler.
/// Extraction needs an external utility and a real payload, so only the signature match is checked.
fn capsule_test(file_name: &str) {
    const SIGNATURE_TYPE: &str = "uefi_capsule";

    let results = common::run_binwalk(SIGNATURE_TYPE, file_name);

    assert!(results.file_map.len() == 1);
    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 128);
}

#[test]
fn integration_test() {
    // AMI Aptio unsigned capsule GUID
    capsule_test("uefi_capsule_ami.bin");
    // Toshiba capsule GUID
    capsule_test("uefi_capsule_toshiba.bin");
}
