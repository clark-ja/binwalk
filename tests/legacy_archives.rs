mod common;

/// The combined input holds an HPACK, a JAM, a Borg segment and a BSA header, one after the other.
///
/// PARity and LBR get their own inputs: their magic is four bytes of text and twelve bytes of
/// whitespace respectively, so those two are only matched at the start of a file.
#[test]
fn integration_test() {
    for (signature, offset) in [("hpack", 0), ("jam", 64), ("borg", 130), ("bsa", 198)] {
        let results = common::run_binwalk(signature, "legacy_archives.bin");
        assert!(results.file_map.len() == 1);
        assert!(results.file_map[0].offset == offset);
    }

    let results = common::run_binwalk("bsa", "legacy_archives.bin");
    assert!(results.file_map[0].description.contains("version: 104"));

    for (signature, input) in [("parity", "parity.bin"), ("lbr", "lbr.bin")] {
        let results = common::run_binwalk(signature, input);
        assert!(results.file_map.len() == 1);
        assert!(results.file_map[0].offset == 0);
    }
}
