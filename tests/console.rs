mod common;

/// Each input is the header of one of the console formats. The Game Boy, Advance and DS inputs
/// carry the logo their hardware checks, at the offset it belongs at, so the match is reported at
/// the start of the ROM rather than at the logo.
#[test]
fn integration_test() {
    for (signature, input, expected) in [
        ("gameboy", "gameboy.bin", "BINWALKTEST"),
        ("gba", "gba.bin", "GBA TITLE"),
        ("megadrive", "megadrive.bin", "BINWALK TEST ROM"),
        ("nds", "nds.bin", "BINWALKNDS"),
    ] {
        let results = common::run_binwalk(signature, input);
        assert!(results.file_map.len() == 1);
        assert!(results.file_map[0].offset == 0);
        assert!(results.file_map[0].description.contains(expected));
    }

    for (signature, input) in [("xbe", "xbe.bin"), ("xip", "xip.bin"), ("xtf", "xtf.bin")] {
        let results = common::run_binwalk(signature, input);
        assert!(results.file_map.len() == 1);
        assert!(results.file_map[0].offset == 0);
    }
}
