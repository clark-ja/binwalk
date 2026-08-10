mod common;

/// The input file holds two captures, one after the other: a little endian one with microsecond
/// timestamps and three Ethernet packets, and a big endian one with nanosecond timestamps and two
/// Linux cooked capture packets.
///
/// The second capture is only found if the record walk of the first one stops at the right place,
/// which makes this a regression test for the walk running on past the end of a capture.
#[test]
fn integration_test() {
    const SIGNATURE_TYPE: &str = "libpcap";
    const INPUT_FILE_NAME: &str = "libpcap.bin";

    let results = common::run_binwalk(SIGNATURE_TYPE, INPUT_FILE_NAME);

    assert!(results.file_map.len() == 2);

    assert!(results.file_map[0].offset == 0);
    assert!(results.file_map[0].size == 254);
    assert!(results.file_map[0].description.contains("little endian"));
    assert!(results.file_map[0].description.contains("microsecond"));

    assert!(results.file_map[1].offset == 254);
    assert!(results.file_map[1].size == 190);
    assert!(results.file_map[1].description.contains("big endian"));
    assert!(results.file_map[1].description.contains("nanosecond"));
}
