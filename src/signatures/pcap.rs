use crate::common::is_offset_safe;
use crate::extractors::pcap::pcapng_carver;
use crate::signatures::common::{CONFIDENCE_HIGH, SignatureError, SignatureResult};
use crate::structures::pcap::{parse_libpcap_header, parse_libpcap_record};

/// Human readable descriptions
pub const PCAPNG_DESCRIPTION: &str = "Pcap-NG capture file";
pub const LIBPCAP_DESCRIPTION: &str = "Libpcap capture file";

/// Libpcap files start with these magic bytes, in either byte order, with a second pair of magics
/// for captures whose timestamps are in nanoseconds
pub fn libpcap_magic() -> Vec<Vec<u8>> {
    vec![
        b"\xA1\xB2\xC3\xD4".to_vec(),
        b"\xD4\xC3\xB2\xA1".to_vec(),
        b"\xA1\xB2\x3C\x4D".to_vec(),
        b"\x4D\x3C\xB2\xA1".to_vec(),
    ]
}

/// Pcap-NG files always start with these bytes
pub fn pcapng_magic() -> Vec<Vec<u8>> {
    vec![b"\x0A\x0D\x0D\x0A".to_vec()]
}

/// Parses and validates the Pcap-NG file
pub fn pcapng_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: PCAPNG_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    // Do an extraction dry-run
    let dry_run = pcapng_carver(file_data, offset, None);

    // If dry-run was successful, this is almost certianly a valid pcap-ng file
    if dry_run.success
        && let Some(pcap_size) = dry_run.size
    {
        // If this file is just a pcap file, no need to carve it out to yet another file on disk
        if offset == 0 && pcap_size == file_data.len() {
            result.extraction_declined = true;
        }

        // Return parser results
        result.size = pcap_size;
        result.description = format!("{}, total size: {} bytes", result.description, result.size);
        return Ok(result);
    }

    Err(SignatureError)
}

/// Parses and validates a libpcap file
pub fn libpcap_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // Successful return value
    let mut result = SignatureResult {
        offset,
        description: LIBPCAP_DESCRIPTION.to_string(),
        confidence: CONFIDENCE_HIGH,
        ..Default::default()
    };

    if let Ok(pcap_header) = parse_libpcap_header(&file_data[offset..]) {
        /*
         * A libpcap file does not record its own length, so the packet records that follow the
         * file header are walked to find where the capture ends.
         */
        let capture_size = get_libpcap_size(
            &file_data[offset..],
            pcap_header.header_size,
            &pcap_header.endianness,
            pcap_header.snap_length,
        );

        result.size = capture_size;
        result.description = format!(
            "{}, {} endian, version: {}.{}, {} timestamps, link type: {}, snap length: {}, total size: {} bytes",
            result.description,
            pcap_header.endianness,
            pcap_header.major_version,
            pcap_header.minor_version,
            pcap_header.timestamp_resolution,
            pcap_header.link_type,
            pcap_header.snap_length,
            result.size
        );

        return Ok(result);
    }

    Err(SignatureError)
}

/// Walks the packet records of a libpcap file and returns the total size of the capture
fn get_libpcap_size(
    pcap_data: &[u8],
    header_size: usize,
    endianness: &str,
    snap_length: usize,
) -> usize {
    let mut capture_size: usize = header_size;
    let mut previous_capture_size = None;
    let available_data = pcap_data.len();

    // Loop while there is still data and while the offsets are sane
    while is_offset_safe(available_data, capture_size, previous_capture_size) {
        match pcap_data.get(capture_size..) {
            None => {
                break;
            }
            Some(record_data) => {
                // Parsing fails once the data no longer looks like a packet record
                match parse_libpcap_record(record_data, endianness, snap_length) {
                    Err(_) => {
                        break;
                    }
                    Ok(record) => {
                        let record_size = record.header_size + record.data_size;

                        // Don't include a truncated record in the reported size
                        if (capture_size + record_size) > available_data {
                            break;
                        }

                        previous_capture_size = Some(capture_size);
                        capture_size += record_size;
                    }
                }
            }
        }
    }

    capture_size
}
