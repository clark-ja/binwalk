use crate::structures::common::StructureError;

/// Walks one bencoded value and returns its length in bytes
///
/// Bencoded data is made of four kinds of value: an integer, written "i<digits>e"; a byte string,
/// written "<length>:<bytes>"; a list of values, written "l<values>e"; and a dictionary of string
/// keys to values, written "d<pairs>e". Lists and dictionaries nest, so this walks them with an
/// explicit stack rather than by recursing.
pub fn parse_bencoded_value(bencode_data: &[u8]) -> Result<usize, StructureError> {
    // Nothing legitimate nests anywhere near this deep
    const MAX_DEPTH: usize = 32;

    // A string this long is not a torrent field, it is a false positive
    const MAX_STRING_LENGTH: usize = 0x10000000;

    let mut offset: usize = 0;
    let mut depth: usize = 0;

    loop {
        let byte = match bencode_data.get(offset) {
            Some(byte) => *byte,
            None => return Err(StructureError),
        };

        match byte {
            // A list or a dictionary; its contents follow until the matching terminator
            b'l' | b'd' => {
                depth += 1;
                offset += 1;

                if depth > MAX_DEPTH {
                    return Err(StructureError);
                }
            }

            // The terminator of a list, a dictionary or an integer
            b'e' => {
                offset += 1;

                if depth == 0 {
                    return Err(StructureError);
                }

                depth -= 1;

                // The outermost value has ended
                if depth == 0 {
                    return Ok(offset);
                }
            }

            // An integer, whose digits run up to the terminator
            b'i' => {
                let digits_start = offset + 1;
                let mut digits_end = digits_start;

                while let Some(digit) = bencode_data.get(digits_end) {
                    if *digit == b'e' {
                        break;
                    }

                    if !digit.is_ascii_digit() && !(digits_end == digits_start && *digit == b'-') {
                        return Err(StructureError);
                    }

                    digits_end += 1;
                }

                if digits_end == digits_start || bencode_data.get(digits_end) != Some(&b'e') {
                    return Err(StructureError);
                }

                // Step past the terminator; an integer is a value, not a container
                offset = digits_end + 1;

                if depth == 0 {
                    return Ok(offset);
                }
            }

            // A byte string, written as its length, a colon, and then the bytes themselves
            b'0'..=b'9' => {
                let mut digits_end = offset;
                let mut length: usize = 0;

                while let Some(digit) = bencode_data.get(digits_end) {
                    if !digit.is_ascii_digit() {
                        break;
                    }

                    length = match length
                        .checked_mul(10)
                        .and_then(|l| l.checked_add((*digit - b'0') as usize))
                    {
                        Some(length) => length,
                        None => return Err(StructureError),
                    };

                    digits_end += 1;
                }

                if bencode_data.get(digits_end) != Some(&b':') || length > MAX_STRING_LENGTH {
                    return Err(StructureError);
                }

                let string_end = match (digits_end + 1).checked_add(length) {
                    Some(string_end) => string_end,
                    None => return Err(StructureError),
                };

                // The string has to be there in its entirety
                if string_end > bencode_data.len() {
                    return Err(StructureError);
                }

                offset = string_end;

                if depth == 0 {
                    return Ok(offset);
                }
            }

            _ => return Err(StructureError),
        }
    }
}
