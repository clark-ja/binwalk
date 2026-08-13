use crate::structures::common::StructureError;

/// Stores info about an EBML header
#[derive(Debug, Default, Clone)]
pub struct EBMLHeader {
    pub header_size: usize,
    pub doc_type: String,
}

/// Parse an EBML header
///
/// Every element of an EBML document is an ID, a length, and a payload. Both the ID and the length
/// are variable width: the number of leading zero bits of the first byte gives the width, and for
/// a length the marker bit itself is not part of the value.
pub fn parse_ebml_header(ebml_data: &[u8]) -> Result<EBMLHeader, StructureError> {
    // The ID of the header element, which is the magic, and of the doc type element inside it
    const HEADER_ID_SIZE: usize = 4;
    const DOC_TYPE_ID: [u8; 2] = [0x42, 0x82];

    // An EBML header is a handful of small elements; nothing legitimate is anywhere near this big
    const MAX_HEADER_SIZE: usize = 1024;
    const MAX_DOC_TYPE_SIZE: usize = 64;

    let (header_length, header_length_size) = parse_variable_integer(ebml_data, HEADER_ID_SIZE)?;

    if header_length == 0 || header_length > MAX_HEADER_SIZE {
        return Err(StructureError);
    }

    let header_size = HEADER_ID_SIZE + header_length_size + header_length;
    let header_end = HEADER_ID_SIZE + header_length_size + header_length;

    let header_body = match ebml_data.get(HEADER_ID_SIZE + header_length_size..header_end) {
        Some(header_body) => header_body,
        None => return Err(StructureError),
    };

    // The doc type element names the format that the document holds, such as matroska or webm
    let doc_type_id_offset = match header_body
        .windows(DOC_TYPE_ID.len())
        .position(|window| window == DOC_TYPE_ID)
    {
        Some(doc_type_id_offset) => doc_type_id_offset,
        None => return Err(StructureError),
    };

    let (doc_type_length, doc_type_length_size) =
        parse_variable_integer(header_body, doc_type_id_offset + DOC_TYPE_ID.len())?;

    if doc_type_length == 0 || doc_type_length > MAX_DOC_TYPE_SIZE {
        return Err(StructureError);
    }

    let doc_type_start = doc_type_id_offset + DOC_TYPE_ID.len() + doc_type_length_size;
    let doc_type_end = doc_type_start + doc_type_length;

    let doc_type = match header_body.get(doc_type_start..doc_type_end) {
        Some(doc_type_data) => match std::str::from_utf8(doc_type_data) {
            Ok(doc_type) if doc_type.chars().all(|c| c.is_ascii_graphic()) => doc_type.to_string(),
            _ => return Err(StructureError),
        },
        None => return Err(StructureError),
    };

    Ok(EBMLHeader {
        header_size,
        doc_type,
    })
}

/// Parse a variable width integer, returning its value and the number of bytes it occupies
fn parse_variable_integer(data: &[u8], offset: usize) -> Result<(usize, usize), StructureError> {
    // Values wider than this cannot be held, and are not used by any header field
    const MAX_WIDTH: usize = 8;

    let first_byte = match data.get(offset) {
        Some(first_byte) => *first_byte,
        None => return Err(StructureError),
    };

    if first_byte == 0 {
        return Err(StructureError);
    }

    // The position of the highest set bit of the first byte gives the width of the value
    let width = first_byte.leading_zeros() as usize + 1;

    if width > MAX_WIDTH {
        return Err(StructureError);
    }

    // The marker bit is not part of the value
    let mut value = (first_byte as usize) & (0xFF >> width);

    for i in 1..width {
        match data.get(offset + i) {
            Some(byte) => value = (value << 8) | (*byte as usize),
            None => return Err(StructureError),
        }
    }

    Ok((value, width))
}
