use crate::structures::common::StructureError;

/// What a DER structure was found to hold
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DERContents {
    PrivateKey,
    Certificate,
    Signature,
}

/// Stores info about a DER structure
#[derive(Debug, Clone)]
pub struct DERStructure {
    pub total_size: usize,
    pub contents: DERContents,
}

/// A tag, and where its value starts and ends
struct DERValue {
    tag: usize,
    value_start: usize,
    value_end: usize,
}

/// Parse a DER structure far enough to tell what it holds
///
/// All three of the structures of interest are a sequence of two or three values, which have to
/// tile the sequence exactly. What those values are is what tells the structures apart: a private
/// key begins with a version integer, a certificate with the sequence that is the body of the
/// certificate, and a signature with an object identifier naming what was signed.
pub fn parse_der_structure(der_data: &[u8]) -> Result<DERStructure, StructureError> {
    // Tags, with the constructed bit set on those whose value holds other values
    const TAG_INTEGER: usize = 0x02;
    const TAG_BIT_STRING: usize = 0x03;
    const TAG_OCTET_STRING: usize = 0x04;
    const TAG_OBJECT_IDENTIFIER: usize = 0x06;
    const TAG_SEQUENCE: usize = 0x30;
    const TAG_CONTEXT_0: usize = 0xA0;

    // The object identifier of signedData, which is what a PKCS#7 signature holds
    const SIGNED_DATA_OID: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];

    // Nothing of interest is smaller than this
    const MIN_TOTAL_SIZE: usize = 64;

    let outer = read_value(der_data, 0)?;

    if outer.tag != TAG_SEQUENCE || outer.value_end < MIN_TOTAL_SIZE {
        return Err(StructureError);
    }

    // The values inside the sequence have to tile it exactly, which is what rejects a chance match
    let children = read_children(der_data, &outer)?;

    let contents = match children.first() {
        // A private key starts with a version, which is followed by its algorithm and the key
        Some(first) if first.tag == TAG_INTEGER => {
            if children.len() < 3
                || (first.value_end - first.value_start) != 1
                || children[1].tag != TAG_SEQUENCE
                || children[2].tag != TAG_OCTET_STRING
            {
                return Err(StructureError);
            }

            DERContents::PrivateKey
        }

        // A certificate is its body, the algorithm it was signed with, and the signature
        Some(first) if first.tag == TAG_SEQUENCE => {
            if children.len() != 3
                || children[1].tag != TAG_SEQUENCE
                || children[2].tag != TAG_BIT_STRING
            {
                return Err(StructureError);
            }

            DERContents::Certificate
        }

        // A signature names the type of content that was signed, and then holds it
        Some(first) if first.tag == TAG_OBJECT_IDENTIFIER => {
            let oid = der_data
                .get(first.value_start..first.value_end)
                .ok_or(StructureError)?;

            if children.len() != 2 || oid != SIGNED_DATA_OID || children[1].tag != TAG_CONTEXT_0 {
                return Err(StructureError);
            }

            DERContents::Signature
        }

        _ => return Err(StructureError),
    };

    Ok(DERStructure {
        total_size: outer.value_end,
        contents,
    })
}

/// Read the values held inside a constructed value, which have to tile it exactly
fn read_children(der_data: &[u8], parent: &DERValue) -> Result<Vec<DERValue>, StructureError> {
    // A structure of interest holds a handful of values, not hundreds
    const MAX_CHILDREN: usize = 8;

    let mut children: Vec<DERValue> = vec![];
    let mut offset = parent.value_start;

    while offset < parent.value_end {
        if children.len() == MAX_CHILDREN {
            return Err(StructureError);
        }

        let child = read_value(der_data, offset)?;

        // A value that runs past the end of the one holding it is not a value at all
        if child.value_end > parent.value_end {
            return Err(StructureError);
        }

        offset = child.value_end;
        children.push(child);
    }

    if children.len() < 2 {
        return Err(StructureError);
    }

    Ok(children)
}

/// Read one tag and length, returning where its value starts and ends
fn read_value(der_data: &[u8], offset: usize) -> Result<DERValue, StructureError> {
    // Lengths below this are held in the length byte itself; above it, it counts the length bytes
    const LONG_FORM_FLAG: u8 = 0x80;
    const MAX_LENGTH_BYTES: usize = 4;

    let tag = *der_data.get(offset).ok_or(StructureError)? as usize;
    let length_byte = *der_data.get(offset + 1).ok_or(StructureError)?;

    let (length, length_size) = if (length_byte & LONG_FORM_FLAG) == 0 {
        (length_byte as usize, 1)
    } else {
        let length_bytes = (length_byte & !LONG_FORM_FLAG) as usize;

        // An indefinite length, or one too large to be real, is not something to report
        if length_bytes == 0 || length_bytes > MAX_LENGTH_BYTES {
            return Err(StructureError);
        }

        let mut length: usize = 0;

        for i in 0..length_bytes {
            let byte = *der_data.get(offset + 2 + i).ok_or(StructureError)?;
            length = (length << 8) | byte as usize;
        }

        (length, 1 + length_bytes)
    };

    let value_start = offset + 1 + length_size;

    Ok(DERValue {
        tag,
        value_start,
        value_end: value_start + length,
    })
}
