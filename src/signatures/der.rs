use crate::signatures::common::{CONFIDENCE_MEDIUM, SignatureError, SignatureResult};
use crate::structures::der::{DERContents, parse_der_structure};

/// Human readable descriptions
pub const PRIVATE_KEY_DESCRIPTION: &str = "Private key in DER format (PKCS#8)";
pub const CERTIFICATE_DESCRIPTION: &str = "Certificate in DER format (x509 v3)";
pub const SIGNATURE_DESCRIPTION: &str = "Object signature in DER format (PKCS#7)";
pub const DESCRIPTION: &str = "DER encoded data";

/// All three of these are a DER sequence whose length is given in two bytes
pub fn der_magic() -> Vec<Vec<u8>> {
    vec![b"\x30\x82".to_vec()]
}

/// Validate a DER structure signature
pub fn der_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    let mut result = SignatureResult {
        offset,
        description: DESCRIPTION.to_string(),
        confidence: CONFIDENCE_MEDIUM,
        ..Default::default()
    };

    let available_data = file_data.len() - offset;

    if let Ok(der) = parse_der_structure(&file_data[offset..]) {
        // The length in the header covers everything after it, which is the size of the structure
        if der.total_size > available_data {
            return Err(SignatureError);
        }

        result.size = der.total_size;
        result.description = format!(
            "{}, total size: {} bytes",
            match der.contents {
                DERContents::PrivateKey => PRIVATE_KEY_DESCRIPTION,
                DERContents::Certificate => CERTIFICATE_DESCRIPTION,
                DERContents::Signature => SIGNATURE_DESCRIPTION,
            },
            result.size
        );
        return Ok(result);
    }

    Err(SignatureError)
}
