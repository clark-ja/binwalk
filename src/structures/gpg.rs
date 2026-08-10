use crate::structures::common::{self, StructureError};

/// Stores info from the version record of a GPG key trust database
#[derive(Debug, Default, Clone)]
pub struct GPGTrustDBVersionRecord {
    pub version: usize,
    pub trust_model: usize,
}

/// Parse the version record that starts a GPG key trust database
pub fn parse_gpg_trustdb_version_record(
    trustdb_data: &[u8],
) -> Result<GPGTrustDBVersionRecord, StructureError> {
    // Only these versions of the trust database have ever been written
    const MIN_VERSION: usize = 2;
    const MAX_VERSION: usize = 3;

    let version_record_structure = vec![
        ("record_type", "u8"),
        ("magic_p1", "u16"),
        ("magic_p2", "u8"),
        ("version", "u8"),
        ("marginals_needed", "u8"),
        ("completes_needed", "u8"),
        ("max_certificate_depth", "u8"),
        ("trust_model", "u8"),
        ("min_certificate_level", "u8"),
        ("reserved", "u16"),
        ("created", "u32"),
        ("next_check", "u32"),
    ];

    if let Ok(version_record) = common::parse(trustdb_data, &version_record_structure, "big")
        && (MIN_VERSION..=MAX_VERSION).contains(&version_record["version"])
        && version_record["reserved"] == 0
    {
        return Ok(GPGTrustDBVersionRecord {
            version: version_record["version"],
            trust_model: version_record["trust_model"],
        });
    }

    Err(StructureError)
}
