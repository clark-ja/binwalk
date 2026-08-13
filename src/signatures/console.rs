use crate::common::get_cstring;
use crate::signatures::common::{
    CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, SignatureError, SignatureResult,
};

/// Human readable descriptions
pub const GAMEBOY_DESCRIPTION: &str = "Game Boy ROM";
pub const GBA_DESCRIPTION: &str = "Game Boy Advance ROM";
pub const MEGADRIVE_DESCRIPTION: &str = "Sega Mega Drive/Genesis ROM";
pub const NDS_DESCRIPTION: &str = "Nintendo DS ROM";
pub const XBE_DESCRIPTION: &str = "Microsoft Xbox executable";
pub const XIP_DESCRIPTION: &str = "Microsoft Xbox XIP data";
pub const XTF_DESCRIPTION: &str = "Microsoft Xbox XTF data";

/// The Nintendo logo that a Game Boy cartridge is checked against sits at this offset
pub const GAMEBOY_MAGIC_OFFSET: usize = 0x104;

/// A Mega Drive cartridge names its console at this offset
pub const MEGADRIVE_MAGIC_OFFSET: usize = 0x100;

/// The first bytes of the Nintendo logo of a Game Boy cartridge
pub fn gameboy_magic() -> Vec<Vec<u8>> {
    vec![b"\xCE\xED\x66\x66\xCC\x0D\x00\x0B".to_vec()]
}

/// A Game Boy Advance cartridge begins with a branch and then its own copy of the logo
pub fn gba_magic() -> Vec<Vec<u8>> {
    vec![b"\x2E\x00\x00\xEA\x24\xFF\xAE\x51\x69\x9A".to_vec()]
}

/// A Mega Drive cartridge names the console it is for
pub fn megadrive_magic() -> Vec<Vec<u8>> {
    vec![b"SEGA".to_vec()]
}

/// A Nintendo DS cartridge carries the same logo, at its own offset
pub fn nds_magic() -> Vec<Vec<u8>> {
    vec![b"\x24\xFF\xAE\x51\x69\x9A\xA2\x21".to_vec()]
}

/// Xbox executables and data files each start with their own magic
pub fn xbe_magic() -> Vec<Vec<u8>> {
    vec![b"XBEH".to_vec()]
}

pub fn xip_magic() -> Vec<Vec<u8>> {
    vec![b"XIP0".to_vec()]
}

pub fn xtf_magic() -> Vec<Vec<u8>> {
    vec![b"XTF0\x00\x00\x00".to_vec()]
}

/// Validate a Game Boy ROM signature
pub fn gameboy_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The cartridge title follows the logo
    const TITLE_OFFSET: usize = 0x134;
    const TITLE_SIZE: usize = 15;

    if offset < GAMEBOY_MAGIC_OFFSET {
        return Err(SignatureError);
    }

    let rom_start = offset - GAMEBOY_MAGIC_OFFSET;
    let mut result = rom(rom_start, GAMEBOY_DESCRIPTION, CONFIDENCE_HIGH);

    if let Some(title) = read_title(file_data, rom_start + TITLE_OFFSET, TITLE_SIZE) {
        result.description = format!("{}, title: \"{}\"", result.description, title);
    }

    Ok(result)
}

/// Validate a Game Boy Advance ROM signature
pub fn gba_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    const TITLE_OFFSET: usize = 0xA0;
    const TITLE_SIZE: usize = 12;

    let mut result = rom(offset, GBA_DESCRIPTION, CONFIDENCE_HIGH);

    if let Some(title) = read_title(file_data, offset + TITLE_OFFSET, TITLE_SIZE) {
        result.description = format!("{}, title: \"{}\"", result.description, title);
    }

    Ok(result)
}

/// Validate a Mega Drive ROM signature
pub fn megadrive_parser(
    file_data: &[u8],
    offset: usize,
) -> Result<SignatureResult, SignatureError> {
    // The console name is followed by the name of the system, and later by the game's own name
    const SYSTEM_NAME_SIZE: usize = 16;
    const DOMESTIC_NAME_OFFSET: usize = 0x120;
    const DOMESTIC_NAME_SIZE: usize = 48;

    if offset < MEGADRIVE_MAGIC_OFFSET {
        return Err(SignatureError);
    }

    let rom_start = offset - MEGADRIVE_MAGIC_OFFSET;

    // The system name is printable text, which is what tells this from any other "SEGA"
    let system_name = match read_title(file_data, offset, SYSTEM_NAME_SIZE) {
        Some(system_name) => system_name,
        None => return Err(SignatureError),
    };

    let mut result = rom(rom_start, MEGADRIVE_DESCRIPTION, CONFIDENCE_MEDIUM);
    result.description = format!("{}, system: \"{}\"", result.description, system_name);

    if let Some(title) = read_title(
        file_data,
        rom_start + DOMESTIC_NAME_OFFSET,
        DOMESTIC_NAME_SIZE,
    ) {
        result.description = format!("{}, title: \"{}\"", result.description, title);
    }

    Ok(result)
}

/// Validate a Nintendo DS ROM signature
pub fn nds_parser(file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    // The logo sits this far into the header, which begins with the title of the game
    const LOGO_OFFSET: usize = 0xC0;
    const TITLE_SIZE: usize = 12;

    if offset < LOGO_OFFSET {
        return Err(SignatureError);
    }

    let rom_start = offset - LOGO_OFFSET;
    let mut result = rom(rom_start, NDS_DESCRIPTION, CONFIDENCE_HIGH);

    if let Some(title) = read_title(file_data, rom_start, TITLE_SIZE) {
        result.description = format!("{}, title: \"{}\"", result.description, title);
    }

    Ok(result)
}

/// Validate an Xbox executable signature
pub fn xbe_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(rom(offset, XBE_DESCRIPTION, CONFIDENCE_MEDIUM))
}

/// Validate an Xbox XIP signature
pub fn xip_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(rom(offset, XIP_DESCRIPTION, CONFIDENCE_MEDIUM))
}

/// Validate an Xbox XTF signature
pub fn xtf_parser(_file_data: &[u8], offset: usize) -> Result<SignatureResult, SignatureError> {
    Ok(rom(offset, XTF_DESCRIPTION, CONFIDENCE_MEDIUM))
}

/// None of these headers describes the length of the image, so none of them reports a size
fn rom(offset: usize, description: &str, confidence: u8) -> SignatureResult {
    SignatureResult {
        offset,
        description: description.to_string(),
        confidence,
        ..Default::default()
    }
}

/// Read a title field, which is printable text padded with NULLs or spaces
fn read_title(file_data: &[u8], offset: usize, size: usize) -> Option<String> {
    let title = get_cstring(file_data.get(offset..offset + size)?);

    if title.is_empty() || !title.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }

    Some(title.trim().to_string())
}
