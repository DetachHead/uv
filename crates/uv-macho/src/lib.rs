//! Validation of thin 64-bit macOS Mach-O dylibs.

mod bytes;
mod macho;

/// An error validating a Mach-O image.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to parse Mach-O: {0}")]
    Parse(#[from] goblin::error::Error),
    #[error("Failed to read Mach-O: {0}")]
    Read(#[from] scroll::Error),
    #[error("Malformed Mach-O: {0}")]
    Malformed(&'static str),
    #[error("Unsupported Mach-O: {0}")]
    Unsupported(&'static str),
    #[error("Mach-O image exceeds the supported size")]
    TooLarge,
}

/// Validate the structure of a thin, little-endian ARM64 or `x86_64` dylib.
///
/// Checks load commands, segment and section boundaries, and the location of any
/// embedded signature. This does not verify code-signing hashes or certificates.
pub fn validate(image: &[u8]) -> Result<(), Error> {
    macho::validate(image)
}
