//! Validation and install-name editing for thin 64-bit macOS Mach-O dylibs.

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
    #[error("Not enough Mach-O header padding for the install name and code signature")]
    InsufficientHeaderPadding,
    #[error("The install name must be nonempty and contain no NUL bytes")]
    InvalidName,
    #[error("Mach-O image exceeds the supported size")]
    TooLarge,
}

/// Validate the structure of a thin, little-endian ARM64 or `x86_64` dylib.
///
/// Checks load commands, segment and section boundaries, and the location of any
/// embedded signature. This does not verify code-signing hashes or certificates.
pub fn validate(image: &[u8]) -> Result<(), Error> {
    macho::parse(image).map(|_| ())
}

/// Replace a dylib's install name using existing header padding.
///
/// The input is never modified, and section data is never relocated. Names are
/// bytes so Unix paths need not be UTF-8. This invalidates any existing signature;
/// the returned image must be re-signed before loading it on macOS.
pub fn replace_install_name(image: &[u8], name: &[u8]) -> Result<Vec<u8>, Error> {
    if name.is_empty() || name.contains(&0) {
        return Err(Error::InvalidName);
    }

    macho::replace_install_name(image, name)
}
