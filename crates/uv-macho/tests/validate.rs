use anyhow::Result;

use uv_macho::validate;

const ARM64: &[u8] = include_bytes!("fixtures/arm64.dylib");
const X86_64: &[u8] = include_bytes!("fixtures/x86_64.dylib");
const SIGNED: &[u8] = include_bytes!("fixtures/signed-arm64.dylib");

#[test]
fn validate_dylibs() -> Result<()> {
    for image in [ARM64, X86_64, SIGNED] {
        validate(image)?;
    }

    Ok(())
}

#[test]
fn malformed_inputs() {
    let mut failures = Vec::new();

    for (description, offset, value) in [
        ("fat", 0, 0xbeba_feca),
        ("32-bit", 0, 0xfeed_face),
        ("swapped", 0, 0xcffa_edfe),
        ("executable", 12, 2),
        ("command count", 16, u32::MAX),
        ("command size", 36, 0),
        ("command alignment", 36, 9),
        ("segment overlap", 72, 1),
    ] {
        let mut bytes = ARM64.to_vec();
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let error = validate(&bytes).expect_err("invalid fixture");
        failures.push(format!("{description}: {error}"));
    }

    insta::assert_snapshot!(failures.join("\n"));

    // Every truncated prefix must fail without panicking, including signature metadata.

    for end in 0..SIGNED.len() {
        assert!(validate(&SIGNED[..end]).is_err());
    }
}
