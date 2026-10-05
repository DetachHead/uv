use anyhow::{Context, Result};
use goblin::mach::MachO;
use goblin::mach::load_command::LC_ID_DYLIB;

use uv_macho::replace_install_name;

const ARM64: &[u8] = include_bytes!("fixtures/arm64.dylib");
const X86_64: &[u8] = include_bytes!("fixtures/x86_64.dylib");
const SIGNED: &[u8] = include_bytes!("fixtures/signed-arm64.dylib");

#[test]
fn edit_install_name() -> Result<()> {
    for image in [ARM64, X86_64, SIGNED] {
        for name in [
            b"x".as_slice(),
            b"/a/longer/install/directory/libfixture.dylib",
        ] {
            let output = replace_install_name(image, name)?;
            let parsed = MachO::parse(&output, 0)?;
            assert_eq!(parsed.name.map(str::as_bytes), Some(name));
            assert_eq!(replace_install_name(&output, name)?, output);

            for segment in &MachO::parse(image, 0)?.segments {
                for (section, data) in segment.sections()? {
                    assert_eq!(&output[section.offset as usize..][..data.len()], data);
                }
            }
        }
    }

    Ok(())
}

#[test]
fn invalid_names() {
    insta::allow_duplicates! {
        for name in [b"".as_slice(), b"invalid\0name"] {
            insta::assert_snapshot!(
                replace_install_name(ARM64, name).expect_err("invalid name"),
                @"The install name must be nonempty and contain no NUL bytes"
            );
        }
    }
}

#[test]
fn non_utf8_name() -> Result<()> {
    let name = b"/non-utf8-\xff/libfixture.dylib";
    let output = replace_install_name(ARM64, name)?;
    let parsed = MachO::parse_lossy(&output, 0)?;
    let command = parsed
        .load_commands
        .iter()
        .find(|command| command.command.cmd() == LC_ID_DYLIB)
        .context("ID command")?;
    assert_eq!(&output[command.offset + 24..][..name.len()], name);
    assert_eq!(replace_install_name(&output, name)?, output);

    Ok(())
}

#[test]
fn header_padding() -> Result<()> {
    let parsed = MachO::parse(ARM64, 0)?;
    let first_section = parsed
        .segments
        .iter()
        .flat_map(|segment| segment.sections().into_iter().flatten())
        .map(|(section, _)| section.offset as usize)
        .min()
        .context("section")?;
    let command = parsed
        .load_commands
        .iter()
        .find(|command| command.command.cmd() == LC_ID_DYLIB)
        .context("ID command")?;

    let available =
        first_section - 32 - parsed.header.sizeofcmds as usize + command.command.cmdsize();
    let name = vec![b'x'; available - 25];
    let output = replace_install_name(ARM64, &name)?;

    uv_macho::validate(&output)?;

    let too_long = vec![b'x'; name.len() + 1];
    insta::assert_snapshot!(
        replace_install_name(ARM64, &too_long).expect_err("padding exhausted"),
        @"Not enough Mach-O header padding for the install name and code signature"
    );

    Ok(())
}
