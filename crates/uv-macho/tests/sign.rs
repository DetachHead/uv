use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::process::Command;

use anyhow::{Context, Result};
use goblin::mach::MachO;
use goblin::mach::load_command::{CommandVariant, LC_ID_DYLIB};
use scroll::{BE, LE, Pread};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use uv_macho::{adhoc_sign, set_install_name};

const ARM64: &[u8] = include_bytes!("fixtures/arm64.dylib");
const X86_64: &[u8] = include_bytes!("fixtures/x86_64.dylib");
const SIGNED: &[u8] = include_bytes!("fixtures/signed-arm64.dylib");

fn signature(image: &[u8]) -> Result<(usize, BTreeMap<u32, &[u8]>)> {
    let macho = MachO::parse_lossy(image, 0)?;
    let command = macho
        .load_commands
        .iter()
        .find_map(|command| {
            if let CommandVariant::CodeSignature(signature) = &command.command {
                Some(signature)
            } else {
                None
            }
        })
        .context("missing signature")?;

    let data = &image[command.dataoff as usize..][..command.datasize as usize];
    assert_eq!(data.pread_with::<u32>(0, BE)?, 0xfade_0cc0);

    let count = data.pread_with::<u32>(8, BE)? as usize;
    let mut blobs = BTreeMap::new();

    for index in 0..count {
        let slot = data.pread_with::<u32>(12 + index * 8, BE)?;
        let offset = data.pread_with::<u32>(16 + index * 8, BE)? as usize;
        let length = data.pread_with::<u32>(offset + 4, BE)? as usize;
        blobs.insert(slot, &data[offset..offset + length]);
    }

    Ok((command.dataoff as usize, blobs))
}

fn verify_hashes(image: &[u8]) -> Result<()> {
    let (limit, blobs) = signature(image)?;
    let parsed = MachO::parse_lossy(image, 0)?;
    let mut info_plist = None;

    for segment in &parsed.segments {
        for (section, data) in segment.sections()? {
            if section.name()? == "__info_plist" {
                info_plist = Some(data);
            }
        }
    }

    for (&slot, directory) in &blobs {
        if slot != 0 && slot != 0x1000 {
            continue;
        }

        let hash_size = usize::from(directory[36]);
        let hash = |data: &[u8]| -> Vec<u8> {
            if directory[37] == 1 {
                Sha1::digest(data).to_vec()
            } else {
                Sha256::digest(data).to_vec()
            }
        };

        let offset = directory.pread_with::<u32>(16, BE)? as usize;
        let count = directory.pread_with::<u32>(28, BE)? as usize;
        assert_eq!(directory.pread_with::<u32>(32, BE)? as usize, limit);
        assert_eq!(count, limit.div_ceil(4096));
        assert_eq!(directory.len(), offset + count * hash_size);

        for (index, page) in image[..limit].chunks(4096).enumerate() {
            assert_eq!(
                &directory[offset + index * hash_size..][..hash_size],
                hash(page)
            );
        }

        let specials = directory.pread_with::<u32>(24, BE)? as usize;

        for special in 1..=specials {
            let actual = &directory[offset - special * hash_size..][..hash_size];
            if let Some(data) = blobs.get(&u32::try_from(special)?) {
                assert_eq!(actual, hash(data));
            } else if special == 1
                && let Some(info_plist) = info_plist
            {
                assert_eq!(actual, hash(info_plist));
            } else {
                assert_eq!(actual, vec![0; hash_size]);
            }
        }
    }

    Ok(())
}

#[test]
fn edit_and_sign() -> Result<()> {
    let mut summary = Vec::new();

    for (architecture, fixture) in [("arm64", ARM64), ("x86_64", X86_64), ("signed", SIGNED)] {
        for name in [
            b"x".as_slice(),
            b"/a/longer/install/directory/libfixture.dylib",
        ] {
            let output = set_install_name(fixture, name, b"fixture")?;
            let parsed = MachO::parse(&output, 0)?;
            assert_eq!(parsed.name.map(str::as_bytes), Some(name));

            verify_hashes(&output)?;
            assert_eq!(set_install_name(&output, name, b"ignored")?, output);

            for segment in &MachO::parse(fixture, 0)?.segments {
                for (section, data) in segment.sections()? {
                    assert_eq!(&output[section.offset as usize..][..data.len()], data);
                }
            }

            let (_, blobs) = signature(&output)?;
            summary.push(format!(
                "{architecture}: {}: slots {:?}",
                String::from_utf8_lossy(name),
                blobs.keys().collect::<Vec<_>>()
            ));
        }
    }

    insta::assert_snapshot!(summary.join("\n"), @r"
    arm64: x: slots [0, 2, 65536]
    arm64: /a/longer/install/directory/libfixture.dylib: slots [0, 2, 65536]
    x86_64: x: slots [0, 2, 4096, 65536]
    x86_64: /a/longer/install/directory/libfixture.dylib: slots [0, 2, 4096, 65536]
    signed: x: slots [0, 2, 5, 7, 65536]
    signed: /a/longer/install/directory/libfixture.dylib: slots [0, 2, 5, 7, 65536]
    ");

    Ok(())
}

#[test]
fn preserve_metadata() -> Result<()> {
    let output = set_install_name(SIGNED, b"/libfixture.dylib", b"ignored")?;
    let (_, before) = signature(SIGNED)?;
    let (_, after) = signature(&output)?;

    for slot in [2, 5, 7] {
        assert_eq!(
            before.get(&slot).context("original metadata")?,
            after.get(&slot).context("preserved metadata")?
        );
    }

    let original = before.get(&0).context("original directory")?;
    let directory = after.get(&0).context("new directory")?;
    assert_eq!(
        directory.pread_with::<u32>(12, BE)?,
        original.pread_with::<u32>(12, BE)?
    );
    assert_eq!(
        directory.pread_with::<u32>(88, BE)?,
        original.pread_with::<u32>(88, BE)?
    );

    let identifier_offset = directory.pread_with::<u32>(20, BE)? as usize;
    insta::assert_snapshot!(
        String::from_utf8_lossy(
            directory[identifier_offset..]
                .split(|byte| *byte == 0)
                .next()
                .context("identifier")?
        ),
        @"org.astral.uv.fixture"
    );

    verify_hashes(&output)?;

    Ok(())
}

#[test]
fn unsupported_signature_metadata() -> Result<()> {
    let (offset, _) = signature(SIGNED)?;
    let mut image = SIGNED.to_vec();

    // Change the requirements slot to an unsupported launch-constraint slot.
    let count = image.pread_with::<u32>(offset + 8, BE)? as usize;

    for index in 0..count {
        let slot = offset + 12 + index * 8;
        if image.pread_with::<u32>(slot, BE)? == 2 {
            image[slot..slot + 4].copy_from_slice(&8u32.to_be_bytes());
        }
    }
    insta::assert_snapshot!(
        set_install_name(&image, b"name", b"fixture").expect_err("unknown metadata"),
        @"Unsupported Mach-O: unavailable or unsupported special-slot data"
    );

    Ok(())
}

#[test]
fn malformed_signatures() -> Result<()> {
    let (signature_offset, _) = signature(SIGNED)?;
    let directory_offset =
        signature_offset + SIGNED.pread_with::<u32>(signature_offset + 16, BE)? as usize;
    let mut failures = Vec::new();

    for (description, offset, value) in [
        ("blob count", signature_offset + 8, u32::MAX),
        ("blob offset", signature_offset + 16, 0),
        ("duplicate slot", signature_offset + 20, 0),
        ("version", directory_offset + 8, u32::MAX),
        ("flags", directory_offset + 12, u32::MAX),
        ("identifier", directory_offset + 20, 0),
        ("special slots", directory_offset + 24, u32::MAX),
        ("page count", directory_offset + 28, u32::MAX),
        ("code limit", directory_offset + 32, 0),
        ("scatter", directory_offset + 44, 96),
    ] {
        let mut image = SIGNED.to_vec();
        image[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        failures.push(format!(
            "{description}: {}",
            set_install_name(&image, b"name", b"fixture").expect_err("invalid signature")
        ));
    }

    let parsed = MachO::parse(SIGNED, 0)?;
    let linkedit = parsed
        .load_commands
        .iter()
        .find(|command| {
            if let CommandVariant::Segment64(segment) = &command.command {
                segment.segname.starts_with(b"__LINKEDIT\0")
            } else {
                false
            }
        })
        .context("linkedit")?;

    let mut trailing = SIGNED.to_vec();
    let filesize = trailing.pread_with::<u64>(linkedit.offset + 48, LE)? + 1;
    trailing[linkedit.offset + 48..linkedit.offset + 56].copy_from_slice(&filesize.to_le_bytes());
    trailing.push(1);
    failures.push(format!(
        "trailing data: {}",
        set_install_name(&trailing, b"name", b"fixture").expect_err("trailing data")
    ));

    insta::assert_snapshot!(failures.join("\n"));

    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn macos_verification() -> Result<()> {
    let temporary = tempfile::tempdir()?;

    for (name, fixture, native) in [
        ("arm64", ARM64, cfg!(target_arch = "aarch64")),
        ("x86_64", X86_64, cfg!(target_arch = "x86_64")),
        ("signed", SIGNED, cfg!(target_arch = "aarch64")),
    ] {
        let path = temporary.path().join(format!("{name}.dylib"));

        // A large identifier forces __LINKEDIT to grow by multiple virtual pages.
        let identifier = vec![b'x'; 25000];
        let output = set_install_name(fixture, path.as_os_str().as_encoded_bytes(), &identifier)?;
        fs_err::write(&path, output)?;

        let verification = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict"])
            .arg(&path)
            .output()?;
        assert!(
            verification.status.success(),
            "{}",
            String::from_utf8_lossy(&verification.stderr)
        );
        if native {
            let load = Command::new("/usr/bin/python3")
                .args([
                    "-c",
                    "import ctypes, sys; assert ctypes.CDLL(sys.argv[1]).uv_macho_fixture() == 42",
                ])
                .arg(&path)
                .output()?;
            assert!(
                load.status.success(),
                "{}",
                String::from_utf8_lossy(&load.stderr)
            );
        }
    }

    Ok(())
}

#[test]
fn sign_without_editing() -> Result<()> {
    for image in [ARM64, X86_64, SIGNED] {
        let signed = adhoc_sign(image, b"fixture")?;
        verify_hashes(&signed)?;
        assert_eq!(adhoc_sign(&signed, b"ignored")?, signed);
    }

    Ok(())
}

#[test]
fn invalid_identifier() {
    insta::allow_duplicates! {
        for identifier in [b"".as_slice(), b"invalid\0identifier"] {
            insta::assert_snapshot!(
                adhoc_sign(ARM64, identifier).expect_err("invalid identifier"),
                @"The signing identifier must be nonempty and contain no NUL bytes"
            );
        }
    }
}

#[test]
fn non_utf8_name() -> Result<()> {
    let name = b"/non-utf8-\xff/libfixture.dylib";
    let output = set_install_name(ARM64, name, b"fixture")?;
    let parsed = MachO::parse_lossy(&output, 0)?;
    let command = parsed
        .load_commands
        .iter()
        .find(|command| command.command.cmd() == LC_ID_DYLIB)
        .context("ID command")?;
    assert_eq!(&output[command.offset + 24..][..name.len()], name);
    assert_eq!(set_install_name(&output, name, b"fixture")?, output);

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
        first_section - 32 - parsed.header.sizeofcmds as usize + command.command.cmdsize() - 16;
    let name = vec![b'x'; available - 25];
    let output = set_install_name(ARM64, &name, b"fixture")?;

    verify_hashes(&output)?;

    let too_long = vec![b'x'; name.len() + 1];
    insta::assert_snapshot!(
        set_install_name(ARM64, &too_long, b"fixture").expect_err("padding exhausted"),
        @"Not enough Mach-O header padding for the install name and code signature"
    );

    Ok(())
}
