use std::ops::Range;

use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::constants::{S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL, S_ZEROFILL, SECTION_TYPE};
use goblin::mach::header::{Header64, MH_DYLIB, MH_MAGIC_64};
use goblin::mach::load_command::{
    CommandVariant, LC_CODE_SIGNATURE, LoadCommand, Section64, SegmentCommand64,
};
use scroll::{LE, Pread};

use crate::Error;
use crate::bytes::{align, c_string, put_le32, put_le64, range, u32_size, usize_size};
use crate::signature::Metadata;

const HEADER_SIZE: usize = 32;

struct Command<'a> {
    data: &'a [u8],
    parsed: CommandVariant,
}

pub(crate) struct Layout<'a> {
    commands: Vec<Command<'a>>,
    install_id: usize,
    command_end: usize,
    data_start: usize,
    code_limit: usize,
    signature: Option<Range<usize>>,
    signature_command: Option<usize>,
    text: SegmentCommand64,
    linkedit: SegmentCommand64,
    linkedit_index: usize,
    info_plist: Option<&'a [u8]>,
    minimum_version: Option<u32>,
    cputype: u32,
}

pub(crate) fn parse(image: &[u8]) -> Result<Layout<'_>, Error> {
    let header: Header64 = image.pread_with(0, LE)?;
    if header.magic != MH_MAGIC_64 || header.filetype != MH_DYLIB {
        return Err(Error::Unsupported(
            "expected a thin little-endian 64-bit dylib",
        ));
    }

    match header.cputype {
        CPU_TYPE_ARM64 | CPU_TYPE_X86_64 => {}
        _ => return Err(Error::Unsupported("CPU architecture")),
    }

    let command_end = range(HEADER_SIZE, header.sizeofcmds as usize, image.len())?.end;
    if header.ncmds as usize > header.sizeofcmds as usize / 8 {
        return Err(Error::Malformed("invalid load-command count"));
    }

    let mut commands = Vec::new();
    let mut offset = HEADER_SIZE;

    for _ in 0..header.ncmds {
        range(offset, 8, command_end)?;
        let size = image.pread_with::<u32>(offset + 4, LE)? as usize;
        if size < 8 || !size.is_multiple_of(8) {
            return Err(Error::Malformed("invalid load-command size"));
        }

        let data = &image[range(offset, size, command_end)?];
        let parsed = LoadCommand::parse(data, &mut 0, LE)?.command;
        commands.push(Command { data, parsed });
        offset += size;
    }

    if offset != command_end {
        return Err(Error::Malformed("load commands do not fill sizeofcmds"));
    }

    let mut install_id = None;
    let mut signature = None;
    let mut signature_command = None;
    let mut text = None;
    let mut linkedit = None;
    let mut info_plist = None;
    let mut minimum_version = None;
    let mut segments = Vec::new();
    let mut virtual_segments = Vec::new();
    let mut sections = Vec::new();
    let mut references = Vec::new();
    let mut data_start = image.len();

    for (index, command) in commands.iter().enumerate() {
        if let CommandVariant::IdDylib(dylib) = &command.parsed {
            if install_id.replace(index).is_some() || dylib.dylib.name < 24 {
                return Err(Error::Malformed("invalid or duplicate LC_ID_DYLIB"));
            }
            c_string(command.data, dylib.dylib.name as usize)?;
        }

        if let CommandVariant::CodeSignature(data) = &command.parsed {
            if signature_command.replace(index).is_some() || command.data.len() != 16 {
                return Err(Error::Malformed("invalid or duplicate LC_CODE_SIGNATURE"));
            }

            if data.datasize > 0 {
                signature = Some(range(
                    data.dataoff as usize,
                    data.datasize as usize,
                    image.len(),
                )?);
            }
        }

        if let CommandVariant::VersionMinMacosx(version) = &command.parsed {
            if minimum_version.replace(version.version).is_some() {
                return Err(Error::Malformed("multiple deployment targets"));
            }
        }

        if let CommandVariant::BuildVersion(version) = &command.parsed {
            if version.platform != 1 {
                return Err(Error::Unsupported("non-macOS build platform"));
            }

            if minimum_version.replace(version.minos).is_some() {
                return Err(Error::Malformed("multiple deployment targets"));
            }
        }

        if let CommandVariant::Segment64(segment) = &command.parsed {
            let segment_range = range(
                usize_size(segment.fileoff)?,
                usize_size(segment.filesize)?,
                image.len(),
            )?;
            if segment.filesize > segment.vmsize {
                return Err(Error::Malformed("segment filesize exceeds vmsize"));
            }

            let virtual_end = segment
                .vmaddr
                .checked_add(segment.vmsize)
                .ok_or(Error::TooLarge)?;
            if segment.vmsize > 0 {
                virtual_segments.push((segment.vmaddr, virtual_end));
            }

            if !segment_range.is_empty() {
                if segment_range.start > 0 {
                    data_start = data_start.min(segment_range.start);
                }
                segments.push(segment_range.clone());
            }

            if segment.segname == *b"__TEXT\0\0\0\0\0\0\0\0\0\0" {
                if text.replace(*segment).is_some()
                    || segment.fileoff != 0
                    || segment_range.end < command_end
                {
                    return Err(Error::Malformed("invalid or duplicate __TEXT segment"));
                }
            }

            if segment.segname == *b"__LINKEDIT\0\0\0\0\0\0" {
                if linkedit.replace((index, *segment)).is_some() || segment.nsects != 0 {
                    return Err(Error::Malformed("invalid or duplicate __LINKEDIT segment"));
                }
            }

            let section_bytes = (segment.nsects as usize)
                .checked_mul(80)
                .ok_or(Error::TooLarge)?;
            if range(72, section_bytes, command.data.len())?.end != command.data.len() {
                return Err(Error::Malformed("invalid segment section table"));
            }

            for section_index in 0..segment.nsects as usize {
                let section: Section64 = command.data.pread_with(72 + section_index * 80, LE)?;
                let section_end = section
                    .addr
                    .checked_add(section.size)
                    .ok_or(Error::TooLarge)?;
                if section.addr < segment.vmaddr || section_end > virtual_end {
                    return Err(Error::Malformed(
                        "section exceeds its segment's virtual address range",
                    ));
                }

                add_reference(
                    &mut references,
                    section.reloff,
                    u64::from(section.nreloc) * 8,
                    image.len(),
                )?;

                let section_type = section.flags & SECTION_TYPE;
                if section_type == S_ZEROFILL
                    || section_type == S_GB_ZEROFILL
                    || section_type == S_THREAD_LOCAL_ZEROFILL
                {
                    continue;
                }

                let section_range = range(
                    section.offset as usize,
                    usize_size(section.size)?,
                    image.len(),
                )?;
                if !section_range.is_empty() {
                    if section_range.start < command_end
                        || section_range.start < segment_range.start
                        || section_range.end > segment_range.end
                    {
                        return Err(Error::Malformed(
                            "section is outside its segment or overlaps load commands",
                        ));
                    }
                    data_start = data_start.min(section_range.start);
                    sections.push(section_range.clone());
                }

                if section.segname == *b"__TEXT\0\0\0\0\0\0\0\0\0\0"
                    && section.sectname == *b"__info_plist\0\0\0\0"
                {
                    if info_plist.replace(&image[section_range]).is_some() {
                        return Err(Error::Malformed("duplicate embedded Info.plist"));
                    }
                }
            }
        }

        file_references(&command.parsed, &mut references, image.len())?;
    }

    check_overlaps(&mut segments)?;
    check_overlaps(&mut sections)?;

    let install_id = install_id.ok_or(Error::Malformed("missing LC_ID_DYLIB"))?;
    let text = text.ok_or(Error::Malformed("missing __TEXT segment"))?;
    let (linkedit_index, linkedit) =
        linkedit.ok_or(Error::Malformed("missing __LINKEDIT segment"))?;

    virtual_segments.sort_unstable();
    if virtual_segments
        .windows(2)
        .any(|pair| pair[0].1 > pair[1].0)
        || virtual_segments
            .last()
            .is_none_or(|segment| segment.0 != linkedit.vmaddr)
    {
        return Err(Error::Unsupported(
            "overlapping virtual segments or nonterminal __LINKEDIT",
        ));
    }

    if usize_size(linkedit.fileoff + linkedit.filesize)? != image.len() {
        return Err(Error::Unsupported(
            "__LINKEDIT is not the final file segment",
        ));
    }

    let code_limit = if let Some(signature) = &signature {
        if signature.start < usize_size(linkedit.fileoff)?
            || !signature.start.is_multiple_of(16)
            || image.len() - signature.end > 15
            || image[signature.end..].iter().any(|byte| *byte != 0)
        {
            return Err(Error::Unsupported(
                "code signature is not at the end of __LINKEDIT",
            ));
        }

        signature.start
    } else {
        image.len()
    };

    for reference in &references {
        if reference.start < command_end || reference.end > code_limit {
            return Err(Error::Malformed(
                "file data overlaps load commands or the signature",
            ));
        }
        data_start = data_start.min(reference.start);
    }

    if sections.iter().any(|section| section.end > code_limit) {
        return Err(Error::Malformed("section overlaps the code signature"));
    }

    Ok(Layout {
        commands,
        install_id,
        command_end,
        data_start,
        code_limit,
        signature,
        signature_command,
        text,
        linkedit,
        linkedit_index,
        info_plist,
        minimum_version,
        cputype: header.cputype,
    })
}

pub(crate) fn replace_install_name(image: &[u8], name: &[u8]) -> Result<Vec<u8>, Error> {
    let layout = parse(image)?;
    let mut output = image[..HEADER_SIZE].to_vec();

    for (index, command) in layout.commands.iter().enumerate() {
        if index == layout.install_id {
            let size = align(name.len().checked_add(25).ok_or(Error::TooLarge)?, 8)?;
            let size_u32 = u32_size(size)?;

            let mut replacement = vec![0; size];
            replacement[..24].copy_from_slice(&command.data[..24]);
            put_le32(&mut replacement, 4, size_u32);
            put_le32(&mut replacement, 8, 24);
            replacement[24..24 + name.len()].copy_from_slice(name);

            output.extend(replacement);
        } else {
            output.extend_from_slice(command.data);
        }
    }

    replace_commands(image, output, &layout)
}

fn replace_commands(
    image: &[u8],
    mut output: Vec<u8>,
    layout: &Layout<'_>,
) -> Result<Vec<u8>, Error> {
    if output.len() > layout.data_start || output.len() > layout.code_limit {
        return Err(Error::InsufficientHeaderPadding);
    }

    if output.len() > layout.command_end
        && image[layout.command_end..output.len()]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(Error::InsufficientHeaderPadding);
    }

    let sizeofcmds = u32_size(output.len() - HEADER_SIZE)?;
    put_le32(&mut output, 20, sizeofcmds);
    output.resize(output.len().max(layout.command_end), 0);
    output.extend_from_slice(&image[output.len()..]);

    Ok(output)
}

pub(crate) fn adhoc_sign(image: &[u8], identifier: &[u8]) -> Result<Vec<u8>, Error> {
    let layout = parse(image)?;
    let metadata = Metadata::read(
        layout
            .signature
            .as_ref()
            .map(|region| &image[region.clone()]),
        identifier,
        layout.code_limit,
        layout.info_plist,
    )?;

    let command_offset = |index: usize| {
        HEADER_SIZE
            + layout.commands[..index]
                .iter()
                .map(|command| command.data.len())
                .sum::<usize>()
    };
    let linkedit_offset = command_offset(layout.linkedit_index);

    let (mut output, signature_offset) = if let Some(index) = layout.signature_command {
        (image.to_vec(), command_offset(index))
    } else {
        let mut commands = image[..layout.command_end].to_vec();
        let offset = commands.len();
        commands.resize(offset + 16, 0);
        put_le32(&mut commands, offset, LC_CODE_SIGNATURE);
        put_le32(&mut commands, offset + 4, 16);
        put_le32(&mut commands, 16, u32_size(layout.commands.len() + 1)?);

        (replace_commands(image, commands, &layout)?, offset)
    };

    output.truncate(layout.code_limit);
    let signature_start = align(output.len(), 16)?;
    output.resize(signature_start, 0);

    let legacy = layout
        .minimum_version
        .is_some_and(|version| version < 0x000a_0b04);
    let text_range = (layout.text.fileoff, layout.text.filesize);
    let signature_size = align(
        metadata
            .build(&output, text_range, layout.info_plist, legacy, false)?
            .len(),
        16,
    )?;
    let final_size = signature_start
        .checked_add(signature_size)
        .ok_or(Error::TooLarge)?;
    u32_size(final_size)?;

    // Finalize the load commands before hashing the image they describe.
    put_le32(
        &mut output,
        signature_offset + 8,
        u32_size(signature_start)?,
    );
    put_le32(
        &mut output,
        signature_offset + 12,
        u32_size(signature_size)?,
    );

    let linkedit_size = final_size
        .checked_sub(usize_size(layout.linkedit.fileoff)?)
        .ok_or(Error::Malformed("invalid __LINKEDIT offset"))?;
    put_le64(&mut output, linkedit_offset + 48, linkedit_size as u64);

    // __LINKEDIT must have enough virtual pages even when a replacement signature grows.
    let segment_alignment = match layout.cputype {
        CPU_TYPE_ARM64 => 16384,
        CPU_TYPE_X86_64 => 4096,
        _ => return Err(Error::Unsupported("CPU architecture")),
    };
    let virtual_size = layout
        .linkedit
        .vmsize
        .max(align(linkedit_size, segment_alignment)? as u64);
    layout
        .linkedit
        .vmaddr
        .checked_add(virtual_size)
        .ok_or(Error::TooLarge)?;
    put_le64(&mut output, linkedit_offset + 32, virtual_size);

    output.extend(metadata.build(&output, text_range, layout.info_plist, legacy, true)?);
    output.resize(final_size, 0);

    Ok(output)
}

fn check_overlaps(regions: &mut [Range<usize>]) -> Result<(), Error> {
    regions.sort_unstable_by_key(|region| region.start);
    if regions.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(Error::Malformed("overlapping file regions"));
    }

    Ok(())
}

fn add_reference(
    references: &mut Vec<Range<usize>>,
    offset: u32,
    size: u64,
    limit: usize,
) -> Result<(), Error> {
    if size > 0 {
        references.push(range(offset as usize, usize_size(size)?, limit)?);
    }

    Ok(())
}

fn file_references(
    command: &CommandVariant,
    references: &mut Vec<Range<usize>>,
    limit: usize,
) -> Result<(), Error> {
    match command {
        CommandVariant::Symtab(command) => {
            add_reference(
                references,
                command.symoff,
                u64::from(command.nsyms) * 16,
                limit,
            )?;

            add_reference(
                references,
                command.stroff,
                u64::from(command.strsize),
                limit,
            )?;
        }
        CommandVariant::Dysymtab(command) => {
            for (offset, count, size) in [
                (command.tocoff, command.ntoc, 8),
                (command.modtaboff, command.nmodtab, 56),
                (command.extrefsymoff, command.nextrefsyms, 4),
                (command.indirectsymoff, command.nindirectsyms, 4),
                (command.extreloff, command.nextrel, 8),
                (command.locreloff, command.nlocrel, 8),
            ] {
                add_reference(references, offset, u64::from(count) * size, limit)?;
            }
        }
        CommandVariant::DyldInfo(command) | CommandVariant::DyldInfoOnly(command) => {
            for (offset, size) in [
                (command.rebase_off, command.rebase_size),
                (command.bind_off, command.bind_size),
                (command.weak_bind_off, command.weak_bind_size),
                (command.lazy_bind_off, command.lazy_bind_size),
                (command.export_off, command.export_size),
            ] {
                add_reference(references, offset, u64::from(size), limit)?;
            }
        }
        CommandVariant::SegmentSplitInfo(command)
        | CommandVariant::FunctionStarts(command)
        | CommandVariant::DataInCode(command)
        | CommandVariant::DylibCodeSignDrs(command)
        | CommandVariant::LinkerOptimizationHint(command)
        | CommandVariant::DyldExportsTrie(command)
        | CommandVariant::DyldChainedFixups(command) => {
            add_reference(
                references,
                command.dataoff,
                u64::from(command.datasize),
                limit,
            )?;
        }
        CommandVariant::Segment64(_)
        | CommandVariant::IdDylib(_)
        | CommandVariant::CodeSignature(_)
        | CommandVariant::Uuid(_)
        | CommandVariant::LoadDylib(_)
        | CommandVariant::LoadWeakDylib(_)
        | CommandVariant::ReexportDylib(_)
        | CommandVariant::LoadUpwardDylib(_)
        | CommandVariant::LazyLoadDylib(_)
        | CommandVariant::Rpath(_)
        | CommandVariant::Routines64(_)
        | CommandVariant::VersionMinMacosx(_)
        | CommandVariant::BuildVersion(_)
        | CommandVariant::SourceVersion(_)
        | CommandVariant::SubFramework(_)
        | CommandVariant::SubUmbrella(_)
        | CommandVariant::SubClient(_)
        | CommandVariant::SubLibrary(_) => {}
        CommandVariant::Segment32(_)
        | CommandVariant::Symseg(_)
        | CommandVariant::Thread(_)
        | CommandVariant::Unixthread(_)
        | CommandVariant::LoadFvmlib(_)
        | CommandVariant::IdFvmlib(_)
        | CommandVariant::Ident(_)
        | CommandVariant::Fvmfile(_)
        | CommandVariant::Prepage(_)
        | CommandVariant::LoadDylinker(_)
        | CommandVariant::IdDylinker(_)
        | CommandVariant::PreboundDylib(_)
        | CommandVariant::Routines32(_)
        | CommandVariant::TwolevelHints(_)
        | CommandVariant::PrebindCksum(_)
        | CommandVariant::EncryptionInfo32(_)
        | CommandVariant::EncryptionInfo64(_)
        | CommandVariant::VersionMinIphoneos(_)
        | CommandVariant::DyldEnvironment(_)
        | CommandVariant::Main(_)
        | CommandVariant::FilesetEntry(_)
        | CommandVariant::VersionMinTvos(_)
        | CommandVariant::VersionMinWatchos(_)
        | CommandVariant::LinkerOption(_)
        | CommandVariant::Note(_)
        | CommandVariant::Unimplemented(_) => {
            return Err(Error::Unsupported("load command"));
        }
        _ => return Err(Error::Unsupported("load command")),
    }

    Ok(())
}
