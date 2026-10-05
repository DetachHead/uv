use std::ops::Range;

use goblin::mach::constants::cputype::{CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use goblin::mach::constants::{S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL, S_ZEROFILL, SECTION_TYPE};
use goblin::mach::header::{Header64, MH_DYLIB, MH_MAGIC_64};
use goblin::mach::load_command::{CommandVariant, LoadCommand, Section64};
use scroll::{LE, Pread};

use crate::Error;
use crate::bytes::{c_string, range, usize_size};

const HEADER_SIZE: usize = 32;

struct Command<'a> {
    data: &'a [u8],
    parsed: CommandVariant,
}

pub(crate) fn validate(image: &[u8]) -> Result<(), Error> {
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

    install_id.ok_or(Error::Malformed("missing LC_ID_DYLIB"))?;
    text.ok_or(Error::Malformed("missing __TEXT segment"))?;
    let (_, linkedit) = linkedit.ok_or(Error::Malformed("missing __LINKEDIT segment"))?;

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
    }

    if sections.iter().any(|section| section.end > code_limit) {
        return Err(Error::Malformed("section overlaps the code signature"));
    }

    Ok(())
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
