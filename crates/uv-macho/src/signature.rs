//! Embedded signatures use big-endian integers, independently of Mach-O endianness.
//! Format definitions: <https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h>.

use std::collections::BTreeMap;

use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::Error;
use crate::bytes::{be32, be64, c_string, put_be32, put_be64, range, u32_size};

const SUPERBLOB: u32 = 0xfade_0cc0;
const CODE_DIRECTORY: u32 = 0xfade_0c02;
const REQUIREMENTS: u32 = 0xfade_0c01;
const ENTITLEMENTS: u32 = 0xfade_7171;
const DER_ENTITLEMENTS: u32 = 0xfade_7172;
const BLOB_WRAPPER: u32 = 0xfade_0b01;
const CS_ADHOC: u32 = 2;
const CS_LINKER_SIGNED: u32 = 0x20000;
const PAGE_SIZE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Metadata {
    identifier: Vec<u8>,
    flags: u32,
    runtime: u32,
    exec_flags: u64,
    components: BTreeMap<u32, Vec<u8>>,
}

impl Metadata {
    pub(crate) fn read(
        signature: Option<&[u8]>,
        identifier: &[u8],
        code_limit: usize,
        info_plist: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut metadata = Self {
            identifier: identifier.to_vec(),
            flags: CS_ADHOC,
            runtime: 0,
            exec_flags: 0,
            components: BTreeMap::new(),
        };

        if let Some(signature) = signature {
            let signature = blob(signature, SUPERBLOB)?;
            let count = be32(signature, 8)? as usize;
            let index_end = range(
                12,
                count.checked_mul(8).ok_or(Error::TooLarge)?,
                signature.len(),
            )?
            .end;

            let mut entries = BTreeMap::new();
            let mut regions = Vec::new();

            for index in 0..count {
                let slot = be32(signature, 12 + index * 8)?;
                let offset = be32(signature, 16 + index * 8)? as usize;
                let header = range(offset, 8, signature.len())?;
                let size = be32(signature, offset + 4)? as usize;
                let region = range(offset, size, signature.len())?;
                if offset < index_end || region.end < header.end {
                    return Err(Error::Malformed("invalid signature blob range"));
                }

                if entries.insert(slot, &signature[region.clone()]).is_some() {
                    return Err(Error::Malformed("duplicate signature slot"));
                }
                regions.push(region);
            }

            regions.sort_unstable_by_key(|region| region.start);
            if regions.windows(2).any(|pair| pair[0].end > pair[1].start) {
                return Err(Error::Malformed("overlapping signature blobs"));
            }

            if !entries.contains_key(&0) {
                return Err(Error::Malformed("missing primary CodeDirectory"));
            }

            let mut directory = None;

            for (&slot, &data) in &entries {
                match slot {
                    0 | 0x1000..=0x1004 => {
                        let parsed = Self::directory(data, code_limit, info_plist, &entries)?;
                        if let Some(previous) = &directory
                            && previous != &parsed
                        {
                            return Err(Error::Unsupported("conflicting CodeDirectory metadata"));
                        }

                        directory = Some(parsed);
                    }
                    2 => {
                        blob(data, REQUIREMENTS)?;
                    }
                    5 => {
                        blob(data, ENTITLEMENTS)?;
                    }
                    7 => {
                        blob(data, DER_ENTITLEMENTS)?;
                    }
                    0x10000 => {
                        blob(data, BLOB_WRAPPER)?;
                    }
                    _ => return Err(Error::Unsupported("unknown code-signing slot")),
                }
            }

            metadata = directory.ok_or(Error::Malformed("signature has no CodeDirectory"))?;

            for slot in [2, 5, 7] {
                if let Some(data) = entries.get(&slot) {
                    metadata.components.insert(slot, data.to_vec());
                }
            }
        }

        // An empty requirements set and CMS wrapper match Apple's bare ad-hoc signatures.
        metadata.components.entry(2).or_insert_with(|| {
            let mut bytes = vec![0; 12];
            put_be32(&mut bytes, 0, REQUIREMENTS);
            put_be32(&mut bytes, 4, 12);

            bytes
        });

        Ok(metadata)
    }

    fn directory(
        data: &[u8],
        code_limit: usize,
        info_plist: Option<&[u8]>,
        entries: &BTreeMap<u32, &[u8]>,
    ) -> Result<Self, Error> {
        let data = blob(data, CODE_DIRECTORY)?;
        let version = be32(data, 8)?;
        let flags = be32(data, 12)?;
        if flags & !0x0003_3f02 != 0 {
            return Err(Error::Unsupported("CodeDirectory flags"));
        }

        let fixed_size = match version {
            0x20000..=0x200ff => 44,
            0x20100..=0x201ff => 48,
            0x20200..=0x202ff => 52,
            0x20300..=0x203ff => 64,
            0x20400..=0x204ff => 88,
            0x20500..=0x205ff => 96,
            0x20600 => 108,
            _ => return Err(Error::Unsupported("CodeDirectory version")),
        };
        range(0, fixed_size, data.len())?;
        if (version >= 0x20100 && be32(data, 44)? != 0)
            || (version >= 0x20500 && be32(data, 92)? != 0)
            || (version >= 0x20600 && data[96..108].iter().any(|byte| *byte != 0))
            || data[38] != 0
        {
            return Err(Error::Unsupported(
                "scatter, pre-encryption, linkage, or platform signature",
            ));
        }

        let identifier_offset = be32(data, 20)? as usize;
        if identifier_offset < fixed_size {
            return Err(Error::Malformed("invalid signing identifier offset"));
        }

        let identifier = c_string(data, identifier_offset)?;
        if identifier.is_empty() {
            return Err(Error::Malformed("empty signing identifier"));
        }

        let mut strings_end = identifier_offset + identifier.len() + 1;
        if version >= 0x20200 {
            let team_offset = be32(data, 48)? as usize;
            if team_offset != 0 {
                if team_offset < strings_end {
                    return Err(Error::Malformed("invalid signing team offset"));
                }
                strings_end = team_offset + c_string(data, team_offset)?.len() + 1;
            }
        }

        let limit = if version >= 0x20300 && be64(data, 56)? != 0 {
            be64(data, 56)?
        } else {
            u64::from(be32(data, 32)?)
        };

        if limit != code_limit as u64 {
            return Err(Error::Unsupported(
                "CodeDirectory does not cover the complete image",
            ));
        }

        let hash_size = usize::from(data[36]);
        let expected_hash_size = match data[37] {
            1 | 3 => 20,
            2 => 32,
            4 => 48,
            _ => return Err(Error::Unsupported("CodeDirectory hash algorithm")),
        };

        if hash_size != expected_hash_size {
            return Err(Error::Malformed("invalid CodeDirectory hash size"));
        }

        let special_count = be32(data, 24)? as usize;
        let code_count = be32(data, 28)? as usize;
        let hash_offset = be32(data, 16)? as usize;
        if special_count > 7 {
            return Err(Error::Unsupported("CodeDirectory special slots"));
        }

        let special_start = hash_offset
            .checked_sub(special_count * hash_size)
            .ok_or(Error::Malformed("invalid special-slot hash range"))?;
        if special_start < strings_end {
            return Err(Error::Malformed("hashes overlap CodeDirectory metadata"));
        }

        range(
            hash_offset,
            code_count.checked_mul(hash_size).ok_or(Error::TooLarge)?,
            data.len(),
        )?;

        let page_size = if data[39] == 0 {
            code_limit.max(1)
        } else {
            1usize
                .checked_shl(u32::from(data[39]))
                .ok_or(Error::TooLarge)?
        };

        if code_count != code_limit.div_ceil(page_size) {
            return Err(Error::Malformed("invalid CodeDirectory page count"));
        }

        for slot in 1..=special_count {
            let hash = &data[hash_offset - slot * hash_size..hash_offset - (slot - 1) * hash_size];
            if hash.iter().all(|byte| *byte == 0) {
                continue;
            }

            match slot {
                1 if info_plist.is_some() => {}
                2 | 5 | 7 if entries.contains_key(&u32_size(slot)?) => {}
                _ => {
                    return Err(Error::Unsupported(
                        "unavailable or unsupported special-slot data",
                    ));
                }
            }
        }

        Ok(Self {
            identifier: identifier.to_vec(),
            flags: (flags & !CS_LINKER_SIGNED) | CS_ADHOC,
            runtime: if version >= 0x20500 {
                be32(data, 88)?
            } else {
                0
            },
            // The main-binary flag is not applicable to a dylib.
            exec_flags: if version >= 0x20400 {
                be64(data, 80)? & !1
            } else {
                0
            },
            components: BTreeMap::new(),
        })
    }

    pub(crate) fn build(
        &self,
        source: &[u8],
        text: (u64, u64),
        info_plist: Option<&[u8]>,
        legacy: bool,
        hashes: bool,
    ) -> Result<Vec<u8>, Error> {
        let mut entries = self.components.clone();
        if legacy {
            entries.insert(
                0,
                self.code_directory(source, text, info_plist, Hash::Sha1, hashes)?,
            );
            entries.insert(
                0x1000,
                self.code_directory(source, text, info_plist, Hash::Sha256, hashes)?,
            );
        } else {
            entries.insert(
                0,
                self.code_directory(source, text, info_plist, Hash::Sha256, hashes)?,
            );
        }

        let mut wrapper = vec![0; 8];
        put_be32(&mut wrapper, 0, BLOB_WRAPPER);
        put_be32(&mut wrapper, 4, 8);
        entries.insert(0x10000, wrapper);

        let mut output = vec![0; 12 + entries.len() * 8];
        put_be32(&mut output, 0, SUPERBLOB);
        put_be32(&mut output, 8, u32_size(entries.len())?);

        for (index, (slot, data)) in entries.into_iter().enumerate() {
            let offset = u32_size(output.len())?;
            put_be32(&mut output, 12 + index * 8, slot);
            put_be32(&mut output, 16 + index * 8, offset);
            output.extend(data);
        }

        let size = u32_size(output.len())?;
        put_be32(&mut output, 4, size);

        Ok(output)
    }

    fn code_directory(
        &self,
        source: &[u8],
        text: (u64, u64),
        info_plist: Option<&[u8]>,
        hash: Hash,
        hashes: bool,
    ) -> Result<Vec<u8>, Error> {
        let fixed_size = if self.runtime == 0 { 88 } else { 96 };
        let special_count = self.components.keys().copied().max().unwrap_or(0) as usize;
        let code_count = source.len().div_ceil(PAGE_SIZE);
        let hash_offset = self
            .identifier
            .len()
            .checked_add(fixed_size + 1 + special_count * hash.size())
            .ok_or(Error::TooLarge)?;
        let length = hash_offset
            .checked_add(code_count.checked_mul(hash.size()).ok_or(Error::TooLarge)?)
            .ok_or(Error::TooLarge)?;
        let length_u32 = u32_size(length)?;

        let mut output = vec![0; length];
        put_be32(&mut output, 0, CODE_DIRECTORY);
        put_be32(&mut output, 4, length_u32);
        put_be32(
            &mut output,
            8,
            if self.runtime == 0 { 0x20400 } else { 0x20500 },
        );
        put_be32(&mut output, 12, self.flags);

        put_be32(&mut output, 16, u32_size(hash_offset)?);
        put_be32(&mut output, 20, u32_size(fixed_size)?);
        put_be32(&mut output, 24, u32_size(special_count)?);
        put_be32(&mut output, 28, u32_size(code_count)?);
        put_be32(&mut output, 32, u32_size(source.len())?);

        output[36] = match hash {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
        };
        output[37] = match hash {
            Hash::Sha1 => 1,
            Hash::Sha256 => 2,
        };
        output[39] = 12;

        put_be64(&mut output, 64, text.0);
        put_be64(&mut output, 72, text.1);
        put_be64(&mut output, 80, self.exec_flags);
        if self.runtime != 0 {
            put_be32(&mut output, 88, self.runtime);
        }

        output[fixed_size..fixed_size + self.identifier.len()].copy_from_slice(&self.identifier);

        if hashes {
            for (&slot, data) in &self.components {
                let offset = hash_offset - slot as usize * hash.size();
                hash.write(data, &mut output[offset..offset + hash.size()]);
            }

            if let Some(info_plist) = info_plist {
                hash.write(
                    info_plist,
                    &mut output[hash_offset - hash.size()..hash_offset],
                );
            }

            for (page, destination) in source
                .chunks(PAGE_SIZE)
                .zip(output[hash_offset..].chunks_mut(hash.size()))
            {
                hash.write(page, destination);
            }
        }

        Ok(output)
    }
}

fn blob(data: &[u8], magic: u32) -> Result<&[u8], Error> {
    if be32(data, 0)? != magic {
        return Err(Error::Malformed("unexpected code-signing blob magic"));
    }

    let length = be32(data, 4)? as usize;
    if length < 8 {
        return Err(Error::Malformed("invalid code-signing blob length"));
    }

    Ok(&data[range(0, length, data.len())?])
}

#[derive(Clone, Copy)]
enum Hash {
    Sha1,
    Sha256,
}

impl Hash {
    fn size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    fn write(self, data: &[u8], destination: &mut [u8]) {
        match self {
            Self::Sha1 => destination.copy_from_slice(&Sha1::digest(data)),
            Self::Sha256 => destination.copy_from_slice(&Sha256::digest(data)),
        }
    }
}
