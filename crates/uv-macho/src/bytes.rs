use std::ops::Range;

use crate::Error;

pub(crate) fn range(offset: usize, size: usize, limit: usize) -> Result<Range<usize>, Error> {
    let end = offset.checked_add(size).ok_or(Error::TooLarge)?;
    if end > limit {
        return Err(Error::Malformed("range extends past its containing data"));
    }

    Ok(offset..end)
}

pub(crate) fn usize_size(value: u64) -> Result<usize, Error> {
    value.try_into().map_err(|_| Error::TooLarge)
}

pub(crate) fn c_string(bytes: &[u8], offset: usize) -> Result<&[u8], Error> {
    let bytes = bytes
        .get(offset..)
        .ok_or(Error::Malformed("invalid string offset"))?;

    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated string"))?;

    Ok(&bytes[..end])
}
