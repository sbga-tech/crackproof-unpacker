use std::ops::Range;

use anyhow::{Context, Result, ensure};

pub(crate) fn checked_range(total_len: usize, offset: usize, len: usize) -> Result<Range<usize>> {
    let end = offset.checked_add(len).context("range end overflow")?;
    ensure!(
        end <= total_len,
        "range {offset:#x}..{end:#x} exceeds buffer length {total_len:#x}"
    );
    Ok(offset..end)
}
pub(crate) fn checked_u32_range(
    total_len: usize,
    offset: u32,
    len: u32,
    label: &str,
) -> Result<Range<usize>> {
    let offset =
        usize::try_from(offset).with_context(|| format!("{label} offset does not fit usize"))?;
    let len = usize::try_from(len).with_context(|| format!("{label} length does not fit usize"))?;
    checked_range(total_len, offset, len).with_context(|| format!("invalid {label} range"))
}

pub(crate) fn read_bytes(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    Ok(&data[checked_range(data.len(), offset, len)?])
}

pub(crate) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = read_bytes(data, offset, size_of::<u16>())?;
    Ok(u16::from_le_bytes(
        bytes.try_into().expect("bounded two-byte read"),
    ))
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = read_bytes(data, offset, size_of::<u32>())?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("bounded four-byte read"),
    ))
}

pub(crate) fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = read_bytes(data, offset, size_of::<u64>())?;
    Ok(u64::from_le_bytes(
        bytes.try_into().expect("bounded eight-byte read"),
    ))
}

pub(crate) fn read_u16_opt(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(size_of::<u16>())?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

pub(crate) fn read_u32_opt(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(size_of::<u32>())?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

pub(crate) fn write_bytes(data: &mut [u8], offset: usize, value: &[u8]) -> Result<()> {
    let destination = checked_range(data.len(), offset, value.len())?;
    data[destination].copy_from_slice(value);
    Ok(())
}

pub(crate) fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

pub(crate) fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

pub(crate) fn write_u64(data: &mut [u8], offset: usize, value: u64) -> Result<()> {
    write_bytes(data, offset, &value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_accessors_reject_truncated_ranges() {
        assert!(read_u32(&[0; 3], 0).is_err());
        assert!(write_u32(&mut [0; 3], 0, 1).is_err());
    }

    #[test]
    fn optional_integer_accessors_return_none_for_truncated_ranges() {
        assert_eq!(read_u32_opt(&[0; 3], 0), None);
    }

    #[test]
    fn checked_u32_range_preserves_range_context() {
        let error = checked_u32_range(4, 3, 2, "payload block").unwrap_err();

        assert_eq!(error.to_string(), "invalid payload block range");
    }
}
