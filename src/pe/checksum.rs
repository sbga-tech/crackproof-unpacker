use anyhow::{Context, Result, ensure};

use super::image::checked_range;

pub fn align_up(value: u32, alignment: u32) -> Result<u32> {
    ensure!(
        alignment.is_power_of_two(),
        "alignment {alignment:#x} is not a power of two"
    );
    value
        .checked_add(alignment - 1)
        .map(|aligned| aligned & !(alignment - 1))
        .context("alignment overflow")
}

/// Computes the checksum stored in IMAGE_OPTIONAL_HEADER32.CheckSum.
/// The four checksum bytes are treated as zero, as required by CheckSumMappedFile.
pub fn pe_checksum(data: &[u8], checksum_offset: usize) -> Result<u32> {
    checked_range(data.len(), checksum_offset, 4).context("checksum field exceeds file")?;
    let file_len = u32::try_from(data.len()).context("PE checksum input exceeds u32 length")?;
    let mut total = 0u64;
    let mut offset = 0usize;
    while offset + 1 < data.len() {
        let low = if (checksum_offset..checksum_offset + 4).contains(&offset) {
            0
        } else {
            data[offset]
        };
        let high_offset = offset + 1;
        let high = if (checksum_offset..checksum_offset + 4).contains(&high_offset) {
            0
        } else {
            data[high_offset]
        };
        total += u64::from(u16::from_le_bytes([low, high]));
        total = (total & 0xffff) + (total >> 16);
        offset += 2;
    }
    if offset < data.len() {
        let byte = if (checksum_offset..checksum_offset + 4).contains(&offset) {
            0
        } else {
            data[offset]
        };
        total += u64::from(byte);
        total = (total & 0xffff) + (total >> 16);
    }
    total = (total & 0xffff) + (total >> 16);
    Ok((total as u32).wrapping_add(file_len))
}
