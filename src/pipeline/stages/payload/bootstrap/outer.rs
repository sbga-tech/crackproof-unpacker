use std::ops::Range;

use anyhow::{Context, Result, ensure};

use super::{MAX_OUTER_SOURCE_BYTES, OUTER_ENCRYPTED_PREFIX_RVA_BIAS, PackedBootstrap};

pub(crate) fn checked_usize(value: u32, field: &str) -> Result<usize> {
    usize::try_from(value).with_context(|| format!("{field} does not fit host address space"))
}

pub(crate) fn bootstrap_source_file_range(
    packed: &[u8],
    bootstrap: PackedBootstrap,
) -> Result<Range<usize>> {
    let start = bootstrap
        .descriptor_file_offset
        .checked_add(checked_usize(
            bootstrap.source_offset,
            "bootstrap source offset",
        )?)
        .context("bootstrap source start overflows")?;
    let length = checked_usize(bootstrap.length, "bootstrap source length")?;
    let end = start
        .checked_add(length)
        .context("bootstrap source end overflows")?;
    ensure!(
        end <= packed.len(),
        "packed input does not contain the bootstrap source"
    );
    Ok(start..end)
}

pub(crate) fn derive_outer_source(
    packed: &[u8],
    bootstrap: PackedBootstrap,
) -> Result<(usize, Vec<u8>)> {
    let source_range = bootstrap_source_file_range(packed, bootstrap)?;
    ensure!(
        source_range.len() <= MAX_OUTER_SOURCE_BYTES,
        "bootstrap source exceeds its {MAX_OUTER_SOURCE_BYTES}-byte per-descriptor cap"
    );
    let source_start = source_range.start;
    let source = packed
        .get(source_range)
        .expect("validated bootstrap source range");

    let encrypted_prefix = bootstrap
        .source_rva
        .checked_sub(bootstrap.destination_rva)
        .context("bootstrap source RVA precedes its destination RVA")?
        .checked_add(OUTER_ENCRYPTED_PREFIX_RVA_BIAS)
        .context("bootstrap encrypted-prefix length overflows")?;
    let encrypted_prefix = checked_usize(encrypted_prefix, "bootstrap encrypted-prefix length")?;
    ensure!(
        encrypted_prefix <= source.len(),
        "bootstrap encrypted prefix exceeds its source"
    );
    ensure!(
        encrypted_prefix.is_multiple_of(4),
        "bootstrap encrypted prefix is not dword aligned"
    );

    let mut output = source.to_vec();
    let prefix_length_u32 = u32::try_from(encrypted_prefix)
        .context("bootstrap encrypted-prefix length does not fit u32")?;
    let mut state = bootstrap
        .key
        .wrapping_sub(prefix_length_u32)
        .wrapping_sub(1);
    for (word_index, bytes) in output[..encrypted_prefix].chunks_exact_mut(4).enumerate() {
        let ciphertext = u32::from_le_bytes(
            (*bytes)
                .try_into()
                .expect("dword-aligned encrypted prefix chunk"),
        );
        bytes.copy_from_slice(&(ciphertext ^ state).to_le_bytes());
        let index = u32::try_from(word_index).context("outer decrypt word index overflows u32")?;
        state = state.wrapping_add(ciphertext).wrapping_add(index) ^ index.wrapping_mul(index);
    }
    Ok((source_start, output))
}
