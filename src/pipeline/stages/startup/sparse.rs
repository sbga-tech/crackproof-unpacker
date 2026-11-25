use anyhow::{Context, Result, ensure};

use crate::pe::Pe;

use super::{IMAGE_SCN_MEM_EXECUTE, SPARSE_BLOCK_SIZE, SPARSE_PAGE_SIZE};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum SparsePageKey {
    PageIndex,
    PageRvaOrTextSizeMask,
    PageRvaRol(u32),
}

pub(super) fn sparse_initial_key(
    page_start: usize,
    text_size_mask: u32,
    page_key: SparsePageKey,
) -> Result<u32> {
    match page_key {
        SparsePageKey::PageIndex => u32::try_from(page_start / SPARSE_PAGE_SIZE)
            .context("sparse executable-page index exceeds u32"),
        SparsePageKey::PageRvaOrTextSizeMask => Ok(u32::try_from(page_start)
            .context("sparse executable-page RVA exceeds u32")?
            | text_size_mask),
        SparsePageKey::PageRvaRol(rotation) => Ok(u32::try_from(page_start)
            .context("sparse executable-page RVA exceeds u32")?
            .rotate_left(rotation)),
    }
}

pub(crate) fn unique_sparse_page_keys(pe: &Pe) -> Result<Vec<SparsePageKey>> {
    let text = pe
        .sections
        .iter()
        .filter(|section| {
            section.name_bytes == *b".text\0\0\0"
                && section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
        })
        .collect::<Vec<_>>();
    ensure!(
        text.len() == 1,
        "image must have one executable .text section for sparse executable-page decoding"
    );
    let text = text[0];
    let start = usize::try_from(text.virtual_address)
        .context("executable .text RVA does not fit host address space")?;
    let length = usize::try_from(text.virtual_size)
        .context("executable .text VirtualSize does not fit host address space")?;
    ensure!(
        start.is_multiple_of(SPARSE_PAGE_SIZE) && length.is_multiple_of(SPARSE_PAGE_SIZE),
        "sparse executable .text range is not page-aligned"
    );
    let end = start
        .checked_add(length)
        .context("sparse executable .text range overflows")?;
    let text_size_mask = text
        .virtual_size
        .checked_sub(1)
        .context("sparse executable .text VirtualSize is zero")?;
    let candidates = [
        SparsePageKey::PageIndex,
        SparsePageKey::PageRvaOrTextSizeMask,
    ]
    .into_iter()
    .chain((0..u32::BITS).map(SparsePageKey::PageRvaRol));
    let mut unique = Vec::new();
    for candidate in candidates {
        let duplicate = unique.iter().copied().any(|existing| {
            (start..end).step_by(SPARSE_PAGE_SIZE).all(|page_start| {
                sparse_initial_key(page_start, text_size_mask, candidate)
                    .expect("validated sparse candidate key")
                    == sparse_initial_key(page_start, text_size_mask, existing)
                        .expect("validated sparse existing key")
            })
        });
        if !duplicate {
            unique.push(candidate);
        }
    }
    Ok(unique)
}

fn block_edit(key: &mut u32, block: u32) -> (usize, u8) {
    let selected = key.rotate_left(17).wrapping_add(block);
    *key = selected.wrapping_add(block);
    ((selected & 15) as usize, *key as u8)
}

const WITNESS_BLOCKS: usize = 8;
const WITNESS_SIZE: usize = WITNESS_BLOCKS * SPARSE_BLOCK_SIZE;
const BREAKPOINTS: [u8; WITNESS_SIZE] = [0xcc; WITNESS_SIZE];

fn breakpoint_edits(window: &[u8]) -> Option<[(usize, u8); WITNESS_BLOCKS]> {
    let mut edits = [(0, 0); WITNESS_BLOCKS];
    for (edit, block) in edits.iter_mut().zip(window.chunks_exact(SPARSE_BLOCK_SIZE)) {
        let diff = u128::from_le_bytes(block.try_into().unwrap()) ^ u128::from_le_bytes([0xcc; 16]);
        if diff == 0 {
            return None;
        }
        let byte = diff.trailing_zeros() / 8;
        *edit = (byte as usize, u8::try_from(diff >> (byte * 8)).ok()?);
    }
    Some(edits)
}

fn predicts_edits(mut key: u32, first: u32, edits: &[(usize, u8); WITNESS_BLOCKS]) -> bool {
    for block in 0..first {
        block_edit(&mut key, block);
    }
    (first..)
        .zip(edits)
        .all(|(block, edit)| block_edit(&mut key, block) == *edit)
}

pub(super) enum PageEvidence {
    None,
    Partial(Vec<SparsePageKey>),
    Unique(SparsePageKey),
}

pub(super) fn page_evidence(mapped: &[u8], pe: &Pe) -> Result<PageEvidence> {
    let Some(text) = pe.sections.iter().find(|s| {
        s.name_bytes == *b".text\0\0\0" && s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }) else {
        return Ok(PageEvidence::None);
    };
    let start = text.virtual_address as usize;
    let size = text.virtual_size as usize;
    if size == 0
        || !start.is_multiple_of(SPARSE_PAGE_SIZE)
        || !size.is_multiple_of(SPARSE_PAGE_SIZE)
    {
        return Ok(PageEvidence::None);
    }
    let bytes = mapped
        .get(start..)
        .and_then(|tail| tail.get(..size))
        .context("executable .text exceeds mapped image")?;
    let mut keys = Vec::new();
    let mut supported = 0u64;
    let mut pages = 0;
    let mut plain = false;
    for (page_index, page) in bytes.chunks_exact(SPARSE_PAGE_SIZE).enumerate() {
        let rva = start + page_index * SPARSE_PAGE_SIZE;
        let mut page_supports = false;
        for (index, window) in page.chunks_exact(WITNESS_SIZE).enumerate() {
            if !plain && window == BREAKPOINTS {
                plain = true;
            }
            if index == 0 {
                continue;
            }
            let Some(edits) = breakpoint_edits(window) else {
                continue;
            };
            if keys.is_empty() {
                keys = unique_sparse_page_keys(pe)?;
            }
            let first = (index * WITNESS_BLOCKS) as u32;
            let predicts = |profile| -> Result<bool> {
                Ok(predicts_edits(
                    sparse_initial_key(rva, text.virtual_size - 1, profile)?,
                    first,
                    &edits,
                ))
            };
            if supported.is_power_of_two() && predicts(keys[supported.trailing_zeros() as usize])? {
                page_supports = true;
                continue;
            }
            let mut matching = 0u64;
            for (i, &profile) in keys.iter().enumerate() {
                if predicts(profile)? {
                    matching |= 1 << i;
                }
            }
            if matching != 0 {
                supported = if supported == 0 {
                    matching
                } else {
                    matching & supported
                };
                ensure!(supported != 0, "conflicting sparse .text encoding evidence");
                page_supports = true;
            }
        }
        pages += usize::from(page_supports);
    }
    if supported == 0 {
        return Ok(PageEvidence::None);
    }
    ensure!(!plain, "mixed plain and sparse .text encoding evidence");
    if pages >= 2 && supported.is_power_of_two() {
        return Ok(PageEvidence::Unique(
            keys[supported.trailing_zeros() as usize],
        ));
    }
    let mut bits = supported;
    keys.retain(|_| {
        let keep = bits & 1 != 0;
        bits >>= 1;
        keep
    });
    Ok(PageEvidence::Partial(keys))
}

/// Reverses a legacy CrackProof executable-page encoding. Each 16-byte block
/// carries one XOR-encoded byte selected by a page-derived state. Applying the
/// same profile twice restores the original bytes.
pub(crate) fn decode_sparse_text_pages_in_place(
    mapped: &mut [u8],
    pe: &Pe,
    page_key: SparsePageKey,
) -> Result<()> {
    let mut text_sections = pe.sections.iter().filter(|section| {
        section.name_bytes == *b".text\0\0\0"
            && section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    });
    let text = text_sections
        .next()
        .context("image has no executable .text section for sparse decoding")?;
    ensure!(
        text_sections.next().is_none(),
        "image has multiple executable .text sections for sparse decoding"
    );
    let start = usize::try_from(text.virtual_address)
        .context("executable .text RVA does not fit host address space")?;
    let length = usize::try_from(text.virtual_size)
        .context("executable .text VirtualSize does not fit host address space")?;
    let text_size_mask = text
        .virtual_size
        .checked_sub(1)
        .context("sparse executable .text VirtualSize is zero")?;
    ensure!(
        start.is_multiple_of(SPARSE_PAGE_SIZE) && length.is_multiple_of(SPARSE_PAGE_SIZE),
        "sparse executable .text range is not page-aligned"
    );
    let end = start
        .checked_add(length)
        .context("sparse executable .text range overflows")?;
    ensure!(
        end <= mapped.len(),
        "sparse executable .text range exceeds image"
    );

    for page_start in (start..end).step_by(SPARSE_PAGE_SIZE) {
        let mut key = sparse_initial_key(page_start, text_size_mask, page_key)?;
        for block in 0..SPARSE_PAGE_SIZE / SPARSE_BLOCK_SIZE {
            let (byte_offset, mask) = block_edit(&mut key, block as u32);
            if block == 0 {
                continue;
            }
            let offset = page_start + block * SPARSE_BLOCK_SIZE + byte_offset;
            mapped[offset] ^= mask;
        }
    }
    Ok(())
}
