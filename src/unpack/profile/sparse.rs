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
            let block = u32::try_from(block).expect("sparse page block count fits u32");
            let selected = key.rotate_left(17).wrapping_add(block);
            key = selected.wrapping_add(block);
            let byte_offset =
                usize::try_from(selected & 0x0f).expect("sparse block byte offset fits usize");
            let offset = page_start
                .checked_add(
                    usize::try_from(block)
                        .expect("sparse block index fits usize")
                        .checked_mul(SPARSE_BLOCK_SIZE)
                        .expect("sparse page block offset fits usize"),
                )
                .and_then(|offset| offset.checked_add(byte_offset))
                .expect("sparse page byte offset remains bounded");
            mapped[offset] ^= key as u8;
        }
    }
    Ok(())
}
