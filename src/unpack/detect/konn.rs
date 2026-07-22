use std::{mem::size_of, ops::Range};

use anyhow::{Context, Result, ensure};

use crate::pe::Pe;

use crate::unpack::detect::{FamilyEvidence, KonnDescriptor};

pub(crate) const KONN_MAGIC: u32 = u32::from_le_bytes(*b"KONN");
pub(crate) const KONN_WORD_COUNT: usize = 8;
pub(crate) const KONN_DESCRIPTOR_SIZE: usize = KONN_WORD_COUNT * size_of::<u32>();
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
// These caps bound structural candidate processing after the cheap encrypted
// magic prefilter. They are not family identities.
pub(crate) const MAX_KONN_CANDIDATES: usize = 8_000_000;
pub(crate) const MAX_KONN_MATCHES: usize = 2;
// Descriptor scanning reads encrypted words at every packed-body byte offset
// before the magic prefilter can reject it. Bound that total offset work,
// independently of input size and the post-prefilter candidate cap.
pub(crate) const MAX_KONN_SCAN_BODY_BYTES: usize = 64 << 20;

pub(crate) fn decode_konn_words(encrypted: [u32; KONN_WORD_COUNT]) -> [u32; KONN_WORD_COUNT] {
    let mut decoded = [0u32; KONN_WORD_COUNT];
    decoded[0] = encrypted[0];
    let mut state = encrypted[0];
    for index in 0..KONN_WORD_COUNT - 1 {
        let ciphertext = encrypted[index + 1];
        decoded[index + 1] = ciphertext ^ state;
        state = state.wrapping_add(ciphertext).wrapping_sub(index as u32)
            ^ (index as u32).wrapping_mul(index as u32);
    }
    decoded
}
#[cfg(test)]
pub(crate) fn encode_konn_words(decoded: [u32; KONN_WORD_COUNT]) -> [u32; KONN_WORD_COUNT] {
    let mut encrypted = [0u32; KONN_WORD_COUNT];
    encrypted[0] = decoded[0];
    let mut state = decoded[0];
    for index in 0..KONN_WORD_COUNT - 1 {
        let ciphertext = decoded[index + 1] ^ state;
        encrypted[index + 1] = ciphertext;
        state = state.wrapping_add(ciphertext).wrapping_sub(index as u32)
            ^ (index as u32).wrapping_mul(index as u32);
    }
    encrypted
}

/// Returns the contiguous packed-image body preceding overlay bytes.
///
/// The body starts at file offset zero and ends at the greatest PE header or
/// raw-section end. It intentionally includes internal file gaps: CrackProof
/// may place its descriptor and descriptor-relative stream before the first
/// section's raw data. Certificate bytes are excluded separately.
fn packed_image_body_range(packed: &[u8], pe: &Pe) -> Result<Range<usize>> {
    let header_end =
        usize::try_from(pe.size_of_headers).context("PE header size does not fit usize")?;
    ensure!(header_end <= packed.len(), "PE headers exceed packed input");

    let mut body_end = header_end;
    for section in &pe.sections {
        if section.raw_size == 0 {
            continue;
        }
        let raw = section.raw_range()?;
        ensure!(
            raw.end <= packed.len(),
            "section {} raw range exceeds packed input",
            section.index
        );
        body_end = body_end.max(raw.end);
    }
    Ok(0..body_end)
}

fn file_ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn range_is_in_packed_body(range: &Range<usize>, body: &Range<usize>) -> bool {
    range.start < range.end && body.start <= range.start && range.end <= body.end
}

pub(crate) fn reserve_konn_candidate(candidates: &mut usize) -> Result<()> {
    *candidates = candidates
        .checked_add(1)
        .context("KONN descriptor candidate counter overflows")?;
    ensure!(
        *candidates <= MAX_KONN_CANDIDATES,
        "KONN descriptor discovery exceeds its bounded candidate work"
    );
    Ok(())
}

pub(crate) fn ensure_konn_scan_body_bound(body_bytes: usize) -> Result<()> {
    ensure!(
        body_bytes <= MAX_KONN_SCAN_BODY_BYTES,
        "KONN descriptor discovery scans {body_bytes} packed-body bytes, exceeding its {MAX_KONN_SCAN_BODY_BYTES}-byte work cap"
    );
    Ok(())
}

/// Scans the packed-image body for structurally valid KONN descriptors.
/// Both the descriptor and its descriptor-relative source must precede the
/// computed overlay boundary and must not intersect the Security directory.
pub(crate) fn scan_konn_descriptors(packed: &[u8], pe: &Pe) -> Result<Vec<KonnDescriptor>> {
    let security_range = pe
        .security_directory_file_range(packed.len())
        .context("validating packed Security Directory")?;
    let body_range = packed_image_body_range(packed, pe)?;
    ensure_konn_scan_body_bound(body_range.len())?;

    let Some(last_offset) = body_range.end.checked_sub(KONN_DESCRIPTOR_SIZE) else {
        return Ok(Vec::new());
    };
    let mut matches = Vec::new();
    let mut candidates = 0usize;
    for file_offset in body_range.start..=last_offset {
        let mut encrypted_words = [0u32; KONN_WORD_COUNT];
        for (index, word) in encrypted_words.iter_mut().enumerate() {
            let start = file_offset + index * size_of::<u32>();
            *word = u32::from_le_bytes(
                packed[start..start + size_of::<u32>()]
                    .try_into()
                    .expect("bounds-checked KONN word"),
            );
        }

        // This is the decoded KONN magic condition, not a recurrence
        // round-trip: the recurrence itself is invertible for every input.
        if encrypted_words[1] ^ encrypted_words[0] != KONN_MAGIC {
            continue;
        }
        reserve_konn_candidate(&mut candidates)?;
        let decoded = decode_konn_words(encrypted_words);
        if decoded[2] != pe.entry_rva
            || decoded[5] == 0
            || !decoded[5].is_multiple_of(size_of::<u32>() as u32)
        {
            continue;
        }

        let descriptor_range = file_offset
            .checked_add(KONN_DESCRIPTOR_SIZE)
            .map(|end| file_offset..end)
            .expect("bounded descriptor range");
        let Ok(source_offset) = usize::try_from(decoded[4]) else {
            continue;
        };
        let Ok(source_length) = usize::try_from(decoded[5]) else {
            continue;
        };
        let Some(source_start) = file_offset.checked_add(source_offset) else {
            continue;
        };
        let Some(source_end) = source_start.checked_add(source_length) else {
            continue;
        };
        let source_range = source_start..source_end;
        if !range_is_in_packed_body(&descriptor_range, &body_range)
            || !range_is_in_packed_body(&source_range, &body_range)
            || security_range.as_ref().is_some_and(|security| {
                file_ranges_overlap(&descriptor_range, security)
                    || file_ranges_overlap(&source_range, security)
            })
        {
            continue;
        }

        let Some(entry_section) = pe.section_containing_rva(decoded[2]) else {
            continue;
        };
        if entry_section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }
        let Ok(destination_section) = pe.section_for_rva_range(decoded[3], source_length) else {
            continue;
        };
        if pe.section_for_rva_range(decoded[6], source_length).is_err() {
            continue;
        }

        matches.push(KonnDescriptor {
            file_offset,
            key: decoded[0],
            entry_rva: decoded[2],
            destination_rva: decoded[3],
            source_offset: decoded[4],
            length: decoded[5],
            source_rva: decoded[6],
            destination_section_index: destination_section.index,
        });
        if matches.len() == MAX_KONN_MATCHES {
            return Ok(matches);
        }
    }
    Ok(matches)
}

/// Requires one unambiguous structurally validated KONN descriptor.
///
/// Decryption supplies the independent proof by uniquely replaying an
/// AES context and custom decoder against the complete A-record chain.
pub(crate) fn combine_family_evidence(descriptors: Vec<KonnDescriptor>) -> Result<FamilyEvidence> {
    ensure!(
        descriptors.len() == 1,
        "expected exactly one valid KONN descriptor, found {}",
        descriptors.len()
    );
    Ok(FamilyEvidence {
        descriptor: descriptors.into_iter().next().expect("one descriptor"),
    })
}

pub(crate) fn detect_family(packed: &[u8], pe: &Pe) -> Result<FamilyEvidence> {
    combine_family_evidence(scan_konn_descriptors(packed, pe)?)
}
