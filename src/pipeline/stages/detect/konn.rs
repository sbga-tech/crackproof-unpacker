use std::{mem::size_of, ops::Range};

use anyhow::{Context, Result, ensure};
use tracing::{debug, info, trace};

use crate::pe::Pe;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::progress::ProgressMilestones;

use crate::pipeline::stages::detect::{FamilyEvidence, KonnDescriptor};

pub(crate) const KONN_MAGIC: u32 = u32::from_le_bytes(*b"KONN");
pub(crate) const KONN_WORD_COUNT: usize = 8;
pub(crate) const KONN_DESCRIPTOR_SIZE: usize = KONN_WORD_COUNT * size_of::<u32>();
pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
// Bound the linear byte-offset prefilter to the CLI's maximum accepted input.
// Full descriptor decoding happens only after the decoded-magic condition.
pub(crate) const MAX_KONN_CANDIDATES: usize = 8_000_000;
pub(crate) const MAX_KONN_MATCHES: usize = 2;
pub(crate) const MAX_KONN_SCAN_BODY_BYTES: usize = 512 << 20;

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
fn scan_konn_descriptors_impl(
    packed: &[u8],
    pe: &Pe,
    cancellation: Option<&CancellationToken>,
    mut progress: Option<&mut dyn FnMut(u64, u64) -> Result<()>>,
) -> Result<Vec<KonnDescriptor>> {
    let security_range = pe
        .security_directory_file_range(packed.len())
        .context("validating packed Security Directory")?;
    let body_range = packed_image_body_range(packed, pe)?;
    ensure_konn_scan_body_bound(body_range.len())?;
    let progress_total =
        u64::try_from(body_range.len()).context("KONN scan length does not fit u64")?;
    let mut milestones = ProgressMilestones::new(progress_total);
    info!(
        body_start = body_range.start,
        body_end = body_range.end,
        body_bytes = body_range.len(),
        security_start = security_range.as_ref().map(|range| range.start),
        security_end = security_range.as_ref().map(|range| range.end),
        "scanning packed body for KONN descriptors"
    );

    let Some(last_offset) = body_range.end.checked_sub(KONN_DESCRIPTOR_SIZE) else {
        return Ok(Vec::new());
    };
    let mut matches = Vec::new();
    let mut candidates = 0usize;
    for file_offset in body_range.start..=last_offset {
        let completed = u64::try_from(file_offset - body_range.start)
            .context("KONN scan progress does not fit u64")?;
        if milestones.should_emit(completed)
            && let Some(progress) = &mut progress
        {
            progress(completed, progress_total)?;
        }
        if file_offset & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let first = u32::from_le_bytes(
            packed[file_offset..file_offset + size_of::<u32>()]
                .try_into()
                .expect("bounds-checked first KONN word"),
        );
        let second_start = file_offset + size_of::<u32>();
        let second = u32::from_le_bytes(
            packed[second_start..second_start + size_of::<u32>()]
                .try_into()
                .expect("bounds-checked second KONN word"),
        );

        // This is the decoded KONN magic condition, not a recurrence
        // round-trip: the recurrence itself is invertible for every input.
        if second ^ first != KONN_MAGIC {
            continue;
        }
        reserve_konn_candidate(&mut candidates)?;
        let mut encrypted_words = [0u32; KONN_WORD_COUNT];
        encrypted_words[0] = first;
        encrypted_words[1] = second;
        for (index, word) in encrypted_words.iter_mut().enumerate().skip(2) {
            let start = file_offset + index * size_of::<u32>();
            *word = u32::from_le_bytes(
                packed[start..start + size_of::<u32>()]
                    .try_into()
                    .expect("bounds-checked KONN word"),
            );
        }
        let decoded = decode_konn_words(encrypted_words);
        debug!(
            file_offset,
            key = decoded[0],
            entry_rva = decoded[2],
            destination_rva = decoded[3],
            source_offset = decoded[4],
            source_length = decoded[5],
            source_rva = decoded[6],
            "decoded KONN magic candidate"
        );
        if decoded[2] != pe.entry_rva
            || decoded[5] == 0
            || !decoded[5].is_multiple_of(size_of::<u32>() as u32)
        {
            debug!(
                file_offset,
                expected_entry_rva = pe.entry_rva,
                candidate_entry_rva = decoded[2],
                source_length = decoded[5],
                "rejected KONN candidate: invalid entry or source length"
            );
            continue;
        }

        let descriptor_range = file_offset
            .checked_add(KONN_DESCRIPTOR_SIZE)
            .map(|end| file_offset..end)
            .expect("bounded descriptor range");
        let Ok(source_offset) = usize::try_from(decoded[4]) else {
            trace!(
                file_offset,
                source_offset = decoded[4],
                "rejected KONN candidate: source offset is not host-addressable"
            );
            continue;
        };
        let Ok(source_length) = usize::try_from(decoded[5]) else {
            trace!(
                file_offset,
                source_length = decoded[5],
                "rejected KONN candidate: source length is not host-addressable"
            );
            continue;
        };
        let Some(source_start) = file_offset.checked_add(source_offset) else {
            trace!(
                file_offset,
                source_offset, "rejected KONN candidate: source start overflows"
            );
            continue;
        };
        let Some(source_end) = source_start.checked_add(source_length) else {
            trace!(
                file_offset,
                source_start, source_length, "rejected KONN candidate: source end overflows"
            );
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
            debug!(
                file_offset,
                descriptor_start = descriptor_range.start,
                descriptor_end = descriptor_range.end,
                source_start = source_range.start,
                source_end = source_range.end,
                "rejected KONN candidate: source or descriptor range is not packed payload data"
            );
            continue;
        }

        let Some(entry_section) = pe.section_containing_rva(decoded[2]) else {
            debug!(
                file_offset,
                entry_rva = decoded[2],
                "rejected KONN candidate: entry RVA is unmapped"
            );
            continue;
        };
        if entry_section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            debug!(
                file_offset,
                entry_rva = decoded[2],
                "rejected KONN candidate: entry section is not executable"
            );
            continue;
        }
        let Ok(destination_section) = pe.section_for_rva_range(decoded[3], source_length) else {
            debug!(
                file_offset,
                destination_rva = decoded[3],
                source_length,
                "rejected KONN candidate: destination range is invalid"
            );
            continue;
        };
        if pe.section_containing_rva(decoded[6]).is_none() {
            debug!(
                file_offset,
                source_rva = decoded[6],
                "rejected KONN candidate: source RVA is unmapped"
            );
            continue;
        }

        info!(
            file_offset,
            key = decoded[0],
            entry_rva = decoded[2],
            destination_rva = decoded[3],
            source_offset = decoded[4],
            source_length = decoded[5],
            source_rva = decoded[6],
            destination_section_index = destination_section.index,
            "accepted structurally valid KONN descriptor"
        );
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
            info!(
                candidates,
                matches = matches.len(),
                "KONN scan stopped at bounded ambiguity threshold"
            );
            return Ok(matches);
        }
    }
    if milestones.should_emit(progress_total)
        && let Some(progress) = &mut progress
    {
        progress(progress_total, progress_total)?;
    }
    info!(
        candidates,
        matches = matches.len(),
        "completed KONN descriptor scan"
    );
    Ok(matches)
}

#[cfg(test)]
pub(crate) fn scan_konn_descriptors(packed: &[u8], pe: &Pe) -> Result<Vec<KonnDescriptor>> {
    scan_konn_descriptors_impl(packed, pe, None, None)
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

#[cfg(test)]
pub(crate) fn detect_family(packed: &[u8], pe: &Pe) -> Result<FamilyEvidence> {
    combine_family_evidence(scan_konn_descriptors(packed, pe)?)
}

pub(crate) fn detect_family_with_cancellation(
    packed: &[u8],
    pe: &Pe,
    cancellation: &CancellationToken,
    mut progress: impl FnMut(u64, u64) -> Result<()>,
) -> Result<FamilyEvidence> {
    combine_family_evidence(scan_konn_descriptors_impl(
        packed,
        pe,
        Some(cancellation),
        Some(&mut progress),
    )?)
}
