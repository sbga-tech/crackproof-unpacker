use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::stages::payload::bootstrap::PackedBootstrap;

pub(super) const PAYLOAD_BLOCK_DESCRIPTOR_SIZE: usize = 16;
pub(super) const PAYLOAD_BLOCK_PHASES: usize = u8::MAX as usize + 1;
pub(super) const MAX_PAYLOAD_BLOCK_DISCOVERY_CANDIDATES: usize = 16_000_000;
pub(super) const MAX_PAYLOAD_BLOCK_CHECKS: usize = 32_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PayloadBlock {
    pub(super) source_offset: usize,
    pub(super) encoded_length: usize,
    pub(super) destination_rva: usize,
    pub(super) destination_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PayloadBlockTable {
    pub(super) stream_base: usize,
    pub(super) blocks: Vec<PayloadBlock>,
}

#[derive(Clone, Copy)]
struct PayloadBlockTableState {
    start: usize,
    phase: u8,
    length: usize,
}

#[derive(Clone, Copy)]
struct PayloadBlockTableSelection<'a> {
    state: PayloadBlockTableState,
    blocks: &'a [PayloadBlock],
}

struct PayloadBlockValidationContext<'a> {
    outer: &'a [u8],
    bootstrap: &'a PackedBootstrap,
    stream_base: usize,
    packed_len: usize,
    security_range: Option<&'a Range<usize>>,
    mapped_len: usize,
}

enum DecodedPayloadBlock {
    Invalid,
    Terminal,
    Record(PayloadBlock),
}

pub(super) fn f2a0_byte(value: u8, dl: u8) -> u8 {
    let bl = dl.wrapping_add(1);
    let mut value = value.rotate_left(3) ^ bl;
    value = value.rotate_left(3) ^ dl;
    value.rotate_left(3)
}

pub(super) fn f2a0_transform_from_dl(bytes: &mut [u8], mut dl: u8) {
    for byte in bytes {
        *byte = f2a0_byte(*byte, dl);
        dl = dl.wrapping_add(1);
    }
}

pub(super) fn f710_record_transform(bytes: &mut [u8], seed: u32) {
    let mut bl = seed as u8;
    for byte in bytes {
        let dl = bl.wrapping_add(1);
        let mut value = (*byte).rotate_left(2) ^ dl;
        value = value.rotate_left(2) ^ bl;
        *byte = value.rotate_left(2);
        bl = dl;
    }
}

pub(super) fn record_words(bytes: &[u8; PAYLOAD_BLOCK_DESCRIPTOR_SIZE]) -> [u32; 4] {
    std::array::from_fn(|index| {
        let offset = index * size_of::<u32>();
        u32::from_le_bytes(
            bytes[offset..offset + size_of::<u32>()]
                .try_into()
                .expect("fixed-width payload block word"),
        )
    })
}

fn decode_payload_block_state(
    context: &PayloadBlockValidationContext<'_>,
    record_offset: usize,
    phase: u8,
    record_checks: &mut usize,
) -> Result<DecodedPayloadBlock> {
    let Some(next_offset) = record_offset.checked_add(PAYLOAD_BLOCK_DESCRIPTOR_SIZE) else {
        return Ok(DecodedPayloadBlock::Invalid);
    };
    let Some(source_record) = context.outer.get(record_offset..next_offset) else {
        return Ok(DecodedPayloadBlock::Invalid);
    };
    *record_checks = record_checks
        .checked_add(1)
        .context("payload block descriptor record-check counter overflows")?;
    ensure!(
        *record_checks <= MAX_PAYLOAD_BLOCK_CHECKS,
        "payload block descriptor discovery exceeds its bounded record work"
    );

    let mut record: [u8; PAYLOAD_BLOCK_DESCRIPTOR_SIZE] = source_record
        .try_into()
        .expect("fixed-width payload block descriptor record");
    f2a0_transform_from_dl(&mut record, phase);
    let target_rva = context
        .bootstrap
        .destination_rva
        .checked_add(
            u32::try_from(record_offset)
                .context("payload block descriptor offset overflows u32")?,
        )
        .context("payload block descriptor target RVA overflows")?;
    f710_record_transform(&mut record, target_rva);
    let [
        source_offset,
        encoded_length,
        destination_rva,
        destination_length,
    ] = record_words(&record);

    if encoded_length == 0 {
        return Ok(
            if source_offset == context.bootstrap.destination_rva
                && destination_rva == 0
                && destination_length == 0
            {
                DecodedPayloadBlock::Terminal
            } else {
                DecodedPayloadBlock::Invalid
            },
        );
    }
    if destination_length == 0 {
        return Ok(DecodedPayloadBlock::Invalid);
    }

    let source_offset = match usize::try_from(source_offset) {
        Ok(value) => value,
        Err(_) => return Ok(DecodedPayloadBlock::Invalid),
    };
    let encoded_length = match usize::try_from(encoded_length) {
        Ok(value) => value,
        Err(_) => return Ok(DecodedPayloadBlock::Invalid),
    };
    let destination_rva = match usize::try_from(destination_rva) {
        Ok(value) => value,
        Err(_) => return Ok(DecodedPayloadBlock::Invalid),
    };
    let destination_length = match usize::try_from(destination_length) {
        Ok(value) => value,
        Err(_) => return Ok(DecodedPayloadBlock::Invalid),
    };
    let stream_start = match context.stream_base.checked_add(source_offset) {
        Some(value) => value,
        None => return Ok(DecodedPayloadBlock::Invalid),
    };
    let stream_end = match stream_start.checked_add(encoded_length) {
        Some(value) if value <= context.packed_len => value,
        _ => return Ok(DecodedPayloadBlock::Invalid),
    };
    if context
        .security_range
        .is_some_and(|security| stream_start < security.end && security.start < stream_end)
    {
        return Ok(DecodedPayloadBlock::Invalid);
    }
    let destination_end = match destination_rva.checked_add(destination_length) {
        Some(value) if value <= context.mapped_len => value,
        _ => return Ok(DecodedPayloadBlock::Invalid),
    };
    debug_assert!(stream_end <= context.packed_len);
    debug_assert!(destination_end <= context.mapped_len);

    Ok(DecodedPayloadBlock::Record(PayloadBlock {
        source_offset,
        encoded_length,
        destination_rva,
        destination_length,
    }))
}

fn reconstruct_payload_block_table(
    context: &PayloadBlockValidationContext<'_>,
    start: usize,
    phase: u8,
    length: usize,
    record_checks: &mut usize,
    cancellation: Option<&CancellationToken>,
) -> Result<PayloadBlockTable> {
    let mut blocks = Vec::with_capacity(length);
    let mut record_offset = start;
    let mut state = phase;
    for _ in 0..length {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        match decode_payload_block_state(context, record_offset, state, record_checks)? {
            DecodedPayloadBlock::Record(block) => blocks.push(block),
            DecodedPayloadBlock::Invalid | DecodedPayloadBlock::Terminal => {
                bail!(
                    "payload block descriptor run reconstruction diverges from memoized structure"
                );
            }
        }
        record_offset = record_offset
            .checked_add(PAYLOAD_BLOCK_DESCRIPTOR_SIZE)
            .context("payload block descriptor record offset overflows while reconstructing")?;
        state = state.wrapping_add(PAYLOAD_BLOCK_DESCRIPTOR_SIZE as u8);
    }
    match decode_payload_block_state(context, record_offset, state, record_checks)? {
        DecodedPayloadBlock::Terminal => Ok(PayloadBlockTable {
            stream_base: context.stream_base,
            blocks,
        }),
        DecodedPayloadBlock::Invalid | DecodedPayloadBlock::Record(_) => {
            bail!("payload block descriptor run reconstruction does not end at its terminal");
        }
    }
}

fn visit_payload_block_tables(
    context: &PayloadBlockValidationContext<'_>,
    starts: usize,
    record_checks: &mut usize,
    cancellation: Option<&CancellationToken>,
    mut visit: impl FnMut(usize, u8, usize, &mut usize) -> Result<()>,
) -> Result<()> {
    let mut next_lengths: [Option<usize>; PAYLOAD_BLOCK_PHASES] = [None; PAYLOAD_BLOCK_PHASES];
    for index in (0..starts).rev() {
        if index & 0x00ff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record_offset = index * PAYLOAD_BLOCK_DESCRIPTOR_SIZE;
        let mut lengths = [None; PAYLOAD_BLOCK_PHASES];
        for phase in u8::MIN..=u8::MAX {
            let phase_index = usize::from(phase);
            lengths[phase_index] =
                match decode_payload_block_state(context, record_offset, phase, record_checks)? {
                    DecodedPayloadBlock::Invalid => None,
                    DecodedPayloadBlock::Terminal => Some(0),
                    DecodedPayloadBlock::Record(_) if index + 1 == starts => None,
                    DecodedPayloadBlock::Record(_) => next_lengths
                        [usize::from(phase.wrapping_add(PAYLOAD_BLOCK_DESCRIPTOR_SIZE as u8))]
                    .map(|length| {
                        length
                            .checked_add(1)
                            .context("payload block descriptor run length overflows")
                    })
                    .transpose()?,
                };

            if let Some(length) = lengths[phase_index]
                && length != 0
            {
                visit(record_offset, phase, length, record_checks)?;
            }
        }
        next_lengths = lengths;
    }
    Ok(())
}

fn payload_block_table_is_exact_suffix(
    context: &PayloadBlockValidationContext<'_>,
    selected: PayloadBlockTableSelection<'_>,
    candidate: PayloadBlockTableState,
    record_checks: &mut usize,
) -> Result<bool> {
    let Some(distance) = candidate.start.checked_sub(selected.state.start) else {
        return Ok(false);
    };
    if !distance.is_multiple_of(PAYLOAD_BLOCK_DESCRIPTOR_SIZE) {
        return Ok(false);
    }
    let suffix_index = distance / PAYLOAD_BLOCK_DESCRIPTOR_SIZE;
    let Some(expected_blocks) = selected.blocks.get(suffix_index..) else {
        return Ok(false);
    };
    let expected_phase = selected
        .state
        .phase
        .wrapping_add((suffix_index as u8).wrapping_mul(PAYLOAD_BLOCK_DESCRIPTOR_SIZE as u8));
    if candidate.phase != expected_phase || candidate.length != expected_blocks.len() {
        return Ok(false);
    }

    let DecodedPayloadBlock::Record(first_record) =
        decode_payload_block_state(context, candidate.start, candidate.phase, record_checks)?
    else {
        return Ok(false);
    };
    // Offset and phase are the complete decoder state. A matching first
    // block leaves both tables at the same successor state, so their remaining
    // decoded PayloadBlock identities and order are identical through the shared
    // terminal; equal length alone is never sufficient.
    Ok(first_record == expected_blocks[0])
}

pub(super) fn ensure_source_excludes_security(
    source: &Range<usize>,
    security: Option<&Range<usize>>,
) -> Result<()> {
    ensure!(
        !security
            .is_some_and(|security| source.start < security.end && security.start < source.end),
        "descriptor-derived source range overlaps the packed Security Directory"
    );
    Ok(())
}

pub(super) fn discover_payload_block_table(
    outer: &[u8],
    bootstrap: PackedBootstrap,
    stream_base: usize,
    packed_len: usize,
    mapped_len: usize,
    security_range: Option<&Range<usize>>,
) -> Result<PayloadBlockTable> {
    discover_payload_block_table_impl(
        outer,
        bootstrap,
        stream_base,
        packed_len,
        mapped_len,
        security_range,
        None,
    )
}

pub(super) fn discover_payload_block_table_with_cancellation(
    outer: &[u8],
    bootstrap: PackedBootstrap,
    stream_base: usize,
    packed_len: usize,
    mapped_len: usize,
    security_range: Option<&Range<usize>>,
    cancellation: &CancellationToken,
) -> Result<PayloadBlockTable> {
    discover_payload_block_table_impl(
        outer,
        bootstrap,
        stream_base,
        packed_len,
        mapped_len,
        security_range,
        Some(cancellation),
    )
}

fn discover_payload_block_table_impl(
    outer: &[u8],
    bootstrap: PackedBootstrap,
    stream_base: usize,
    packed_len: usize,
    mapped_len: usize,
    security_range: Option<&Range<usize>>,
    cancellation: Option<&CancellationToken>,
) -> Result<PayloadBlockTable> {
    let Some(last_start) = outer.len().checked_sub(PAYLOAD_BLOCK_DESCRIPTOR_SIZE) else {
        bail!("bootstrap source cannot contain a complete payload block descriptor record");
    };
    let starts = last_start / PAYLOAD_BLOCK_DESCRIPTOR_SIZE + 1;
    let candidate_count = starts
        .checked_mul(PAYLOAD_BLOCK_PHASES)
        .context("payload block descriptor candidate count overflows")?;
    ensure!(
        candidate_count <= MAX_PAYLOAD_BLOCK_DISCOVERY_CANDIDATES,
        "payload block descriptor discovery exceeds its bounded candidate work"
    );
    let validation_work = candidate_count
        .checked_mul(2)
        .and_then(|work| {
            starts
                .checked_mul(2)
                .and_then(|extra| work.checked_add(extra))
        })
        .context("payload block descriptor validation work counter overflows")?;
    ensure!(
        validation_work <= MAX_PAYLOAD_BLOCK_CHECKS,
        "payload block descriptor discovery exceeds its bounded record work"
    );

    let mut record_checks = 0usize;
    let context = PayloadBlockValidationContext {
        outer,
        bootstrap: &bootstrap,
        stream_base,
        packed_len,
        security_range,
        mapped_len,
    };
    let mut longest: Option<PayloadBlockTableState> = None;
    let mut longest_is_ambiguous = false;
    visit_payload_block_tables(
        &context,
        starts,
        &mut record_checks,
        cancellation,
        |record_offset, phase, length, _record_checks| {
            let candidate = PayloadBlockTableState {
                start: record_offset,
                phase,
                length,
            };
            match longest.as_ref().map(|run| run.length) {
                None => longest = Some(candidate),
                Some(longest_length) if length > longest_length => {
                    longest = Some(candidate);
                    longest_is_ambiguous = false;
                }
                Some(longest_length) if length == longest_length => longest_is_ambiguous = true,
                Some(_) => {}
            }
            Ok(())
        },
    )?;

    let Some(selected_state) = longest else {
        bail!("no structurally valid payload block descriptor run exists");
    };
    ensure!(
        !longest_is_ambiguous,
        "multiple longest structurally valid payload block descriptor runs exist"
    );
    let selected = reconstruct_payload_block_table(
        &context,
        selected_state.start,
        selected_state.phase,
        selected_state.length,
        &mut record_checks,
        cancellation,
    )?;

    let selected_identity = PayloadBlockTableSelection {
        state: selected_state,
        blocks: &selected.blocks,
    };
    let mut has_independent_shorter_run = false;
    visit_payload_block_tables(
        &context,
        starts,
        &mut record_checks,
        cancellation,
        |candidate_start, candidate_phase, candidate_length, record_checks| {
            let candidate = PayloadBlockTableState {
                start: candidate_start,
                phase: candidate_phase,
                length: candidate_length,
            };
            if candidate.length < selected_state.length
                && !payload_block_table_is_exact_suffix(
                    &context,
                    selected_identity,
                    candidate,
                    record_checks,
                )?
            {
                has_independent_shorter_run = true;
            }
            Ok(())
        },
    )?;
    ensure!(
        !has_independent_shorter_run,
        "an independent shorter structurally valid payload block descriptor run exists"
    );
    Ok(selected)
}

pub(super) fn payload_block_destination_range(record: &PayloadBlock) -> Result<Range<u32>> {
    let start = u32::try_from(record.destination_rva)
        .context("payload block destination RVA exceeds u32")?;
    let length = u32::try_from(record.destination_length)
        .context("payload block destination length exceeds u32")?;
    let end = start
        .checked_add(length)
        .context("payload block destination range overflows")?;
    Ok(start..end)
}

pub(super) fn merged_payload_block_destination_ranges(
    records: &[PayloadBlock],
) -> Result<Vec<Range<u32>>> {
    let mut ranges = Vec::with_capacity(records.len());
    for record in records {
        ranges.push(payload_block_destination_range(record)?);
    }
    ranges.sort_unstable_by_key(|range| range.start);

    let mut merged: Vec<Range<u32>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    Ok(merged)
}
