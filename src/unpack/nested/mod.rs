use std::collections::HashSet;
use std::mem::size_of;
use std::ops::Range;

use anyhow::{Context, Result, ensure};

use crate::pe::{Machine, Pe};
use crate::unpack::bootstrap::PackedBootstrap;

#[cfg(test)]
mod tests;

const A_RECORD_SIZE: usize = 16;
const MAX_NESTED_STAGE_CONTEXTS: usize = 8;
pub(crate) const MAX_AL_PROGRAM_BYTES: usize = 96;
const MIN_AL_PROGRAM_BYTES: usize = 8;
const MAX_AL_MAP_CANDIDATES: usize = 64;
const MAX_NESTED_RECORD_CANDIDATES: usize = 64;
const MAX_NESTED_SPAN_CANDIDATES: usize = 128;
const MAX_NESTED_SCALAR_CANDIDATES: usize = 8_192;
const MAX_NESTED_KEY_CANDIDATES: usize = 1_048_576;
pub(crate) const MAX_NESTED_REPLAY_OUTPUTS: usize = 8;
const MAX_NESTED_CONTEXT_WORDS: usize = 1_536;
const NESTED_STAGE_SUM_FOUR: u32 = 0x0002_4be4;
const NESTED_STAGE_SUM_THREE: u32 = 0x0001_129c;
const CRC32_TABLE_BYTES: usize = 256 * size_of::<u32>();

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NestedRecord {
    pub(crate) descriptor_offset: usize,
    pub(crate) source_rva: u32,
    pub(crate) encoded_length: u32,
    pub(crate) destination_rva: u32,
    pub(crate) destination_length: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum NestedReplay {
    NoMatch,
    Unique(Vec<u8>, u32),
    Ambiguous,
}

pub(crate) trait NestedRecordReplayer {
    fn begin_graph(&mut self, extended_profile: bool) -> Result<()>;

    fn replay(
        &mut self,
        staged_outer: &[u8],
        bootstrap: PackedBootstrap,
        record: &NestedRecord,
        keys: &[u32],
        byte_maps: &[(usize, Box<[u8; 256]>)],
    ) -> Result<NestedReplay>;
}

#[allow(clippy::too_many_arguments)]
fn replay_nested_keys(
    replayer: &mut impl NestedRecordReplayer,
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    record: &NestedRecord,
    keys: &[u32],
    direct_key_count: usize,
    byte_maps: &[(usize, Box<[u8; 256]>)],
    extended_profile: bool,
) -> Result<NestedReplay> {
    ensure!(
        direct_key_count <= keys.len(),
        "nested direct-key prefix exceeds the complete key set"
    );
    if direct_key_count != 0 {
        let direct = replayer.replay(
            staged_outer,
            bootstrap,
            record,
            &keys[..direct_key_count],
            byte_maps,
        )?;
        if !matches!(direct, NestedReplay::NoMatch)
            && (!extended_profile || matches!(direct, NestedReplay::Unique(..)))
        {
            return Ok(direct);
        }
    }
    if extended_profile {
        replayer.replay(staged_outer, bootstrap, record, keys, byte_maps)
    } else if direct_key_count < keys.len() {
        replayer.replay(
            staged_outer,
            bootstrap,
            record,
            &keys[direct_key_count..],
            byte_maps,
        )
    } else {
        Ok(NestedReplay::NoMatch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NestedSpan {
    descriptor_offset: usize,
    rva: u32,
    length: u32,
}

pub(super) fn read_u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(size_of::<u32>())?)?;
    Some(u32::from_le_bytes(value.try_into().ok()?))
}

pub(crate) fn crc32_table() -> [u32; 256] {
    std::array::from_fn(|index| {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xedb8_8320
            } else {
                value >> 1
            };
        }
        value
    })
}

pub(super) fn crc32_table_bytes(table: &[u32; 256]) -> [u8; CRC32_TABLE_BYTES] {
    let mut bytes = [0u8; CRC32_TABLE_BYTES];
    for (index, word) in table.iter().enumerate() {
        let offset = index * size_of::<u32>();
        bytes[offset..offset + size_of::<u32>()].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

pub(crate) fn crackproof_checksum(bytes: &[u8], table: &[u32; 256]) -> u32 {
    let mut state = u32::MAX;
    for &byte in bytes {
        let index = usize::from((state as u8) ^ byte);
        state = (state >> 8) ^ table[index];
    }
    (!state) ^ bytes.len() as u32
}

pub(crate) fn nested_outer_range(
    bootstrap: PackedBootstrap,
    outer_len: usize,
    rva: u32,
    length: u32,
) -> Option<Range<usize>> {
    let start = rva.checked_sub(bootstrap.destination_rva)? as usize;
    let end = start.checked_add(length as usize)?;
    (end <= outer_len).then_some(start..end)
}

pub(super) fn decode_nested_dword_stage(
    outer: &[u8],
    range: Range<usize>,
    initial_key: u32,
    shift: u32,
) -> Option<Vec<u8>> {
    if !range.len().is_multiple_of(size_of::<u32>()) {
        return None;
    }
    let mut decoded = outer.get(range)?.to_vec();
    let mut key = initial_key;
    for (index, bytes) in decoded.chunks_exact_mut(size_of::<u32>()).enumerate() {
        let index = u32::try_from(index).ok()?;
        let ciphertext = u32::from_le_bytes(bytes.try_into().ok()?);
        let plaintext = (ciphertext ^ key).rotate_right(shift).wrapping_sub(index);
        bytes.copy_from_slice(&plaintext.to_le_bytes());
        key = key.wrapping_add(index);
    }
    Some(decoded)
}

pub(crate) fn lfsr_decode_program(source: &[u8]) -> [u8; MAX_AL_PROGRAM_BYTES] {
    let mut decoded = [0u8; MAX_AL_PROGRAM_BYTES];
    let mut state = 1u32;
    for (destination, &ciphertext) in decoded.iter_mut().zip(source) {
        let mut plaintext = ciphertext;
        for bit in 0..8 {
            plaintext ^= ((state & 1) as u8) << bit;
            state <<= 1;
            if state & 0x8000 != 0 {
                state ^= 0x8003;
            }
        }
        *destination = plaintext;
    }
    decoded
}

pub(crate) fn parse_al_byte_map(program: &[u8]) -> Option<(usize, Box<[u8; 256]>)> {
    let mut map = Box::new(std::array::from_fn(|value| value as u8));
    let mut offset = 0usize;
    while offset < program.len() {
        let opcode = program[offset];
        offset += 1;
        match opcode {
            0x04 | 0x2c | 0x34 => {
                let immediate = *program.get(offset)?;
                offset += 1;
                for value in map.iter_mut() {
                    *value = match opcode {
                        0x04 => value.wrapping_add(immediate),
                        0x2c => value.wrapping_sub(immediate),
                        0x34 => *value ^ immediate,
                        _ => unreachable!(),
                    };
                }
            }
            0x90 => {}
            0xc0 => {
                let mod_rm = *program.get(offset)?;
                let count = u32::from(*program.get(offset.checked_add(1)?)?);
                offset = offset.checked_add(2)?;
                if mod_rm & 0xc7 != 0xc0 {
                    return None;
                }
                match (mod_rm >> 3) & 7 {
                    0 => map
                        .iter_mut()
                        .for_each(|value| *value = value.rotate_left(count)),
                    1 => map
                        .iter_mut()
                        .for_each(|value| *value = value.rotate_right(count)),
                    _ => return None,
                }
            }
            0xfe => {
                let mod_rm = *program.get(offset)?;
                offset += 1;
                if mod_rm & 0xc7 != 0xc0 {
                    return None;
                }
                match (mod_rm >> 3) & 7 {
                    0 => map
                        .iter_mut()
                        .for_each(|value| *value = value.wrapping_add(1)),
                    1 => map
                        .iter_mut()
                        .for_each(|value| *value = value.wrapping_sub(1)),
                    _ => return None,
                }
            }
            0xc3 => return Some((offset, map)),
            _ => return None,
        }
    }
    None
}

pub(crate) fn lfsr_al_maps(decoded: &[u8]) -> Vec<(usize, Box<[u8; 256]>)> {
    let mut candidates = Vec::new();
    for start in 0..decoded.len() {
        let available = (decoded.len() - start).min(MAX_AL_PROGRAM_BYTES);
        let program = lfsr_decode_program(&decoded[start..start + available]);
        let Some((length, map)) = parse_al_byte_map(&program[..available]) else {
            continue;
        };
        if length < MIN_AL_PROGRAM_BYTES
            || candidates.iter().any(|(_, existing)| existing == &map)
            || candidates.len() >= MAX_AL_MAP_CANDIDATES
        {
            continue;
        }
        candidates.push((length, map));
    }
    candidates
}

pub(super) fn patch_nested_runtime_header(
    mapped: &[u8],
    size_of_headers: usize,
    old_rva: u32,
    new_rva: u32,
    first_size: u32,
    second_rva: u32,
    second_size: u32,
) -> Option<Vec<u8>> {
    let header = mapped.get(..size_of_headers)?;
    let mut matches = header
        .windows(2 * size_of::<u32>())
        .enumerate()
        .filter(|(offset, bytes)| {
            offset.is_multiple_of(size_of::<u32>())
                && read_u32_at(bytes, 0) == Some(old_rva)
                && read_u32_at(bytes, size_of::<u32>()) == Some(first_size)
        })
        .map(|(offset, _)| offset);
    let offset = matches.next()?;
    if matches.next().is_some() || offset.checked_add(4 * size_of::<u32>())? > header.len() {
        return None;
    }
    let mut patched = header.to_vec();
    for (index, value) in [new_rva, first_size, second_rva, second_size]
        .into_iter()
        .enumerate()
    {
        let position = offset + index * size_of::<u32>();
        patched[position..position + size_of::<u32>()].copy_from_slice(&value.to_le_bytes());
    }
    Some(patched)
}

pub(crate) fn amd64_runtime_header_checksums(
    mapped: &[u8],
    pe: &Pe,
    staged_outer: &[u8],
    stage_range: Range<usize>,
    table: &[u32; 256],
) -> Result<Vec<u32>> {
    const IMPORT_DIRECTORY: usize = 1;
    const RESOURCE_DIRECTORY: usize = 2;
    const BASE_RELOCATION_DIRECTORY: usize = 5;
    const COM_DESCRIPTOR_DIRECTORY: usize = 14;
    const MIN_HEADER_RANGE_COUNT: usize = 3;
    const MAX_HEADER_RANGE_COUNT: usize = 8;
    const MAX_HEADER_CANDIDATES: usize = 128;

    let Some(header) = mapped.get(..pe.size_of_headers as usize) else {
        return Ok(Vec::new());
    };
    let Some(import) = pe.directories.get(IMPORT_DIRECTORY).copied() else {
        return Ok(Vec::new());
    };
    if import.is_empty() {
        return Ok(Vec::new());
    }
    let resource = pe
        .directories
        .get(RESOURCE_DIRECTORY)
        .copied()
        .filter(|directory| !directory.is_empty());

    let mut import_rvas = vec![import.virtual_address];
    for offset in
        (0..staged_outer.len().saturating_sub(4 * size_of::<u32>() - 1)).step_by(size_of::<u32>())
    {
        let values = [
            read_u32_at(staged_outer, offset),
            read_u32_at(staged_outer, offset + 4),
            read_u32_at(staged_outer, offset + 8),
            read_u32_at(staged_outer, offset + 12),
        ];
        let [Some(size), Some(new_rva), Some(old_rva), Some(_)] = values else {
            continue;
        };
        if size != import.size
            || old_rva != import.virtual_address
            || new_rva == old_rva
            || pe
                .section_for_rva_range(new_rva, usize::try_from(size).unwrap_or(usize::MAX))
                .is_err()
        {
            continue;
        }
        if !import_rvas.contains(&new_rva) {
            import_rvas.push(new_rva);
        }
    }

    let mut resources = vec![(0, 0)];
    if let Some(resource) = resource {
        resources[0] = (resource.virtual_address, resource.size);
        let resource_size_limit = resource.size.saturating_add(pe.section_alignment);
        for offset in (0..staged_outer.len().saturating_sub(2 * size_of::<u32>() - 1))
            .step_by(size_of::<u32>())
        {
            let (Some(rva), Some(size)) = (
                read_u32_at(staged_outer, offset),
                read_u32_at(staged_outer, offset + 4),
            ) else {
                continue;
            };
            if !rva.is_multiple_of(pe.section_alignment)
                || size < resource.size
                || size > resource_size_limit
                || !size.is_multiple_of(8)
                || rva
                    .checked_add(size)
                    .is_none_or(|end| end > pe.size_of_image)
            {
                continue;
            }
            if !resources.contains(&(rva, size)) {
                resources.push((rva, size));
            }
        }
    }

    let nt_headers_rva = pe
        .opt
        .checked_sub(24)
        .context("AMD64 optional-header offset precedes NT headers")?;
    let mut header_ranges = Vec::<Vec<Range<usize>>>::new();
    for offset in (0..staged_outer
        .len()
        .saturating_sub(MIN_HEADER_RANGE_COUNT * 2 * size_of::<u32>() - 1))
        .step_by(size_of::<u32>())
    {
        let mut ranges = Vec::with_capacity(MAX_HEADER_RANGE_COUNT);
        for index in 0..MAX_HEADER_RANGE_COUNT {
            let pair = offset + index * 2 * size_of::<u32>();
            if pair.saturating_add(2 * size_of::<u32>()) > stage_range.end {
                break;
            }
            let (Some(start), Some(length)) = (
                read_u32_at(staged_outer, pair),
                read_u32_at(staged_outer, pair + 4),
            ) else {
                break;
            };
            let (Ok(start), Ok(length)) = (usize::try_from(start), usize::try_from(length)) else {
                break;
            };
            let Some(end) = start.checked_add(length) else {
                break;
            };
            if (index == 0 && start != nt_headers_rva)
                || length == 0
                || end > header.len()
                || ranges
                    .last()
                    .is_some_and(|previous: &Range<usize>| previous.end > start)
            {
                break;
            }
            ranges.push(start..end);
            if ranges.len() >= MIN_HEADER_RANGE_COUNT && !header_ranges.contains(&ranges) {
                ensure!(
                    header_ranges.len() < MAX_HEADER_CANDIDATES,
                    "AMD64 runtime-header range discovery exceeds its candidate cap"
                );
                header_ranges.push(ranges.clone());
            }
        }
    }

    ensure!(
        import_rvas.len() <= MAX_HEADER_CANDIDATES
            && resources.len() <= MAX_HEADER_CANDIDATES
            && header_ranges.len() <= MAX_HEADER_CANDIDATES,
        "AMD64 runtime-header discovery exceeds its candidate cap"
    );
    let directory_base = pe.number_of_rva_and_sizes_offset() + size_of::<u32>();
    let import_offset = directory_base + IMPORT_DIRECTORY * 2 * size_of::<u32>();
    let resource_offset = directory_base + RESOURCE_DIRECTORY * 2 * size_of::<u32>();
    let relocation_offset = directory_base + BASE_RELOCATION_DIRECTORY * 2 * size_of::<u32>();
    let com_descriptor_offset = directory_base + COM_DESCRIPTOR_DIRECTORY * 2 * size_of::<u32>();
    let mut checksums = Vec::new();
    for &import_rva in import_rvas.iter().rev() {
        for &(resource_rva, resource_size) in resources.iter().rev() {
            let mut patched = header.to_vec();
            patched[import_offset..import_offset + 4].copy_from_slice(&import_rva.to_le_bytes());
            patched[resource_offset..resource_offset + 4]
                .copy_from_slice(&resource_rva.to_le_bytes());
            patched[resource_offset + 4..resource_offset + 8]
                .copy_from_slice(&resource_size.to_le_bytes());
            patched[relocation_offset..relocation_offset + 8].fill(0);
            let mut variants = vec![patched];
            if pe
                .directories
                .get(COM_DESCRIPTOR_DIRECTORY)
                .is_some_and(|directory| !directory.is_empty())
            {
                let mut without_com = variants[0].clone();
                without_com[com_descriptor_offset..com_descriptor_offset + 8].fill(0);
                variants.push(without_com);
            }
            for patched in variants {
                for ranges in header_ranges.iter().rev() {
                    let checksum = ranges.iter().fold(0u32, |checksum, range| {
                        checksum ^ crackproof_checksum(&patched[range.clone()], table)
                    });
                    if !checksums.contains(&checksum) {
                        ensure!(
                            checksums.len() < MAX_HEADER_CANDIDATES,
                            "AMD64 runtime-header checksum discovery exceeds its candidate cap"
                        );
                        checksums.push(checksum);
                    }
                }
            }
        }
    }
    if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some() {
        eprintln!(
            "nested header candidates: imports={import_rvas:x?} resources={resources:x?} ranges={header_ranges:?} checksums={checksums:x?}"
        );
    }
    Ok(checksums)
}

pub(super) fn discover_nested_records(
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    stage_range: Range<usize>,
) -> Result<Vec<NestedRecord>> {
    let mut records = Vec::new();
    for descriptor_offset in (stage_range.start..stage_range.end.saturating_sub(A_RECORD_SIZE - 1))
        .step_by(size_of::<u32>())
    {
        let Some(bytes) = staged_outer.get(descriptor_offset..descriptor_offset + A_RECORD_SIZE)
        else {
            continue;
        };
        let Some(source_rva) = read_u32_at(bytes, 0) else {
            continue;
        };
        let Some(encoded_length) = read_u32_at(bytes, 4) else {
            continue;
        };
        let Some(destination_rva) = read_u32_at(bytes, 8) else {
            continue;
        };
        let Some(destination_length) = read_u32_at(bytes, 12) else {
            continue;
        };
        if encoded_length == 0
            || destination_length <= encoded_length
            || nested_outer_range(bootstrap, staged_outer.len(), source_rva, encoded_length)
                .is_none()
            || nested_outer_range(
                bootstrap,
                staged_outer.len(),
                destination_rva,
                destination_length,
            )
            .is_none()
        {
            continue;
        }
        let candidate = NestedRecord {
            descriptor_offset,
            source_rva,
            encoded_length,
            destination_rva,
            destination_length,
        };
        if !records.iter().any(|record| record == &candidate) {
            ensure!(
                records.len() < MAX_NESTED_RECORD_CANDIDATES,
                "nested stage produced too many expanding record candidates"
            );
            records.push(candidate);
        }
    }
    Ok(records)
}

fn discover_nested_spans(
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    stage_range: Range<usize>,
) -> Result<Vec<NestedSpan>> {
    let mut spans = Vec::new();
    for descriptor_offset in (stage_range.start
        ..stage_range.end.saturating_sub(2 * size_of::<u32>() - 1))
        .step_by(size_of::<u32>())
    {
        let Some(rva) = read_u32_at(staged_outer, descriptor_offset) else {
            continue;
        };
        let Some(length) = read_u32_at(staged_outer, descriptor_offset + size_of::<u32>()) else {
            continue;
        };
        if length == 0 || nested_outer_range(bootstrap, staged_outer.len(), rva, length).is_none() {
            continue;
        }
        ensure!(
            spans.len() < MAX_NESTED_SPAN_CANDIDATES,
            "nested stage produced too many bounded span candidates"
        );
        spans.push(NestedSpan {
            descriptor_offset,
            rva,
            length,
        });
    }
    Ok(spans)
}

fn nested_checksum_bases(
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    spans: &[NestedSpan],
    header_checksum: u32,
    table: &[u32; 256],
    extended_profile: bool,
) -> Vec<u32> {
    let mut checksums = Vec::with_capacity(spans.len());
    for span in spans {
        let range = nested_outer_range(bootstrap, staged_outer.len(), span.rva, span.length)
            .expect("validated nested span remains bounded");
        checksums.push(crackproof_checksum(&staged_outer[range], table));
    }
    let mut bases = vec![header_checksum];
    for &checksum in &checksums {
        let value = header_checksum ^ checksum;
        if !bases.contains(&value) {
            bases.push(value);
        }
    }
    for (index, pair) in spans.windows(2).enumerate() {
        if pair[1].descriptor_offset == pair[0].descriptor_offset + 2 * size_of::<u32>() {
            let value = header_checksum ^ checksums[index] ^ checksums[index + 1];
            if !bases.contains(&value) {
                bases.push(value);
            }
        }
    }
    if extended_profile {
        let mut suffix = 0u32;
        for index in (0..spans.len()).rev() {
            if index + 1 == spans.len()
                || spans[index + 1].descriptor_offset
                    != spans[index].descriptor_offset + 2 * size_of::<u32>()
            {
                suffix = 0;
            }
            suffix ^= checksums[index];
            let value = header_checksum ^ suffix;
            if !bases.contains(&value) {
                bases.push(value);
            }
        }
    }
    bases
}

pub(super) fn push_nested_scalar_variants(
    values: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
    value: u32,
) -> Result<()> {
    for candidate in [
        value,
        !value,
        value.wrapping_add(NESTED_STAGE_SUM_FOUR),
        value.wrapping_add(NESTED_STAGE_SUM_THREE),
    ] {
        if !seen.insert(candidate) {
            continue;
        }
        ensure!(
            values.len() < MAX_NESTED_SCALAR_CANDIDATES,
            "nested stage produced too many scalar candidates"
        );
        values.push(candidate);
    }
    Ok(())
}

pub(super) fn push_nested_adjacent_scalar_variants(
    values: &mut Vec<u32>,
    seen: &mut HashSet<u32>,
    previous: &mut Option<u32>,
    value: u32,
) -> Result<()> {
    push_nested_scalar_variants(values, seen, value)?;
    if let Some(previous) = *previous {
        push_nested_scalar_variants(values, seen, previous ^ value)?;
    }
    *previous = Some(value);
    Ok(())
}

/// Scalar values with explicit metadata references precede bounded raw-word fallbacks.
/// `values[..direct_len]` records that stronger-evidence prefix for diagnostics.
struct NestedScalarCandidates {
    values: Vec<u32>,
    direct_len: usize,
}

#[allow(clippy::too_many_arguments)]
fn nested_scalar_candidates(
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    stage_range: Range<usize>,
    spans: &[NestedSpan],
    output_ranges: &[Range<usize>],
    include_outputs: bool,
    image_base: u64,
    extended_profile: bool,
) -> Result<NestedScalarCandidates> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();

    let max_scalar_offset = output_ranges
        .iter()
        .map(Range::len)
        .max()
        .unwrap_or(0)
        .saturating_sub(size_of::<u32>());
    let mut scalar_offsets = Vec::new();
    for bytes in output_ranges
        .iter()
        .rev()
        .map(|range| &staged_outer[range.clone()])
        .chain(std::iter::once(&staged_outer[stage_range.clone()]))
    {
        for encoded in bytes.windows(size_of::<u32>()) {
            let offset = u32::from_le_bytes(encoded.try_into().expect("dword window"));
            if offset == 0
                || offset as usize > max_scalar_offset
                || !offset.is_multiple_of(size_of::<u32>() as u32)
                || scalar_offsets.contains(&offset)
            {
                continue;
            }
            if scalar_offsets.len() == 256 {
                break;
            }
            scalar_offsets.push(offset);
        }
    }
    if include_outputs {
        'contexts: for context in output_ranges.iter().rev() {
            for &offset in &scalar_offsets {
                let Some(target_offset) = context.start.checked_add(offset as usize) else {
                    continue;
                };
                if target_offset
                    .checked_add(size_of::<u32>())
                    .is_none_or(|end| end > context.end)
                {
                    continue;
                }
                let Some(value) = read_u32_at(staged_outer, target_offset) else {
                    continue;
                };
                if values.len() > MAX_NESTED_SCALAR_CANDIDATES.saturating_sub(4) {
                    break 'contexts;
                }
                push_nested_scalar_variants(&mut values, &mut seen, value)?;
            }
        }
    }

    for span in spans {
        let start = span
            .descriptor_offset
            .saturating_sub(4 * size_of::<u32>())
            .max(stage_range.start);
        let end = span
            .descriptor_offset
            .checked_add(6 * size_of::<u32>())
            .unwrap_or(stage_range.end)
            .min(stage_range.end);
        for offset in (start..end).step_by(size_of::<u32>()) {
            if let Some(value) = read_u32_at(staged_outer, offset) {
                push_nested_scalar_variants(&mut values, &mut seen, value)?;
            }
        }
    }

    if extended_profile {
        const SELECTOR_TABLE_WORDS: usize = 8;
        for offset in (stage_range.start
            ..stage_range
                .end
                .saturating_sub(SELECTOR_TABLE_WORDS * size_of::<u32>() - 1))
            .step_by(size_of::<u32>())
        {
            let words = std::array::from_fn::<_, SELECTOR_TABLE_WORDS, _>(|index| {
                read_u32_at(staged_outer, offset + index * size_of::<u32>()).unwrap_or(0)
            });
            if words[..4].contains(&0)
                || words[4..].iter().any(|&value| value != 0)
                || words[..4]
                    .iter()
                    .enumerate()
                    .any(|(index, value)| words[..index].contains(value))
            {
                continue;
            }
            for &value in &words[..4] {
                push_nested_scalar_variants(&mut values, &mut seen, value)?;
            }
        }
    }

    for pointer_bytes in staged_outer[stage_range.clone()].chunks_exact(size_of::<u32>()) {
        let pointer = u32::from_le_bytes(pointer_bytes.try_into().expect("dword chunk"));
        let relocated = u64::from(pointer)
            .checked_sub(image_base)
            .and_then(|value| u32::try_from(value).ok());
        for rva in [Some(pointer), relocated].into_iter().flatten() {
            let Some(target_offset) = rva
                .checked_sub(bootstrap.destination_rva)
                .and_then(|value| usize::try_from(value).ok())
            else {
                continue;
            };
            if !stage_range.contains(&target_offset) {
                continue;
            }
            for index in 0..4 {
                let Some(offset) = target_offset.checked_add(index * size_of::<u32>()) else {
                    break;
                };
                let Some(value) = read_u32_at(staged_outer, offset) else {
                    break;
                };
                push_nested_scalar_variants(&mut values, &mut seen, value)?;
            }
        }
    }
    // Exact offset and pointer relationships are stronger evidence than an arbitrary
    // dword in prior output. Preserve the latter only as a compatibility fallback.
    let direct_len = values.len();
    if include_outputs {
        let mut output_words = 0usize;
        for range in output_ranges.iter().rev() {
            let mut previous = None;
            for bytes in staged_outer[range.clone()].chunks_exact(size_of::<u32>()) {
                let value = u32::from_le_bytes(bytes.try_into().expect("dword chunk"));
                push_nested_adjacent_scalar_variants(&mut values, &mut seen, &mut previous, value)?;
                output_words += 1;
                if output_words >= MAX_NESTED_CONTEXT_WORDS {
                    break;
                }
            }
            if output_words >= MAX_NESTED_CONTEXT_WORDS {
                break;
            }
        }
    }
    Ok(NestedScalarCandidates { values, direct_len })
}

pub(crate) fn nested_transform_dwords_into(
    source: &[u8],
    destination: &mut [u8],
    mut key: u32,
    shift: u32,
) {
    assert_eq!(
        source.len(),
        destination.len(),
        "nested dword transform buffers differ in length"
    );
    let transformed_len = source.len() - source.len() % size_of::<u32>();
    for (index, (source, destination)) in source[..transformed_len]
        .chunks_exact(size_of::<u32>())
        .zip(destination[..transformed_len].chunks_exact_mut(size_of::<u32>()))
        .enumerate()
    {
        let index = index as u32;
        let ciphertext = u32::from_le_bytes(source.try_into().expect("dword chunk"));
        let plaintext = (ciphertext ^ key).rotate_right(shift).wrapping_sub(index);
        destination.copy_from_slice(&plaintext.to_le_bytes());
        key = key.wrapping_add(index);
    }
    destination[transformed_len..].copy_from_slice(&source[transformed_len..]);
}

fn commit_nested_output_maps(
    maps: &mut Vec<(usize, Box<[u8; 256]>)>,
    output_maps: Vec<(usize, Box<[u8; 256]>)>,
    map_generations: &mut usize,
) -> bool {
    if output_maps.is_empty() {
        return false;
    }
    maps.clear();
    maps.extend(output_maps);
    *map_generations += 1;
    *map_generations >= 2
}

#[allow(clippy::too_many_arguments)]
fn collect_nested_maps_from_graph_profile(
    outer: &[u8],
    bootstrap: PackedBootstrap,
    image_base: u64,
    stage_range: Range<usize>,
    stage_bytes: &[u8],
    header_checksum: u32,
    root_spans: &[NestedSpan],
    table: &[u32; 256],
    maps: &mut Vec<(usize, Box<[u8; 256]>)>,
    replayer: &mut impl NestedRecordReplayer,
    extended_profile: bool,
) -> Result<bool> {
    replayer.begin_graph(extended_profile)?;
    let mut staged_outer = outer.to_vec();
    staged_outer[stage_range.clone()].copy_from_slice(stage_bytes);
    let records = discover_nested_records(&staged_outer, bootstrap, stage_range.clone())?;
    let mut spans = discover_nested_spans(&staged_outer, bootstrap, stage_range.clone())?;
    for span in root_spans {
        if !spans.contains(span) {
            spans.push(*span);
        }
    }
    let mut output_ranges = Vec::<Range<usize>>::new();
    let mut processed = HashSet::new();
    let mut map_generations = 0usize;

    for _ in 0..records.len() {
        let checksum_bases = nested_checksum_bases(
            &staged_outer,
            bootstrap,
            &spans,
            header_checksum,
            table,
            extended_profile,
        );
        let mut progress = false;
        for output_pass in 0..=output_ranges.len() {
            let include_outputs = output_pass != 0;
            let output_contexts: &[Range<usize>] = if output_pass == 0 {
                &[]
            } else {
                std::slice::from_ref(&output_ranges[output_ranges.len() - output_pass])
            };
            let scalar_candidates = nested_scalar_candidates(
                &staged_outer,
                bootstrap,
                stage_range.clone(),
                &spans,
                output_contexts,
                include_outputs,
                image_base,
                extended_profile,
            )?;
            let mut keys = Vec::new();
            let key_capacity = checksum_bases
                .len()
                .saturating_mul(scalar_candidates.values.len())
                .min(MAX_NESTED_KEY_CANDIDATES);
            let mut key_set = HashSet::with_capacity(key_capacity);
            let mut direct_key_count = 0;
            for (scalar_index, &scalar) in scalar_candidates.values.iter().enumerate() {
                for &base in &checksum_bases {
                    let key = base ^ scalar;
                    if !key_set.insert(key) {
                        continue;
                    }
                    ensure!(
                        keys.len() < MAX_NESTED_KEY_CANDIDATES,
                        "nested stage produced too many key candidates"
                    );
                    keys.push(key);
                }
                if scalar_index + 1 == scalar_candidates.direct_len {
                    direct_key_count = keys.len();
                }
            }
            if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some() && output_pass == 0 {
                eprintln!(
                    "nested keys: bases={checksum_bases:x?} scalars={} direct={} keys={}",
                    scalar_candidates.values.len(),
                    scalar_candidates.direct_len,
                    keys.len()
                );
            }
            let ordered_records = records.iter().collect::<Vec<_>>();
            for record in ordered_records {
                if processed.contains(&record.descriptor_offset) {
                    continue;
                }
                // A unique metadata-rooted result needs no speculative search. If that
                // prefix is empty or ambiguous, validate the complete candidate set so
                // a uniquely structured bounded-output candidate can close the graph.
                let replayed = replay_nested_keys(
                    replayer,
                    &staged_outer,
                    bootstrap,
                    record,
                    &keys,
                    direct_key_count,
                    maps,
                    extended_profile,
                )?;
                let NestedReplay::Unique(output, selected_key) = replayed else {
                    continue;
                };
                let destination = nested_outer_range(
                    bootstrap,
                    staged_outer.len(),
                    record.destination_rva,
                    record.destination_length,
                )
                .expect("validated nested destination remains bounded");
                staged_outer[destination.clone()].copy_from_slice(&output);

                let context_length = destination
                    .len()
                    .min(MAX_NESTED_CONTEXT_WORDS * size_of::<u32>());
                let head = destination.start..destination.start + context_length;
                let tail = destination.end - context_length..destination.end;
                output_ranges.push(head.clone());
                if tail != head {
                    output_ranges.push(tail);
                }
                processed.insert(record.descriptor_offset);
                let output_maps = lfsr_al_maps(&output);
                if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some() {
                    eprintln!(
                        "nested commit record {:#x}: key={selected_key:#x} output_maps={}, generation={}",
                        record.descriptor_offset,
                        output_maps.len(),
                        map_generations + usize::from(!output_maps.is_empty())
                    );
                }
                if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some() {
                    let path = std::env::temp_dir().join(format!(
                        "crackproof_nested_{header_checksum:08x}_{:08x}_{selected_key:08x}_{map_generations}.bin",
                        record.descriptor_offset
                    ));
                    std::fs::write(path, &output).context("writing nested diagnostic output")?;
                }
                if commit_nested_output_maps(maps, output_maps, &mut map_generations) {
                    return Ok(true);
                }
                progress = true;
                break;
            }
            if progress {
                break;
            }
        }
        if !progress {
            break;
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn collect_nested_maps_from_graph(
    outer: &[u8],
    bootstrap: PackedBootstrap,
    image_base: u64,
    stage_range: Range<usize>,
    stage_bytes: &[u8],
    header_checksum: u32,
    root_spans: &[NestedSpan],
    table: &[u32; 256],
    maps: &mut Vec<(usize, Box<[u8; 256]>)>,
    replayer: &mut impl NestedRecordReplayer,
) -> Result<bool> {
    let initial_maps = maps.clone();
    if collect_nested_maps_from_graph_profile(
        outer,
        bootstrap,
        image_base,
        stage_range.clone(),
        stage_bytes,
        header_checksum,
        root_spans,
        table,
        maps,
        replayer,
        false,
    )? {
        return Ok(true);
    }
    maps.clone_from(&initial_maps);
    collect_nested_maps_from_graph_profile(
        outer,
        bootstrap,
        image_base,
        stage_range,
        stage_bytes,
        header_checksum,
        root_spans,
        table,
        maps,
        replayer,
        true,
    )
}

#[allow(clippy::vec_box)]
pub(crate) fn discover_nested_byte_maps(
    mapped: &[u8],
    pe: &Pe,
    bootstrap: PackedBootstrap,
    outer: &[u8],
    mut replayer: impl NestedRecordReplayer,
) -> Result<Vec<Box<[u8; 256]>>> {
    let table = crc32_table();
    let table_bytes = crc32_table_bytes(&table);
    let mut contexts = outer
        .windows(table_bytes.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == table_bytes).then_some(offset))
        .collect::<Vec<_>>();
    ensure!(
        contexts.len() <= MAX_NESTED_STAGE_CONTEXTS,
        "nested stage discovery produced too many CRC contexts"
    );
    contexts.sort_unstable();

    let mut maps = lfsr_al_maps(outer);
    if maps.is_empty() && pe.machine == Machine::I386 {
        for &table_offset in &contexts {
            let Some(context_start) = table_offset.checked_sub(0xa0) else {
                continue;
            };
            let at = |relative: usize| {
                table_offset
                    .checked_sub(relative)
                    .and_then(|offset| read_u32_at(outer, offset))
            };
            let Some(literal) = at(0x9c) else {
                continue;
            };
            let header_ranges = [0x84usize, 0x7c, 0x74]
                .map(|relative| (at(relative), at(relative - size_of::<u32>())));
            if at(0x6c) != Some(0)
                || at(0x68) != Some(0)
                || header_ranges
                    .iter()
                    .any(|(start, length)| start.is_none() || length.is_none_or(|value| value == 0))
            {
                continue;
            }
            let (Some(stage_rva), Some(stage_length)) = (at(0x44), at(0x40)) else {
                continue;
            };
            let (Some(checksum_rva), Some(checksum_length)) = (at(0x34), at(0x30)) else {
                continue;
            };
            let Some(stage_range) =
                nested_outer_range(bootstrap, outer.len(), stage_rva, stage_length)
            else {
                continue;
            };
            let Some(checksum_range) =
                nested_outer_range(bootstrap, outer.len(), checksum_rva, checksum_length)
            else {
                continue;
            };
            let (Some(old_rva), Some(new_rva), Some(first_size)) = (at(0x24), at(0x20), at(0x1c))
            else {
                continue;
            };
            let (Some(0), Some(second_rva), Some(second_size)) = (at(0x18), at(0x14), at(0x10))
            else {
                continue;
            };
            let Some(header) = patch_nested_runtime_header(
                mapped,
                pe.size_of_headers as usize,
                old_rva,
                new_rva,
                first_size,
                second_rva,
                second_size,
            ) else {
                continue;
            };
            let mut header_checksum = 0u32;
            let mut key = literal ^ crackproof_checksum(&outer[checksum_range], &table);
            let mut valid = true;
            for (start, length) in header_ranges {
                let (Some(start), Some(length)) = (start, length) else {
                    valid = false;
                    break;
                };
                let (Ok(start), Ok(length)) = (usize::try_from(start), usize::try_from(length))
                else {
                    valid = false;
                    break;
                };
                let Some(end) = start.checked_add(length) else {
                    valid = false;
                    break;
                };
                let Some(bytes) = header.get(start..end) else {
                    valid = false;
                    break;
                };
                let checksum = crackproof_checksum(bytes, &table);
                header_checksum ^= checksum;
                key ^= checksum;
            }
            if !valid {
                continue;
            }
            let root_spans = discover_nested_spans(outer, bootstrap, context_start..table_offset)?;
            for shift in [19u32, 21] {
                let Some(decoded) =
                    decode_nested_dword_stage(outer, stage_range.clone(), key, shift)
                else {
                    continue;
                };
                if collect_nested_maps_from_graph(
                    outer,
                    bootstrap,
                    pe.image_base,
                    stage_range.clone(),
                    &decoded,
                    header_checksum,
                    &root_spans,
                    &table,
                    &mut maps,
                    &mut replayer,
                )? {
                    return Ok(maps.into_iter().map(|(_, map)| map).collect());
                }
            }
        }
    }

    if maps.is_empty() {
        for &table_offset in &contexts {
            let context_start = table_offset.saturating_sub(0x180);
            let root_spans = discover_nested_spans(outer, bootstrap, context_start..table_offset)?;
            let header = &mapped[..pe.size_of_headers as usize];
            let mut combined_header_checksum = 0u32;
            for offset in (context_start..table_offset.saturating_sub(2 * size_of::<u32>() - 1))
                .step_by(size_of::<u32>())
            {
                let Some(start) =
                    read_u32_at(outer, offset).and_then(|value| usize::try_from(value).ok())
                else {
                    continue;
                };
                let Some(length) = read_u32_at(outer, offset + size_of::<u32>())
                    .and_then(|value| usize::try_from(value).ok())
                else {
                    continue;
                };
                let Some(bytes) = start
                    .checked_add(length)
                    .and_then(|end| (length != 0).then(|| header.get(start..end)).flatten())
                else {
                    continue;
                };
                combined_header_checksum ^= crackproof_checksum(bytes, &table);
            }
            let mut header_checksums = if combined_header_checksum == 0 {
                vec![0]
            } else {
                vec![0, combined_header_checksum]
            };
            if pe.machine == Machine::Amd64 {
                let derived = amd64_runtime_header_checksums(
                    mapped,
                    pe,
                    outer,
                    context_start..table_offset,
                    &table,
                )?;
                if !derived.is_empty() {
                    header_checksums = derived;
                }
                if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some() {
                    eprintln!(
                        "nested amd64 context {table_offset:#x}: header_checksums={header_checksums:x?}"
                    );
                }
            }
            for descriptor_offset in (context_start
                ..table_offset.saturating_sub(2 * size_of::<u32>() - 1))
                .step_by(size_of::<u32>())
            {
                let Some(stage_rva) = read_u32_at(outer, descriptor_offset) else {
                    continue;
                };
                let Some(stage_length) = read_u32_at(outer, descriptor_offset + size_of::<u32>())
                else {
                    continue;
                };
                let Some(stage_range) =
                    nested_outer_range(bootstrap, outer.len(), stage_rva, stage_length)
                else {
                    continue;
                };
                if stage_range.len() < A_RECORD_SIZE
                    || !stage_range.len().is_multiple_of(size_of::<u32>())
                {
                    continue;
                }
                let Some(initial_key) = read_u32_at(outer, stage_range.start) else {
                    continue;
                };
                for shift in [19u32, 21] {
                    let Some(decoded) =
                        decode_nested_dword_stage(outer, stage_range.clone(), initial_key, shift)
                    else {
                        continue;
                    };
                    let mut staged_outer = outer.to_vec();
                    staged_outer[stage_range.clone()].copy_from_slice(&decoded);
                    if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some() {
                        let record_count =
                            discover_nested_records(&staged_outer, bootstrap, stage_range.clone())?
                                .len();
                        eprintln!(
                            "nested stage {descriptor_offset:#x}: rva={stage_rva:#x} length={stage_length:#x} key={initial_key:#x} shift={shift} records={record_count}"
                        );
                    }
                    if discover_nested_records(&staged_outer, bootstrap, stage_range.clone())?
                        .is_empty()
                    {
                        continue;
                    }
                    let mut candidate_maps = Vec::new();
                    let mut graph_complete = false;
                    for &header_checksum in &header_checksums {
                        graph_complete = collect_nested_maps_from_graph(
                            outer,
                            bootstrap,
                            pe.image_base,
                            stage_range.clone(),
                            &decoded,
                            header_checksum,
                            &root_spans,
                            &table,
                            &mut candidate_maps,
                            &mut replayer,
                        )?;
                        if graph_complete {
                            break;
                        }
                    }
                    for candidate in candidate_maps {
                        if !maps.iter().any(|(_, map)| map == &candidate.1) {
                            ensure!(
                                maps.len() < MAX_AL_MAP_CANDIDATES,
                                "nested root discovery produced too many byte maps"
                            );
                            maps.push(candidate);
                        }
                    }
                    if graph_complete {
                        return Ok(maps.into_iter().map(|(_, map)| map).collect());
                    }
                }
            }
        }
    }
    Ok(maps.into_iter().map(|(_, map)| map).collect())
}
