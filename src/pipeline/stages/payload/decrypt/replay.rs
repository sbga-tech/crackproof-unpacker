use std::mem::size_of;
use std::ops::Range;

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    ByteTransform, DecryptionDetails, SelectedAesContext, SelectedDecoder, SelectedDecryptionChain,
};
use anyhow::{Context, Result, ensure};
use rayon::prelude::*;
use tracing::{debug, info};

use crate::pe::Machine;
use crate::pipeline::stages::payload::bootstrap::PackedBootstrap;
#[cfg(test)]
use crate::pipeline::stages::payload::bootstrap::{
    bootstrap_source_file_range, derive_outer_source,
};
use crate::pipeline::stages::payload::nested::{
    MAX_NESTED_REPLAY_OUTPUTS, NestedRecord, NestedRecordReplayer, NestedReplay,
    discover_nested_byte_maps, has_lfsr_al_program_at_start, nested_outer_range,
    nested_transform_dwords_into,
};

use super::aes::{AES_256_KEY_SIZE, Aes256CbcDecryptor};
use super::decoder::{
    CustomDecodeError, CustomDecoderSource, decode_custom_stream_with_history_source_mode,
};
use super::grammar::BoundPayloadSource;
#[cfg(test)]
use super::grammar::derive_payload_stream_provenance;
use super::{
    ARecord, AesContextMatch, DecoderCandidate, DecryptedImage, custom_decoder_prefix_is_viable,
    decode_custom_stream_with_history, discover_a_record_run,
    discover_a_record_run_with_cancellation, discover_decoder_candidates,
    discover_decoder_candidates_with_cancellation, scan_aes_contexts_in_range,
    scan_aes_contexts_in_range_with_cancellation,
};
use super::{a_record_destination_range, merged_a_record_destination_ranges};

pub(super) const MAX_DECRYPTION_REPLAY_WORK: usize = 512 << 20;
pub(super) const MAX_DECRYPTION_REPLAY_PAIRS: usize = 64;
pub(super) const MAX_DECRYPTION_AGGREGATE_REPLAY_WORK: usize = 16 << 30;
const MAX_PARALLEL_REPLAY_SCRATCH_BYTES: usize = 256 << 20;

/// A bounded diagnostic produced when no replay chain can authenticate every
/// custom-coded A record.
#[derive(Debug)]
pub(crate) struct DecryptionSelectionError {
    pub(crate) decryption_details: DecryptionDetails,
}

impl std::fmt::Display for DecryptionSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("no AES-context and decoder-precursor chain replays every A record")
    }
}

impl std::error::Error for DecryptionSelectionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PayloadPostTransform {
    F8,
    None,
    ByteMap(Box<[u8; 256]>),
}

impl PayloadPostTransform {
    fn apply(&self, payload: &mut [u8]) {
        match self {
            Self::F8 => f8_transform(payload),
            Self::None => {}
            Self::ByteMap(map) => {
                for byte in payload {
                    *byte = map[usize::from(*byte)];
                }
            }
        }
    }

    fn profile(&self) -> ByteTransform {
        match self {
            Self::F8 => ByteTransform::FixedF8,
            Self::None => ByteTransform::Identity,
            Self::ByteMap(_) => ByteTransform::ByteMap,
        }
    }

    fn mapping(&self) -> [u8; 256] {
        match self {
            Self::F8 => std::array::from_fn(|value| f8_byte(value as u8)),
            Self::None => std::array::from_fn(|value| value as u8),
            Self::ByteMap(map) => **map,
        }
    }
}

#[derive(Clone)]
pub(super) struct DecryptionPlan {
    pub(super) records: Vec<ARecord>,
    pub(super) aes_key: [u8; AES_256_KEY_SIZE],
    pub(super) decoder: DecoderCandidate,
    pub(super) post_transform: PayloadPostTransform,
}

struct PreparedAesContext {
    evidence: AesContextMatch,
    decryptor: Aes256CbcDecryptor,
}

impl PreparedAesContext {
    fn new(evidence: AesContextMatch) -> Self {
        let decryptor = Aes256CbcDecryptor::new(&evidence.raw_key);
        Self {
            evidence,
            decryptor,
        }
    }
}

#[derive(Default)]
pub(super) struct ReplayBudget {
    work: usize,
}

impl ReplayBudget {
    fn reserve(&mut self, record: &ARecord) -> Result<()> {
        let record_work = record
            .encoded_length
            .checked_add(record.destination_length)
            .context("A-record replay work overflows")?;
        self.work = self
            .work
            .checked_add(record_work)
            .context("A-record replay work counter overflows")?;
        ensure!(
            self.work <= MAX_DECRYPTION_REPLAY_WORK,
            "AES-context and decoder replay exceeds its bounded work"
        );
        Ok(())
    }
}

pub(super) fn ensure_decryption_work_bound(records: &[ARecord]) -> Result<()> {
    let mut budget = ReplayBudget::default();
    for record in records {
        budget.reserve(record)?;
    }
    Ok(())
}

fn ensure_decryption_replay_pair_bound(
    contexts: usize,
    decoder_candidates: usize,
) -> Result<usize> {
    let pairs = contexts
        .checked_mul(decoder_candidates)
        .context("AES-context and decoder replay pair count overflows")?;
    ensure!(
        pairs <= MAX_DECRYPTION_REPLAY_PAIRS,
        "AES-context and decoder replay has {pairs} candidate pairs, exceeding its {MAX_DECRYPTION_REPLAY_PAIRS}-pair cap"
    );
    Ok(pairs)
}

pub(super) fn ensure_aggregate_replay_work_bound(records: &[ARecord], pairs: usize) -> Result<()> {
    let mut per_pair = 0usize;
    for record in records {
        if record.encoded_length == record.destination_length {
            continue;
        }
        let record_work = record
            .encoded_length
            .checked_add(record.destination_length)
            .context("custom A-record replay work overflows")?;
        per_pair = per_pair
            .checked_add(record_work)
            .context("per-pair custom A-record replay work overflows")?;
    }
    let aggregate = per_pair
        .checked_mul(pairs)
        .context("aggregate custom A-record replay work overflows")?;
    ensure!(
        aggregate <= MAX_DECRYPTION_AGGREGATE_REPLAY_WORK,
        "AES-context and decoder replay exceeds its {MAX_DECRYPTION_AGGREGATE_REPLAY_WORK}-byte aggregate work cap"
    );
    Ok(())
}

pub(super) fn f8_byte(mut value: u8) -> u8 {
    value ^= 0x71;
    value ^= 0x39;
    value = value.rotate_left(2);
    value = value.wrapping_sub(0xd4);
    value = value.wrapping_sub(0x5b);
    value = value.wrapping_sub(0x09);
    value = value.rotate_left(2);
    value = value.rotate_left(4);
    value = value.wrapping_sub(0x6a);
    value = value.wrapping_sub(1);
    value ^= 0x8f;
    value = value.wrapping_add(0xb5);
    value = value.wrapping_add(1);
    value = value.wrapping_sub(0x25);
    value = value.wrapping_add(2);
    value = value.rotate_left(3);
    value = value.rotate_left(5);
    value = value.wrapping_sub(0xce);
    value ^= 0x48;
    value ^= 0x9d;
    value ^= 0xd6;
    value = value.wrapping_sub(1);
    value = value.rotate_left(0);
    value = value.wrapping_sub(1);
    value = value.rotate_left(5);
    value = value.wrapping_add(1);
    value = value.wrapping_sub(1);
    value ^= 0x46;
    value = value.wrapping_add(1);
    value = value.wrapping_add(1);
    value = value.wrapping_sub(1);
    value = value.wrapping_add(1);
    value = value.rotate_left(5);
    value ^= 0xb5;
    value = value.wrapping_sub(0xd1);
    value = value.wrapping_sub(0x02);
    value = value.wrapping_sub(0xd4);
    value = value.rotate_left(7);
    value = value.wrapping_sub(0xcf);
    value = value.rotate_left(0);
    value.wrapping_sub(0x6c)
}

pub(super) fn f8_transform(bytes: &mut [u8]) {
    for byte in bytes {
        *byte = f8_byte(*byte);
    }
}

pub(super) struct NestedTransformedSource<'a> {
    source: &'a [u8],
    initial_key: u32,
    byte_map: Option<&'a [u8; 256]>,
    shift: u32,
    cached_indices: [usize; 2],
    cached_dwords: [u32; 2],
}

impl<'a> NestedTransformedSource<'a> {
    #[cfg(test)]
    pub(super) fn new(source: &'a [u8], initial_key: u32, byte_map: Option<&'a [u8; 256]>) -> Self {
        Self::with_shift(source, initial_key, byte_map, 19)
    }

    fn with_shift(
        source: &'a [u8],
        initial_key: u32,
        byte_map: Option<&'a [u8; 256]>,
        shift: u32,
    ) -> Self {
        Self {
            source,
            initial_key,
            byte_map,
            shift,
            cached_indices: [usize::MAX; 2],
            cached_dwords: [0; 2],
        }
    }

    #[inline]
    fn transformed_dword(&mut self, dword_index: usize) -> u32 {
        let slot = dword_index & 1;
        if self.cached_indices[slot] != dword_index {
            let offset = dword_index * size_of::<u32>();
            let ciphertext = u32::from_le_bytes(
                self.source[offset..offset + size_of::<u32>()]
                    .try_into()
                    .expect("bounded nested source dword"),
            );
            let index = u64::try_from(dword_index).expect("nested dword index fits u64");
            let key_delta = index * index.saturating_sub(1) / 2;
            let round_key = self.initial_key.wrapping_add(key_delta as u32);
            self.cached_dwords[slot] = (ciphertext ^ round_key)
                .rotate_right(self.shift)
                .wrapping_sub(index as u32);
            self.cached_indices[slot] = dword_index;
        }
        self.cached_dwords[slot]
    }
}

impl CustomDecoderSource for NestedTransformedSource<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.source.len()
    }

    #[inline]
    fn byte(&mut self, index: usize) -> u8 {
        let transformed_len = self.source.len() - self.source.len() % size_of::<u32>();
        let value = if index < transformed_len {
            let dword = self.transformed_dword(index / size_of::<u32>());
            (dword >> ((index % size_of::<u32>()) * 8)) as u8
        } else {
            self.source[index]
        };
        self.byte_map
            .map_or(value, |byte_map| byte_map[usize::from(value)])
    }
}

#[inline]
fn nested_decoder_prefix_is_viable(
    decoder: &DecoderCandidate,
    transformed_prefix: &[u8],
    byte_map: Option<&[u8; 256]>,
    source_len: usize,
    history_len: usize,
    destination_len: usize,
) -> bool {
    let mut mapped = [0u8; NESTED_REPLAY_PREFIX_BYTES];
    let prefix = if let Some(byte_map) = byte_map {
        for (destination, &source) in mapped.iter_mut().zip(transformed_prefix) {
            *destination = byte_map[usize::from(source)];
        }
        &mapped[..transformed_prefix.len()]
    } else {
        transformed_prefix
    };
    custom_decoder_prefix_is_viable(
        &decoder.table,
        prefix,
        source_len,
        history_len,
        destination_len,
        false,
    )
}

fn nested_replay_byte_maps<'a>(
    extended: bool,
    fixed_map: &'a [u8; 256],
    byte_maps: &'a [(usize, Box<[u8; 256]>)],
) -> impl Iterator<Item = Option<&'a [u8; 256]>> {
    std::iter::once(None)
        .chain(extended.then_some(Some(fixed_map)))
        .chain(byte_maps.iter().map(|(_, map)| Some(map.as_ref())))
}

const NESTED_REPLAY_PREFIX_BYTES: usize = 4;
const MIN_PARALLEL_NESTED_KEYS: usize = 4_096;
const MIN_NESTED_KEYS_PER_WORKER: usize = 1_024;
const MAX_PARALLEL_NESTED_BYTES: usize = 256 << 20;
const MAX_LOCAL_NESTED_OUTPUTS: usize = MAX_NESTED_REPLAY_OUTPUTS * 2 + 1;

struct NestedReplayCandidate {
    output: Vec<u8>,
    key: u32,
}

#[derive(Default)]
struct NestedReplayBatch {
    structured: Vec<NestedReplayCandidate>,
    unstructured: Vec<NestedReplayCandidate>,
    structured_truncated: bool,
    unstructured_truncated: bool,
}

impl NestedReplayBatch {
    fn consider(&mut self, output: &[u8], key: u32) {
        let structured = has_lfsr_al_program_at_start(output);
        let (candidates, truncated) = if structured {
            (&mut self.structured, &mut self.structured_truncated)
        } else {
            (&mut self.unstructured, &mut self.unstructured_truncated)
        };
        if *truncated
            || candidates
                .iter()
                .any(|candidate| candidate.output.as_slice() == output)
        {
            return;
        }
        if candidates.len() < MAX_LOCAL_NESTED_OUTPUTS {
            candidates.push(NestedReplayCandidate {
                output: output.to_vec(),
                key,
            });
        } else {
            *truncated = true;
        }
    }
}

struct NestedReplayScratch {
    transformed: Vec<u8>,
    mapped_payload: Vec<u8>,
    output: Vec<u8>,
    transformed_prefix: [u8; NESTED_REPLAY_PREFIX_BYTES],
}

impl NestedReplayScratch {
    fn new(source_len: usize, destination_len: usize, direct_record: bool) -> Self {
        Self {
            transformed: if direct_record {
                vec![0; source_len]
            } else {
                Vec::new()
            },
            mapped_payload: if direct_record {
                vec![0; source_len]
            } else {
                Vec::new()
            },
            output: vec![0; destination_len],
            transformed_prefix: [0; NESTED_REPLAY_PREFIX_BYTES],
        }
    }
}

fn nested_key_worker_count(key_count: usize, source_len: usize, destination_len: usize) -> usize {
    if key_count < MIN_PARALLEL_NESTED_KEYS {
        return 1;
    }
    let retained_outputs = MAX_LOCAL_NESTED_OUTPUTS * 2;
    let per_worker_bytes = source_len
        .checked_mul(2)
        .and_then(|source_bytes| {
            destination_len
                .checked_mul(retained_outputs + 1)
                .and_then(|output_bytes| source_bytes.checked_add(output_bytes))
        })
        .unwrap_or(usize::MAX);
    let memory_workers = MAX_PARALLEL_NESTED_BYTES
        .checked_div(per_worker_bytes)
        .unwrap_or(1)
        .max(1);
    let work_workers = key_count.div_ceil(MIN_NESTED_KEYS_PER_WORKER).max(1);
    rayon::current_num_threads()
        .min(memory_workers)
        .min(work_workers)
        .max(1)
}

#[allow(clippy::too_many_arguments)]
fn replay_nested_key_slice(
    aes_plaintext: &[u8],
    keys: &[u32],
    decoders: &[DecoderCandidate],
    replay_maps: &[Option<&[u8; 256]>],
    history: &[u8],
    destination_len: usize,
    exhaustive_rotations: bool,
    direct_record: bool,
    cancellation: Option<&CancellationToken>,
    scratch: &mut NestedReplayScratch,
) -> Result<NestedReplayBatch> {
    let prefix_len = aes_plaintext.len().min(scratch.transformed_prefix.len());
    let mut batch = NestedReplayBatch::default();
    for &key in keys {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        let shifts = if exhaustive_rotations {
            0..u32::BITS
        } else {
            19..20
        };
        for shift in shifts {
            if direct_record {
                nested_transform_dwords_into(aes_plaintext, &mut scratch.transformed, key, shift);
                for &byte_map in replay_maps {
                    let payload = if let Some(byte_map) = byte_map {
                        for (destination, &source) in
                            scratch.mapped_payload.iter_mut().zip(&scratch.transformed)
                        {
                            *destination = byte_map[usize::from(source)];
                        }
                        scratch.mapped_payload.as_slice()
                    } else {
                        scratch.transformed.as_slice()
                    };
                    batch.consider(payload, key);
                }
                continue;
            }

            nested_transform_dwords_into(
                &aes_plaintext[..prefix_len],
                &mut scratch.transformed_prefix[..prefix_len],
                key,
                shift,
            );
            for &byte_map in replay_maps {
                for decoder in decoders {
                    if !nested_decoder_prefix_is_viable(
                        decoder,
                        &scratch.transformed_prefix[..prefix_len],
                        byte_map,
                        aes_plaintext.len(),
                        history.len(),
                        destination_len,
                    ) {
                        continue;
                    }
                    let mut payload =
                        NestedTransformedSource::with_shift(aes_plaintext, key, byte_map, shift);
                    // The decoder reads only history and bytes below its current write cursor,
                    // so failed attempts do not require clearing the reusable destination.
                    if decode_custom_stream_with_history_source_mode(
                        &decoder.table,
                        &mut payload,
                        history,
                        &mut scratch.output,
                        false,
                    )
                    .is_ok()
                    {
                        batch.consider(&scratch.output, key);
                    }
                }
            }
        }
    }
    Ok(batch)
}

fn merge_nested_replay_batch(
    batch: NestedReplayBatch,
    structured_outputs: &mut Vec<(Vec<u8>, u32)>,
    outputs: &mut Vec<(Vec<u8>, u32)>,
    unstructured_overflow: &mut bool,
) -> Result<()> {
    for candidate in batch.structured {
        if structured_outputs
            .iter()
            .any(|(existing, _)| existing == &candidate.output)
        {
            continue;
        }
        ensure!(
            structured_outputs.len() < MAX_NESTED_REPLAY_OUTPUTS,
            "nested record replay produced too many structured outputs"
        );
        structured_outputs.push((candidate.output, candidate.key));
    }
    ensure!(
        !batch.structured_truncated,
        "nested replay structured reduction exceeded its canonical retention bound"
    );

    for candidate in batch.unstructured {
        if outputs
            .iter()
            .any(|(existing, _)| existing == &candidate.output)
        {
            continue;
        }
        if outputs.len() < MAX_NESTED_REPLAY_OUTPUTS {
            outputs.push((candidate.output, candidate.key));
        } else {
            *unstructured_overflow = true;
        }
    }
    if batch.unstructured_truncated {
        *unstructured_overflow = true;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn replay_nested_record(
    contexts: &[PreparedAesContext],
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    record: &NestedRecord,
    keys: &[u32],
    decoders: &[DecoderCandidate],
    byte_maps: &[(usize, Box<[u8; 256]>)],
    include_extended_maps: bool,
    exhaustive_rotations: bool,
    cancellation: Option<&CancellationToken>,
) -> Result<NestedReplay> {
    let source_range = nested_outer_range(
        bootstrap,
        staged_outer.len(),
        record.source_rva,
        record.encoded_length,
    )
    .expect("validated nested source remains bounded");
    let destination_range = nested_outer_range(
        bootstrap,
        staged_outer.len(),
        record.destination_rva,
        record.destination_length,
    )
    .expect("validated nested destination remains bounded");
    let history_start = destination_range
        .start
        .saturating_sub(std::mem::size_of::<u32>());
    let history = &staged_outer[history_start..destination_range.start];
    let source = &staged_outer[source_range];
    let direct_record = record.encoded_length == record.destination_length;
    let fixed_map = std::array::from_fn(|value| f8_byte(value as u8));
    let replay_maps =
        nested_replay_byte_maps(include_extended_maps, &fixed_map, byte_maps).collect::<Vec<_>>();
    let key_workers = nested_key_worker_count(keys.len(), source.len(), destination_range.len());
    let parallel_key_replay = key_workers > 1;
    let key_chunk_size = keys.len().div_ceil(key_workers).max(1);

    let mut outputs = Vec::<(Vec<u8>, u32)>::new();
    let mut structured_outputs = Vec::<(Vec<u8>, u32)>::new();
    let mut unstructured_overflow = false;
    let mut aes_plaintext = vec![0u8; source.len()];
    for context in contexts {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        aes_plaintext.copy_from_slice(source);
        context
            .decryptor
            .decrypt_full_blocks_in_place(&mut aes_plaintext);
        if parallel_key_replay {
            let mut batches = keys
                .par_chunks(key_chunk_size)
                .enumerate()
                .map(|(chunk_index, key_chunk)| {
                    let mut scratch = NestedReplayScratch::new(
                        source.len(),
                        destination_range.len(),
                        direct_record,
                    );
                    (
                        chunk_index,
                        replay_nested_key_slice(
                            &aes_plaintext,
                            key_chunk,
                            decoders,
                            &replay_maps,
                            history,
                            destination_range.len(),
                            exhaustive_rotations,
                            direct_record,
                            cancellation,
                            &mut scratch,
                        ),
                    )
                })
                .collect::<Vec<_>>();
            batches.sort_unstable_by_key(|(chunk_index, _)| *chunk_index);
            for (_, batch) in batches {
                merge_nested_replay_batch(
                    batch?,
                    &mut structured_outputs,
                    &mut outputs,
                    &mut unstructured_overflow,
                )?;
            }
        } else {
            let mut scratch =
                NestedReplayScratch::new(source.len(), destination_range.len(), direct_record);
            let batch = replay_nested_key_slice(
                &aes_plaintext,
                keys,
                decoders,
                &replay_maps,
                history,
                destination_range.len(),
                exhaustive_rotations,
                direct_record,
                cancellation,
                &mut scratch,
            )?;
            merge_nested_replay_batch(
                batch,
                &mut structured_outputs,
                &mut outputs,
                &mut unstructured_overflow,
            )?;
        }
    }
    if !structured_outputs.is_empty() || outputs.len() == 1 {
        debug!(
            descriptor_offset = record.descriptor_offset,
            structured_outputs = structured_outputs.len(),
            unstructured_outputs = outputs.len(),
            unstructured_overflow,
            key_candidates = keys.len(),
            input_maps = byte_maps.len(),
            parallel_key_replay,
            key_workers,
            key_chunk_size,
            "completed nested record replay"
        );
    }
    if structured_outputs.len() == 1 {
        let (output, key) = structured_outputs.pop().expect("one structured output");
        Ok(NestedReplay::Unique(output, key))
    } else if structured_outputs.len() > 1 || unstructured_overflow || outputs.len() > 1 {
        Ok(NestedReplay::Ambiguous)
    } else if outputs.len() == 1 {
        let (output, key) = outputs.pop().expect("one unstructured output");
        Ok(NestedReplay::Unique(output, key))
    } else {
        Ok(NestedReplay::NoMatch)
    }
}

#[cfg(test)]
mod nested_replay_parallel_tests {
    use super::*;
    use crate::pipeline::stages::payload::decrypt::decoder::{
        CUSTOM_DECODER_NODE_SIZE, CUSTOM_DECODER_ROOT_NODES,
    };

    fn root_literal_table(literal: u8) -> Vec<u8> {
        let mut table = vec![0; CUSTOM_DECODER_ROOT_NODES * CUSTOM_DECODER_NODE_SIZE];
        for node in table.chunks_exact_mut(CUSTOM_DECODER_NODE_SIZE) {
            node[..2].copy_from_slice(&(0x8000u16 | u16::from(literal)).to_le_bytes());
            node[2] = 4;
        }
        table
    }

    fn fixture() -> (
        Vec<PreparedAesContext>,
        Vec<u8>,
        PackedBootstrap,
        NestedRecord,
        Vec<u32>,
        Vec<DecoderCandidate>,
    ) {
        let contexts = vec![PreparedAesContext::new(AesContextMatch {
            file_offset: 0,
            seed: 0,
            raw_key: [0; AES_256_KEY_SIZE],
        })];
        let bootstrap = PackedBootstrap {
            descriptor_file_offset: 0,
            key: 0,
            destination_rva: 0,
            source_offset: 0,
            length: 3,
            source_rva: 0,
        };
        let record = NestedRecord {
            descriptor_offset: 0,
            source_rva: 0,
            encoded_length: 1,
            destination_rva: 1,
            destination_length: 2,
        };
        let keys = (0..u32::try_from(MIN_PARALLEL_NESTED_KEYS + 128).unwrap()).collect();
        let decoders = vec![DecoderCandidate {
            source_file_offset: 0,
            phase: 0,
            table: root_literal_table(0),
        }];
        (contexts, vec![0; 3], bootstrap, record, keys, decoders)
    }

    #[test]
    fn parallel_nested_keys_match_single_thread_reduction() {
        let (contexts, staged_outer, bootstrap, record, keys, decoders) = fixture();
        let replay = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    replay_nested_record(
                        &contexts,
                        &staged_outer,
                        bootstrap,
                        &record,
                        &keys,
                        &decoders,
                        &[],
                        false,
                        false,
                        None,
                    )
                })
                .unwrap()
        };

        let single_threaded = replay(1);
        let parallel = replay(4);
        assert_eq!(parallel, single_threaded);
        assert_eq!(parallel, NestedReplay::Unique(vec![0, 0], 0));
    }

    #[test]
    fn parallel_nested_keys_observe_cancellation() {
        let (contexts, staged_outer, bootstrap, record, keys, decoders) = fixture();
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let error = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap()
            .install(|| {
                replay_nested_record(
                    &contexts,
                    &staged_outer,
                    bootstrap,
                    &record,
                    &keys,
                    &decoders,
                    &[],
                    false,
                    false,
                    Some(&cancellation),
                )
            })
            .unwrap_err();

        assert_eq!(error.to_string(), "operation cancelled");
    }
}

struct DecryptionNestedReplayer<'a> {
    payload_source: &'a [u8],
    source_file_range: Range<usize>,
    decoders: &'a [DecoderCandidate],
    contexts: Vec<PreparedAesContext>,
    extended_profile: bool,
    exhaustive_rotations: bool,
    cancellation: Option<&'a CancellationToken>,
}

impl NestedRecordReplayer for DecryptionNestedReplayer<'_> {
    fn begin_graph(&mut self, extended_profile: bool, exhaustive_rotations: bool) -> Result<()> {
        self.extended_profile = extended_profile;
        self.exhaustive_rotations = exhaustive_rotations;
        let contexts = if let Some(cancellation) = self.cancellation {
            scan_aes_contexts_in_range_with_cancellation(
                self.payload_source,
                self.source_file_range.clone(),
                cancellation,
            )?
        } else {
            scan_aes_contexts_in_range(self.payload_source, self.source_file_range.clone())?
        };
        self.contexts = contexts.into_iter().map(PreparedAesContext::new).collect();
        for (context_index, context) in self.contexts.iter().enumerate() {
            debug!(
                context_index,
                file_offset = context.evidence.file_offset,
                seed = context.evidence.seed,
                raw_key_hex = %hex::encode(context.evidence.raw_key),
                "discovered nested AES context"
            );
        }
        Ok(())
    }

    fn replay(
        &mut self,
        staged_outer: &[u8],
        bootstrap: PackedBootstrap,
        record: &NestedRecord,
        keys: &[u32],
        byte_maps: &[(usize, Box<[u8; 256]>)],
    ) -> Result<NestedReplay> {
        let legacy = replay_nested_record(
            &self.contexts,
            staged_outer,
            bootstrap,
            record,
            keys,
            self.decoders,
            byte_maps,
            false,
            false,
            self.cancellation,
        )?;
        if !self.extended_profile || !matches!(legacy, NestedReplay::NoMatch) {
            return Ok(legacy);
        }
        replay_nested_record(
            &self.contexts,
            staged_outer,
            bootstrap,
            record,
            keys,
            self.decoders,
            byte_maps,
            true,
            self.exhaustive_rotations,
            self.cancellation,
        )
    }
}

fn transform_record_payload_into(
    payload: &mut Vec<u8>,
    packed: &[u8],
    stream_base: usize,
    record: &ARecord,
    decryptor: &Aes256CbcDecryptor,
) -> Result<()> {
    let start = stream_base
        .checked_add(record.source_offset)
        .context("A record stream start overflows")?;
    let end = start
        .checked_add(record.encoded_length)
        .context("A record stream end overflows")?;
    let source = packed
        .get(start..end)
        .context("validated A record stream range disappeared")?;
    payload.clear();
    payload
        .try_reserve_exact(source.len())
        .context("reserving A record transform payload")?;
    payload.extend_from_slice(source);
    decryptor.decrypt_full_blocks_in_place(payload);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CustomDecoderRejection {
    record_index: usize,
    error: CustomDecodeError,
}

fn decryption_details(
    records: &[ARecord],
    aes_key_candidates: usize,
    decoder_candidates: usize,
    byte_transform_candidates: usize,
) -> DecryptionDetails {
    let copied_chunk_count = records
        .iter()
        .filter(|record| record.encoded_length == record.destination_length)
        .count();
    DecryptionDetails {
        chunk_count: records.len(),
        copied_chunk_count,
        decoded_chunk_count: records.len() - copied_chunk_count,
        aes_key_candidates,
        decoder_candidates,
        byte_transform_candidates,
        ..DecryptionDetails::default()
    }
}

#[allow(clippy::too_many_arguments)]
fn chain_replays(
    packed: &[u8],
    stream_base: usize,
    replay: &mut [u8],
    records: &[ARecord],
    decryptor: &Aes256CbcDecryptor,
    decoder_table: &[u8],
    replay_budget: &mut ReplayBudget,
    post_transform: &PayloadPostTransform,
    payload: &mut Vec<u8>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<CustomDecoderRejection>> {
    for (record_index, record) in records.iter().enumerate() {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        replay_budget.reserve(record)?;
        transform_record_payload_into(payload, packed, stream_base, record, decryptor)?;
        post_transform.apply(payload);
        let destination_end = record
            .destination_rva
            .checked_add(record.destination_length)
            .context("validated replay destination end overflows")?;
        ensure!(
            destination_end <= replay.len(),
            "validated replay destination range disappeared"
        );
        let (before, destination_and_after) = replay.split_at_mut(record.destination_rva);
        let destination = &mut destination_and_after[..record.destination_length];
        if record.encoded_length == record.destination_length {
            destination.copy_from_slice(payload);
            continue;
        }
        let history = &before[before.len().saturating_sub(4)..];
        if let Err(error) =
            decode_custom_stream_with_history(decoder_table, payload, history, destination)
        {
            return Ok(Some(CustomDecoderRejection {
                record_index,
                error,
            }));
        }
    }
    Ok(None)
}

fn chain_prefixes_are_viable(
    packed: &[u8],
    stream_base: usize,
    records: &[ARecord],
    decryptor: &Aes256CbcDecryptor,
    decoder_table: &[u8],
    post_transform: &PayloadPostTransform,
) -> Result<bool> {
    let mut prefix = [0u8; 16];
    for record in records {
        if record.encoded_length == record.destination_length {
            continue;
        }
        let start = stream_base
            .checked_add(record.source_offset)
            .context("A record prefix start overflows")?;
        let prefix_len = record.encoded_length.min(prefix.len());
        let end = start
            .checked_add(prefix_len)
            .context("A record prefix end overflows")?;
        prefix[..prefix_len].copy_from_slice(
            packed
                .get(start..end)
                .context("validated A record prefix range disappeared")?,
        );
        decryptor.decrypt_full_blocks_in_place(&mut prefix[..prefix_len]);
        post_transform.apply(&mut prefix[..prefix_len]);
        let history_len = record.destination_rva.min(4);
        if !custom_decoder_prefix_is_viable(
            decoder_table,
            &prefix[..prefix_len.min(4)],
            record.encoded_length,
            history_len,
            record.destination_length,
            false,
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateIndex {
    ordinal: usize,
    context_index: usize,
    decoder_index: usize,
    transform_index: usize,
}

enum CandidateReplay {
    Rejected(CustomDecoderRejection),
    Authenticated,
}

struct CandidateReplayResult {
    candidate: CandidateIndex,
    result: Result<CandidateReplay>,
}

struct CandidateScratch {
    replay: Vec<u8>,
    payload: Vec<u8>,
}

impl CandidateScratch {
    fn new(mapped: &[u8], max_payload: usize) -> Result<Self> {
        let mut replay = Vec::new();
        replay
            .try_reserve_exact(mapped.len())
            .context("reserving candidate replay image")?;
        replay.extend_from_slice(mapped);
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(max_payload)
            .context("reserving candidate payload scratch")?;
        Ok(Self { replay, payload })
    }

    fn reset(&mut self, mapped: &[u8], ranges: &[Range<usize>]) {
        for range in ranges {
            self.replay[range.clone()].copy_from_slice(&mapped[range.clone()]);
        }
    }
}

fn candidate_replay_worker_count(candidate_count: usize, scratch_bytes: usize) -> usize {
    if candidate_count == 0 {
        return 0;
    }
    let memory_workers = MAX_PARALLEL_REPLAY_SCRATCH_BYTES
        .checked_div(scratch_bytes)
        .unwrap_or(candidate_count)
        .max(1);
    candidate_count
        .min(rayon::current_num_threads())
        .min(memory_workers)
        .max(1)
}

pub(super) fn select_decryption_plan(
    packed: &[u8],
    source_file_range: Range<usize>,
    stream_base: usize,
    mapped: &[u8],
    records: &[ARecord],
    decoder_candidates: Vec<DecoderCandidate>,
    post_transforms: &[PayloadPostTransform],
) -> Result<(DecryptionPlan, DecryptionDetails)> {
    select_decryption_plan_impl(
        packed,
        source_file_range,
        stream_base,
        mapped,
        records,
        decoder_candidates,
        post_transforms,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn select_decryption_plan_with_cancellation(
    packed: &[u8],
    source_file_range: Range<usize>,
    stream_base: usize,
    mapped: &[u8],
    records: &[ARecord],
    decoder_candidates: Vec<DecoderCandidate>,
    post_transforms: &[PayloadPostTransform],
    cancellation: &CancellationToken,
) -> Result<(DecryptionPlan, DecryptionDetails)> {
    select_decryption_plan_impl(
        packed,
        source_file_range,
        stream_base,
        mapped,
        records,
        decoder_candidates,
        post_transforms,
        Some(cancellation),
    )
}

#[allow(clippy::too_many_arguments)]
fn select_decryption_plan_impl(
    packed: &[u8],
    source_file_range: Range<usize>,
    stream_base: usize,
    mapped: &[u8],
    records: &[ARecord],
    decoder_candidates: Vec<DecoderCandidate>,
    post_transforms: &[PayloadPostTransform],
    cancellation: Option<&CancellationToken>,
) -> Result<(DecryptionPlan, DecryptionDetails)> {
    ensure!(
        records
            .iter()
            .any(|record| record.encoded_length != record.destination_length),
        "A-record graph has no custom-coded record to authenticate the AES and decoder chain"
    );
    ensure_decryption_work_bound(records)?;
    let context_matches = if let Some(cancellation) = cancellation {
        scan_aes_contexts_in_range_with_cancellation(packed, source_file_range, cancellation)?
    } else {
        scan_aes_contexts_in_range(packed, source_file_range)?
    };
    ensure!(
        !context_matches.is_empty(),
        "no self-validating AES context exists in the descriptor-derived source range"
    );
    let contexts = context_matches
        .into_iter()
        .map(PreparedAesContext::new)
        .collect::<Vec<_>>();
    let decoder_variants = decoder_candidates
        .len()
        .checked_mul(post_transforms.len())
        .context("decoder post-transform count overflows")?;
    let replay_pairs = ensure_decryption_replay_pair_bound(contexts.len(), decoder_variants)?;
    ensure_aggregate_replay_work_bound(records, replay_pairs)?;

    let mut decryption_details = decryption_details(
        records,
        contexts.len(),
        decoder_candidates.len(),
        post_transforms.len(),
    );
    let reset_ranges = merged_a_record_destination_ranges(records)?
        .into_iter()
        .map(|range| {
            let start =
                usize::try_from(range.start).context("replay reset start does not fit usize")?;
            let end = usize::try_from(range.end).context("replay reset end does not fit usize")?;
            Ok(start..end)
        })
        .collect::<Result<Vec<_>>>()?;
    let max_payload = records
        .iter()
        .map(|record| record.encoded_length)
        .max()
        .unwrap_or(0);
    let mut candidates = Vec::with_capacity(replay_pairs);
    for (context_index, context) in contexts.iter().enumerate() {
        for (decoder_index, decoder) in decoder_candidates.iter().enumerate() {
            for (transform_index, post_transform) in post_transforms.iter().enumerate() {
                if !chain_prefixes_are_viable(
                    packed,
                    stream_base,
                    records,
                    &context.decryptor,
                    &decoder.table,
                    post_transform,
                )? {
                    continue;
                }
                candidates.push(CandidateIndex {
                    ordinal: candidates.len(),
                    context_index,
                    decoder_index,
                    transform_index,
                });
            }
        }
    }
    ensure!(
        candidates.len() <= replay_pairs,
        "prefix-viable replay candidate count exceeds its bounded product"
    );
    if candidates.is_empty() {
        return Err(DecryptionSelectionError { decryption_details }.into());
    }

    let scratch_bytes = mapped
        .len()
        .checked_add(max_payload)
        .context("candidate replay scratch size overflows")?;
    let requested_workers = candidate_replay_worker_count(candidates.len(), scratch_bytes);
    let mut scratches = Vec::with_capacity(requested_workers);
    for worker_index in 0..requested_workers {
        match CandidateScratch::new(mapped, max_payload) {
            Ok(scratch) => scratches.push(scratch),
            Err(error) if !scratches.is_empty() => {
                debug!(
                    worker_index,
                    requested_workers,
                    active_workers = scratches.len(),
                    reason = %error,
                    "candidate replay scratch allocation reduced parallelism"
                );
                break;
            }
            Err(error) => return Err(error),
        }
    }
    let worker_count = scratches.len();
    debug!(
        candidate_count = candidates.len(),
        worker_count,
        scratch_bytes,
        scratch_budget = MAX_PARALLEL_REPLAY_SCRATCH_BYTES,
        "prepared deterministic candidate replay workers"
    );

    let mut lanes = (0..worker_count)
        .map(|_| Vec::new())
        .collect::<Vec<Vec<CandidateIndex>>>();
    for (index, candidate) in candidates.iter().copied().enumerate() {
        lanes[index % worker_count].push(candidate);
    }
    let work = scratches.into_iter().zip(lanes).collect::<Vec<_>>();
    let mut candidate_results = work
        .into_par_iter()
        .map(|(mut scratch, lane)| {
            let mut results = Vec::with_capacity(lane.len());
            let mut dirty = false;
            for candidate in lane {
                if dirty {
                    scratch.reset(mapped, &reset_ranges);
                }
                dirty = true;
                let context = &contexts[candidate.context_index];
                let decoder = &decoder_candidates[candidate.decoder_index];
                let post_transform = &post_transforms[candidate.transform_index];
                let mut replay_budget = ReplayBudget::default();
                let result = chain_replays(
                    packed,
                    stream_base,
                    &mut scratch.replay,
                    records,
                    &context.decryptor,
                    &decoder.table,
                    &mut replay_budget,
                    post_transform,
                    &mut scratch.payload,
                    cancellation,
                )
                .map(|rejection| match rejection {
                    Some(rejection) => CandidateReplay::Rejected(rejection),
                    None => CandidateReplay::Authenticated,
                });
                let failed = result.is_err();
                results.push(CandidateReplayResult { candidate, result });
                if failed {
                    break;
                }
            }
            results
        })
        .collect::<Vec<_>>()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    candidate_results.sort_unstable_by_key(|result| result.candidate.ordinal);

    let mut selected = None;
    let mut selected_is_ambiguous = false;
    for candidate_result in candidate_results {
        let candidate = candidate_result.candidate;
        let context = &contexts[candidate.context_index];
        let decoder = &decoder_candidates[candidate.decoder_index];
        let post_transform = &post_transforms[candidate.transform_index];
        debug!(
            context_index = candidate.context_index,
            aes_context_offset = context.evidence.file_offset,
            aes_seed = context.evidence.seed,
            raw_key_hex = %hex::encode(context.evidence.raw_key),
            decoder_index = candidate.decoder_index,
            decoder_offset = decoder.source_file_offset,
            decoder_phase = decoder.phase,
            transform_index = candidate.transform_index,
            transform = ?post_transform.profile(),
            "tested bounded decryption chain"
        );
        match candidate_result.result? {
            CandidateReplay::Rejected(rejection) => {
                debug!(
                    context_index = candidate.context_index,
                    decoder_index = candidate.decoder_index,
                    transform_index = candidate.transform_index,
                    chunk_index = rejection.record_index,
                    reason = %rejection.error,
                    "decryption chain rejected"
                );
            }
            CandidateReplay::Authenticated => {
                if selected.is_some() {
                    selected_is_ambiguous = true;
                    debug!(
                        context_index = candidate.context_index,
                        decoder_index = candidate.decoder_index,
                        transform_index = candidate.transform_index,
                        "additional decryption chain authenticated"
                    );
                } else {
                    selected = Some(candidate);
                }
            }
        }
    }
    ensure!(
        !selected_is_ambiguous,
        "multiple AES-context, post-transform, and decoder-precursor chains replay every A record"
    );
    let Some(selected) = selected else {
        return Err(DecryptionSelectionError { decryption_details }.into());
    };
    let context = &contexts[selected.context_index];
    let decoder = &decoder_candidates[selected.decoder_index];
    let post_transform = &post_transforms[selected.transform_index];
    let byte_map = post_transform.mapping();
    decryption_details.selected_chain = Some(SelectedDecryptionChain {
        aes: SelectedAesContext {
            file_offset: context.evidence.file_offset,
            seed: context.evidence.seed,
            raw_key_hex: hex::encode(context.evidence.raw_key),
        },
        decoder: SelectedDecoder {
            source_file_offset: decoder.source_file_offset,
            phase: decoder.phase,
            table_nodes: decoder.table.len() / 3,
        },
        byte_transform: post_transform.profile(),
        byte_map: byte_map.to_vec(),
    });
    info!(
        aes_context_offset = context.evidence.file_offset,
        aes_seed = context.evidence.seed,
        decoder_offset = decoder.source_file_offset,
        decoder_phase = decoder.phase,
        transform = ?post_transform.profile(),
        byte_map_hex = %hex::encode(byte_map),
        "selected unique decryption chain"
    );
    Ok((
        DecryptionPlan {
            records: records.to_vec(),
            aes_key: context.evidence.raw_key,
            decoder: decoder.clone(),
            post_transform: post_transform.clone(),
        },
        decryption_details,
    ))
}

pub(super) fn apply_decryption_plan(
    packed: &[u8],
    stream_base: usize,
    mapped: &mut [u8],
    plan: DecryptionPlan,
) -> Result<()> {
    apply_decryption_plan_impl(packed, stream_base, mapped, plan, None)
}

fn apply_decryption_plan_with_cancellation(
    packed: &[u8],
    stream_base: usize,
    mapped: &mut [u8],
    plan: DecryptionPlan,
    cancellation: &CancellationToken,
) -> Result<()> {
    apply_decryption_plan_impl(packed, stream_base, mapped, plan, Some(cancellation))
}

fn apply_decryption_plan_impl(
    packed: &[u8],
    stream_base: usize,
    mapped: &mut [u8],
    plan: DecryptionPlan,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let mut payload = Vec::new();
    let decryptor = Aes256CbcDecryptor::new(&plan.aes_key);
    for record in plan.records {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        transform_record_payload_into(&mut payload, packed, stream_base, &record, &decryptor)?;
        plan.post_transform.apply(&mut payload);
        let destination_end = record
            .destination_rva
            .checked_add(record.destination_length)
            .context("validated replay destination end overflows")?;
        ensure!(
            destination_end <= mapped.len(),
            "validated replay destination range disappeared"
        );
        let (before, destination_and_after) = mapped.split_at_mut(record.destination_rva);
        let destination = &mut destination_and_after[..record.destination_length];
        if record.encoded_length == record.destination_length {
            destination.copy_from_slice(&payload);
        } else {
            let history = &before[before.len().saturating_sub(4)..];
            decode_custom_stream_with_history(&plan.decoder.table, &payload, history, destination)
                .context("selected custom decoder chain no longer replays")?;
        }
    }
    Ok(())
}

pub(super) fn recover_a_record_payload(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<DecryptedImage> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let packed = source.packed;
    let pe = source.pe;
    let payload_source = source.payload_source;
    let bootstrap = source.bootstrap;
    let source_security_range = source.source_security_range;
    let source_file_range = source.source_file_range.clone();
    let source_start = source.source_start;
    let source_length = source_file_range.len();
    let stream_base = source.stream.base_file_offset;
    let outer = source.outer.as_slice();

    let mut mapped = pe.map_image(packed).context("mapping packed PE image")?;
    let outer_start = usize::try_from(bootstrap.destination_rva)
        .context("bootstrap destination RVA does not fit host address space")?;
    let outer_end = outer_start
        .checked_add(outer.len())
        .context("bootstrap destination range overflows")?;
    mapped
        .get_mut(outer_start..outer_end)
        .context("bootstrap destination range exceeds mapped image")?
        .copy_from_slice(outer);
    let records = if let Some(cancellation) = cancellation {
        discover_a_record_run_with_cancellation(
            outer,
            bootstrap,
            stream_base,
            payload_source.len(),
            mapped.len(),
            source_security_range,
            cancellation,
        )?
    } else {
        discover_a_record_run(
            outer,
            bootstrap,
            stream_base,
            payload_source.len(),
            mapped.len(),
            source_security_range,
        )?
    };
    let first_record = records
        .records
        .first()
        .expect("selected A-record run is nonempty");
    debug!(
        stream_base,
        first_source_offset = first_record.source_offset,
        first_encoded_length = first_record.encoded_length,
        max_source_end = records
            .records
            .iter()
            .map(|record| record.source_offset + record.encoded_length)
            .max()
            .expect("selected A-record run is nonempty"),
        "diagnostic A-record source geometry"
    );
    let mut destination_record_ranges = records
        .records
        .iter()
        .map(a_record_destination_range)
        .collect::<Result<Vec<_>>>()?;
    destination_record_ranges.sort_unstable_by_key(|range| range.start);
    let destination_ranges = merged_a_record_destination_ranges(&records.records)?;
    let decoder_candidates = if let Some(cancellation) = cancellation {
        discover_decoder_candidates_with_cancellation(
            source_start,
            payload_source,
            source_length,
            cancellation,
        )?
    } else {
        discover_decoder_candidates(source_start, payload_source, source_length)?
    };
    let nested_replayer = DecryptionNestedReplayer {
        payload_source,
        source_file_range: source_file_range.clone(),
        decoders: &decoder_candidates,
        contexts: Vec::new(),
        extended_profile: false,
        exhaustive_rotations: false,
        cancellation,
    };
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let mut post_transforms =
        discover_nested_byte_maps(&mapped, pe, bootstrap, outer, nested_replayer)?
            .into_iter()
            .map(PayloadPostTransform::ByteMap)
            .collect::<Vec<_>>();
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    post_transforms.push(PayloadPostTransform::F8);
    if pe.machine_kind() == Machine::Amd64 {
        post_transforms.push(PayloadPostTransform::None);
    }
    let mut unique_mappings = Vec::<[u8; 256]>::new();
    post_transforms.retain(|transform| {
        let mapping = transform.mapping();
        if unique_mappings.contains(&mapping) {
            false
        } else {
            unique_mappings.push(mapping);
            true
        }
    });
    let transform_count = post_transforms.len();
    let decoder_count = decoder_candidates.len();
    let (plan, decryption_details) = if let Some(cancellation) = cancellation {
        select_decryption_plan_with_cancellation(
            payload_source,
            source_file_range,
            stream_base,
            &mapped,
            &records.records,
            decoder_candidates,
            &post_transforms,
            cancellation,
        )
    } else {
        select_decryption_plan(
            payload_source,
            source_file_range,
            stream_base,
            &mapped,
            &records.records,
            decoder_candidates,
            &post_transforms,
        )
    }
    .with_context(|| {
        format!(
            "selecting from {transform_count} payload transforms and {decoder_count} decoder precursors"
        )
    })?;
    if let Some(cancellation) = cancellation {
        apply_decryption_plan_with_cancellation(
            payload_source,
            stream_base,
            &mut mapped,
            plan,
            cancellation,
        )?;
    } else {
        apply_decryption_plan(payload_source, stream_base, &mut mapped, plan)?;
    }
    for metadata_offset in [32usize, 64] {
        let start = outer_start + metadata_offset;
        let end = start + 144;
        let mut metadata = mapped[start..end].to_vec();
        super::records::f710_record_transform(&mut metadata, start as u32);
        let words = metadata[..32]
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("metadata dword")))
            .collect::<Vec<_>>();
        debug!(
            metadata_offset,
            ?words,
            "diagnostic decoded CrackProof metadata"
        );
    }
    Ok(DecryptedImage {
        destination_record_ranges,
        image: mapped,
        destination_ranges,
        decryption_details,
    })
}

#[cfg(test)]
pub(super) fn decrypt_bootstrap_into(
    packed: &[u8],
    bootstrap: PackedBootstrap,
    mapped: &mut [u8],
) -> Result<()> {
    let source_file_range = bootstrap_source_file_range(packed, bootstrap)?;
    let (source_start, outer) = derive_outer_source(packed, bootstrap)?;
    let source_length = source_file_range.len();
    let stream_base =
        derive_payload_stream_provenance(packed, bootstrap, &source_file_range, None)?
            .base_file_offset;

    let records = discover_a_record_run(
        &outer,
        bootstrap,
        stream_base,
        packed.len(),
        mapped.len(),
        None,
    )?;
    merged_a_record_destination_ranges(&records.records)?;
    let decoder_candidates = discover_decoder_candidates(source_start, packed, source_length)?;
    let (plan, _) = select_decryption_plan(
        packed,
        source_file_range,
        stream_base,
        mapped,
        &records.records,
        decoder_candidates,
        &[PayloadPostTransform::F8],
    )?;
    apply_decryption_plan(packed, stream_base, mapped, plan)
}
