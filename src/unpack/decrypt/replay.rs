use std::ops::Range;

use crate::report::{ByteTransform, CandidateRejection, DecryptionDetails};
use anyhow::{Context, Result, ensure};

use crate::pe::{Machine, Pe};
use crate::unpack::bootstrap::{PackedBootstrap, bootstrap_source_file_range, derive_outer_source};
use crate::unpack::nested::{
    MAX_NESTED_REPLAY_OUTPUTS, NestedRecord, NestedRecordReplayer, discover_nested_byte_maps,
    lfsr_al_maps, nested_apply_dword_transform, nested_outer_range,
};

use super::aes::AES_256_KEY_SIZE;
use super::decoder::CustomDecodeError;
use super::merged_a_record_destination_ranges;
use super::{
    ARecord, AesContextMatch, DecoderCandidate, DecryptedImage,
    aes256_cbc_decrypt_full_blocks_in_place, decode_custom_stream_with_history,
    decode_custom_stream_with_history_mode, discover_a_record_run, discover_decoder_candidates,
    ensure_source_excludes_security, scan_aes_contexts_in_range,
};

pub(super) const MAX_DECRYPTION_REPLAY_WORK: usize = 64 << 20;
pub(super) const MAX_DECRYPTION_REPLAY_PAIRS: usize = 64;
pub(super) const MAX_DECRYPTION_AGGREGATE_REPLAY_WORK: usize = 1 << 30;

const MAX_RECORDED_CUSTOM_DECODER_REJECTIONS: usize = 8;

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

fn replay_nested_record(
    contexts: &[AesContextMatch],
    staged_outer: &[u8],
    bootstrap: PackedBootstrap,
    record: &NestedRecord,
    keys: &[u32],
    decoders: &[DecoderCandidate],
    byte_maps: &[(usize, Box<[u8; 256]>)],
) -> Result<Option<(Vec<u8>, u32)>> {
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
    let mut outputs = Vec::<(Vec<u8>, u32)>::new();
    let mut structured_outputs = Vec::<(Vec<u8>, u32)>::new();
    let mut unstructured_overflow = false;
    let mut consider_output = |output: Vec<u8>, key: u32| -> Result<()> {
        if !lfsr_al_maps(&output).is_empty() {
            if !structured_outputs
                .iter()
                .any(|(existing, _)| existing == &output)
            {
                ensure!(
                    structured_outputs.len() < MAX_NESTED_REPLAY_OUTPUTS,
                    "nested record replay produced too many structured outputs"
                );
                structured_outputs.push((output, key));
            }
        } else if !outputs.iter().any(|(existing, _)| existing == &output) {
            if outputs.len() < MAX_NESTED_REPLAY_OUTPUTS {
                outputs.push((output, key));
            } else {
                unstructured_overflow = true;
            }
        }
        Ok(())
    };
    for context in contexts {
        let mut aes_plaintext = staged_outer[source_range.clone()].to_vec();
        aes256_cbc_decrypt_full_blocks_in_place(&mut aes_plaintext, &context.raw_key);
        for &key in keys {
            for shift in [19] {
                let mut transformed = aes_plaintext.clone();
                nested_apply_dword_transform(&mut transformed, key, shift);
                for map in std::iter::once(None).chain(byte_maps.iter().map(|(_, map)| Some(map))) {
                    let mut payload = transformed.clone();
                    if let Some(map) = map {
                        for byte in &mut payload {
                            *byte = map[usize::from(*byte)];
                        }
                    }
                    if record.encoded_length == record.destination_length {
                        consider_output(payload, key)?;
                        continue;
                    }
                    for decoder in decoders {
                        let mut output = vec![0u8; destination_range.len()];
                        if decode_custom_stream_with_history_mode(
                            &decoder.table,
                            &payload,
                            history,
                            &mut output,
                            false,
                        )
                        .is_ok()
                        {
                            consider_output(output, key)?;
                        }
                    }
                }
            }
        }
    }
    if std::env::var_os("CRACKPROOF_TRACE_NESTED").is_some()
        && (!structured_outputs.is_empty() || outputs.len() == 1)
    {
        eprintln!(
            "nested record {:#x}: structured={}, unstructured={}, overflow={}, keys={}, input_maps={}",
            record.descriptor_offset,
            structured_outputs.len(),
            outputs.len(),
            unstructured_overflow,
            keys.len(),
            byte_maps.len()
        );
    }
    if structured_outputs.len() == 1 {
        Ok(structured_outputs.pop())
    } else if structured_outputs.is_empty() && !unstructured_overflow && outputs.len() == 1 {
        Ok(outputs.pop())
    } else {
        Ok(None)
    }
}

struct DecryptionNestedReplayer<'a> {
    packed: &'a [u8],
    source_file_range: Range<usize>,
    decoders: &'a [DecoderCandidate],
    contexts: Vec<AesContextMatch>,
}

impl NestedRecordReplayer for DecryptionNestedReplayer<'_> {
    fn begin_graph(&mut self) -> Result<()> {
        self.contexts = scan_aes_contexts_in_range(self.packed, self.source_file_range.clone())?;
        Ok(())
    }

    fn replay(
        &mut self,
        staged_outer: &[u8],
        bootstrap: PackedBootstrap,
        record: &NestedRecord,
        keys: &[u32],
        byte_maps: &[(usize, Box<[u8; 256]>)],
    ) -> Result<Option<(Vec<u8>, u32)>> {
        replay_nested_record(
            &self.contexts,
            staged_outer,
            bootstrap,
            record,
            keys,
            self.decoders,
            byte_maps,
        )
    }
}

pub(super) fn transform_record_payload(
    packed: &[u8],
    stream_base: usize,
    record: &ARecord,
    key: &[u8; AES_256_KEY_SIZE],
) -> Result<Vec<u8>> {
    let start = stream_base
        .checked_add(record.source_offset)
        .context("A record stream start overflows")?;
    let end = start
        .checked_add(record.encoded_length)
        .context("A record stream end overflows")?;
    let source = packed
        .get(start..end)
        .context("validated A record stream range disappeared")?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(source.len())
        .context("reserving A record transform payload")?;
    payload.extend_from_slice(source);
    aes256_cbc_decrypt_full_blocks_in_place(&mut payload, key);
    Ok(payload)
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

fn record_replay_attempt(decryption_details: &mut DecryptionDetails) -> Result<()> {
    decryption_details.candidate_combinations_tested = decryption_details
        .candidate_combinations_tested
        .checked_add(1)
        .context("decryption replay attempt counter overflows")?;
    ensure!(
        decryption_details.candidate_combinations_tested <= MAX_DECRYPTION_REPLAY_PAIRS,
        "decryption replay attempts exceed their bounded candidate work"
    );
    Ok(())
}

fn record_replay_rejection(
    decryption_details: &mut DecryptionDetails,
    rejection: CustomDecoderRejection,
) -> Result<()> {
    decryption_details.candidate_combinations_rejected = decryption_details
        .candidate_combinations_rejected
        .checked_add(1)
        .context("decryption replay rejection counter overflows")?;
    ensure!(
        decryption_details.candidate_combinations_rejected
            <= decryption_details.candidate_combinations_tested,
        "decryption replay rejection count exceeds attempted chains"
    );
    if decryption_details.sample_rejections.len() < MAX_RECORDED_CUSTOM_DECODER_REJECTIONS {
        decryption_details
            .sample_rejections
            .push(CandidateRejection {
                chunk_index: rejection.record_index,
                reason: rejection.error.to_string(),
            });
    }
    Ok(())
}

fn chain_replays(
    packed: &[u8],
    stream_base: usize,
    mapped: &[u8],
    records: &[ARecord],
    key: &[u8; AES_256_KEY_SIZE],
    decoder_table: &[u8],
    replay_budget: &mut ReplayBudget,
    post_transform: &PayloadPostTransform,
) -> Result<Option<CustomDecoderRejection>> {
    let mut replay = Vec::new();
    replay
        .try_reserve_exact(mapped.len())
        .context("reserving custom-decoder replay image")?;
    replay.extend_from_slice(mapped);
    for (record_index, record) in records.iter().enumerate() {
        replay_budget.reserve(record)?;
        let mut payload = transform_record_payload(packed, stream_base, record, key)?;
        post_transform.apply(&mut payload);
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
            destination.copy_from_slice(&payload);
            continue;
        }
        let history = &before[before.len().saturating_sub(4)..];
        if let Err(error) =
            decode_custom_stream_with_history(decoder_table, &payload, history, destination)
        {
            return Ok(Some(CustomDecoderRejection {
                record_index,
                error,
            }));
        }
    }
    Ok(None)
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
    ensure!(
        records
            .iter()
            .any(|record| record.encoded_length != record.destination_length),
        "A-record graph has no custom-coded record to authenticate the AES and decoder chain"
    );
    ensure_decryption_work_bound(records)?;
    let contexts = scan_aes_contexts_in_range(packed, source_file_range)?;
    ensure!(
        !contexts.is_empty(),
        "no self-validating AES context exists in the descriptor-derived source range"
    );
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
    let mut selected = None;
    let mut selected_is_ambiguous = false;
    for context in contexts {
        for decoder in &decoder_candidates {
            for post_transform in post_transforms {
                record_replay_attempt(&mut decryption_details)?;
                let mut replay_budget = ReplayBudget::default();
                if let Some(rejection) = chain_replays(
                    packed,
                    stream_base,
                    mapped,
                    records,
                    &context.raw_key,
                    &decoder.table,
                    &mut replay_budget,
                    post_transform,
                )? {
                    record_replay_rejection(&mut decryption_details, rejection)?;
                    continue;
                }
                if selected.is_some() {
                    selected_is_ambiguous = true;
                    continue;
                }
                selected = Some(DecryptionPlan {
                    records: records.to_vec(),
                    aes_key: context.raw_key,
                    decoder: decoder.clone(),
                    post_transform: post_transform.clone(),
                });
                decryption_details.selected_byte_transform = Some(post_transform.profile());
            }
        }
    }
    ensure!(
        !selected_is_ambiguous,
        "multiple AES-context, post-transform, and decoder-precursor chains replay every A record"
    );
    match selected {
        Some(plan) => Ok((plan, decryption_details)),
        None => Err(DecryptionSelectionError { decryption_details }.into()),
    }
}

pub(super) fn apply_decryption_plan(
    packed: &[u8],
    stream_base: usize,
    mapped: &mut [u8],
    plan: DecryptionPlan,
) -> Result<()> {
    for record in plan.records {
        let mut payload = transform_record_payload(packed, stream_base, &record, &plan.aes_key)?;
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

/// Decrypts the packed A records selected by `bootstrap` into a fresh
/// RVA-mapped image.
///
/// `bootstrap` must originate from the unique structurally validated KONN
/// descriptor selected by the detection stage. This function performs every
/// remaining packed-only selection before it mutates the newly mapped image.
pub(crate) fn decrypt_packed_image(
    packed: &[u8],
    pe: &Pe,
    bootstrap: PackedBootstrap,
) -> Result<DecryptedImage> {
    let source_file_range = bootstrap_source_file_range(packed, bootstrap)?;
    let (source_start, outer) = derive_outer_source(packed, bootstrap)?;
    let source_length = source_file_range.len();
    let stream_base = source_file_range.end;
    let security_range = pe
        .security_directory_file_range(packed.len())
        .context("validating packed Security Directory against A-record sources")?;
    ensure_source_excludes_security(&source_file_range, security_range.as_ref())?;

    let mut mapped = pe.map_image(packed).context("mapping packed PE image")?;
    let records = discover_a_record_run(
        &outer,
        bootstrap,
        stream_base,
        packed.len(),
        mapped.len(),
        security_range.as_ref(),
    )?;
    let destination_ranges = merged_a_record_destination_ranges(&records.records)?;
    let decoder_candidates = discover_decoder_candidates(source_start, packed, source_length)?;
    let nested_replayer = DecryptionNestedReplayer {
        packed,
        source_file_range: source_file_range.clone(),
        decoders: &decoder_candidates,
        contexts: Vec::new(),
    };
    let mut post_transforms =
        discover_nested_byte_maps(&mapped, pe, bootstrap, &outer, nested_replayer)?
            .into_iter()
            .map(PayloadPostTransform::ByteMap)
            .collect::<Vec<_>>();
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
    let (plan, decryption_details) = select_decryption_plan(
        packed,
        source_file_range,
        stream_base,
        &mapped,
        &records.records,
        decoder_candidates,
        &post_transforms,
    )
    .with_context(|| {
        format!(
            "selecting from {transform_count} payload transforms and {decoder_count} decoder precursors"
        )
    })?;
    apply_decryption_plan(packed, stream_base, &mut mapped, plan)?;
    Ok(DecryptedImage {
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
    let stream_base = source_file_range.end;

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
