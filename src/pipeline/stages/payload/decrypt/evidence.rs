use std::ops::Range;

use anyhow::{Context, Result};
use tracing::debug;

use crate::pe::Machine;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::stages::payload::nested::discover_nested_byte_maps;

use super::replay::{
    DecryptionNestedReplayer, PayloadPlanSelectionInput, PayloadPostTransform, select_payload_plan,
    select_payload_plan_with_cancellation,
};
use super::source::BoundPayloadSource;
use super::{
    DecryptedImage, discover_decoder_candidates, discover_decoder_candidates_with_cancellation,
    discover_payload_block_table, discover_payload_block_table_with_cancellation,
    merged_payload_block_destination_ranges, payload_block_destination_range,
};

pub(super) fn recover(
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
        discover_payload_block_table_with_cancellation(
            outer,
            bootstrap,
            stream_base,
            payload_source.len(),
            mapped.len(),
            source_security_range,
            cancellation,
        )?
    } else {
        discover_payload_block_table(
            outer,
            bootstrap,
            stream_base,
            payload_source.len(),
            mapped.len(),
            source_security_range,
        )?
    };
    let first_block = records
        .blocks
        .first()
        .expect("selected payload-block table is nonempty");
    debug!(
        stream_base,
        first_source_offset = first_block.source_offset,
        first_encoded_length = first_block.encoded_length,
        max_source_end = records
            .blocks
            .iter()
            .map(|block| block.source_offset + block.encoded_length)
            .max()
            .expect("selected payload-block table is nonempty"),
        "diagnostic payload-block source geometry"
    );
    let mut destination_record_ranges = records
        .blocks
        .iter()
        .map(payload_block_destination_range)
        .collect::<Result<Vec<Range<u32>>>>()?;
    destination_record_ranges.sort_unstable_by_key(|range| range.start);
    let destination_ranges = merged_payload_block_destination_ranges(&records.blocks)?;
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
        fixed_contexts: false,
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
    let selection_input = || PayloadPlanSelectionInput {
        packed: payload_source,
        source_file_range: source_file_range.clone(),
        stream_base,
        mapped: &mapped,
        records: &records.blocks,
        post_transforms: &post_transforms,
    };
    let (authenticated, decryption_details) = if let Some(cancellation) = cancellation {
        select_payload_plan_with_cancellation(
            selection_input(),
            decoder_candidates,
            cancellation,
        )
    } else {
        select_payload_plan(selection_input(), decoder_candidates)
    }
    .with_context(|| {
        format!(
            "selecting from {transform_count} payload transforms and {decoder_count} decoder precursors"
        )
    })?;
    let (_, _, image) = authenticated.into_parts();
    mapped = image;
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
