use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    DecryptionDetails, SelectedCodecControlPayloadController, SelectedController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crc32_table,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::{
    AuthenticatedPayloadPlan, PayloadMaterializationPlan, PayloadPlanCandidate,
    PayloadPostTransform,
};
use super::super::source::BoundPayloadSource;
use super::super::{
    DecoderCandidate, DecryptedImage, PayloadBlock, PayloadBlockTable,
    merged_payload_block_destination_ranges, payload_block_destination_range,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};

const ROOT_FROM_KONN_SOURCE: u32 = 0x1a48;
const ROOT_PRIMARY_DESCRIPTOR: u32 = 0x78;
const ROOT_PRIMARY_LITERAL: u32 = 0x14;
const ROOT_SECONDARY_CHECKSUM: u32 = 0x30;
const ROOT_PRIMARY_CHECKSUM: u32 = 0x38;
const ROOT_HEADER_LIST: u32 = 0xb8;
const PRIMARY_STAGE2_KEY_BACK: u32 = 20;
const PRIMARY_STAGE2_ACCUM_BACK: u32 = 16;
const PRIMARY_STAGE2_DESCRIPTOR_FROM_STAGE1_SOURCE: u32 = 0xe30;
const PRIMARY_CHECKSUM_PAIRS_FROM_STAGE1_SOURCE: u32 = 0xd88;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3: u32 = 0x58;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3B: u32 = 0x68;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE4: u32 = 0x88;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE5: u32 = 0xd8;
const CODEC_TABLE_FROM_STAGE2_SOURCE: u32 = 0x23b0;
const CODEC_HEAD_FROM_TABLE: u32 = 32;
const CODEC_KEY_TABLE_FROM_HEAD: u32 = 88;
const STAGE3_LITERAL_FROM_DESTINATION: u32 = 0x1254;
const STAGE3B_LITERAL_FROM_DESTINATION: u32 = 0x7a8;
const STAGE4_ACCUMULATOR_FROM_DESTINATION: u32 = 0xdb0;
const STAGE5_PAYLOAD_LIST_FROM_DESTINATION: u32 = 0x4c18;
const STAGE4_LAYER_PROGRAM_FROM_DESTINATION: u32 = 0xe00;
const STAGE5_FILE_PROGRAM_FROM_DESTINATION: u32 = 0x4fa0;
const AL_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;
const MAX_REPLAY_WORK: usize = 512 << 20;

/// A fully structural root probe for this AMD64 executable controller layout.
pub(crate) struct Probe {
    info: KonnInfo,
    root: u32,
    base_image: Vec<u8>,
    controller_image: Vec<u8>,
    header_checksum: u32,
    primary_checksum: u32,
    primary_literal: u32,
}

/// Concrete native replay material for shared-router integration.
pub(crate) struct Proposal {
    pub(crate) base_image: Vec<u8>,
    pub(crate) block_table: PayloadBlockTable,
    pub(crate) candidate: PayloadPlanCandidate,
    pub(crate) finalizer: Finalizer,
}

pub(crate) struct Finalizer {
    block_table: PayloadBlockTable,
    root_rva: u32,
    primary_descriptor_rva: u32,
    stage2_descriptor_rva: u32,
    codec_table_rva: u32,
    payload_list_rva: u32,
    key_offsets: [u32; 4],
    file_raw_aes_key: [u8; 32],
    layer_raw_aes_key: [u8; 32],
    file_decoder_table: Vec<u8>,
    layer_program: LfsrAlMapCandidate,
    file_program: LfsrAlMapCandidate,
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn offset(base: u32, relative: u32, label: &str) -> Result<usize> {
    usize::try_from(add_rva(base, relative, label)?)
        .with_context(|| format!("{label} RVA does not fit usize"))
}

fn descriptor(image: &[u8], at: u32, label: &str) -> Result<StageDescriptor> {
    shared::read_stage_descriptor(
        image,
        usize::try_from(at).with_context(|| format!("{label} RVA does not fit usize"))?,
    )
}

fn checksum_descriptor(image: &[u8], at: u32, table: &[u32; 256], label: &str) -> Result<u32> {
    shared::checksum_descriptor(
        image,
        usize::try_from(at).with_context(|| format!("{label} RVA does not fit usize"))?,
        table,
    )
}

fn range(image: &[u8], start: u32, length: u32, label: &str) -> Result<Range<usize>> {
    checked_range(image.len(), start, length, label)
}

fn stage_relative_rva(
    stage: StageDescriptor,
    relative: u32,
    length: u32,
    label: &str,
) -> Result<u32> {
    let end = relative
        .checked_add(length)
        .with_context(|| format!("{label} relative range overflows"))?;
    ensure!(
        end <= stage.destination_length,
        "{label} lies outside its rooted producer stage"
    );
    add_rva(stage.destination, relative, label)
}

fn root_is_well_formed(image: &[u8], info: &KonnInfo, root: u32) -> Result<bool> {
    let root = usize::try_from(root).context("root RVA does not fit usize")?;
    let Some(control) = image.get(root..root.saturating_add(0xc8)) else {
        return Ok(false);
    };
    let first = u32::from_le_bytes(control[0..4].try_into().expect("bounded root field"));
    let import_size = u32::from_le_bytes(control[4..8].try_into().expect("bounded root field"));
    let anchor_end = u32::from_le_bytes(control[8..12].try_into().expect("bounded root field"));
    if first != info[3]
        || import_size == 0
        || anchor_end >= info[6]
        || !info[6].wrapping_sub(anchor_end).is_multiple_of(0x200)
        || info[6].wrapping_sub(anchor_end) > 0x1000
    {
        return Ok(false);
    }
    let primary = shared::read_stage_descriptor(image, root + ROOT_PRIMARY_DESCRIPTOR as usize)?;
    if primary.source_length == 0 || !primary.source_length.is_multiple_of(4) {
        return Ok(false);
    }
    let _ = range(
        image,
        primary.source,
        primary.source_length,
        "native primary source",
    )?;
    let checksum = shared::read_stage_descriptor(image, root + ROOT_PRIMARY_CHECKSUM as usize)?;
    Ok(checksum.source == info[6] && checksum.source_length >= 0x1000)
}

fn prepare_header(image: &mut [u8], source: &BoundPayloadSource<'_>, root: u32) -> Result<()> {
    let pe = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE header offset underflows")?;
    for (relative, pe_relative) in [(8u32, 0x90usize), (4, 0x94), (40, 0x98), (44, 0x9c)] {
        let value = read_u32(image, offset(root, relative, "native header control")?)?;
        write_u32(image, pe + pe_relative, value)?;
    }
    write_u32(image, pe + 0xb0, 0)?;
    write_u32(image, pe + 0xb4, 0)?;
    Ok(())
}

fn header_checksum(
    image: &[u8],
    root: u32,
    table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut at = add_rva(root, ROOT_HEADER_LIST, "native header list")?;
    let mut value = 0u32;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = descriptor(image, at, "native header checksum record")?;
        if record.source_length == 0 {
            ensure!(index != 0, "native header checksum list is empty");
            return Ok(value);
        }
        value ^= checksum_descriptor(image, at, table, "native header checksum")?;
        at = at
            .checked_add(8)
            .context("native header checksum cursor overflows")?;
    }
    bail!("native header checksum list exceeds entry budget")
}

/// Native code uses ROL(11)/ROL(13), the encrypt-side direction of the older
/// controller helper's ROR(21)/ROR(19) operations.
fn decrypt_native_dwords(
    image: &mut [u8],
    descriptor_at: u32,
    mut key: u32,
    rotation: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<StageDescriptor> {
    let stage = descriptor(image, descriptor_at, "native dword descriptor")?;
    ensure!(
        stage.source_length.is_multiple_of(4),
        "native dword stage is not aligned"
    );
    let source = range(
        image,
        stage.source,
        stage.source_length,
        "native dword stage",
    )?;
    for (index, word) in image[source].chunks_exact_mut(4).enumerate() {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let ciphertext = u32::from_le_bytes(word.try_into().expect("dword chunk"));
        let index = u32::try_from(index).context("native dword index exceeds u32")?;
        let plaintext = (ciphertext ^ key).rotate_left(rotation).wrapping_sub(index);
        word.copy_from_slice(&plaintext.to_le_bytes());
        key = key.wrapping_add(index);
    }
    Ok(stage)
}
fn validate_stage2(stage: StageDescriptor, info: &KonnInfo) -> Result<()> {
    let raw_end = info[3]
        .checked_add(info[5])
        .context("native raw controller extent overflows")?;
    let stage_end = stage
        .source
        .checked_add(stage.source_length)
        .context("native stage2 source range overflows")?;
    ensure!(
        stage.source == stage.destination,
        "native stage2 source and destination differ"
    );
    ensure!(
        stage.source >= info[3] && stage_end <= raw_end,
        "native stage2 source is outside controller input"
    );
    ensure!(
        stage.source_length > 0x1_0000,
        "native stage2 input is too small"
    );
    ensure!(
        stage.destination_length != 0 && stage.destination_length < stage.source_length,
        "native stage2 output shape is invalid"
    );
    Ok(())
}

fn validate_checksum_pairs(
    image: &[u8],
    info: &KonnInfo,
    stage1: StageDescriptor,
    checksum_pairs: u32,
) -> Result<()> {
    let raw_end = info[3]
        .checked_add(info[5])
        .context("native raw controller extent overflows")?;
    for slot in 0..4u32 {
        let at = stage1
            .source
            .checked_add(checksum_pairs)
            .and_then(|value| value.checked_add(slot * 8))
            .context("native checksum pair RVA overflows")?;
        let pair = descriptor(image, at, "native checksum pair")?;
        let pair_end = pair
            .source
            .checked_add(pair.source_length)
            .context("native checksum pair source range overflows")?;
        ensure!(
            pair.source >= info[3] && pair_end <= raw_end,
            "native checksum pair source is outside controller input"
        );
        ensure!(
            pair.source_length != 0 && pair.source_length < 0x10000,
            "native checksum pair length is invalid"
        );
        range(
            image,
            pair.source,
            pair.source_length,
            "native checksum pair source",
        )?;
    }
    Ok(())
}
fn validate_in_place_stage(
    stage: StageDescriptor,
    destination_length: u32,
    label: &str,
) -> Result<()> {
    ensure!(
        stage.source == stage.destination,
        "native {label} source and destination differ"
    );
    ensure!(
        stage.source_length != 0 && stage.source_length < stage.destination_length,
        "native {label} compressed input shape is invalid"
    );
    ensure!(
        stage.destination_length == destination_length,
        "native {label} destination size is invalid"
    );
    Ok(())
}

fn transform_shift2_descriptor(
    image: &mut [u8],
    at: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<StageDescriptor> {
    shared::transform_shift2_range(image, at, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
    descriptor(image, at, "native transformed descriptor")
}

fn copy_shift2_list(
    image: &mut [u8],
    mut at: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = transform_shift2_descriptor(image, at, cancellation)?;
        if record.source_length == 0 {
            return Ok(());
        }
        ensure!(
            record.destination_length == record.source_length,
            "native copy-list length mismatch"
        );
        let source = range(
            image,
            record.source,
            record.source_length,
            "native copy-list source",
        )?;
        let destination = range(
            image,
            record.destination,
            record.destination_length,
            "native copy-list destination",
        )?;
        image.copy_within(source, destination.start);
        at = at
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("native copy-list cursor overflows")?;
    }
    bail!("native copy-list exceeds entry budget")
}
fn validate_codec_table(image: &[u8], codec_table: u32, info: &KonnInfo) -> Result<()> {
    let table =
        usize::try_from(codec_table).context("native codec table RVA does not fit usize")?;
    ensure!(
        read_u32(image, table)? & 0x0f == 1,
        "native codec first action kind is invalid"
    );
    ensure!(
        read_u32(image, table + 4)? == 0,
        "native codec first action reserved field is nonzero"
    );
    ensure!(
        read_u32(image, table + 8)? == info[3],
        "native codec bootstrap source does not match KONN input"
    );
    ensure!(
        read_u32(image, table + 12)? == 0,
        "native codec second reserved field is nonzero"
    );
    Ok(())
}

fn replay_codec_controls(
    image: &mut [u8],
    codec_table: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<[u32; 4]> {
    let head = codec_table
        .checked_add(CODEC_HEAD_FROM_TABLE)
        .context("native codec head overflows")?;
    for record_at in [
        head,
        head.checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("native codec record overflows")?,
    ] {
        let kind = read_u32(
            image,
            usize::try_from(record_at).context("codec record RVA does not fit usize")?,
        )?;
        if kind & 0x0f == 1 {
            shared::transform_shift3_descriptor(
                image,
                usize::try_from(record_at + 4)
                    .context("codec shift descriptor RVA does not fit usize")?,
                cancellation,
            )?;
        } else if kind == 2 {
            let list = read_u32(
                image,
                usize::try_from(record_at + 4)
                    .context("codec list pointer RVA does not fit usize")?,
            )?;
            copy_shift2_list(image, list, cancellation)?;
        } else {
            bail!("unsupported native codec control action {kind:#x}");
        }
    }
    let key_base = head
        .checked_sub(CODEC_KEY_TABLE_FROM_HEAD)
        .context("native codec key table underflows")?;
    let mut offsets = [0u32; 4];
    for (slot, relative) in offsets.iter_mut().zip([0u32, 8, 32, 40]) {
        let at = key_base
            .checked_add(relative)
            .context("native key descriptor overflows")?;
        shared::transform_shift3_descriptor(
            image,
            usize::try_from(at).context("native key descriptor RVA does not fit usize")?,
            cancellation,
        )?;
        *slot = read_u32(
            image,
            usize::try_from(at).context("native key RVA does not fit usize")?,
        )?;
    }
    Ok(offsets)
}
fn parse_payload_lists(
    image: &mut [u8],
    list: u32,
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<PayloadBlock>> {
    let mut cursor = list;
    let mut blocks = Vec::new();
    let mut work = 0usize;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = transform_shift2_descriptor(image, cursor, cancellation)?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("native payload cursor overflows")?;
        if record.source_length == 0 {
            ensure!(
                !blocks.is_empty(),
                "native payload descriptor list is empty"
            );
            return Ok(blocks);
        }
        let encoded_length = usize::try_from(record.source_length)
            .context("native payload encoded length does not fit usize")?;
        let destination_length = usize::try_from(record.destination_length)
            .context("native payload destination length does not fit usize")?;
        let source_offset = source
            .stream
            .base_file_offset
            .checked_add(
                usize::try_from(record.source)
                    .context("native payload source displacement does not fit usize")?,
            )
            .context("native payload source offset overflows")?;
        let source_end = source_offset
            .checked_add(encoded_length)
            .context("native payload source end overflows")?;
        ensure!(
            source_end <= source.payload_source.len(),
            "native payload source exceeds bound source"
        );
        if let Some(security) = source.source_security_range {
            ensure!(
                source_end <= security.start || source_offset >= security.end,
                "native payload overlaps security directory"
            );
        }
        let _ = range(
            image,
            record.destination,
            record.destination_length,
            "native payload destination",
        )?;
        work = work
            .checked_add(encoded_length)
            .and_then(|value| value.checked_add(destination_length))
            .context("native payload work overflows")?;
        ensure!(work <= MAX_REPLAY_WORK, "native payload work exceeds cap");
        blocks.push(PayloadBlock {
            source_offset,
            encoded_length,
            destination_rva: usize::try_from(record.destination)
                .context("native payload destination does not fit usize")?,
            destination_length,
        });
    }
    bail!("native payload descriptor list exceeds entry budget")
}

pub(super) fn probe(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<Probe>> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let info = match shared::decode_konn_info(source) {
        Ok(info) => info,
        Err(_) => return Ok(None),
    };
    let bootstrap_image = match shared::materialize_konn_bootstrap(source, &info, cancellation) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let mut base_image = match source.pe.map_image(source.packed) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let controller_range = match range(
        &base_image,
        info[3],
        info[5],
        "native controller bootstrap range",
    ) {
        Ok(range) => range,
        Err(_) => return Ok(None),
    };
    base_image[controller_range.clone()].copy_from_slice(&bootstrap_image[controller_range]);
    let mut controller_image = base_image.clone();
    let mut output_image = match source.pe.map_image(source.packed) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let outer_length = match u32::try_from(source.outer.len()) {
        Ok(length) => length,
        Err(_) => return Ok(None),
    };
    let output_outer = match range(
        &output_image,
        source.bootstrap.destination_rva,
        outer_length,
        "native output bootstrap range",
    ) {
        Ok(range) => range,
        Err(_) => return Ok(None),
    };
    output_image[output_outer].copy_from_slice(source.outer.as_slice());
    let root = match add_rva(
        info[6],
        ROOT_FROM_KONN_SOURCE,
        "native rooted control block",
    ) {
        Ok(root)
            if matches!(
                root_is_well_formed(&controller_image, &info, root),
                Ok(true)
            ) =>
        {
            root
        }
        _ => return Ok(None),
    };
    if prepare_header(&mut controller_image, source, root).is_err() {
        return Ok(None);
    }
    let table = crc32_table();
    let header_checksum = match header_checksum(&controller_image, root, &table, cancellation) {
        Ok(checksum) => checksum,
        Err(_) => return Ok(None),
    };
    let primary_checksum = match checksum_descriptor(
        &controller_image,
        add_rva(root, ROOT_PRIMARY_CHECKSUM, "native primary checksum")?,
        &table,
        "native primary checksum",
    ) {
        Ok(checksum) => checksum,
        Err(_) => return Ok(None),
    };
    let primary_literal = match read_u32(
        &controller_image,
        offset(root, ROOT_PRIMARY_LITERAL, "native primary literal")?,
    ) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    Ok(Some(Probe {
        info,
        root,
        base_image: output_image,
        controller_image,
        header_checksum,
        primary_checksum,
        primary_literal,
    }))
}

pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<Proposal> {
    let Probe {
        info,
        root,
        base_image: output_image,
        controller_image: mut base_image,
        header_checksum,
        primary_checksum,
        primary_literal,
    } = probe;
    let table = crc32_table();
    let primary_descriptor = add_rva(root, ROOT_PRIMARY_DESCRIPTOR, "native primary descriptor")?;
    let stage1 = decrypt_native_dwords(
        &mut base_image,
        primary_descriptor,
        header_checksum ^ primary_checksum ^ primary_literal,
        11,
        cancellation,
    )?;
    let stage2_descriptor = stage1
        .source
        .checked_add(PRIMARY_STAGE2_DESCRIPTOR_FROM_STAGE1_SOURCE)
        .context("native stage2 descriptor RVA overflows")?;
    validate_stage2(
        descriptor(&base_image, stage2_descriptor, "native stage2 descriptor")?,
        &info,
    )?;
    let checksum_pairs = PRIMARY_CHECKSUM_PAIRS_FROM_STAGE1_SOURCE;
    validate_checksum_pairs(&base_image, &info, stage1, checksum_pairs)?;
    let stage2_key_at = stage1
        .source
        .checked_add(checksum_pairs)
        .and_then(|value| value.checked_sub(PRIMARY_STAGE2_KEY_BACK))
        .context("native stage2 key address underflows")?;
    let stage2_key = read_u32(
        &base_image,
        usize::try_from(stage2_key_at).context("native stage2 key RVA does not fit usize")?,
    )?;
    let stage2 = decrypt_native_dwords(
        &mut base_image,
        stage2_descriptor,
        stage2_key,
        13,
        cancellation,
    )?;
    let codec_table = stage2
        .source
        .checked_add(CODEC_TABLE_FROM_STAGE2_SOURCE)
        .context("native codec table RVA overflows")?;
    validate_codec_table(&base_image, codec_table, &info)?;
    let key_offsets = replay_codec_controls(&mut base_image, codec_table, cancellation)?;
    let layer_decoder = shared::snapshot_decoder_table(&base_image, key_offsets[1])?;
    let file_decoder = shared::snapshot_decoder_table(&base_image, key_offsets[0])?;
    let (file_raw_aes_key, _) = shared::recover_aes_context(&base_image, key_offsets[2])?;
    let (layer_raw_aes_key, layer_aes) = shared::recover_aes_context(&base_image, key_offsets[3])?;

    let checksum2 = checksum_descriptor(
        &base_image,
        add_rva(root, ROOT_SECONDARY_CHECKSUM, "native stage3 checksum")?,
        &table,
        "native stage3 checksum",
    )?;
    let accum_at = stage1
        .source
        .checked_add(checksum_pairs)
        .and_then(|value| value.checked_sub(PRIMARY_STAGE2_ACCUM_BACK))
        .context("native stage3 accumulator underflows")?;
    let accum = shared::advance_key(
        read_u32(
            &base_image,
            usize::try_from(accum_at)
                .context("native stage3 accumulator RVA does not fit usize")?,
        )?,
        4,
    );
    let stage3_descriptor = stage2_descriptor
        .checked_add(PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3)
        .context("native stage3 descriptor overflows")?;
    let stage3_before = descriptor(&base_image, stage3_descriptor, "native stage3 descriptor")?;
    validate_in_place_stage(stage3_before, 0x1270, "stage3")?;
    shared::decrypt_stage(
        &mut base_image,
        usize::try_from(stage3_descriptor)
            .context("native stage3 descriptor RVA does not fit usize")?,
        header_checksum ^ checksum2 ^ accum,
        &layer_aes,
        &layer_decoder,
        None,
        cancellation,
    )?;
    let v4_at = add_rva(
        stage3_before.destination,
        STAGE3_LITERAL_FROM_DESTINATION,
        "native stage3 literal",
    )?;
    let v4_marker = range(
        &base_image,
        v4_at
            .checked_sub(4)
            .context("native stage3 literal marker underflows")?,
        4,
        "native stage3 literal marker",
    )?;
    ensure!(
        base_image[v4_marker] == [0xc3, 0xcc, 0xcc, 0xcc],
        "native stage3 literal marker is invalid"
    );
    let v4 = read_u32(
        &base_image,
        usize::try_from(v4_at).context("native stage3 literal RVA does not fit usize")?,
    )?;
    ensure!(v4 != 0, "native stage3 literal is zero");

    let stage3b_descriptor = stage2_descriptor
        .checked_add(PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3B)
        .context("native stage3b descriptor overflows")?;
    let stage3b_before = descriptor(&base_image, stage3b_descriptor, "native stage3b descriptor")?;
    validate_in_place_stage(stage3b_before, 0x8a0, "stage3b")?;
    let checksum3 = checksum_descriptor(
        &base_image,
        stage1
            .source
            .checked_add(checksum_pairs + 24)
            .context("native stage3 checksum pair overflows")?,
        &table,
        "native stage3 checksum pair",
    )?;
    shared::decrypt_stage(
        &mut base_image,
        usize::try_from(stage3b_descriptor)
            .context("native stage3b descriptor RVA does not fit usize")?,
        header_checksum ^ checksum3 ^ v4,
        &layer_aes,
        &layer_decoder,
        None,
        cancellation,
    )?;
    let v5_at = add_rva(
        stage3b_before.destination,
        STAGE3B_LITERAL_FROM_DESTINATION,
        "native stage3b literal",
    )?;
    let v5 = !read_u32(
        &base_image,
        usize::try_from(v5_at).context("native stage3b literal RVA does not fit usize")?,
    )?;

    let stage4_descriptor = stage2_descriptor
        .checked_add(PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE4)
        .context("native stage4 descriptor overflows")?;
    let stage4_before = descriptor(&base_image, stage4_descriptor, "native stage4 descriptor")?;
    validate_in_place_stage(stage4_before, 0xed0, "stage4")?;
    let checksum4 = checksum_descriptor(
        &base_image,
        stage1
            .source
            .checked_add(checksum_pairs + 16)
            .context("native stage4 checksum pair overflows")?,
        &table,
        "native stage4 checksum pair",
    )?;
    shared::decrypt_stage(
        &mut base_image,
        usize::try_from(stage4_descriptor)
            .context("native stage4 descriptor RVA does not fit usize")?,
        header_checksum ^ checksum4 ^ v5,
        &layer_aes,
        &layer_decoder,
        None,
        cancellation,
    )?;
    let layer_program_rva = stage_relative_rva(
        stage4_before,
        STAGE4_LAYER_PROGRAM_FROM_DESTINATION,
        AL_PROGRAM_WINDOW_LENGTH,
        "native layer byte-program",
    )?;
    let layer_program = shared::exact_lfsr_al_map(
        &base_image,
        layer_program_rva,
        AL_PROGRAM_WINDOW_LENGTH,
        "native layer byte-program",
    )?;

    let stage5_descriptor = stage2_descriptor
        .checked_add(PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE5)
        .context("native stage5 descriptor overflows")?;
    let stage5_before = descriptor(&base_image, stage5_descriptor, "native stage5 descriptor")?;
    validate_in_place_stage(stage5_before, 0x542c, "stage5")?;
    let checksum5 = checksum_descriptor(
        &base_image,
        stage1
            .source
            .checked_add(checksum_pairs + 8)
            .context("native stage5 checksum pair overflows")?,
        &table,
        "native stage5 checksum pair",
    )?;
    let accum2_at = add_rva(
        stage4_before.destination,
        STAGE4_ACCUMULATOR_FROM_DESTINATION,
        "native stage4 accumulator",
    )?;
    let accum2 = shared::advance_key(
        read_u32(
            &base_image,
            usize::try_from(accum2_at)
                .context("native stage4 accumulator RVA does not fit usize")?,
        )?,
        3,
    );
    shared::decrypt_stage(
        &mut base_image,
        usize::try_from(stage5_descriptor)
            .context("native stage5 descriptor RVA does not fit usize")?,
        header_checksum ^ checksum4 ^ checksum5 ^ accum2,
        &layer_aes,
        &layer_decoder,
        Some(layer_program.map.as_ref()),
        cancellation,
    )?;
    let payload_slot = add_rva(
        stage5_before.destination,
        STAGE5_PAYLOAD_LIST_FROM_DESTINATION,
        "native payload list slot",
    )?;
    let payload_list = read_u32(
        &base_image,
        usize::try_from(payload_slot).context("native payload list slot RVA does not fit usize")?,
    )?;
    let file_program_rva = stage_relative_rva(
        stage5_before,
        STAGE5_FILE_PROGRAM_FROM_DESTINATION,
        AL_PROGRAM_WINDOW_LENGTH,
        "native file byte-program",
    )?;
    let file_program = shared::exact_lfsr_al_map(
        &base_image,
        file_program_rva,
        AL_PROGRAM_WINDOW_LENGTH,
        "native file byte-program",
    )?;
    let blocks = parse_payload_lists(&mut base_image, payload_list, source, cancellation)?;
    let block_table = PayloadBlockTable {
        stream_base: 0,
        blocks,
    };
    let candidate = PayloadPlanCandidate::new(PayloadMaterializationPlan {
        block_table: block_table.clone(),
        aes_key: file_raw_aes_key,
        decoder: DecoderCandidate {
            source_file_offset: usize::try_from(key_offsets[0])
                .context("native file decoder RVA does not fit usize")?,
            phase: 0,
            table: file_decoder.clone(),
        },
        post_transform: PayloadPostTransform::ByteMap(file_program.map.clone()),
    });
    Ok(Proposal {
        base_image: output_image,
        block_table: block_table.clone(),
        candidate,
        finalizer: Finalizer {
            block_table,
            root_rva: root,
            primary_descriptor_rva: primary_descriptor,
            stage2_descriptor_rva: stage2_descriptor,
            codec_table_rva: codec_table,
            payload_list_rva: payload_list,
            key_offsets,
            file_raw_aes_key,
            layer_raw_aes_key,
            file_decoder_table: file_decoder,
            layer_program,
            file_program,
        },
    })
}

pub(super) fn finalize(
    _source: &BoundPayloadSource<'_>,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let (plan, _chain, image) = authenticated.into_parts();
    let file_decoder_offset = usize::try_from(finalizer.key_offsets[0])
        .context("native file decoder RVA does not fit usize")?;
    ensure!(
        plan.block_table == finalizer.block_table,
        "authenticated native block table differs from controller table"
    );
    ensure!(
        plan.aes_key == finalizer.file_raw_aes_key,
        "authenticated native AES key differs from controller key"
    );
    ensure!(
        plan.decoder.source_file_offset == file_decoder_offset && plan.decoder.phase == 0,
        "authenticated native decoder location differs from controller decoder"
    );
    ensure!(
        plan.decoder.table == finalizer.file_decoder_table,
        "authenticated native decoder differs from controller decoder"
    );
    ensure!(
        plan.post_transform.mapping() == *finalizer.file_program.map,
        "authenticated native byte map differs from controller map"
    );
    let mut destination_record_ranges = finalizer
        .block_table
        .blocks
        .iter()
        .map(payload_block_destination_range)
        .collect::<Result<Vec<_>>>()?;
    destination_record_ranges.sort_unstable_by_key(|range| range.start);
    let destination_ranges =
        merged_payload_block_destination_ranges(&finalizer.block_table.blocks)?;
    let copied_block_count = finalizer
        .block_table
        .blocks
        .iter()
        .filter(|block| block.encoded_length == block.destination_length)
        .count();
    Ok(DecryptedImage {
        destination_record_ranges,
        destination_ranges,
        image,
        decryption_details: DecryptionDetails {
            block_count: finalizer.block_table.blocks.len(),
            copied_block_count,
            decoded_block_count: finalizer.block_table.blocks.len() - copied_block_count,
            aes_key_candidates: 1,
            decoder_candidates: 1,
            byte_transform_candidates: 1,
            selected_chain: None,
            selected_controller: Some(SelectedController::CodecControlPayload(
                SelectedCodecControlPayloadController {
                    root_rva: finalizer.root_rva,
                    primary_descriptor_rva: finalizer.primary_descriptor_rva,
                    stage2_descriptor_rva: finalizer.stage2_descriptor_rva,
                    codec_table_rva: finalizer.codec_table_rva,
                    payload_list_rva: finalizer.payload_list_rva,
                    file_decoder_rva: finalizer.key_offsets[0],
                    layer_decoder_rva: finalizer.key_offsets[1],
                    file_aes_context_rva: finalizer.key_offsets[2],
                    layer_aes_context_rva: finalizer.key_offsets[3],
                    file_raw_key_hex: hex::encode(finalizer.file_raw_aes_key),
                    layer_raw_key_hex: hex::encode(finalizer.layer_raw_aes_key),
                    layer_program_rva: u32::try_from(finalizer.layer_program.offset)
                        .context("native layer program mapped-image RVA exceeds u32")?,
                    layer_program_length: finalizer.layer_program.length,
                    layer_byte_map: finalizer.layer_program.map.to_vec(),
                    file_program_rva: u32::try_from(finalizer.file_program.offset)
                        .context("native file program mapped-image RVA exceeds u32")?,
                    file_program_length: finalizer.file_program.length,
                    file_byte_map: finalizer.file_program.map.to_vec(),
                },
            )),
            ..DecryptionDetails::default()
        },
    })
}
