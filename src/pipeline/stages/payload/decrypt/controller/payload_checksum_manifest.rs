use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind, SelectedController,
    SelectedRootedNativeController,
};
use crate::pipeline::stages::payload::nested::{LfsrAlMapCandidate, crc32_table};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::{AuthenticatedPayloadPlan, PayloadPlanCandidate};
use super::super::source::BoundPayloadSource;
use super::super::{DecryptedImage, PayloadBlockTable};
use super::codec_relocation::{
    ExactPostStage5Input, ExactPostStage5Replay, PostStage5Finalizer,
    finalize_post_stage5_as_authenticated_image, replay_exact_post_stage5,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};

// These values describe the decoded AMD64 controller grammar. They are offsets
// from controller-owned state, never packed-input identifiers.
const ROOT_FROM_KONN_SOURCE: u32 = 0x1a38;
const ROOT_PRIMARY_DESCRIPTOR: u32 = 0x78;
const ROOT_PRIMARY_LITERAL: u32 = 0x14;
const ROOT_SECONDARY_CHECKSUM: u32 = 0x30;
const ROOT_PRIMARY_CHECKSUM: u32 = 0x38;
const ROOT_HEADER_LIST: u32 = 0xb8;
const ROOT_CONTROL_LENGTH: u32 = 0xe8;
const ROOT_PRIMARY_SOURCE_LENGTH: u32 = 0x1118;
const ROOT_PRIMARY_CHECKSUM_LENGTH: u32 = 0x20c0;
const ROOT_SECONDARY_CHECKSUM_LENGTH: u32 = 0x0e30;

const PRIMARY_STAGE2_DESCRIPTOR_FROM_STAGE1_SOURCE: u32 = 0xe80;
const PRIMARY_CHECKSUM_PAIRS_FROM_STAGE1_SOURCE: u32 = 0xde0;
const PRIMARY_STAGE2_KEY_BACK: u32 = 20;
const PRIMARY_STAGE2_ACCUMULATOR_BACK: u32 = 16;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3: u32 = 0x58;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3B: u32 = 0x68;
const PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE4: u32 = 0x88;
const PRIMARY_STAGE2_DESCRIPTOR_TO_TERMINAL: u32 = 0xd8;

const CODEC_TABLE_FROM_STAGE2_SOURCE: u32 = 0x23b0;
const CODEC_HEAD_FROM_TABLE: u32 = 0x20;
const CODEC_KEY_TABLE_FROM_HEAD: u32 = 0x58;
const CODEC_PARAMETER_DESCRIPTOR_RELATIVES: [u32; 4] = [0, 8, 32, 40];

const STAGE3_DESTINATION_LENGTH: u32 = 0x1270;
const STAGE3_LITERAL_FROM_DESTINATION: u32 = 0x1254;
const STAGE3_LITERAL_MARKER_FROM_DESTINATION: u32 = 0x1250;
const STAGE3B_DESTINATION_LENGTH: u32 = 0x8d0;
const STAGE3B_LITERAL_FROM_DESTINATION: u32 = 0x7d8;
const STAGE3B_LITERAL_MARKER_FROM_DESTINATION: u32 = 0x7e0;
const STAGE4_DESTINATION_LENGTH: u32 = 0xf78;
const STAGE4_ACCUMULATOR_FROM_DESTINATION: u32 = 0xe40;
const STAGE4_ACCUMULATOR_MARKER_FROM_DESTINATION: u32 = 0xe38;
const STAGE4_LAYER_PROGRAM_FROM_DESTINATION: u32 = 0xea0;
const STAGE4_LAYER_PROGRAM_WINDOW_LENGTH: u32 =
    STAGE4_DESTINATION_LENGTH - STAGE4_LAYER_PROGRAM_FROM_DESTINATION;
const TERMINAL_DESTINATION_LENGTH: u32 = 0x5544;

const TERMINAL_MARKER_FROM_DESTINATION: u32 = 0x4d40;
const TERMINAL_KIND_FROM_DESTINATION: u32 = 0x4d98;
const TERMINAL_PAYLOAD_LIST_SLOT_FROM_DESTINATION: u32 = 0x4d78;
const TERMINAL_PROGRAM_WINDOW_FROM_DESTINATION: u32 = 0x5000;
const TERMINAL_PROGRAM_WINDOW_LENGTH: u32 = 0x544;
const TERMINAL_FILE_PROGRAM_FROM_DESTINATION: u32 = 0x50d8;
const TERMINAL_FILE_PROGRAM_WINDOW_LENGTH: u32 =
    TERMINAL_DESTINATION_LENGTH - TERMINAL_FILE_PROGRAM_FROM_DESTINATION;
const TERMINAL_FILE_CHECKSUM_SLOT_FROM_DESTINATION: u32 = 0x5080;
const TERMINAL_MARKER: [u8; 8] = *b"pm\0\0cm\0\0";
const TERMINAL_KIND: [u8; 8] = [0, 0, 0, 0x40, 1, 0, 0, 0];

const MAX_REPLAY_WORK: usize = 512 << 20;

/// State established by a bounded KONN-root probe.
pub(crate) struct Probe {
    info: KonnInfo,
    base_image: Vec<u8>,
    controller_image: Vec<u8>,
    root_rva: u32,
    header_checksum: u32,
    primary_checksum: u32,
    primary_literal: u32,
}

/// Family-owned state awaiting the shared full-table authentication step.
pub(super) struct Proposal {
    pub(super) base_image: Vec<u8>,
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: Finalizer,
}

/// Provenance and terminal state retained after exact rooted replay.
pub(crate) struct Finalizer {
    pub(super) root_rva: u32,
    pub(super) primary_descriptor_rva: u32,
    pub(super) stage1_rva: u32,
    pub(super) stage2_descriptor_rva: u32,
    pub(super) stage2_rva: u32,
    pub(super) codec_table_rva: u32,
    pub(super) stage3_descriptor_rva: u32,
    pub(super) stage3_rva: u32,
    pub(super) stage3b_descriptor_rva: u32,
    pub(super) stage3b_rva: u32,
    pub(super) stage4_descriptor_rva: u32,
    pub(super) map_layer_rva: u32,
    pub(super) terminal_descriptor_rva: u32,
    pub(super) terminal_rva: u32,
    pub(super) payload_list_rva: u32,
    pub(super) file_decoder_rva: u32,
    pub(super) layer_decoder_rva: u32,
    pub(super) file_aes_context_rva: u32,
    pub(super) layer_aes_context_rva: u32,
    pub(super) file_raw_aes_key: [u8; 32],
    pub(super) layer_raw_aes_key: [u8; 32],
    pub(super) layer_program: LfsrAlMapCandidate,
    pub(super) file_program: LfsrAlMapCandidate,
    pub(super) terminal: PostStage5Finalizer,
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn rva_offset(base: u32, relative: u32, label: &str) -> Result<usize> {
    usize::try_from(add_rva(base, relative, label)?)
        .with_context(|| format!("{label} RVA does not fit host address space"))
}

fn descriptor(image: &[u8], at: u32, label: &str) -> Result<StageDescriptor> {
    shared::read_stage_descriptor(
        image,
        usize::try_from(at)
            .with_context(|| format!("{label} RVA does not fit host address space"))?,
    )
}

fn checksum_descriptor(image: &[u8], at: u32, table: &[u32; 256], label: &str) -> Result<u32> {
    shared::checksum_descriptor(
        image,
        usize::try_from(at)
            .with_context(|| format!("{label} RVA does not fit host address space"))?,
        table,
    )
}

fn range(image: &[u8], start: u32, length: u32, label: &str) -> Result<Range<usize>> {
    checked_range(image.len(), start, length, label)
}
fn charge_replay_work(work: &mut usize, amount: u32, label: &str) -> Result<()> {
    let amount =
        usize::try_from(amount).with_context(|| format!("{label} length does not fit usize"))?;
    *work = work
        .checked_add(amount)
        .with_context(|| format!("{label} replay work overflows"))?;
    ensure!(*work <= MAX_REPLAY_WORK, "{label} replay work exceeds cap");
    Ok(())
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
        "{label} lies outside its rooted terminal stage"
    );
    add_rva(stage.destination, relative, label)
}

fn root_is_well_formed(image: &[u8], info: &KonnInfo, root: u32) -> Result<bool> {
    let root_offset = match usize::try_from(root) {
        Ok(offset) => offset,
        Err(_) => return Ok(false),
    };
    let Some(control_end) = root_offset.checked_add(ROOT_CONTROL_LENGTH as usize) else {
        return Ok(false);
    };
    let Some(control) = image.get(root_offset..control_end) else {
        return Ok(false);
    };

    let first = u32::from_le_bytes(control[0..4].try_into().expect("bounded root field"));
    let import_size = u32::from_le_bytes(control[4..8].try_into().expect("bounded root field"));
    let anchor_end = u32::from_le_bytes(control[8..12].try_into().expect("bounded root field"));
    let Some(expected_anchor_end) = info[6].checked_sub(0x200) else {
        return Ok(false);
    };
    if first != info[3] || import_size != 0x28 || anchor_end != expected_anchor_end {
        return Ok(false);
    }

    let raw_end = match info[3].checked_add(info[5]) {
        Some(end) => end,
        None => return Ok(false),
    };
    let primary = match descriptor(
        image,
        add_rva(root, ROOT_PRIMARY_DESCRIPTOR, "root primary descriptor")?,
        "root primary descriptor",
    ) {
        Ok(stage) => stage,
        Err(_) => return Ok(false),
    };
    let primary_end = match primary.source.checked_add(primary.source_length) {
        Some(end) => end,
        None => return Ok(false),
    };
    if primary.source < info[3]
        || primary_end > raw_end
        || primary.source_length != ROOT_PRIMARY_SOURCE_LENGTH
        || primary.destination != 0
        || primary.destination_length != 0
        || range(
            image,
            primary.source,
            primary.source_length,
            "root primary source",
        )
        .is_err()
    {
        return Ok(false);
    }

    let secondary = match descriptor(
        image,
        add_rva(root, ROOT_SECONDARY_CHECKSUM, "root secondary checksum")?,
        "root secondary checksum",
    ) {
        Ok(stage) => stage,
        Err(_) => return Ok(false),
    };
    if secondary.source != primary.source
        || secondary.source_length != ROOT_SECONDARY_CHECKSUM_LENGTH
    {
        return Ok(false);
    }
    let checksum = match descriptor(
        image,
        add_rva(root, ROOT_PRIMARY_CHECKSUM, "root primary checksum")?,
        "root primary checksum",
    ) {
        Ok(stage) => stage,
        Err(_) => return Ok(false),
    };
    if checksum.source != info[6]
        || checksum.source_length != ROOT_PRIMARY_CHECKSUM_LENGTH
        || range(
            image,
            checksum.source,
            checksum.source_length,
            "root primary checksum input",
        )
        .is_err()
    {
        return Ok(false);
    }

    let header_first = match descriptor(
        image,
        add_rva(root, ROOT_HEADER_LIST, "root header checksum list")?,
        "root header checksum record",
    ) {
        Ok(stage) => stage,
        Err(_) => return Ok(false),
    };
    if header_first.source_length == 0
        || range(
            image,
            header_first.source,
            header_first.source_length,
            "root header checksum input",
        )
        .is_err()
    {
        return Ok(false);
    }
    Ok(true)
}

fn prepare_header(image: &mut [u8], source: &BoundPayloadSource<'_>, root: u32) -> Result<()> {
    let pe_header = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE header offset underflows")?;
    for (relative, pe_relative) in [(8u32, 0x90usize), (4, 0x94), (40, 0x98), (44, 0x9c)] {
        let value = read_u32(image, rva_offset(root, relative, "root header control")?)?;
        write_u32(image, pe_header + pe_relative, value)?;
    }
    write_u32(image, pe_header + 0xb0, 0)?;
    write_u32(image, pe_header + 0xb4, 0)?;
    Ok(())
}

fn header_checksum(
    image: &[u8],
    root: u32,
    table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut cursor = add_rva(root, ROOT_HEADER_LIST, "root header checksum list")?;
    let mut checksum = 0u32;
    let mut replay_work = 0usize;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = descriptor(image, cursor, "root header checksum record")?;
        if record.source_length == 0 {
            ensure!(index != 0, "root header checksum list is empty");
            return Ok(checksum);
        }
        range(
            image,
            record.source,
            record.source_length,
            "root header checksum input",
        )?;
        charge_replay_work(
            &mut replay_work,
            record.source_length,
            "root header checksum list",
        )?;
        checksum ^= checksum_descriptor(image, cursor, table, "root header checksum")?;
        cursor = cursor
            .checked_add(8)
            .context("root header checksum cursor overflows")?;
    }
    bail!("root header checksum list exceeds its entry budget")
}

fn decrypt_native_dwords(
    image: &mut [u8],
    descriptor_rva: u32,
    mut key: u32,
    rotation: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<StageDescriptor> {
    let stage = descriptor(image, descriptor_rva, "native dword descriptor")?;
    ensure!(
        stage.source_length.is_multiple_of(4),
        "native dword stage is not dword aligned"
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
        let ciphertext = u32::from_le_bytes(word.try_into().expect("dword-aligned stage chunk"));
        let index = u32::try_from(index).context("native dword index exceeds u32")?;
        let plaintext = (ciphertext ^ key).rotate_left(rotation).wrapping_sub(index);
        word.copy_from_slice(&plaintext.to_le_bytes());
        key = key.wrapping_add(index);
    }
    Ok(stage)
}

fn validate_stage2(image: &[u8], stage: StageDescriptor, info: &KonnInfo) -> Result<()> {
    let raw_end = info[3]
        .checked_add(info[5])
        .context("controller raw range overflows")?;
    let source_end = stage
        .source
        .checked_add(stage.source_length)
        .context("stage2 source range overflows")?;
    ensure!(stage.source == stage.destination, "stage2 is not in place");
    ensure!(
        stage.source >= info[3] && source_end <= raw_end,
        "stage2 source lies outside the rooted controller input"
    );
    ensure!(
        stage.source_length != 0
            && stage.source_length.is_multiple_of(4)
            && stage.destination_length != 0
            && stage.destination_length < stage.source_length,
        "stage2 compressed shape is invalid"
    );
    range(image, stage.source, stage.source_length, "stage2 source")?;
    range(
        image,
        stage.destination,
        stage.destination_length,
        "stage2 destination",
    )?;
    Ok(())
}

fn validate_checksum_pairs(
    image: &[u8],
    info: &KonnInfo,
    stage1: StageDescriptor,
    pairs: u32,
) -> Result<()> {
    let raw_end = info[3]
        .checked_add(info[5])
        .context("controller raw range overflows")?;
    for slot in 0..4u32 {
        let at = stage1
            .source
            .checked_add(pairs)
            .and_then(|value| value.checked_add(slot * 8))
            .context("checksum-pair RVA overflows")?;
        let pair = descriptor(image, at, "checksum pair")?;
        let pair_end = pair
            .source
            .checked_add(pair.source_length)
            .context("checksum-pair source range overflows")?;
        ensure!(
            pair.source >= info[3] && pair_end <= raw_end && pair.source_length != 0,
            "checksum pair lies outside the rooted controller input"
        );
        range(
            image,
            pair.source,
            pair.source_length,
            "checksum-pair source",
        )?;
    }
    Ok(())
}

fn validate_in_place_stage(
    image: &[u8],
    stage: StageDescriptor,
    destination_length: u32,
    label: &str,
) -> Result<()> {
    ensure!(stage.source == stage.destination, "{label} is not in place");
    ensure!(
        stage.source_length != 0 && stage.source_length < stage.destination_length,
        "{label} compressed-stage shape is invalid"
    );
    ensure!(
        stage.destination_length == destination_length,
        "{label} destination length is invalid"
    );
    range(image, stage.source, stage.source_length, label)?;
    range(image, stage.destination, stage.destination_length, label)?;
    Ok(())
}

fn transform_shift2_descriptor(
    image: &mut [u8],
    at: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<StageDescriptor> {
    shared::transform_shift2_range(image, at, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
    descriptor(image, at, "transformed descriptor")
}

fn copy_shift2_list(
    image: &mut [u8],
    mut cursor: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let mut replay_work = 0usize;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = transform_shift2_descriptor(image, cursor, cancellation)?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("codec copy-list cursor overflows")?;
        if record.source_length == 0 {
            return Ok(());
        }
        ensure!(
            record.destination_length == record.source_length,
            "codec copy-list record has mismatched lengths"
        );
        let source = range(
            image,
            record.source,
            record.source_length,
            "codec copy-list source",
        )?;
        let destination = range(
            image,
            record.destination,
            record.destination_length,
            "codec copy-list destination",
        )?;
        charge_replay_work(
            &mut replay_work,
            record.source_length,
            "codec copy-list source",
        )?;
        charge_replay_work(
            &mut replay_work,
            record.destination_length,
            "codec copy-list destination",
        )?;
        image.copy_within(source, destination.start);
    }
    bail!("codec copy-list exceeds its entry budget")
}

fn validate_codec_table(image: &[u8], table_rva: u32, info: &KonnInfo) -> Result<()> {
    let table =
        usize::try_from(table_rva).context("codec table RVA does not fit host address space")?;
    let _ = image
        .get(
            table
                ..table
                    .checked_add(STAGE_DESCRIPTOR_SIZE)
                    .context("codec table range overflows")?,
        )
        .context("codec table exceeds controller image")?;
    ensure!(
        read_u32(image, table)? & 0x0f == 1,
        "codec first action kind is invalid"
    );
    ensure!(
        read_u32(image, table + 4)? == 0,
        "codec first action reserved field is nonzero"
    );
    ensure!(
        read_u32(image, table + 8)? == info[3],
        "codec bootstrap source differs from the KONN root"
    );
    ensure!(
        read_u32(image, table + 12)? == 0,
        "codec second reserved field is nonzero"
    );
    Ok(())
}

fn replay_codec_controls(
    image: &mut [u8],
    table_rva: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<[u32; 4]> {
    let head = table_rva
        .checked_add(CODEC_HEAD_FROM_TABLE)
        .context("codec control head overflows")?;
    for record_rva in [
        head,
        head.checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("codec control record overflows")?,
    ] {
        let record = usize::try_from(record_rva)
            .context("codec control record RVA does not fit host address space")?;
        let kind = read_u32(image, record)?;
        if kind & 0x0f == 1 {
            shared::transform_shift3_descriptor(image, record + 4, cancellation)?;
        } else if kind == 2 {
            copy_shift2_list(image, read_u32(image, record + 4)?, cancellation)?;
        } else {
            bail!("unsupported codec control action {kind:#x}");
        }
    }

    let key_base = head
        .checked_sub(CODEC_KEY_TABLE_FROM_HEAD)
        .context("codec key table underflows")?;
    let mut offsets = [0u32; 4];
    for (slot, relative) in offsets.iter_mut().zip(CODEC_PARAMETER_DESCRIPTOR_RELATIVES) {
        let descriptor_rva = key_base
            .checked_add(relative)
            .context("codec key descriptor RVA overflows")?;
        let descriptor = usize::try_from(descriptor_rva)
            .context("codec key descriptor RVA does not fit host address space")?;
        shared::transform_shift3_descriptor(image, descriptor, cancellation)?;
        *slot = read_u32(image, descriptor)?;
        ensure!(*slot != 0, "codec key context is null");
    }
    Ok(offsets)
}

/// Recognizes the fixed AMD64 executable root without inspecting names or hashes.
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
    let mut controller_image = match source.pe.map_image(source.packed) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let controller_range = match range(
        &controller_image,
        info[3],
        info[5],
        "controller bootstrap range",
    ) {
        Ok(range) => range,
        Err(_) => return Ok(None),
    };
    controller_image[controller_range.clone()].copy_from_slice(&bootstrap_image[controller_range]);

    let mut base_image = match source.pe.map_image(source.packed) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let outer_length = match u32::try_from(source.outer.len()) {
        Ok(length) if length == info[5] => length,
        _ => return Ok(None),
    };
    let output_outer = match range(
        &base_image,
        source.bootstrap.destination_rva,
        outer_length,
        "output bootstrap range",
    ) {
        Ok(range) => range,
        Err(_) => return Ok(None),
    };
    base_image[output_outer].copy_from_slice(source.outer.as_slice());

    let root_rva = match add_rva(info[6], ROOT_FROM_KONN_SOURCE, "root control block") {
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
    if prepare_header(&mut controller_image, source, root_rva).is_err() {
        return Ok(None);
    }

    let table = crc32_table();
    let header_checksum = match header_checksum(&controller_image, root_rva, &table, cancellation) {
        Ok(checksum) => checksum,
        Err(_) => return Ok(None),
    };
    let primary_checksum = match checksum_descriptor(
        &controller_image,
        add_rva(root_rva, ROOT_PRIMARY_CHECKSUM, "primary checksum")?,
        &table,
        "primary checksum",
    ) {
        Ok(checksum) => checksum,
        Err(_) => return Ok(None),
    };
    let primary_literal = match read_u32(
        &controller_image,
        rva_offset(root_rva, ROOT_PRIMARY_LITERAL, "primary literal")?,
    ) {
        Ok(value) if value != 0 => value,
        _ => return Ok(None),
    };

    Ok(Some(Probe {
        info,
        base_image,
        controller_image,
        root_rva,
        header_checksum,
        primary_checksum,
        primary_literal,
    }))
}

/// Replays the fixed family prefix and its rooted terminal byte-map producer.
pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<Proposal> {
    let Probe {
        info,
        base_image,
        mut controller_image,
        root_rva,
        header_checksum,
        primary_checksum,
        primary_literal,
    } = probe;
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }

    let table = crc32_table();
    let primary_descriptor_rva = add_rva(root_rva, ROOT_PRIMARY_DESCRIPTOR, "primary descriptor")?;
    let stage1 = decrypt_native_dwords(
        &mut controller_image,
        primary_descriptor_rva,
        header_checksum ^ primary_checksum ^ primary_literal,
        11,
        cancellation,
    )?;
    ensure!(
        stage1.source_length == ROOT_PRIMARY_SOURCE_LENGTH
            && stage1.destination == 0
            && stage1.destination_length == 0,
        "primary stage changed from the rooted Family-6 grammar"
    );

    let stage2_descriptor_rva = stage1
        .source
        .checked_add(PRIMARY_STAGE2_DESCRIPTOR_FROM_STAGE1_SOURCE)
        .context("stage2 descriptor RVA overflows")?;
    let stage2_before = descriptor(
        &controller_image,
        stage2_descriptor_rva,
        "stage2 descriptor",
    )?;
    validate_stage2(&controller_image, stage2_before, &info)?;
    let checksum_pairs_rva = stage1
        .source
        .checked_add(PRIMARY_CHECKSUM_PAIRS_FROM_STAGE1_SOURCE)
        .context("checksum-pair RVA overflows")?;
    validate_checksum_pairs(
        &controller_image,
        &info,
        stage1,
        PRIMARY_CHECKSUM_PAIRS_FROM_STAGE1_SOURCE,
    )?;
    let stage2_key_rva = checksum_pairs_rva
        .checked_sub(PRIMARY_STAGE2_KEY_BACK)
        .context("stage2 key RVA underflows")?;
    let stage2_key = read_u32(
        &controller_image,
        usize::try_from(stage2_key_rva)
            .context("stage2 key RVA does not fit host address space")?,
    )?;
    let stage2 = decrypt_native_dwords(
        &mut controller_image,
        stage2_descriptor_rva,
        stage2_key,
        13,
        cancellation,
    )?;
    validate_stage2(&controller_image, stage2, &info)?;

    let codec_table_rva = stage2
        .source
        .checked_add(CODEC_TABLE_FROM_STAGE2_SOURCE)
        .context("codec table RVA overflows")?;
    validate_codec_table(&controller_image, codec_table_rva, &info)?;
    let key_offsets = replay_codec_controls(&mut controller_image, codec_table_rva, cancellation)?;
    let file_decoder_table = shared::snapshot_decoder_table(&controller_image, key_offsets[0])?;
    let layer_decoder_table = shared::snapshot_decoder_table(&controller_image, key_offsets[1])?;
    let (file_raw_aes_key, _) = shared::recover_aes_context(&controller_image, key_offsets[2])?;
    let (layer_raw_aes_key, layer_aes) =
        shared::recover_aes_context(&controller_image, key_offsets[3])?;

    let checksum2 = checksum_descriptor(
        &controller_image,
        add_rva(root_rva, ROOT_SECONDARY_CHECKSUM, "stage3 checksum")?,
        &table,
        "stage3 checksum",
    )?;
    let accumulator_rva = checksum_pairs_rva
        .checked_sub(PRIMARY_STAGE2_ACCUMULATOR_BACK)
        .context("stage3 accumulator RVA underflows")?;
    let accumulator = shared::advance_key(
        read_u32(
            &controller_image,
            usize::try_from(accumulator_rva)
                .context("stage3 accumulator RVA does not fit host address space")?,
        )?,
        4,
    );

    let stage3_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3,
        "stage3 descriptor",
    )?;
    let stage3_before = descriptor(
        &controller_image,
        stage3_descriptor_rva,
        "stage3 descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage3_before,
        STAGE3_DESTINATION_LENGTH,
        "stage3",
    )?;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(stage3_descriptor_rva)
            .context("stage3 descriptor RVA does not fit host address space")?,
        header_checksum ^ checksum2 ^ accumulator,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )?;
    let stage3_marker_rva = stage_relative_rva(
        stage3_before,
        STAGE3_LITERAL_MARKER_FROM_DESTINATION,
        4,
        "stage3 literal marker",
    )?;
    ensure!(
        controller_image[range(
            &controller_image,
            stage3_marker_rva,
            4,
            "stage3 literal marker"
        )?] == [0xc3, 0xcc, 0xcc, 0xcc],
        "stage3 literal marker is invalid"
    );
    let stage3_literal_rva = stage_relative_rva(
        stage3_before,
        STAGE3_LITERAL_FROM_DESTINATION,
        4,
        "stage3 literal",
    )?;
    let stage3_literal = read_u32(
        &controller_image,
        usize::try_from(stage3_literal_rva)
            .context("stage3 literal RVA does not fit host address space")?,
    )?;

    let stage3b_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE3B,
        "stage3b descriptor",
    )?;
    let stage3b_before = descriptor(
        &controller_image,
        stage3b_descriptor_rva,
        "stage3b descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage3b_before,
        STAGE3B_DESTINATION_LENGTH,
        "stage3b",
    )?;
    let checksum3 = checksum_descriptor(
        &controller_image,
        checksum_pairs_rva
            .checked_add(24)
            .context("stage3b checksum RVA overflows")?,
        &table,
        "stage3b checksum",
    )?;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(stage3b_descriptor_rva)
            .context("stage3b descriptor RVA does not fit host address space")?,
        header_checksum ^ checksum3 ^ stage3_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )?;
    let stage3b_marker_rva = stage_relative_rva(
        stage3b_before,
        STAGE3B_LITERAL_MARKER_FROM_DESTINATION,
        b"Virtual".len() as u32,
        "stage3b literal marker",
    )?;
    ensure!(
        controller_image[range(
            &controller_image,
            stage3b_marker_rva,
            b"Virtual".len() as u32,
            "stage3b literal marker",
        )?] == *b"Virtual",
        "stage3b literal marker is invalid"
    );
    let stage3b_literal_rva = stage_relative_rva(
        stage3b_before,
        STAGE3B_LITERAL_FROM_DESTINATION,
        4,
        "stage3b literal",
    )?;
    let stage3b_literal = !read_u32(
        &controller_image,
        usize::try_from(stage3b_literal_rva)
            .context("stage3b literal RVA does not fit host address space")?,
    )?;

    let stage4_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        PRIMARY_STAGE2_DESCRIPTOR_TO_STAGE4,
        "stage4 descriptor",
    )?;
    let stage4_before = descriptor(
        &controller_image,
        stage4_descriptor_rva,
        "stage4 descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage4_before,
        STAGE4_DESTINATION_LENGTH,
        "stage4",
    )?;
    let checksum4 = checksum_descriptor(
        &controller_image,
        checksum_pairs_rva
            .checked_add(16)
            .context("stage4 checksum RVA overflows")?,
        &table,
        "stage4 checksum",
    )?;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(stage4_descriptor_rva)
            .context("stage4 descriptor RVA does not fit host address space")?,
        header_checksum ^ checksum4 ^ stage3b_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )?;
    let stage4_marker_rva = stage_relative_rva(
        stage4_before,
        STAGE4_ACCUMULATOR_MARKER_FROM_DESTINATION,
        8,
        "stage4 accumulator marker",
    )?;
    ensure!(
        controller_image[range(
            &controller_image,
            stage4_marker_rva,
            8,
            "stage4 accumulator marker",
        )?] == [0x48, 0xeb, 0x01, 0xb9, 0xcc, 0xcc, 0xcc, 0xcc],
        "stage4 accumulator marker is invalid"
    );
    let stage4_accumulator_rva = stage_relative_rva(
        stage4_before,
        STAGE4_ACCUMULATOR_FROM_DESTINATION,
        4,
        "stage4 accumulator",
    )?;
    let terminal_key = shared::advance_key(
        read_u32(
            &controller_image,
            usize::try_from(stage4_accumulator_rva)
                .context("stage4 accumulator RVA does not fit host address space")?,
        )?,
        3,
    );

    let terminal_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        PRIMARY_STAGE2_DESCRIPTOR_TO_TERMINAL,
        "terminal descriptor",
    )?;
    let terminal_before = descriptor(
        &controller_image,
        terminal_descriptor_rva,
        "terminal descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        terminal_before,
        TERMINAL_DESTINATION_LENGTH,
        "terminal",
    )?;
    let layer_program_rva = stage_relative_rva(
        stage4_before,
        STAGE4_LAYER_PROGRAM_FROM_DESTINATION,
        STAGE4_LAYER_PROGRAM_WINDOW_LENGTH,
        "stage4 layer byte-map program",
    )?;
    let layer_program = shared::exact_lfsr_al_map(
        &controller_image,
        layer_program_rva,
        STAGE4_LAYER_PROGRAM_WINDOW_LENGTH,
        "stage4 layer byte-map program",
    )?;
    let checksum5 = checksum_descriptor(
        &controller_image,
        checksum_pairs_rva
            .checked_add(8)
            .context("terminal checksum RVA overflows")?,
        &table,
        "terminal checksum",
    )?;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(terminal_descriptor_rva)
            .context("terminal descriptor RVA does not fit host address space")?,
        header_checksum ^ checksum4 ^ checksum5 ^ terminal_key,
        &layer_aes,
        &layer_decoder_table,
        Some(layer_program.map.as_ref()),
        cancellation,
    )?;

    let terminal_window_rva = stage_relative_rva(
        terminal_before,
        TERMINAL_PROGRAM_WINDOW_FROM_DESTINATION,
        TERMINAL_PROGRAM_WINDOW_LENGTH,
        "terminal program window",
    )?;
    let _ = range(
        &controller_image,
        terminal_window_rva,
        TERMINAL_PROGRAM_WINDOW_LENGTH,
        "terminal program window",
    )?;
    let terminal_marker_rva = stage_relative_rva(
        terminal_before,
        TERMINAL_MARKER_FROM_DESTINATION,
        TERMINAL_MARKER.len() as u32,
        "terminal marker",
    )?;
    ensure!(
        controller_image[range(
            &controller_image,
            terminal_marker_rva,
            TERMINAL_MARKER.len() as u32,
            "terminal marker",
        )?] == TERMINAL_MARKER,
        "terminal marker is invalid"
    );
    let terminal_kind_rva = stage_relative_rva(
        terminal_before,
        TERMINAL_KIND_FROM_DESTINATION,
        TERMINAL_KIND.len() as u32,
        "terminal kind marker",
    )?;
    ensure!(
        controller_image[range(
            &controller_image,
            terminal_kind_rva,
            TERMINAL_KIND.len() as u32,
            "terminal kind marker",
        )?] == TERMINAL_KIND,
        "terminal kind marker is invalid"
    );
    let file_program_rva = stage_relative_rva(
        terminal_before,
        TERMINAL_FILE_PROGRAM_FROM_DESTINATION,
        TERMINAL_FILE_PROGRAM_WINDOW_LENGTH,
        "terminal file byte-map program",
    )?;
    let file_program = shared::exact_lfsr_al_map(
        &controller_image,
        file_program_rva,
        TERMINAL_FILE_PROGRAM_WINDOW_LENGTH,
        "terminal file byte-map program",
    )?;

    let metadata_list_pointer_slot_rva = stage_relative_rva(
        terminal_before,
        TERMINAL_FILE_CHECKSUM_SLOT_FROM_DESTINATION,
        4,
        "terminal metadata-list pointer slot",
    )?;
    let payload_list_pointer_slot_rva = stage_relative_rva(
        terminal_before,
        TERMINAL_PAYLOAD_LIST_SLOT_FROM_DESTINATION,
        4,
        "terminal payload-list pointer slot",
    )?;
    let ExactPostStage5Replay {
        block_table,
        payload_list_rva,
        candidate,
        finalizer: terminal,
    } = replay_exact_post_stage5(
        &mut controller_image,
        source,
        ExactPostStage5Input {
            metadata_list_pointer_slot_rva,
            payload_list_pointer_slot_rva,
            file_program: file_program.clone(),
            file_raw_aes_key,
            file_decoder_rva: key_offsets[0],
            file_decoder_table,
        },
        cancellation,
    )?;

    // The exact authenticated image leaves these fields in place, but decoding
    // this rooted record remains required to reject malformed metadata.
    let _ = shared::extract_metadata(&mut controller_image, info[3], cancellation)?;

    Ok(Proposal {
        base_image,
        block_table,
        candidate,
        finalizer: Finalizer {
            root_rva,
            primary_descriptor_rva,
            stage1_rva: stage1.source,
            stage2_descriptor_rva,
            stage2_rva: stage2.source,
            codec_table_rva,
            stage3_descriptor_rva,
            stage3_rva: stage3_before.destination,
            stage3b_descriptor_rva,
            stage3b_rva: stage3b_before.destination,
            stage4_descriptor_rva,
            map_layer_rva: stage4_before.destination,
            terminal_descriptor_rva,
            terminal_rva: terminal_before.destination,
            payload_list_rva,
            file_decoder_rva: key_offsets[0],
            layer_decoder_rva: key_offsets[1],
            file_aes_context_rva: key_offsets[2],
            layer_aes_context_rva: key_offsets[3],
            file_raw_aes_key,
            layer_raw_aes_key,
            layer_program,
            file_program,
            terminal,
        },
    })
}

/// Returns the controller-authenticated terminal image without header teardown.
pub(super) fn finalize(
    block_table: PayloadBlockTable,
    mut finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let selected_mapping = authenticated.plan().post_transform.mapping();
    ensure!(
        *finalizer.file_program.map == selected_mapping,
        "authenticated payload-checksum-manifest plan diverges from the rooted file-map program"
    );
    let file_program = finalizer.file_program.clone();
    finalizer.terminal.file_program = file_program.clone();
    let mut image = finalize_post_stage5_as_authenticated_image(
        block_table,
        &finalizer.terminal,
        authenticated,
    )?;
    image.decryption_details.selected_controller = Some(
        SelectedController::PayloadChecksumManifest(SelectedRootedNativeController {
            root_rva: finalizer.root_rva,
            graph_nodes: vec![
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::PrimaryDescriptor,
                    rva: finalizer.primary_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage1,
                    rva: finalizer.stage1_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage2Descriptor,
                    rva: finalizer.stage2_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage2,
                    rva: finalizer.stage2_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Codec,
                    rva: finalizer.codec_table_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage3Descriptor,
                    rva: finalizer.stage3_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage3,
                    rva: finalizer.stage3_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage3bDescriptor,
                    rva: finalizer.stage3b_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage3b,
                    rva: finalizer.stage3b_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Stage4Descriptor,
                    rva: finalizer.stage4_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::MapLayer,
                    rva: finalizer.map_layer_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::TerminalDescriptor,
                    rva: finalizer.terminal_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Terminal,
                    rva: finalizer.terminal_rva,
                },
            ],
            payload_list_rva: finalizer.payload_list_rva,
            file_decoder_rva: finalizer.file_decoder_rva,
            layer_decoder_rva: Some(finalizer.layer_decoder_rva),
            file_aes_context_rva: finalizer.file_aes_context_rva,
            layer_aes_context_rva: Some(finalizer.layer_aes_context_rva),
            file_raw_key_hex: hex::encode(finalizer.file_raw_aes_key),
            layer_raw_key_hex: Some(hex::encode(finalizer.layer_raw_aes_key)),
            layer_program_rva: Some(
                u32::try_from(finalizer.layer_program.offset)
                    .context("Family-6 layer byte-map program RVA exceeds u32")?,
            ),
            layer_program_length: Some(finalizer.layer_program.length),
            layer_byte_map: Some(finalizer.layer_program.map.to_vec()),
            file_program_rva: u32::try_from(file_program.offset)
                .context("Family-6 file byte-map program RVA exceeds u32")?,
            file_program_length: file_program.length,
            file_byte_map: file_program.map.to_vec(),
            terminal_profile: None,
        }),
    );
    Ok(image)
}
