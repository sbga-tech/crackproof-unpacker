use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use tracing::info;

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind, SelectedController,
    SelectedRootedNativeController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crc32_table,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::{
    AuthenticatedPayloadPlan, PayloadMaterializationPlan, PayloadPlanCandidate,
    PayloadPostTransform, ensure_terminal_zero_ranges_are_disjoint_from_payload_destinations,
};
use super::super::source::BoundPayloadSource;
use super::super::{DecoderCandidate, DecryptedImage, PayloadBlock, PayloadBlockTable};
use super::codec_relocation::{PostStage5Finalizer, finalize_post_stage5_as_authenticated_image};
use super::shared::{
    MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, advance_key, checksum_descriptor,
    copy_stage_list, decode_konn_info, decrypt_rotating_dword_descriptor, decrypt_stage,
    extract_metadata, materialize_konn_bootstrap, read_stage_descriptor, recover_aes_context,
    snapshot_decoder_table, transform_shift2_range, transform_shift3_descriptor,
};

const CONTROLLER_DIRECTORY_BASE_LENGTH: u32 = 0xbc0;
const FAMILY_LAYOUT_SHIFT: u32 = 0x10;
const CODEC_DESCRIPTOR_RELATIVE: u32 = 0xb8c;
const CODEC_KEY_RELATIVE: u32 = 0x968;
const MAPPED_KEY_RELATIVE: u32 = 0x964;
const CHECKSUM_BASE_RELATIVE: u32 = 0x96c;
const DESCRIPTOR_BASE_RELATIVE: u32 = 0xa9c;
const CODEC_OPERATION_RELATIVE: u32 = 0x15e0;
const EIGHTH_DESCRIPTOR_RELATIVE: u32 = 0xd0;
const EIGHTH_KEY_RELATIVE: u32 = 0xa00;
const TERMINAL_CONFIG_RELATIVE: u32 = 0x3c48;
const TERMINAL_CONFIG_MAGIC: u32 = 0x7679;
const SEVENTH_LAYER_PROGRAM_FROM_END: u32 = 0x60;
const SEVENTH_LAYER_PROGRAM_WINDOW_LENGTH: u32 = SEVENTH_LAYER_PROGRAM_FROM_END;
const TERMINAL_FILE_PROGRAM_RELATIVE: u32 = 0x40dc;
const TERMINAL_FILE_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;
const MAX_CONTROLLER_BLOCKS: usize = 1 << 20;
const MAX_CONTROLLER_REPLAY_WORK: usize = 512 << 20;

const SHELL_TABLE_FROM_ROOT: u32 = 0x1670;
const ROOTED_RECORD_MODE: u32 = 0x0001_0000;

// The dispatch's first two embedded control records are local table offsets.
// They distinguish this controller's producer graph from the later manifest
// controller before either graph can propose a payload plan.
const ROOTED_CONTROL_RECORD_WORDS: [(usize, u32); 3] =
    [(0x58, 0x150), (0x60, 0x1ac), (0x68, 0x1f0)];
/// Structurally rooted state retained between recognition and replay.
pub(crate) struct Probe {
    info_words: [u32; 8],
    base_image: Vec<u8>,
    shell_table: usize,
}

/// Exact terminal data retained for the shared controller adapter.
pub(crate) struct Finalizer {
    pub(super) root_rva: u32,
    pub(super) shell_table_rva: u32,
    pub(super) control_descriptor_rva: u32,
    pub(super) control_rva: u32,
    pub(super) codec_descriptor_rva: u32,
    pub(super) codec_rva: u32,
    pub(super) codec_operation_table_rva: u32,
    pub(super) mapped_stage_descriptor_rva: u32,
    pub(super) fifth_stage_descriptor_rva: u32,
    pub(super) seventh_stage_descriptor_rva: u32,
    pub(super) eighth_stage_descriptor_rva: u32,
    pub(super) eighth_stage_rva: u32,
    pub(super) payload_list_rva: u32,
    pub(super) zero_ranges: Vec<Range<u32>>,
    pub(super) layer_program: LfsrAlMapCandidate,
    pub(super) file_decoder_rva: u32,
    pub(super) layer_decoder_rva: u32,
    pub(super) file_aes_rva: u32,
    pub(super) layer_aes_rva: u32,
    pub(super) terminal: PostStage5Finalizer,
    pub(super) layer_raw_aes_key: [u8; 32],
}

/// Native-controller proposal before the shared full-table authenticator runs.
pub(super) struct Proposal {
    pub(super) base_image: Vec<u8>,
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: Finalizer,
}

fn rooted_shell_table(image: &[u8], info: &[u32; 8]) -> Result<Option<usize>> {
    // The shell entry's fixed base-relative table operand is +0x1670 from the
    // KONN-produced shell root. This is part of the family dispatch layout,
    // not a search over table-shaped data.
    let root = usize::try_from(info[6]).context("native PE32 shell root does not fit usize")?;
    let table = root
        .checked_add(usize::try_from(SHELL_TABLE_FROM_ROOT).expect("fixed shell-table offset"))
        .context("native PE32 shell-table offset overflows")?;
    let marker = table
        .checked_add(0x88)
        .context("native PE32 shell-table marker offset overflows")?;
    let marker_value = match read_u32(image, marker) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if marker_value != info[6] {
        return Ok(None);
    }

    let shell_length = read_u32(image, marker + 4)?;
    ensure!(
        read_u32(image, table + 0x4c)? == ROOTED_RECORD_MODE,
        "native PE32 rooted shell uses a different record-sequencing mode"
    );
    for (offset, expected) in ROOTED_CONTROL_RECORD_WORDS {
        ensure!(
            read_u32(image, table + offset)? == expected,
            "native PE32 rooted shell control-record geometry does not match this family"
        );
    }
    ensure!(
        (0x1001..0x10_0000).contains(&shell_length),
        "native PE32 rooted shell length is invalid"
    );
    let list = read_u32(image, table + 0x58)?;
    ensure!(list != 0, "native PE32 rooted shell list is null");
    checked_range(image.len(), list, 8, "native PE32 rooted shell list")?;
    Ok(Some(table))
}

fn materialize_payload_base(source: &BoundPayloadSource<'_>) -> Result<Vec<u8>> {
    let mut image = source
        .pe
        .map_image(source.packed)
        .context("mapping packed PE for native payload replay")?;
    let start = usize::try_from(source.bootstrap.destination_rva)
        .context("native payload bootstrap destination does not fit usize")?;
    let end = start
        .checked_add(source.outer.len())
        .context("native payload bootstrap range overflows")?;
    image
        .get_mut(start..end)
        .context("native payload bootstrap range exceeds mapped image")?
        .copy_from_slice(&source.outer);
    Ok(image)
}
fn header_checksum(
    image: &[u8],
    table: usize,
    crc_table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut checksum = 0u32;
    let mut cursor = table + 0x58;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        if read_u32(image, cursor + 4)? == 0 {
            return Ok(checksum);
        }
        checksum ^= checksum_descriptor(image, cursor, crc_table)?;
        cursor = cursor
            .checked_add(8)
            .context("native PE32 header-checksum cursor overflows")?;
    }
    bail!("native PE32 header-checksum list exceeds entry budget")
}

fn decode_file_checksum_records(
    image: &mut [u8],
    cursor: u32,
    size: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    if size != 0 {
        ensure!(
            size.is_multiple_of(STAGE_DESCRIPTOR_SIZE as u32),
            "rooted file-checksum records are not descriptor aligned"
        );
        let count = size / STAGE_DESCRIPTOR_SIZE as u32;
        for index in 0..count {
            if index & 0x3fff == 0
                && let Some(cancellation) = cancellation
            {
                cancellation.checkpoint()?;
            }
            let at = cursor
                .checked_add(index * STAGE_DESCRIPTOR_SIZE as u32)
                .context("rooted file-checksum cursor overflows")?;
            transform_shift2_range(image, at, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        }
        return Ok(());
    }

    let mut at = cursor;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        transform_shift2_range(image, at, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        if read_u32(
            image,
            usize::try_from(at).context("rooted checksum cursor does not fit usize")? + 4,
        )? == 0
        {
            return Ok(());
        }
        at = at
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("rooted file-checksum cursor overflows")?;
    }
    bail!("rooted file-checksum list exceeds entry budget")
}

fn parse_zero_records(
    image: &mut [u8],
    mut cursor: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Range<u32>>> {
    let mut ranges = Vec::new();
    let mut total = 0usize;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = read_stage_descriptor(
            image,
            usize::try_from(cursor).context("rooted zero-list cursor does not fit usize")?,
        )?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("rooted zero-list cursor overflows")?;
        if record.source_length == 0 {
            return Ok(ranges);
        }
        let range = checked_range(
            image.len(),
            record.source,
            record.source_length,
            "rooted zero range",
        )?;
        total = total
            .checked_add(range.len())
            .context("rooted zero-fill byte count overflows")?;
        ensure!(
            total <= MAX_CONTROLLER_REPLAY_WORK,
            "rooted zero-fill list exceeds byte budget"
        );
        let end = record
            .source
            .checked_add(record.source_length)
            .context("rooted zero range end overflows")?;
        ranges.push(record.source..end);
    }
    bail!("rooted zero-list exceeds entry budget")
}

fn parse_rooted_blocks(
    image: &mut [u8],
    mut cursor: u32,
    source: &BoundPayloadSource<'_>,
    info_base: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<PayloadBlockTable> {
    let encoded_base_offset = source
        .bootstrap
        .descriptor_file_offset
        .checked_add(0x80)
        .context("rooted compressed-stream key offset overflows")?;
    let encoded_base = read_u32(source.payload_source, encoded_base_offset)?;
    let stream_base = usize::try_from(
        (!encoded_base).wrapping_add(
            u32::try_from(source.bootstrap.descriptor_file_offset)
                .context("rooted descriptor file offset exceeds u32")?,
        ),
    )
    .context("rooted compressed-stream base does not fit usize")?;
    ensure!(
        stream_base <= source.payload_source.len(),
        "rooted compressed-stream base exceeds payload source"
    );

    let mut blocks = Vec::new();
    let mut work = 0usize;
    for index in 0..MAX_CONTROLLER_BLOCKS {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record_offset =
            usize::try_from(cursor).context("rooted A-record cursor does not fit usize")?;
        let record: [u8; STAGE_DESCRIPTOR_SIZE] = image
            .get(record_offset..record_offset + STAGE_DESCRIPTOR_SIZE)
            .context("rooted A-record exceeds image")?
            .try_into()
            .expect("fixed-width rooted A-record");
        let source_offset = u32::from_le_bytes(record[0..4].try_into().expect("A-record source"));
        let encoded_length = u32::from_le_bytes(record[4..8].try_into().expect("A-record length"));
        let destination_rva =
            u32::from_le_bytes(record[8..12].try_into().expect("A-record destination"));
        let destination_length = u32::from_le_bytes(
            record[12..16]
                .try_into()
                .expect("A-record destination length"),
        );
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("rooted A-record cursor overflows")?;

        if encoded_length == 0 {
            ensure!(
                source_offset == info_base && destination_rva == 0 && destination_length == 0,
                "rooted A-record terminator is malformed"
            );
            ensure!(!blocks.is_empty(), "rooted A-record list is empty");
            return Ok(PayloadBlockTable {
                stream_base: 0,
                blocks,
            });
        }
        ensure!(
            destination_length != 0,
            "rooted A-record has an empty destination"
        );
        let file_start = stream_base
            .checked_add(
                usize::try_from(source_offset)
                    .context("rooted source offset does not fit usize")?,
            )
            .context("rooted source offset overflows")?;
        let file_end = file_start
            .checked_add(
                usize::try_from(encoded_length)
                    .context("rooted encoded length does not fit usize")?,
            )
            .context("rooted source end overflows")?;
        ensure!(
            file_end <= source.payload_source.len(),
            "rooted payload block exceeds bound source"
        );
        if let Some(security) = source.source_security_range {
            ensure!(
                file_end <= security.start || file_start >= security.end,
                "rooted payload block overlaps the PE Security Directory"
            );
        }
        checked_range(
            image.len(),
            destination_rva,
            destination_length,
            "rooted payload destination",
        )?;
        work = work
            .checked_add(usize::try_from(encoded_length).expect("checked encoded length"))
            .and_then(|value| {
                value.checked_add(
                    usize::try_from(destination_length).expect("checked destination length"),
                )
            })
            .context("rooted payload replay work overflows")?;
        ensure!(
            work <= MAX_CONTROLLER_REPLAY_WORK,
            "rooted payload replay exceeds byte budget"
        );
        blocks.push(PayloadBlock {
            source_offset: file_start,
            encoded_length: usize::try_from(encoded_length).expect("checked encoded length"),
            destination_rva: usize::try_from(destination_rva).expect("checked destination RVA"),
            destination_length: usize::try_from(destination_length)
                .expect("checked destination length"),
        });
    }
    bail!("rooted A-record list exceeds entry budget")
}

/// Recognizes only the I386 controller layout rooted in the KONN shell graph.
pub(super) fn probe(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<Probe>> {
    let Ok(info_words) = decode_konn_info(source) else {
        return Ok(None);
    };
    let base_image = materialize_konn_bootstrap(source, &info_words, cancellation)?;
    let Some(shell_table) = rooted_shell_table(&base_image, &info_words)? else {
        return Ok(None);
    };
    Ok(Some(Probe {
        info_words,
        base_image,
        shell_table,
    }))
}

/// Replays the family’s fixed controller graph through its terminal A-record producer.
pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<Proposal> {
    let Probe {
        info_words,
        mut base_image,
        shell_table,
    } = probe;
    // Controller stages only authenticate transient code, maps, and lists.
    // Payload output starts from the exact mapped PE plus KONN bootstrap used by
    // evidence replay; terminal records do not own output teardown.
    let payload_base_image = materialize_payload_base(source)?;
    let crc_table = crc32_table();
    let pe_header = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE header offset underflows")?;
    let import_rva = read_u32(&base_image, shell_table + 0xbc)?;
    let resource_rva = read_u32(&base_image, shell_table + 0xc8)?;
    let resource_size = read_u32(&base_image, shell_table + 0xcc)?;
    write_u32(&mut base_image, pe_header + 0x80, import_rva)?;
    write_u32(&mut base_image, pe_header + 0x88, resource_rva)?;
    write_u32(&mut base_image, pe_header + 0x8c, resource_size)?;
    write_u32(&mut base_image, pe_header + 0xb0, 0)?;
    write_u32(&mut base_image, pe_header + 0xb4, 0)?;

    let bootstrap_checksum = checksum_descriptor(&base_image, shell_table + 0xa8, &crc_table)?;
    let controller_literal = read_u32(&base_image, shell_table + 0x40)?;
    let controller_descriptor = shell_table + 0x98;
    let controller = read_stage_descriptor(&base_image, controller_descriptor)?;
    ensure!(
        controller.source_length >= CONTROLLER_DIRECTORY_BASE_LENGTH,
        "native PE32 controller directory is shorter than the family layout"
    );
    let layout_shift = controller.source_length - CONTROLLER_DIRECTORY_BASE_LENGTH;
    ensure!(
        layout_shift == FAMILY_LAYOUT_SHIFT,
        "native PE32 controller layout shift does not match this family"
    );
    let header_checksum = header_checksum(&base_image, shell_table, &crc_table, cancellation)?;
    decrypt_rotating_dword_descriptor(
        &mut base_image,
        controller_descriptor,
        header_checksum ^ bootstrap_checksum ^ controller_literal,
        21,
        cancellation,
    )?;

    let controller_start = usize::try_from(controller.source)
        .context("native PE32 controller RVA does not fit usize")?;
    let codec_descriptor = controller_start
        .checked_add(
            usize::try_from(CODEC_DESCRIPTOR_RELATIVE + layout_shift).expect("fixed codec offset"),
        )
        .context("native PE32 codec descriptor overflows")?;
    let codec = read_stage_descriptor(&base_image, codec_descriptor)?;
    checked_range(
        base_image.len(),
        codec.source,
        codec.source_length,
        "native PE32 codec stage",
    )?;
    let codec_key = read_u32(
        &base_image,
        controller_start
            + usize::try_from(CODEC_KEY_RELATIVE + layout_shift).expect("fixed codec key offset"),
    )?;
    decrypt_rotating_dword_descriptor(
        &mut base_image,
        codec_descriptor,
        codec_key,
        19,
        cancellation,
    )?;

    let operation_table = usize::try_from(codec.source)
        .context("native PE32 codec RVA does not fit usize")?
        .checked_add(usize::try_from(CODEC_OPERATION_RELATIVE).expect("fixed operation offset"))
        .context("native PE32 operation table overflows")?;
    ensure!(
        operation_table + 32 <= base_image.len(),
        "native PE32 operation table exceeds image"
    );
    ensure!(
        matches!(read_u32(&base_image, operation_table)?, 1 | 0x11)
            && read_u32(&base_image, operation_table + 16)? == 2,
        "native PE32 operation table has the wrong action sequence"
    );
    transform_shift3_descriptor(&mut base_image, operation_table + 4, cancellation)?;
    let copy_list = read_u32(&base_image, operation_table + 20)?;
    copy_stage_list(&mut base_image, copy_list, cancellation)?;

    ensure!(
        operation_table >= 0x58,
        "native PE32 asset-key table underflows"
    );
    let mut asset_offsets = [0u32; 4];
    for group in 0..2usize {
        for index in 0..2usize {
            let at = operation_table - 0x58 + group * 32 + index * 8;
            transform_shift3_descriptor(&mut base_image, at, cancellation)?;
            asset_offsets[group * 2 + index] = read_u32(&base_image, at)?;
        }
    }
    let file_decoder = snapshot_decoder_table(&base_image, asset_offsets[0])?;
    let layer_decoder = snapshot_decoder_table(&base_image, asset_offsets[1])?;
    let (file_raw_aes_key, _) = recover_aes_context(&base_image, asset_offsets[2])?;
    let (layer_raw_aes_key, layer_aes) = recover_aes_context(&base_image, asset_offsets[3])?;

    let checksum_base = controller_start
        + usize::try_from(CHECKSUM_BASE_RELATIVE + layout_shift).expect("fixed checksum offset");
    // The three intermediate descriptors live in the shifted extension.  The
    // terminal descriptor remains in the original, unshifted table.
    let stage_descriptor_base = controller_start
        + usize::try_from(DESCRIPTOR_BASE_RELATIVE + layout_shift)
            .expect("fixed shifted descriptor offset");
    let unshifted_descriptor_base = controller_start
        + usize::try_from(DESCRIPTOR_BASE_RELATIVE).expect("fixed descriptor offset");
    let controller_checksum = checksum_descriptor(&base_image, shell_table + 0xb0, &crc_table)?;
    let mapped_key = advance_key(
        read_u32(
            &base_image,
            controller_start
                + usize::try_from(MAPPED_KEY_RELATIVE + layout_shift)
                    .expect("fixed map key offset"),
        )?,
        4,
    );
    decrypt_stage(
        &mut base_image,
        stage_descriptor_base + 0x40,
        header_checksum ^ controller_checksum ^ mapped_key,
        &layer_aes,
        &layer_decoder,
        None,
        cancellation,
    )
    .context("native PE32 mapped-stage replay")?;
    let mapped_checksum = checksum_descriptor(&base_image, checksum_base, &crc_table)?;
    let mapped_checksum_record = read_stage_descriptor(&base_image, checksum_base)?;
    ensure!(
        mapped_checksum_record.source_length >= 4,
        "native PE32 mapped checksum record is short"
    );
    let transformed_literal = read_u32(
        &base_image,
        usize::try_from(
            mapped_checksum_record
                .source
                .checked_add(mapped_checksum_record.source_length)
                .and_then(|value| value.checked_sub(4))
                .context("native PE32 transformed literal underflows")?,
        )
        .context("native PE32 transformed literal does not fit usize")?,
    )?;
    decrypt_stage(
        &mut base_image,
        stage_descriptor_base + 0x50,
        header_checksum ^ mapped_checksum ^ transformed_literal,
        &layer_aes,
        &layer_decoder,
        None,
        cancellation,
    )
    .context("native PE32 fifth-stage replay")?;
    let fifth_checksum = checksum_descriptor(&base_image, checksum_base + 8, &crc_table)?;
    let fifth_record = read_stage_descriptor(&base_image, checksum_base + 8)?;
    ensure!(
        fifth_record.source_length >= 0x10,
        "native PE32 fifth checksum record is short"
    );
    let seven_literal = !read_u32(
        &base_image,
        usize::try_from(
            fifth_record
                .source
                .checked_add(fifth_record.source_length)
                .and_then(|value| value.checked_sub(0x10))
                .context("native PE32 seven literal underflows")?,
        )
        .context("native PE32 seven literal does not fit usize")?,
    )?;
    decrypt_stage(
        &mut base_image,
        stage_descriptor_base + 0x70,
        header_checksum ^ fifth_checksum ^ seven_literal,
        &layer_aes,
        &layer_decoder,
        None,
        cancellation,
    )
    .context("native PE32 seven-stage replay")?;
    let seven_checksum = checksum_descriptor(&base_image, checksum_base + 0x10, &crc_table)?;
    let seven_descriptor = read_stage_descriptor(&base_image, stage_descriptor_base + 0x70)?;
    ensure!(
        seven_descriptor.destination_length >= EIGHTH_KEY_RELATIVE + 4,
        "native PE32 seven-stage output is too short for the eighth key"
    );
    ensure!(
        seven_descriptor.source == seven_descriptor.destination,
        "native PE32 seven-stage map is not in-place"
    );
    let layer_program_rva = seven_descriptor
        .source
        .checked_add(
            seven_descriptor
                .destination_length
                .checked_sub(SEVENTH_LAYER_PROGRAM_FROM_END)
                .context("native PE32 seven-stage layer-program slot underflows")?,
        )
        .context("native PE32 seven-stage layer-program RVA overflows")?;
    let layer_program = super::shared::exact_lfsr_al_map(
        &base_image,
        layer_program_rva,
        SEVENTH_LAYER_PROGRAM_WINDOW_LENGTH,
        "native PE32 seven-stage layer byte-map program",
    )?;

    let eighth_descriptor = unshifted_descriptor_base + EIGHTH_DESCRIPTOR_RELATIVE as usize;
    let eighth = read_stage_descriptor(&base_image, eighth_descriptor)?;
    ensure!(
        eighth.destination_length
            >= TERMINAL_FILE_PROGRAM_RELATIVE + TERMINAL_FILE_PROGRAM_WINDOW_LENGTH,
        "native PE32 terminal controller is too short"
    );
    ensure!(
        eighth.source == eighth.destination,
        "native PE32 terminal controller is not an in-place producer"
    );
    let eighth_key_literal = read_u32(
        &base_image,
        usize::try_from(
            seven_descriptor
                .source
                .checked_add(EIGHTH_KEY_RELATIVE)
                .context("native PE32 eighth key literal overflows")?,
        )
        .context("native PE32 eighth key literal does not fit usize")?,
    )?;
    let eighth_key =
        header_checksum ^ fifth_checksum ^ seven_checksum ^ advance_key(eighth_key_literal, 3);
    decrypt_stage(
        &mut base_image,
        eighth_descriptor,
        eighth_key,
        &layer_aes,
        &layer_decoder,
        Some(layer_program.map.as_ref()),
        cancellation,
    )
    .context("native PE32 eighth-stage replay")?;

    let config = eighth
        .source
        .checked_add(TERMINAL_CONFIG_RELATIVE)
        .context("native PE32 terminal configuration overflows")?;
    let config =
        usize::try_from(config).context("native PE32 terminal configuration does not fit usize")?;
    ensure!(
        read_u32(&base_image, config)? == TERMINAL_CONFIG_MAGIC,
        "native PE32 terminal configuration marker is invalid"
    );
    let checksum_cursor = read_u32(&base_image, config + 0x30)?;
    let checksum_size = read_u32(&base_image, config + 0x34)?;
    let compressed_cursor = read_u32(&base_image, config + 0x40)?;
    let zero_cursor = read_u32(&base_image, config + 0x48)?;
    ensure!(
        compressed_cursor != 0 && zero_cursor != 0,
        "native PE32 terminal list pointer is zero"
    );

    let file_program_rva = eighth
        .source
        .checked_add(TERMINAL_FILE_PROGRAM_RELATIVE)
        .context("native PE32 terminal file-program RVA overflows")?;
    let file_program = super::shared::exact_lfsr_al_map(
        &base_image,
        file_program_rva,
        TERMINAL_FILE_PROGRAM_WINDOW_LENGTH,
        "native PE32 terminal file byte-map program",
    )?;
    ensure!(
        read_u32(
            &base_image,
            usize::try_from(info_words[3])
                .context("native PE32 metadata base does not fit usize")?
                + 0x10,
        )? <= 0x10000,
        "native PE32 terminal metadata selected the unsupported layout"
    );
    let (_metadata_entry, _metadata_directories) =
        extract_metadata(&mut base_image, info_words[3], cancellation)?;
    decode_file_checksum_records(
        &mut base_image,
        checksum_cursor,
        checksum_size,
        cancellation,
    )?;
    let zero_ranges = parse_zero_records(&mut base_image, zero_cursor, cancellation)?;
    let block_table = parse_rooted_blocks(
        &mut base_image,
        compressed_cursor,
        source,
        info_words[3],
        cancellation,
    )?;

    let terminal = PostStage5Finalizer {
        file_raw_aes_key,
        file_decoder_table: file_decoder,
        file_program,
        metadata_records: 0,
        zero_ranges: Vec::new(),
    };
    let candidate = PayloadPlanCandidate::new(PayloadMaterializationPlan {
        block_table: block_table.clone(),
        aes_key: file_raw_aes_key,
        decoder: DecoderCandidate {
            source_file_offset: usize::try_from(asset_offsets[0])
                .context("native PE32 file decoder RVA does not fit usize")?,
            phase: 0,
            table: terminal.file_decoder_table.clone(),
        },
        post_transform: PayloadPostTransform::ByteMap(terminal.file_program.map.clone()),
    });
    Ok(Proposal {
        base_image: payload_base_image,
        block_table,
        candidate,
        finalizer: Finalizer {
            root_rva: info_words[6],
            shell_table_rva: u32::try_from(shell_table)
                .context("native PE32 shell-table RVA does not fit u32")?,
            control_descriptor_rva: u32::try_from(controller_descriptor)
                .context("native PE32 control descriptor RVA does not fit u32")?,
            control_rva: controller.source,
            codec_descriptor_rva: u32::try_from(codec_descriptor)
                .context("native PE32 codec descriptor RVA does not fit u32")?,
            codec_rva: codec.source,
            codec_operation_table_rva: u32::try_from(operation_table)
                .context("native PE32 codec operation-table RVA does not fit u32")?,
            mapped_stage_descriptor_rva: u32::try_from(stage_descriptor_base + 0x40)
                .context("native PE32 mapped-stage descriptor RVA does not fit u32")?,
            fifth_stage_descriptor_rva: u32::try_from(stage_descriptor_base + 0x50)
                .context("native PE32 fifth-stage descriptor RVA does not fit u32")?,
            seventh_stage_descriptor_rva: u32::try_from(stage_descriptor_base + 0x70)
                .context("native PE32 seventh-stage descriptor RVA does not fit u32")?,
            eighth_stage_descriptor_rva: u32::try_from(eighth_descriptor)
                .context("native PE32 eighth-stage descriptor RVA does not fit u32")?,
            eighth_stage_rva: eighth.source,
            payload_list_rva: compressed_cursor,
            zero_ranges,
            layer_program,
            file_decoder_rva: asset_offsets[0],
            layer_decoder_rva: asset_offsets[1],
            file_aes_rva: asset_offsets[2],
            layer_aes_rva: asset_offsets[3],
            terminal,
            layer_raw_aes_key,
        },
    })
}

/// Retains the fully authenticated mapped image; this terminal has no output teardown.
pub(super) fn finalize(
    source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let image_length = usize::try_from(source.pe.size_of_image)
        .context("native PE32 mapped image length does not fit host address space")?;
    let zero_ranges = finalizer
        .zero_ranges
        .iter()
        .map(|range| {
            let length = range
                .end
                .checked_sub(range.start)
                .context("rooted final zero range underflows")?;
            checked_range(image_length, range.start, length, "rooted final zero range")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure_terminal_zero_ranges_are_disjoint_from_payload_destinations(&zero_ranges, &block_table)?;

    let file_program_rva = u32::try_from(finalizer.terminal.file_program.offset)
        .context("native PE32 terminal file-program RVA does not fit u32")?;
    let mut image = finalize_post_stage5_as_authenticated_image(
        block_table,
        &finalizer.terminal,
        authenticated,
    )?;
    info!(
        zero_records = finalizer.zero_ranges.len(),
        terminal_stage_rva = finalizer.eighth_stage_rva,
        file_program_rva,
        file_decoder_rva = finalizer.file_decoder_rva,
        file_aes_rva = finalizer.file_aes_rva,
        blocks = image.decryption_details.block_count,
        "selected PE32 codec-operation-dispatch controller",
    );
    image.decryption_details.selected_controller = Some(
        SelectedController::CodecOperationDispatch(SelectedRootedNativeController {
            root_rva: finalizer.root_rva,
            graph_nodes: vec![
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::ShellTable,
                    rva: finalizer.shell_table_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::ControlDescriptor,
                    rva: finalizer.control_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Control,
                    rva: finalizer.control_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::CodecDescriptor,
                    rva: finalizer.codec_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Codec,
                    rva: finalizer.codec_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::CodecOperationTable,
                    rva: finalizer.codec_operation_table_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::MappedStageDescriptor,
                    rva: finalizer.mapped_stage_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::FifthStageDescriptor,
                    rva: finalizer.fifth_stage_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::SeventhStageDescriptor,
                    rva: finalizer.seventh_stage_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::EighthStageDescriptor,
                    rva: finalizer.eighth_stage_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::EighthStage,
                    rva: finalizer.eighth_stage_rva,
                },
            ],
            payload_list_rva: finalizer.payload_list_rva,
            file_decoder_rva: finalizer.file_decoder_rva,
            layer_decoder_rva: Some(finalizer.layer_decoder_rva),
            file_aes_context_rva: finalizer.file_aes_rva,
            layer_aes_context_rva: Some(finalizer.layer_aes_rva),
            file_raw_key_hex: hex::encode(finalizer.terminal.file_raw_aes_key),
            layer_raw_key_hex: Some(hex::encode(finalizer.layer_raw_aes_key)),
            layer_program_rva: Some(
                u32::try_from(finalizer.layer_program.offset)
                    .context("native PE32 layer-program RVA does not fit u32")?,
            ),
            layer_program_length: Some(finalizer.layer_program.length),
            layer_byte_map: Some(finalizer.layer_program.map.to_vec()),
            file_program_rva,
            file_program_length: finalizer.terminal.file_program.length,
            file_byte_map: finalizer.terminal.file_program.map.to_vec(),
            terminal_profile: None,
        }),
    );
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u32 = 0x100;

    fn info_words() -> [u32; 8] {
        [0, 0, 0, 0, 0, 0, ROOT, 0]
    }

    #[test]
    fn rooted_shell_table_returns_none_without_its_marker() {
        let image = vec![0; 0x3000];

        assert_eq!(rooted_shell_table(&image, &info_words()).unwrap(), None);
    }

    #[test]
    fn rooted_shell_table_rejects_malformed_owned_geometry() {
        let mut image = vec![0; 0x3000];
        let table = usize::try_from(ROOT + SHELL_TABLE_FROM_ROOT).unwrap();
        write_u32(&mut image, table + 0x88, ROOT).unwrap();

        assert!(rooted_shell_table(&image, &info_words()).is_err());
    }
}
