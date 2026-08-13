use anyhow::{Context, Result, bail, ensure};

use crate::pipeline::cancellation::{CancellationToken, Cancelled};
use crate::pipeline::outcome::{
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind,
    RootedNativeControllerTerminalProfile, SelectedController, SelectedRootedNativeController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crc32_table, lfsr_decode_program,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::{AuthenticatedPayloadPlan, PayloadPlanCandidate};
use super::super::source::BoundPayloadSource;
use super::super::{DecryptedImage, PayloadBlockTable};
use super::codec_relocation::{
    ExactPostStage5Input, ExactPostStage5Replay, HeaderMetadata, PostStage5Finalizer,
    finalize_post_stage5, finalize_post_stage5_as_authenticated_image, prefill_managed_section,
    replay_exact_post_stage5_after_transient_metadata,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};

const ROOT_FROM_KONN_SOURCE: u32 = 0x1b08;
const ROOT_LAYOUT_EXTRA: u32 = 8;
const ROOT_PRIMARY_LITERAL: u32 = 0x14;
const ROOT_PRIMARY_CHECKSUM: u32 = 0x38;
const ROOT_SECONDARY_CHECKSUM: u32 = 0x30;
const ROOT_STAGE1_DESCRIPTOR: u32 = 0x78;
const ROOT_HEADER_LIST: u32 = 0xb8;

const STAGE1_LENGTH: u32 = 0x1158;
const STAGE2_FROM_STAGE1: u32 = 0xec0;
const CHECKSUM_PAIRS_FROM_STAGE1: u32 = 0xe18;
const STAGE2_KEY_BACK: u32 = 20;
const STAGE3_ACCUMULATOR_BACK: u32 = 16;
const CODEC_TABLE_FROM_STAGE2: u32 = 0x26e0;
const CODEC_HEAD_FROM_TABLE: u32 = 32;
const CODEC_KEY_TABLE_FROM_HEAD: u32 = 88;

const STAGE3_FROM_STAGE2_DESCRIPTOR: u32 = 0x58;
const STAGE3B_FROM_STAGE2_DESCRIPTOR: u32 = 0x68;
const STAGE4_FROM_STAGE2_DESCRIPTOR: u32 = 0x88;
const STAGE5_FROM_STAGE2_DESCRIPTOR: u32 = 0xd8;
const SELECTOR_RECORDS_FROM_STAGE2_DESCRIPTOR: u32 = 0x18;
const SELECTOR_RECORD_COUNT: u32 = 4;
const SELECTOR_ACTIVE_SOURCE_LENGTH_MIN: u32 = 5;
const STAGE3_OUTPUT_LENGTH: u32 = 0x1298;
const STAGE3B_OUTPUT_LENGTH: u32 = 0x930;
const STAGE4_OUTPUT_LENGTH: u32 = 0x1090;
const DIRECT_PAYLOAD_LIST_TERMINAL_OUTPUT_LENGTH: u32 = 0x578c;
const NESTED_FINAL_DESCRIPTOR_TERMINAL_OUTPUT_LENGTH: u32 = 0x576c;
const STAGE3_LITERAL_FROM_END: u32 = 0x1c;
const STAGE3B_LITERAL_FROM_DESTINATION: u32 = 0x830;

const DIRECT_LAYER_MAP_FROM_STAGE4: u32 = 0xfc0;
const DIRECT_TERMINAL_SEED_FROM_STAGE4: u32 = 0xf70;
const DIRECT_PAYLOAD_LIST_SLOT_FROM_TERMINAL: u32 = 0x4dc0;
const DIRECT_TRANSIENT_CHECKSUM_CHAIN_SLOT_FROM_TERMINAL: u32 = 0x4dc8;
const DIRECT_FILE_MAP_FROM_TERMINAL: u32 = 0x5120;
const NESTED_LAYER_MAP_FROM_STAGE4: u32 = 0xfc0;
const NESTED_PRIMARY_FROM_STAGE1: u32 = 0x98;
const NESTED_FINAL_DESCRIPTOR_FROM_PRIMARY: u32 = 0xf00;
const NESTED_FINAL_CHECKSUM_FROM_PRIMARY: u32 = 0xd88;
const NESTED_TERMINAL_SEED_FROM_STAGE4: u32 = 0xf70;
const AL_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;
const CONTROLLER_METADATA_RELATIVE: u32 = 0x40;
const CONTROLLER_METADATA_LENGTH: u32 = 0x90;
const CONTROLLER_DIRECTORIES_RELATIVE: u32 = 0x50;
const CONTROLLER_DIRECTORIES_LENGTH: usize = 0x80;
const MAX_REPLAY_WORK: usize = 512 << 20;
const DATA_DIRECTORY_LENGTH: usize = 8;
const RESOURCE_DIRECTORY: usize = 2;

/// The two terminal layouts reached by the fixed terminal-profile-dispatch prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Profile {
    DirectPayloadList,
    NestedFinalDescriptor,
}

/// State established by the closed KONN-root probe.
pub(crate) struct Probe {
    info: KonnInfo,
    root_rva: u32,
    base_image: Vec<u8>,
    controller_image: Vec<u8>,
    header_checksum: u32,
    primary_checksum: u32,
    primary_literal: u32,
}

/// The direct controller proposal before shared full-table authentication.
pub(super) struct Proposal {
    pub(super) base_image: Vec<u8>,
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: Finalizer,
}

/// Rooted state retained for final outcome provenance and terminal teardown.
pub(crate) struct Finalizer {
    pub(super) profile: Profile,
    pub(super) root_rva: u32,
    pub(super) stage1_descriptor_rva: u32,
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
    pub(super) stage5_descriptor_rva: u32,
    pub(super) terminal_rva: u32,
    pub(super) payload_list_rva: u32,
    pub(super) file_decoder_rva: u32,
    pub(super) layer_decoder_rva: u32,
    pub(super) file_aes_context_rva: u32,
    pub(super) layer_aes_context_rva: u32,
    pub(super) file_raw_aes_key: [u8; 32],
    pub(super) layer_raw_aes_key: [u8; 32],
    pub(super) layer_program: LfsrAlMapCandidate,
    metadata: HeaderMetadata,
    terminal: PostStage5Finalizer,
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn rva_offset(rva: u32, label: &str) -> Result<usize> {
    usize::try_from(rva).with_context(|| format!("{label} RVA does not fit host address space"))
}

fn descriptor(image: &[u8], at: u32, label: &str) -> Result<StageDescriptor> {
    shared::read_stage_descriptor(image, rva_offset(at, label)?)
}

fn range(image: &[u8], start: u32, length: u32, label: &str) -> Result<std::ops::Range<usize>> {
    checked_range(image.len(), start, length, label)
}

fn exact_program_from_stage(
    image: &[u8],
    stage: StageDescriptor,
    relative: u32,
    label: &str,
) -> Result<LfsrAlMapCandidate> {
    let stage_range = range(image, stage.destination, stage.destination_length, label)?;
    let program_rva = add_rva(stage.destination, relative, label)?;
    let program = range(image, program_rva, AL_PROGRAM_WINDOW_LENGTH, label)?;
    ensure!(
        program.start >= stage_range.start && program.end <= stage_range.end,
        "{label} lies outside its rooted stage"
    );
    shared::exact_lfsr_al_map(image, program_rva, AL_PROGRAM_WINDOW_LENGTH, label)
}

fn nested_terminal_iterations(first_opcode: u8) -> Result<u32> {
    match first_opcode {
        0x90 => Ok(3),
        0x34 | 0xfe => Ok(4),
        opcode => bail!(
            "unsupported terminal-profile-dispatch nested stage-five selector opcode {opcode:#x}"
        ),
    }
}

fn checksum_descriptor(image: &[u8], at: u32, table: &[u32; 256], label: &str) -> Result<u32> {
    shared::checksum_descriptor(image, rva_offset(at, label)?, table)
}

fn root_slot(root: u32, relative: u32, label: &str) -> Result<u32> {
    add_rva(root, relative, label)
}

fn output_image(source: &BoundPayloadSource<'_>) -> Result<Vec<u8>> {
    let mut image = source
        .pe
        .map_image(source.packed)
        .context("mapping packed image for terminal-profile-dispatch payload replay")?;
    let start = usize::try_from(source.bootstrap.destination_rva)
        .context("PE64 EXE terminal-profile-dispatch bootstrap destination does not fit usize")?;
    let end = start
        .checked_add(source.outer.len())
        .context("PE64 EXE terminal-profile-dispatch bootstrap destination end overflows")?;
    image
        .get_mut(start..end)
        .context("PE64 EXE terminal-profile-dispatch bootstrap outer range exceeds mapped image")?
        .copy_from_slice(&source.outer);
    Ok(image)
}

fn prepare_header(image: &mut [u8], source: &BoundPayloadSource<'_>, root: u32) -> Result<()> {
    let pe = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE64 EXE terminal-profile-dispatch PE header offset underflows")?;
    for (root_relative, pe_relative) in [
        (8, 0x90usize),
        (4, 0x94),
        (40 + ROOT_LAYOUT_EXTRA, 0x98),
        (44 + ROOT_LAYOUT_EXTRA, 0x9c),
    ] {
        let value = read_u32(
            image,
            rva_offset(
                root_slot(
                    root,
                    root_relative,
                    "PE64 EXE terminal-profile-dispatch header control",
                )?,
                "PE64 EXE terminal-profile-dispatch header control",
            )?,
        )?;
        write_u32(image, pe + pe_relative, value)?;
    }
    write_u32(image, pe + 0xb0, 0)?;
    write_u32(image, pe + 0xb4, 0)?;
    Ok(())
}
fn header_record_count(image: &[u8], root: u32) -> Result<u32> {
    match read_u32(
        image,
        rva_offset(
            root_slot(root, 4, "PE64 EXE terminal-profile-dispatch root")?,
            "PE64 EXE terminal-profile-dispatch root",
        )?,
    )? {
        0x28 => Ok(4),
        0x50 => Ok(5),
        marker => {
            bail!("PE64 EXE terminal-profile-dispatch root layout marker {marker:#x} is invalid")
        }
    }
}

fn header_checksum(
    image: &[u8],
    root: u32,
    table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let records = header_record_count(image, root)?;
    let mut checksum = 0u32;
    let mut cursor = root_slot(
        root,
        ROOT_HEADER_LIST + ROOT_LAYOUT_EXTRA,
        "PE64 EXE terminal-profile-dispatch header checksum list",
    )?;
    for index in 0..records {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = descriptor(
            image,
            cursor,
            "PE64 EXE terminal-profile-dispatch header checksum record",
        )?;
        ensure!(
            record.source_length != 0,
            "PE64 EXE terminal-profile-dispatch header checksum record is empty"
        );
        range(
            image,
            record.source,
            record.source_length,
            "PE64 EXE terminal-profile-dispatch header checksum range",
        )?;
        checksum ^= checksum_descriptor(
            image,
            cursor,
            table,
            "PE64 EXE terminal-profile-dispatch header checksum",
        )?;
        cursor = cursor
            .checked_add(8)
            .context("PE64 EXE terminal-profile-dispatch header checksum cursor overflows")?;
    }
    ensure!(
        descriptor(
            image,
            cursor,
            "PE64 EXE terminal-profile-dispatch header checksum terminator"
        )?
        .source_length
            == 0,
        "PE64 EXE terminal-profile-dispatch header checksum list is not closed"
    );
    Ok(checksum)
}

fn root_is_well_formed(image: &[u8], info: &KonnInfo, root: u32) -> Result<()> {
    ensure!(
        read_u32(
            image,
            rva_offset(root, "PE64 EXE terminal-profile-dispatch root")?
        )? == info[3],
        "PE64 EXE terminal-profile-dispatch root does not identify its KONN destination"
    );
    let header_records = header_record_count(image, root)?;
    let expected_end = info[6]
        .checked_sub(0x200)
        .context("PE64 EXE terminal-profile-dispatch KONN root cannot precede its header span")?;
    ensure!(
        read_u32(
            image,
            rva_offset(
                root_slot(root, 8, "PE64 EXE terminal-profile-dispatch root")?,
                "PE64 EXE terminal-profile-dispatch root"
            )?
        )? == expected_end,
        "PE64 EXE terminal-profile-dispatch root does not close over the KONN shell"
    );

    let primary = descriptor(
        image,
        root_slot(
            root,
            ROOT_STAGE1_DESCRIPTOR + ROOT_LAYOUT_EXTRA,
            "PE64 EXE terminal-profile-dispatch primary descriptor",
        )?,
        "PE64 EXE terminal-profile-dispatch primary descriptor",
    )?;
    ensure!(
        primary.source_length == STAGE1_LENGTH && primary.source_length.is_multiple_of(4),
        "PE64 EXE terminal-profile-dispatch primary stage shape is invalid"
    );
    let controller_end = info[3]
        .checked_add(info[5])
        .context("PE64 EXE terminal-profile-dispatch controller range overflows")?;
    let primary_end = primary
        .source
        .checked_add(primary.source_length)
        .context("PE64 EXE terminal-profile-dispatch primary stage range overflows")?;
    ensure!(
        primary.source >= info[3] && primary_end <= controller_end,
        "PE64 EXE terminal-profile-dispatch primary stage is outside its KONN controller"
    );
    range(
        image,
        primary.source,
        primary.source_length,
        "PE64 EXE terminal-profile-dispatch primary stage",
    )?;

    for relative in [
        ROOT_PRIMARY_CHECKSUM + ROOT_LAYOUT_EXTRA,
        ROOT_SECONDARY_CHECKSUM + ROOT_LAYOUT_EXTRA,
    ] {
        let at = root_slot(
            root,
            relative,
            "PE64 EXE terminal-profile-dispatch root checksum",
        )?;
        let record = descriptor(
            image,
            at,
            "PE64 EXE terminal-profile-dispatch root checksum",
        )?;
        ensure!(
            record.source_length != 0,
            "PE64 EXE terminal-profile-dispatch root checksum is empty"
        );
        range(
            image,
            record.source,
            record.source_length,
            "PE64 EXE terminal-profile-dispatch root checksum range",
        )?;
    }

    let header_list = root_slot(
        root,
        ROOT_HEADER_LIST + ROOT_LAYOUT_EXTRA,
        "PE64 EXE terminal-profile-dispatch header checksum list",
    )?;
    for index in 0..header_records {
        let record = descriptor(
            image,
            header_list.checked_add(index * 8).context(
                "PE64 EXE terminal-profile-dispatch header checksum record RVA overflows",
            )?,
            "PE64 EXE terminal-profile-dispatch header checksum record",
        )?;
        ensure!(
            record.source_length != 0,
            "PE64 EXE terminal-profile-dispatch header checksum record is empty"
        );
        range(
            image,
            record.source,
            record.source_length,
            "PE64 EXE terminal-profile-dispatch header checksum range",
        )?;
    }
    let terminator = descriptor(
        image,
        header_list.checked_add(header_records * 8).context(
            "PE64 EXE terminal-profile-dispatch header checksum terminator RVA overflows",
        )?,
        "PE64 EXE terminal-profile-dispatch header checksum terminator",
    )?;
    ensure!(
        terminator.source_length == 0,
        "PE64 EXE terminal-profile-dispatch header checksum list is not closed"
    );
    Ok(())
}

fn validate_stage2(stage: StageDescriptor, info: &KonnInfo, image: &[u8]) -> Result<()> {
    let controller_end = info[3]
        .checked_add(info[5])
        .context("PE64 EXE terminal-profile-dispatch controller range overflows")?;
    let source_end = stage
        .source
        .checked_add(stage.source_length)
        .context("PE64 EXE terminal-profile-dispatch stage-two source range overflows")?;
    ensure!(
        stage.source == stage.destination,
        "PE64 EXE terminal-profile-dispatch stage two is not in place"
    );
    ensure!(
        stage.source >= info[3] && source_end <= controller_end,
        "PE64 EXE terminal-profile-dispatch stage-two source is outside its KONN controller"
    );
    ensure!(
        stage.source_length != 0 && stage.source_length.is_multiple_of(4),
        "PE64 EXE terminal-profile-dispatch stage-two encrypted shape is invalid"
    );
    ensure!(
        stage.destination_length != 0 && stage.destination_length < stage.source_length,
        "PE64 EXE terminal-profile-dispatch stage-two output shape is invalid"
    );
    range(
        image,
        stage.source,
        stage.source_length,
        "PE64 EXE terminal-profile-dispatch stage-two source",
    )?;
    range(
        image,
        stage.destination,
        stage.destination_length,
        "PE64 EXE terminal-profile-dispatch stage-two destination",
    )?;
    Ok(())
}

fn validate_checksum_pairs(image: &[u8], info: &KonnInfo, stage1: u32) -> Result<()> {
    let controller_end = info[3]
        .checked_add(info[5])
        .context("PE64 EXE terminal-profile-dispatch controller range overflows")?;
    let base = add_rva(
        stage1,
        CHECKSUM_PAIRS_FROM_STAGE1,
        "PE64 EXE terminal-profile-dispatch checksum-pair base",
    )?;
    for index in 0..4u32 {
        let at = base
            .checked_add(index * 8)
            .context("PE64 EXE terminal-profile-dispatch checksum pair RVA overflows")?;
        let pair = descriptor(
            image,
            at,
            "PE64 EXE terminal-profile-dispatch checksum pair",
        )?;
        let pair_end = pair
            .source
            .checked_add(pair.source_length)
            .context("PE64 EXE terminal-profile-dispatch checksum-pair range overflows")?;
        ensure!(
            pair.source >= info[3] && pair_end <= controller_end,
            "PE64 EXE terminal-profile-dispatch checksum-pair source is outside its KONN controller"
        );
        ensure!(
            pair.source_length != 0 && pair.source_length < 0x10000,
            "PE64 EXE terminal-profile-dispatch checksum-pair length is invalid"
        );
        range(
            image,
            pair.source,
            pair.source_length,
            "PE64 EXE terminal-profile-dispatch checksum-pair range",
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
    ensure!(
        stage.source == stage.destination,
        "PE64 EXE terminal-profile-dispatch {label} is not in place"
    );
    ensure!(
        stage.source_length != 0 && stage.source_length < stage.destination_length,
        "PE64 EXE terminal-profile-dispatch {label} compressed shape is invalid"
    );
    ensure!(
        stage.destination_length == destination_length,
        "PE64 EXE terminal-profile-dispatch {label} output span is invalid"
    );
    range(
        image,
        stage.source,
        stage.source_length,
        &format!("PE64 EXE terminal-profile-dispatch {label} source"),
    )?;
    range(
        image,
        stage.destination,
        stage.destination_length,
        &format!("PE64 EXE terminal-profile-dispatch {label} destination"),
    )?;
    Ok(())
}

fn transform_shift2_descriptor(
    image: &mut [u8],
    at: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<StageDescriptor> {
    shared::transform_shift2_range(image, at, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
    descriptor(
        image,
        at,
        "PE64 EXE terminal-profile-dispatch transformed descriptor",
    )
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
        at = at
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("PE64 EXE terminal-profile-dispatch copy-list cursor overflows")?;
        if record.source_length == 0 {
            return Ok(());
        }
        ensure!(
            record.source != 0
                && record.destination != 0
                && record.destination_length == record.source_length,
            "PE64 EXE terminal-profile-dispatch copy-list record is malformed"
        );
        let source = range(
            image,
            record.source,
            record.source_length,
            "PE64 EXE terminal-profile-dispatch copy-list source",
        )?;
        let destination = range(
            image,
            record.destination,
            record.destination_length,
            "PE64 EXE terminal-profile-dispatch copy-list destination",
        )?;
        image.copy_within(source, destination.start);
    }
    bail!("PE64 EXE terminal-profile-dispatch copy list exceeds entry budget")
}

fn replay_codec_controls(
    image: &mut [u8],
    table: u32,
    info: &KonnInfo,
    cancellation: Option<&CancellationToken>,
) -> Result<[u32; 4]> {
    let table_offset = rva_offset(table, "PE64 EXE terminal-profile-dispatch codec table")?;
    ensure!(
        read_u32(image, table_offset)? & 0x0f == 1
            && read_u32(image, table_offset + 4)? == 0
            && read_u32(image, table_offset + 8)? == info[3]
            && read_u32(image, table_offset + 12)? == 0,
        "PE64 EXE terminal-profile-dispatch codec table root is invalid"
    );

    let head = add_rva(
        table,
        CODEC_HEAD_FROM_TABLE,
        "PE64 EXE terminal-profile-dispatch codec head",
    )?;
    for record in [
        head,
        head.checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("PE64 EXE terminal-profile-dispatch codec control record overflows")?,
    ] {
        let record_offset = rva_offset(
            record,
            "PE64 EXE terminal-profile-dispatch codec control record",
        )?;
        let kind = read_u32(image, record_offset)?;
        if kind & 0x0f == 1 {
            shared::transform_shift3_descriptor(image, record_offset + 4, cancellation)?;
        } else if kind == 2 {
            let list = read_u32(image, record_offset + 4)?;
            copy_shift2_list(image, list, cancellation)?;
        } else {
            bail!("unsupported terminal-profile-dispatch codec control action {kind:#x}");
        }
    }

    let key_base = head
        .checked_sub(CODEC_KEY_TABLE_FROM_HEAD)
        .context("PE64 EXE terminal-profile-dispatch codec key table underflows")?;
    let mut offsets = [0u32; 4];
    for (slot, relative) in offsets.iter_mut().zip([0u32, 8, 32, 40]) {
        let at = key_base
            .checked_add(relative)
            .context("PE64 EXE terminal-profile-dispatch codec-key descriptor overflows")?;
        shared::transform_shift3_descriptor(
            image,
            rva_offset(
                at,
                "PE64 EXE terminal-profile-dispatch codec-key descriptor",
            )?,
            cancellation,
        )?;
        *slot = read_u32(
            image,
            rva_offset(at, "PE64 EXE terminal-profile-dispatch codec key")?,
        )?;
    }
    Ok(offsets)
}

fn profile(stage5: StageDescriptor) -> Result<Profile> {
    match stage5.destination_length {
        DIRECT_PAYLOAD_LIST_TERMINAL_OUTPUT_LENGTH => Ok(Profile::DirectPayloadList),
        NESTED_FINAL_DESCRIPTOR_TERMINAL_OUTPUT_LENGTH => Ok(Profile::NestedFinalDescriptor),
        length => {
            bail!(
                "PE64 EXE terminal-profile-dispatch final-controller output span {length:#x} is unsupported"
            )
        }
    }
}

fn replay_controller_metadata(
    image: &mut [u8],
    controller_rva: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<HeaderMetadata> {
    let metadata_rva = add_rva(
        controller_rva,
        CONTROLLER_METADATA_RELATIVE,
        "PE64 EXE terminal-profile-dispatch controller metadata",
    )?;
    let metadata_range = range(
        image,
        metadata_rva,
        CONTROLLER_METADATA_LENGTH,
        "PE64 EXE terminal-profile-dispatch controller metadata",
    )?;
    let entry_range = range(
        image,
        metadata_rva,
        4,
        "PE64 EXE terminal-profile-dispatch entry",
    )?;
    let directories_rva = add_rva(
        controller_rva,
        CONTROLLER_DIRECTORIES_RELATIVE,
        "PE64 EXE terminal-profile-dispatch controller directories",
    )?;
    let directories_range = range(
        image,
        directories_rva,
        CONTROLLER_DIRECTORIES_LENGTH as u32,
        "PE64 EXE terminal-profile-dispatch controller directories",
    )?;
    let mut original = [0u8; 0x90];
    original.copy_from_slice(&image[metadata_range.clone()]);
    shared::transform_shift2_range(
        image,
        metadata_rva,
        CONTROLLER_METADATA_LENGTH,
        cancellation,
    )?;
    let entry = read_u32(image, entry_range.start)?;
    let directories: [u8; CONTROLLER_DIRECTORIES_LENGTH] = image[directories_range]
        .try_into()
        .expect("PE64 EXE terminal-profile-dispatch controller directory span is fixed");
    image[metadata_range].copy_from_slice(&original);
    Ok(HeaderMetadata { entry, directories })
}

// The rooted checksum header substitutes a loader-owned resource location.
// Terminal metadata carries that transient value, while the unpacked image must
// retain the static resource directory from the packed PE header.
fn restore_static_resource_directory(
    metadata: &mut HeaderMetadata,
    source: &BoundPayloadSource<'_>,
) -> Result<()> {
    let resource = source
        .pe
        .directories
        .get(RESOURCE_DIRECTORY)
        .context("PE64 EXE terminal-profile-dispatch packed PE has no resource directory")?;
    let start = RESOURCE_DIRECTORY * DATA_DIRECTORY_LENGTH;
    metadata.directories[start..start + 4].copy_from_slice(&resource.virtual_address.to_le_bytes());
    metadata.directories[start + 4..start + DATA_DIRECTORY_LENGTH]
        .copy_from_slice(&resource.size.to_le_bytes());
    Ok(())
}
fn validate_transient_checksum_chain(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    pointer_slot_rva: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<usize> {
    let mut cursor = read_u32(
        image,
        rva_offset(
            pointer_slot_rva,
            "PE64 EXE terminal-profile-dispatch checksum-chain pointer slot",
        )?,
    )?;
    ensure!(
        cursor != 0,
        "PE64 EXE terminal-profile-dispatch checksum-chain pointer is null"
    );
    let mut records = 0usize;
    let mut backups = Vec::new();
    let result = (|| -> Result<usize> {
        for index in 0..MAX_STAGE_LIST_ENTRIES {
            if index & 0x3fff == 0
                && let Some(cancellation) = cancellation
            {
                cancellation.checkpoint()?;
            }
            let record_range = range(
                image,
                cursor,
                STAGE_DESCRIPTOR_SIZE as u32,
                "PE64 EXE terminal-profile-dispatch transient checksum-chain record",
            )?;
            let bytes: [u8; STAGE_DESCRIPTOR_SIZE] = image[record_range.clone()]
                .try_into()
                .expect("PE64 EXE terminal-profile-dispatch checksum-chain record length is fixed");
            backups.push((record_range, bytes));
            shared::transform_shift2_range(
                image,
                cursor,
                STAGE_DESCRIPTOR_SIZE as u32,
                cancellation,
            )?;
            let source_offset = read_u32(
                image,
                rva_offset(
                    cursor,
                    "PE64 EXE terminal-profile-dispatch transient checksum-chain source",
                )?,
            )?;
            let length = read_u32(
                image,
                rva_offset(
                    cursor.checked_add(4).context(
                        "PE64 EXE terminal-profile-dispatch checksum-chain length RVA overflows",
                    )?,
                    "PE64 EXE terminal-profile-dispatch transient checksum-chain length",
                )?,
            )?;
            if length == 0 {
                return Ok(records);
            }
            // The first decoded record seeds the native checksum walk; only
            // subsequent records address the bound packed source.
            if records != 0 {
                checked_range(
                    source.packed.len(),
                    source_offset,
                    length,
                    "PE64 EXE terminal-profile-dispatch transient checksum-chain source",
                )?;
            }
            cursor = cursor
                .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
                .context("PE64 EXE terminal-profile-dispatch checksum-chain cursor overflows")?;
            records = records.checked_add(1).context(
                "PE64 EXE terminal-profile-dispatch checksum-chain record count overflows",
            )?;
        }
        bail!("PE64 EXE terminal-profile-dispatch transient checksum chain exceeds entry budget")
    })();
    for (record_range, bytes) in backups {
        image[record_range].copy_from_slice(&bytes);
    }
    result
}
/// Recognizes the AMD64 executable grammar solely through its KONN-rooted controller.
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
    let root_rva = match add_rva(
        info[6],
        ROOT_FROM_KONN_SOURCE,
        "PE64 EXE terminal-profile-dispatch root",
    ) {
        Ok(root) => root,
        Err(_) => return Ok(None),
    };
    let mut controller_image = match shared::materialize_konn_bootstrap(source, &info, cancellation)
    {
        Ok(image) => image,
        Err(error) if error.downcast_ref::<Cancelled>().is_some() => return Err(error),
        Err(_) => return Ok(None),
    };
    let root_offset = match rva_offset(root_rva, "PE64 EXE terminal-profile-dispatch root") {
        Ok(offset) => offset,
        Err(_) => return Ok(None),
    };
    if read_u32(&controller_image, root_offset).ok() != Some(info[3]) {
        return Ok(None);
    }
    root_is_well_formed(&controller_image, &info, root_rva)?;
    prepare_header(&mut controller_image, source, root_rva)?;
    let table = crc32_table();
    let header_checksum = header_checksum(&controller_image, root_rva, &table, cancellation)?;
    let primary_checksum = checksum_descriptor(
        &controller_image,
        root_slot(
            root_rva,
            ROOT_PRIMARY_CHECKSUM + ROOT_LAYOUT_EXTRA,
            "PE64 EXE terminal-profile-dispatch primary checksum",
        )?,
        &table,
        "PE64 EXE terminal-profile-dispatch primary checksum",
    )?;
    let primary_literal = read_u32(
        &controller_image,
        rva_offset(
            root_slot(
                root_rva,
                ROOT_PRIMARY_LITERAL,
                "PE64 EXE terminal-profile-dispatch primary literal",
            )?,
            "PE64 EXE terminal-profile-dispatch primary literal",
        )?,
    )?;
    let base_image = output_image(source)?;
    Ok(Some(Probe {
        info,
        root_rva,
        base_image,
        controller_image,
        header_checksum,
        primary_checksum,
        primary_literal,
    }))
}

/// Replays the fixed terminal-profile-dispatch graph and returns exactly one rooted payload plan.
pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<Proposal> {
    let Probe {
        info,
        root_rva,
        base_image,
        mut controller_image,
        header_checksum,
        primary_checksum,
        primary_literal,
    } = probe;
    let table = crc32_table();

    let stage1_descriptor_rva = root_slot(
        root_rva,
        ROOT_STAGE1_DESCRIPTOR + ROOT_LAYOUT_EXTRA,
        "PE64 EXE terminal-profile-dispatch primary descriptor",
    )?;
    shared::decrypt_rotating_dword_descriptor(
        &mut controller_image,
        rva_offset(
            stage1_descriptor_rva,
            "PE64 EXE terminal-profile-dispatch primary descriptor",
        )?,
        header_checksum ^ primary_checksum ^ primary_literal,
        21,
        cancellation,
    )
    .context("decrypting terminal-profile-dispatch primary controller stage")?;
    let stage1 = descriptor(
        &controller_image,
        stage1_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch primary descriptor",
    )?;
    ensure!(
        stage1.source_length == STAGE1_LENGTH,
        "PE64 EXE terminal-profile-dispatch primary stage length changed after decrypt"
    );
    let stage1_rva = stage1.source;

    let stage2_descriptor_rva = add_rva(
        stage1_rva,
        STAGE2_FROM_STAGE1,
        "PE64 EXE terminal-profile-dispatch stage-two descriptor",
    )?;
    let stage2_before = descriptor(
        &controller_image,
        stage2_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch stage-two descriptor",
    )?;
    validate_stage2(stage2_before, &info, &controller_image)?;
    validate_checksum_pairs(&controller_image, &info, stage1_rva)?;
    let checksum_pairs = add_rva(
        stage1_rva,
        CHECKSUM_PAIRS_FROM_STAGE1,
        "PE64 EXE terminal-profile-dispatch checksum-pair base",
    )?;
    let stage2_key_at = checksum_pairs
        .checked_sub(STAGE2_KEY_BACK)
        .context("PE64 EXE terminal-profile-dispatch stage-two key underflows")?;
    let stage2_key = read_u32(
        &controller_image,
        rva_offset(
            stage2_key_at,
            "PE64 EXE terminal-profile-dispatch stage-two key",
        )?,
    )?;
    shared::decrypt_rotating_dword_descriptor(
        &mut controller_image,
        rva_offset(
            stage2_descriptor_rva,
            "PE64 EXE terminal-profile-dispatch stage-two descriptor",
        )?,
        stage2_key,
        19,
        cancellation,
    )
    .context("decrypting terminal-profile-dispatch stage two")?;
    let stage2 = descriptor(
        &controller_image,
        stage2_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch stage-two descriptor",
    )?;
    validate_stage2(stage2, &info, &controller_image)?;

    let codec_table_rva = add_rva(
        stage2.source,
        CODEC_TABLE_FROM_STAGE2,
        "PE64 EXE terminal-profile-dispatch codec table",
    )?;
    let key_offsets =
        replay_codec_controls(&mut controller_image, codec_table_rva, &info, cancellation)?;
    let file_decoder_table = shared::snapshot_decoder_table(&controller_image, key_offsets[0])?;
    let layer_decoder_table = shared::snapshot_decoder_table(&controller_image, key_offsets[1])?;
    let (file_raw_aes_key, _) = shared::recover_aes_context(&controller_image, key_offsets[2])?;
    let (layer_raw_aes_key, layer_aes) =
        shared::recover_aes_context(&controller_image, key_offsets[3])?;

    let stage3_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        STAGE3_FROM_STAGE2_DESCRIPTOR,
        "PE64 EXE terminal-profile-dispatch stage-three descriptor",
    )?;
    let stage3_before = descriptor(
        &controller_image,
        stage3_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch stage-three descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage3_before,
        STAGE3_OUTPUT_LENGTH,
        "stage three",
    )?;
    let checksum2 = checksum_descriptor(
        &controller_image,
        root_slot(
            root_rva,
            ROOT_SECONDARY_CHECKSUM + ROOT_LAYOUT_EXTRA,
            "PE64 EXE terminal-profile-dispatch stage-three checksum",
        )?,
        &table,
        "PE64 EXE terminal-profile-dispatch stage-three checksum",
    )?;
    let selector_records = add_rva(
        stage2_descriptor_rva,
        SELECTOR_RECORDS_FROM_STAGE2_DESCRIPTOR,
        "PE64 EXE terminal-profile-dispatch selector records",
    )?;
    let mut active_selector_records = 0u32;
    for index in 0..SELECTOR_RECORD_COUNT {
        let record = descriptor(
            &controller_image,
            add_rva(
                selector_records,
                index * STAGE_DESCRIPTOR_SIZE as u32,
                "PE64 EXE terminal-profile-dispatch selector record",
            )?,
            "PE64 EXE terminal-profile-dispatch selector record",
        )?;
        validate_in_place_stage(
            &controller_image,
            record,
            record.destination_length,
            "selector record",
        )?;
        if record.source_length >= SELECTOR_ACTIVE_SOURCE_LENGTH_MIN {
            active_selector_records += 1;
        }
    }
    ensure!(
        active_selector_records >= 3,
        "PE64 EXE terminal-profile-dispatch selector has fewer than three active records"
    );
    let accumulator_at = checksum_pairs
        .checked_sub(STAGE3_ACCUMULATOR_BACK)
        .context("PE64 EXE terminal-profile-dispatch stage-three accumulator underflows")?;
    let accumulator = shared::advance_key(
        read_u32(
            &controller_image,
            rva_offset(
                accumulator_at,
                "PE64 EXE terminal-profile-dispatch stage-three accumulator",
            )?,
        )?,
        active_selector_records,
    );
    shared::decrypt_stage(
        &mut controller_image,
        rva_offset(
            stage3_descriptor_rva,
            "PE64 EXE terminal-profile-dispatch stage-three descriptor",
        )?,
        header_checksum ^ checksum2 ^ accumulator,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("decrypting terminal-profile-dispatch stage three")?;
    let stage3_literal_at = stage3_before
        .destination
        .checked_add(
            stage3_before
                .destination_length
                .checked_sub(STAGE3_LITERAL_FROM_END)
                .context("PE64 EXE terminal-profile-dispatch stage-three literal underflows")?,
        )
        .context("PE64 EXE terminal-profile-dispatch stage-three literal RVA overflows")?;
    let stage3_marker = stage3_literal_at
        .checked_sub(4)
        .context("PE64 EXE terminal-profile-dispatch stage-three literal marker underflows")?;
    ensure!(
        controller_image[range(
            &controller_image,
            stage3_marker,
            4,
            "PE64 EXE terminal-profile-dispatch stage-three literal marker"
        )?] == [0xc3, 0xcc, 0xcc, 0xcc],
        "PE64 EXE terminal-profile-dispatch stage-three literal marker is invalid"
    );
    let stage3_literal = read_u32(
        &controller_image,
        rva_offset(
            stage3_literal_at,
            "PE64 EXE terminal-profile-dispatch stage-three literal",
        )?,
    )?;

    let stage3b_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        STAGE3B_FROM_STAGE2_DESCRIPTOR,
        "PE64 EXE terminal-profile-dispatch stage-three-b descriptor",
    )?;
    let stage3b_before = descriptor(
        &controller_image,
        stage3b_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch stage-three-b descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage3b_before,
        STAGE3B_OUTPUT_LENGTH,
        "stage three-b",
    )?;
    let checksum3 = checksum_descriptor(
        &controller_image,
        add_rva(
            checksum_pairs,
            24,
            "PE64 EXE terminal-profile-dispatch stage-three-b checksum",
        )?,
        &table,
        "PE64 EXE terminal-profile-dispatch stage-three-b checksum",
    )?;
    shared::decrypt_stage(
        &mut controller_image,
        rva_offset(
            stage3b_descriptor_rva,
            "PE64 EXE terminal-profile-dispatch stage-three-b descriptor",
        )?,
        header_checksum ^ checksum3 ^ stage3_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("decrypting terminal-profile-dispatch stage three-b")?;
    let stage3b_literal_at = add_rva(
        stage3b_before.destination,
        STAGE3B_LITERAL_FROM_DESTINATION,
        "PE64 EXE terminal-profile-dispatch stage-three-b literal",
    )?;
    let stage3b_literal = !read_u32(
        &controller_image,
        rva_offset(
            stage3b_literal_at,
            "PE64 EXE terminal-profile-dispatch stage-three-b literal",
        )?,
    )?;

    let stage4_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        STAGE4_FROM_STAGE2_DESCRIPTOR,
        "PE64 EXE terminal-profile-dispatch stage-four descriptor",
    )?;
    let stage4_before = descriptor(
        &controller_image,
        stage4_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch stage-four descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage4_before,
        STAGE4_OUTPUT_LENGTH,
        "stage four",
    )?;
    let checksum4 = checksum_descriptor(
        &controller_image,
        add_rva(
            checksum_pairs,
            16,
            "PE64 EXE terminal-profile-dispatch stage-four checksum",
        )?,
        &table,
        "PE64 EXE terminal-profile-dispatch stage-four checksum",
    )?;
    shared::decrypt_stage(
        &mut controller_image,
        rva_offset(
            stage4_descriptor_rva,
            "PE64 EXE terminal-profile-dispatch stage-four descriptor",
        )?,
        header_checksum ^ checksum4 ^ stage3b_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("decrypting terminal-profile-dispatch stage four")?;
    let map_layer_rva = stage4_before.destination;
    let stage5_descriptor_rva = add_rva(
        stage2_descriptor_rva,
        STAGE5_FROM_STAGE2_DESCRIPTOR,
        "PE64 EXE terminal-profile-dispatch stage-five descriptor",
    )?;
    let stage5_before = descriptor(
        &controller_image,
        stage5_descriptor_rva,
        "PE64 EXE terminal-profile-dispatch stage-five descriptor",
    )?;
    validate_in_place_stage(
        &controller_image,
        stage5_before,
        stage5_before.destination_length,
        "stage five",
    )?;
    let profile = profile(stage5_before)?;
    match profile {
        Profile::DirectPayloadList => ensure!(
            stage2.destination_length == 0x3a00,
            "PE64 EXE terminal-profile-dispatch direct-payload-list stage-two output span is invalid"
        ),
        Profile::NestedFinalDescriptor => {
            let primary_rva = add_rva(
                stage1_rva,
                NESTED_PRIMARY_FROM_STAGE1,
                "PE64 EXE terminal-profile-dispatch nested standard primary",
            )?;
            ensure!(
                add_rva(
                    primary_rva,
                    NESTED_FINAL_DESCRIPTOR_FROM_PRIMARY,
                    "PE64 EXE terminal-profile-dispatch nested final descriptor",
                )? == stage5_descriptor_rva,
                "PE64 EXE terminal-profile-dispatch nested final descriptor does not close over D5"
            );
            ensure!(
                add_rva(
                    primary_rva,
                    NESTED_FINAL_CHECKSUM_FROM_PRIMARY,
                    "PE64 EXE terminal-profile-dispatch nested final checksum",
                )? == add_rva(
                    checksum_pairs,
                    8,
                    "PE64 EXE terminal-profile-dispatch final-controller checksum"
                )?,
                "PE64 EXE terminal-profile-dispatch nested final checksum does not close over D4 and its successor"
            );
        }
    }
    let layer_program = exact_program_from_stage(
        &controller_image,
        stage4_before,
        match profile {
            Profile::DirectPayloadList => DIRECT_LAYER_MAP_FROM_STAGE4,
            Profile::NestedFinalDescriptor => NESTED_LAYER_MAP_FROM_STAGE4,
        },
        match profile {
            Profile::DirectPayloadList => {
                "PE64 EXE terminal-profile-dispatch direct-payload-list layer byte-program"
            }
            Profile::NestedFinalDescriptor => {
                "PE64 EXE terminal-profile-dispatch nested-final-descriptor layer byte-program"
            }
        },
    )?;
    let checksum5 = checksum_descriptor(
        &controller_image,
        add_rva(
            checksum_pairs,
            8,
            "PE64 EXE terminal-profile-dispatch stage-five checksum",
        )?,
        &table,
        "PE64 EXE terminal-profile-dispatch stage-five checksum",
    )?;
    let stage5_seed = read_u32(
        &controller_image,
        rva_offset(
            add_rva(
                map_layer_rva,
                match profile {
                    Profile::DirectPayloadList => DIRECT_TERMINAL_SEED_FROM_STAGE4,
                    Profile::NestedFinalDescriptor => NESTED_TERMINAL_SEED_FROM_STAGE4,
                },
                "PE64 EXE terminal-profile-dispatch stage-five seed",
            )?,
            "PE64 EXE terminal-profile-dispatch stage-five seed",
        )?,
    )?;
    let stage5_iterations = match profile {
        Profile::DirectPayloadList => 3,
        Profile::NestedFinalDescriptor => {
            let layer_program_end = layer_program
                .offset
                .checked_add(layer_program.length)
                .context("PE64 EXE terminal-profile-dispatch nested stage-five selector program end overflows")?;
            let encoded = controller_image
                .get(layer_program.offset..layer_program_end)
                .context("PE64 EXE terminal-profile-dispatch nested stage-five selector program exceeds the mapped image")?;
            nested_terminal_iterations(lfsr_decode_program(encoded)[0])?
        }
    };
    let stage5_rva = stage5_before.destination;
    let stage5_key = header_checksum
        ^ checksum4
        ^ checksum5
        ^ shared::advance_key(stage5_seed, stage5_iterations);
    shared::decrypt_stage(
        &mut controller_image,
        rva_offset(
            stage5_descriptor_rva,
            "PE64 EXE terminal-profile-dispatch stage-five descriptor",
        )?,
        stage5_key,
        &layer_aes,
        &layer_decoder_table,
        Some(layer_program.map.as_ref()),
        cancellation,
    )
    .context("decrypting terminal-profile-dispatch stage five")?;
    let checksum_chain_slot = add_rva(
        stage5_rva,
        DIRECT_TRANSIENT_CHECKSUM_CHAIN_SLOT_FROM_TERMINAL,
        "PE64 EXE terminal-profile-dispatch transient checksum-chain slot",
    )?;
    let metadata_records = validate_transient_checksum_chain(
        &mut controller_image,
        source,
        checksum_chain_slot,
        cancellation,
    )?;
    let file_program = exact_program_from_stage(
        &controller_image,
        stage5_before,
        DIRECT_FILE_MAP_FROM_TERMINAL,
        "PE64 EXE terminal-profile-dispatch file byte-program",
    )?;
    let ExactPostStage5Replay {
        block_table,
        payload_list_rva,
        candidate,
        finalizer: post_stage5,
    } = replay_exact_post_stage5_after_transient_metadata(
        &mut controller_image,
        source,
        ExactPostStage5Input {
            metadata_list_pointer_slot_rva: checksum_chain_slot,
            payload_list_pointer_slot_rva: add_rva(
                stage5_rva,
                DIRECT_PAYLOAD_LIST_SLOT_FROM_TERMINAL,
                "PE64 EXE terminal-profile-dispatch payload-list slot",
            )?,
            file_program,
            file_raw_aes_key,
            file_decoder_rva: key_offsets[0],
            file_decoder_table,
        },
        metadata_records,
        cancellation,
    )?;
    let mut metadata = replay_controller_metadata(&mut controller_image, info[3], cancellation)?;
    restore_static_resource_directory(&mut metadata, source)?;
    prefill_managed_section(&mut controller_image, source)?;
    let terminal_rva = stage5_before.destination;
    let replay_work = block_table.blocks.iter().try_fold(0usize, |work, block| {
        work.checked_add(block.encoded_length)
            .and_then(|value| value.checked_add(block.destination_length))
            .context("PE64 EXE terminal-profile-dispatch payload replay work overflows")
    })?;
    ensure!(
        replay_work <= MAX_REPLAY_WORK,
        "PE64 EXE terminal-profile-dispatch payload replay exceeds byte-work cap"
    );

    Ok(Proposal {
        base_image,
        block_table,
        candidate,
        finalizer: Finalizer {
            profile,
            root_rva,
            stage1_descriptor_rva,
            stage1_rva,
            stage2_descriptor_rva,
            stage2_rva: stage2.source,
            codec_table_rva,
            stage3_descriptor_rva,
            stage3_rva: stage3_before.destination,
            stage3b_descriptor_rva,
            stage3b_rva: stage3b_before.destination,
            stage4_descriptor_rva,
            map_layer_rva,
            stage5_descriptor_rva,
            terminal_rva,
            payload_list_rva,
            file_decoder_rva: key_offsets[0],
            layer_decoder_rva: key_offsets[1],
            file_aes_context_rva: key_offsets[2],
            layer_aes_context_rva: key_offsets[3],
            file_raw_aes_key,
            layer_raw_aes_key,
            layer_program,
            metadata,
            terminal: post_stage5,
        },
    })
}

/// Applies the shared terminal teardown after the selected rooted plan authenticates.
pub(super) fn finalize(
    source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let mut image = match finalizer.profile {
        Profile::DirectPayloadList => finalize_post_stage5(
            source,
            block_table,
            &finalizer.terminal,
            &finalizer.metadata,
            authenticated,
        )?,
        Profile::NestedFinalDescriptor => finalize_post_stage5_as_authenticated_image(
            block_table,
            &finalizer.terminal,
            authenticated,
        )?,
    };
    let file_program = &finalizer.terminal.file_program;
    image.decryption_details.selected_controller = Some(
        SelectedController::TerminalProfileDispatch(SelectedRootedNativeController {
            root_rva: finalizer.root_rva,
            graph_nodes: vec![
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::PrimaryDescriptor,
                    rva: finalizer.stage1_descriptor_rva,
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
                    kind: RootedNativeControllerNodeKind::Stage5Descriptor,
                    rva: finalizer.stage5_descriptor_rva,
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
            layer_program_rva: Some(u32::try_from(finalizer.layer_program.offset).context(
                "native terminal-profile-dispatch layer program mapped-image RVA exceeds u32",
            )?),
            layer_program_length: Some(finalizer.layer_program.length),
            layer_byte_map: Some(finalizer.layer_program.map.to_vec()),
            file_program_rva: u32::try_from(file_program.offset).context(
                "native terminal-profile-dispatch file program mapped-image RVA exceeds u32",
            )?,
            file_program_length: file_program.length,
            file_byte_map: file_program.map.to_vec(),
            terminal_profile: Some(match finalizer.profile {
                Profile::DirectPayloadList => {
                    RootedNativeControllerTerminalProfile::DirectPayloadList
                }
                Profile::NestedFinalDescriptor => {
                    RootedNativeControllerTerminalProfile::NestedFinalDescriptor
                }
            }),
        }),
    );
    Ok(image)
}
