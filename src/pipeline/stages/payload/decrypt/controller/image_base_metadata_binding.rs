use anyhow::{Context, Result, bail, ensure};
use tracing::info;

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind,
    RootedNativeControllerTerminalProfile, SelectedController, SelectedRootedNativeController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crc32_table,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::{AuthenticatedPayloadPlan, PayloadPlanCandidate};
use super::super::source::BoundPayloadSource;
use super::super::{DecryptedImage, PayloadBlockTable};
use super::codec_relocation::{
    self as terminal, ExactPostStage5Input, ExactPostStage5Replay, HeaderMetadata,
    PostStage5Finalizer, replay_exact_post_stage5,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};

// Every address below is reached from the decoded KONN shell end. They are
const ROOT_CONTROL_LENGTH: u32 = 0xe8;
const ROOT_FROM_KONN_SHELL_END: u32 = 0x1a58;
const ROOT_IMPORT_SIZE: u32 = 0x28;
const ROOT_ANCHOR_END_BACK: u32 = 0x200;
const ROOT_LAYOUT_STAMP_RELATIVE: u32 = 0x68;
const ROOT_PRIMARY_DESCRIPTOR_RELATIVE: u32 = 0x78;
const ROOT_PRIMARY_LITERAL_RELATIVE: u32 = 0x14;
const ROOT_STAGE3_CHECKSUM_RELATIVE: u32 = 0x30;
const ROOT_PRIMARY_CHECKSUM_RELATIVE: u32 = 0x38;
const ROOT_HEADER_CHECKSUM_LIST_RELATIVE: u32 = 0xb8;
const ROOT_HEADER_CHECKSUM_LENGTHS: [u32; 4] = [48, 32, 76, 88];
const ROOT_PRIMARY_SOURCE_RELATIVE: u32 = 0x9188;
const ROOT_PRIMARY_LENGTH: u32 = 0x10b8;
const ROOT_STAGE3_CHECKSUM_LENGTH: u32 = 0xdd0;
const ROOT_PRIMARY_CHECKSUM_LENGTH: u32 = 0x20d0;

const STAGE1_STAGE2_KEY_RELATIVE: u32 = 0xd6c;
const STAGE1_STAGE3_ACCUMULATOR_RELATIVE: u32 = 0xd70;
const STAGE1_CHECKSUM_BASE_RELATIVE: u32 = 0xd80;
const STAGE1_STAGE2_DESCRIPTOR_RELATIVE: u32 = 0xe20;
const STAGE1_STAGE3_DESCRIPTOR_RELATIVE: u32 = 0xe78;
const STAGE1_STAGE3B_DESCRIPTOR_RELATIVE: u32 = 0xe88;
const STAGE1_STAGE4_DESCRIPTOR_RELATIVE: u32 = 0xea8;
const STAGE1_TERMINAL_DESCRIPTOR_RELATIVE: u32 = 0xef8;
const CODEC_PARAMETER_RELATIVE: u32 = 0x23c8;
const CODEC_ACTION_RELATIVE: u32 = 0x2420;
const CODEC_PARAMETER_DESCRIPTOR_RELATIVES: [u32; 4] = [0, 8, 0x20, 0x28];

const STAGE3_DESTINATION_LENGTH: u32 = 0x1270;
const STAGE3_LITERAL_RELATIVE: u32 = 0x1254;
const STAGE3B_DESTINATION_LENGTH: u32 = 0x8b0;
const STAGE3B_LITERAL_RELATIVE: u32 = 0x7b0;
const STAGE4_DESTINATION_LENGTH: u32 = 0xec0;
const STAGE4_ACCUMULATOR_RELATIVE: u32 = 0xd98;
const STAGE4_LAYER_PROGRAM_RELATIVE: u32 = 0xdf0;
const STAGE4_LAYER_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;
const TERMINAL_DESTINATION_LENGTH: u32 = 0x548c;
const TERMINAL_MARKER_RELATIVE: u32 = 0x4c40;
const TERMINAL_PAYLOAD_LIST_SLOT_RELATIVE: u32 = 0x4c80;
const TERMINAL_CHECKSUM_LIST_SLOT_RELATIVE: u32 = 0x4c88;
const TERMINAL_IMPORT_LIST_SLOT_RELATIVE: u32 = 0x4ca8;
const TERMINAL_METADATA_LIST_SLOT_RELATIVE: u32 = 0x4fa8;
const TERMINAL_KIND_MARKER_RELATIVE: u32 = 0x4ca0;
const TERMINAL_FILE_PROGRAM_RELATIVE: u32 = 0x5000;
const TERMINAL_FILE_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;

const DIRECT_PAYLOAD_LIST_TERMINAL_MARKER: [u8; 8] = *b"pm\0\0cm\0\0";
const DIRECT_PAYLOAD_LIST_TERMINAL_KIND: [u32; 2] = [0x4000_0000, 1];

const IMAGE_BASE_METADATA_RELATIVES: [u32; 2] = [0x20, 0x40];
const IMAGE_BASE_METADATA_IMAGE_BASE_RELATIVE: usize = 4;
const IMAGE_BASE_METADATA_SENTINEL_LENGTH: u32 = 8;
const IMAGE_BASE_METADATA_LENGTH: u32 = 144;

/// State established by the fixed KONN-rooted Family-4 prefix.
pub(crate) struct Probe {
    info: KonnInfo,
    root_rva: u32,
    primary_descriptor_rva: u32,
    stage1_rva: u32,
    base_image: Vec<u8>,
    controller_image: Vec<u8>,
    header_checksum: u32,
}

/// Native controller proposal before the shared full-table authenticator runs.
pub(super) struct Proposal {
    pub(super) base_image: Vec<u8>,
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: Finalizer,
}

/// Rooted state retained for terminal output evidence and shared finalization.
pub(crate) struct Finalizer {
    pub(super) root_rva: u32,
    pub(super) primary_descriptor_rva: u32,
    pub(super) stage1_rva: u32,
    pub(super) stage2_descriptor_rva: u32,
    pub(super) stage2_rva: u32,
    pub(super) stage3_descriptor_rva: u32,
    pub(super) stage3_rva: u32,
    pub(super) stage3b_descriptor_rva: u32,
    pub(super) stage3b_rva: u32,
    pub(super) stage4_descriptor_rva: u32,
    pub(super) stage4_rva: u32,
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
    pub(super) terminal_profile: RootedNativeControllerTerminalProfile,
    pub(super) terminal: PostStage5Finalizer,
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn offset(base: u32, relative: u32, label: &str) -> Result<usize> {
    usize::try_from(add_rva(base, relative, label)?)
        .with_context(|| format!("{label} RVA does not fit usize"))
}
fn rva_offset(rva: u32, label: &str) -> Result<usize> {
    usize::try_from(rva).with_context(|| format!("{label} RVA does not fit usize"))
}

fn descriptor(image: &[u8], at: u32, label: &str) -> Result<StageDescriptor> {
    shared::read_stage_descriptor(
        image,
        usize::try_from(at).with_context(|| format!("{label} RVA does not fit usize"))?,
    )
}

fn range(image: &[u8], start: u32, length: u32, label: &str) -> Result<std::ops::Range<usize>> {
    checked_range(image.len(), start, length, label)
}

fn checksum(image: &[u8], at: u32, table: &[u32; 256], label: &str) -> Result<u32> {
    shared::checksum_descriptor(
        image,
        usize::try_from(at).with_context(|| format!("{label} RVA does not fit usize"))?,
        table,
    )
}

fn stage_relative(
    stage_rva: u32,
    stage_length: u32,
    relative: u32,
    length: u32,
    label: &str,
) -> Result<u32> {
    let end = relative
        .checked_add(length)
        .with_context(|| format!("{label} relative range overflows"))?;
    ensure!(end <= stage_length, "{label} lies outside its rooted stage");
    add_rva(stage_rva, relative, label)
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
        .copy_from_slice(source.outer.as_slice());
    Ok(image)
}

fn root_is_well_formed(image: &[u8], info: &KonnInfo, root_rva: u32) -> Result<bool> {
    range(image, root_rva, ROOT_CONTROL_LENGTH, "native root control")?;
    if read_u32(image, offset(root_rva, 0, "native root base")?)? != info[3]
        || read_u32(image, offset(root_rva, 4, "native root import size")?)? != ROOT_IMPORT_SIZE
        || read_u32(image, offset(root_rva, 8, "native root anchor end")?)?
            != info[6]
                .checked_sub(ROOT_ANCHOR_END_BACK)
                .context("KONN shell end precedes native root anchor end")?
        || read_u32(
            image,
            offset(
                root_rva,
                ROOT_LAYOUT_STAMP_RELATIVE,
                "native root layout stamp",
            )?,
        )? >> 28
            != 4
    {
        return Ok(false);
    }

    let primary_descriptor_rva = add_rva(
        root_rva,
        ROOT_PRIMARY_DESCRIPTOR_RELATIVE,
        "native root primary descriptor",
    )?;
    let primary = descriptor(
        image,
        primary_descriptor_rva,
        "native root primary descriptor",
    )?;
    if primary.source
        != add_rva(
            root_rva,
            ROOT_PRIMARY_SOURCE_RELATIVE,
            "native root primary source",
        )?
        || primary.source_length != ROOT_PRIMARY_LENGTH
        || primary.source == 0
        || primary.source_length % 4 != 0
        || primary.destination != 0
        || primary.destination_length != 0
    {
        return Ok(false);
    }
    range(
        image,
        primary.source,
        primary.source_length,
        "native root primary source",
    )?;

    let stage3_checksum = descriptor(
        image,
        add_rva(
            root_rva,
            ROOT_STAGE3_CHECKSUM_RELATIVE,
            "native root stage-three checksum",
        )?,
        "native root stage-three checksum",
    )?;
    if stage3_checksum.source != primary.source
        || stage3_checksum.source_length != ROOT_STAGE3_CHECKSUM_LENGTH
    {
        return Ok(false);
    }
    range(
        image,
        stage3_checksum.source,
        stage3_checksum.source_length,
        "native root stage-three checksum input",
    )?;

    let primary_checksum = descriptor(
        image,
        add_rva(
            root_rva,
            ROOT_PRIMARY_CHECKSUM_RELATIVE,
            "native root primary checksum",
        )?,
        "native root primary checksum",
    )?;
    if primary_checksum.source != info[6]
        || primary_checksum.source_length != ROOT_PRIMARY_CHECKSUM_LENGTH
    {
        return Ok(false);
    }
    range(
        image,
        primary_checksum.source,
        primary_checksum.source_length,
        "native root primary checksum input",
    )?;
    Ok(true)
}

fn prepare_header(image: &mut [u8], source: &BoundPayloadSource<'_>, root_rva: u32) -> Result<()> {
    let pe_header = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE header offset underflows")?;
    for (relative, pe_relative) in [(8u32, 0x90usize), (4, 0x94), (40, 0x98), (44, 0x9c)] {
        write_u32(
            image,
            pe_header + pe_relative,
            read_u32(
                image,
                offset(root_rva, relative, "native root header field")?,
            )?,
        )?;
    }
    write_u32(image, pe_header + 0xb0, 0)?;
    write_u32(image, pe_header + 0xb4, 0)?;
    Ok(())
}

fn header_checksum(
    image: &[u8],
    root_rva: u32,
    table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut cursor = add_rva(
        root_rva,
        ROOT_HEADER_CHECKSUM_LIST_RELATIVE,
        "native root header-checksum list",
    )?;
    let root_end = add_rva(root_rva, ROOT_CONTROL_LENGTH, "native root control")?;
    let mut value = 0u32;
    let mut preceding_destination = None;
    for (index, source_length) in ROOT_HEADER_CHECKSUM_LENGTHS.iter().copied().enumerate() {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        let record_end = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("native root header-checksum record end overflows")?;
        ensure!(
            cursor >= root_rva && record_end <= root_end,
            "native root header-checksum record lies outside the rooted control block"
        );
        let record = descriptor(image, cursor, "native root header-checksum record")?;
        ensure!(
            record.source != 0 && record.source_length == source_length,
            "native root header-checksum record has the wrong source shape"
        );
        if let Some(destination) = preceding_destination {
            ensure!(
                record.source == destination,
                "native root header-checksum records are not contiguous"
            );
        }
        let expected_destination_length = ROOT_HEADER_CHECKSUM_LENGTHS
            .get(index + 1)
            .copied()
            .unwrap_or(0);
        ensure!(
            record.destination_length == expected_destination_length,
            "native root header-checksum record has the wrong destination shape"
        );
        if expected_destination_length == 0 {
            ensure!(
                record.destination == 0,
                "native root header-checksum terminator record has a destination"
            );
        } else {
            range(
                image,
                record.destination,
                record.destination_length,
                "native root header-checksum destination",
            )?;
        }
        range(
            image,
            record.source,
            record.source_length,
            "native root header-checksum source",
        )?;
        value ^= checksum(image, cursor, table, "native root header checksum")?;
        preceding_destination = Some(record.destination);
        cursor = cursor
            .checked_add(8)
            .context("native root header-checksum cursor overflows")?;
    }
    let terminator_end = cursor
        .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
        .context("native root header-checksum terminator end overflows")?;
    ensure!(
        terminator_end <= root_end,
        "native root header-checksum terminator lies outside the rooted control block"
    );
    let terminator = descriptor(image, cursor, "native root header-checksum terminator")?;
    ensure!(
        terminator.source == 0
            && terminator.source_length == 0
            && terminator.destination == 0
            && terminator.destination_length == 0,
        "native root header-checksum list has no exact terminator"
    );
    Ok(value)
}

fn validate_stage2(image: &[u8], info: &KonnInfo, stage: StageDescriptor) -> Result<()> {
    let outer_end = info[3]
        .checked_add(info[5])
        .context("KONN outer range overflows")?;
    let stage_end = stage
        .source
        .checked_add(stage.source_length)
        .context("native stage-two source range overflows")?;
    ensure!(
        stage.source == stage.destination,
        "native stage-two source and destination differ"
    );
    ensure!(
        stage.source >= info[3] && stage_end <= outer_end,
        "native stage-two source is outside the KONN-rooted controller range"
    );
    ensure!(
        stage.source_length != 0 && stage.source_length.is_multiple_of(4),
        "native stage-two source shape is invalid"
    );
    ensure!(
        stage.destination_length != 0 && stage.destination_length < stage.source_length,
        "native stage-two destination shape is invalid"
    );
    range(
        image,
        stage.source,
        stage.source_length,
        "native stage-two source",
    )?;
    range(
        image,
        stage.destination,
        stage.destination_length,
        "native stage-two destination",
    )?;
    Ok(())
}

fn validate_compressed_in_place_stage(
    image: &[u8],
    stage: StageDescriptor,
    destination_length: u32,
    label: &str,
) -> Result<()> {
    ensure!(
        stage.source != 0 && stage.destination != 0,
        "native {label} has an empty range"
    );
    ensure!(
        stage.source == stage.destination,
        "native {label} source and destination differ"
    );
    ensure!(
        stage.source_length != 0
            && stage.source_length < stage.destination_length
            && stage.destination_length == destination_length,
        "native {label} shape is invalid"
    );
    range(
        image,
        stage.source,
        stage.source_length,
        &format!("native {label} source"),
    )?;
    range(
        image,
        stage.destination,
        stage.destination_length,
        &format!("native {label} destination"),
    )?;
    Ok(())
}

fn validate_decoded_stage1(image: &[u8], info: &KonnInfo, stage1_rva: u32) -> Result<()> {
    let stage2_descriptor_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native stage-two descriptor",
    )?;
    validate_stage2(
        image,
        info,
        descriptor(image, stage2_descriptor_rva, "native stage-two descriptor")?,
    )?;
    let _ = read_u32(
        image,
        offset(
            stage1_rva,
            STAGE1_STAGE2_KEY_RELATIVE,
            "native stage-two key",
        )?,
    )?;
    stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_CHECKSUM_BASE_RELATIVE,
        0x28,
        "native stage checksum descriptors",
    )?;

    for (relative, destination_length, label) in [
        (
            STAGE1_STAGE3_DESCRIPTOR_RELATIVE,
            STAGE3_DESTINATION_LENGTH,
            "stage-three",
        ),
        (
            STAGE1_STAGE3B_DESCRIPTOR_RELATIVE,
            STAGE3B_DESTINATION_LENGTH,
            "stage-three-b",
        ),
        (
            STAGE1_STAGE4_DESCRIPTOR_RELATIVE,
            STAGE4_DESTINATION_LENGTH,
            "stage-four",
        ),
        (
            STAGE1_TERMINAL_DESCRIPTOR_RELATIVE,
            TERMINAL_DESTINATION_LENGTH,
            "terminal",
        ),
    ] {
        let at = stage_relative(
            stage1_rva,
            ROOT_PRIMARY_LENGTH,
            relative,
            STAGE_DESCRIPTOR_SIZE as u32,
            &format!("native {label} descriptor"),
        )?;
        validate_compressed_in_place_stage(
            image,
            descriptor(image, at, &format!("native {label} descriptor"))?,
            destination_length,
            label,
        )?;
    }
    Ok(())
}

fn codec_relative(
    codec_rva: u32,
    codec_length: u32,
    relative: u32,
    length: u32,
    label: &str,
) -> Result<u32> {
    stage_relative(codec_rva, codec_length, relative, length, label)
}
fn replay_codec_actions(
    image: &mut [u8],
    codec_rva: u32,
    codec_length: u32,
    controller_rva: u32,
    controller_length: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let first_action_rva = codec_relative(
        codec_rva,
        codec_length,
        CODEC_ACTION_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native first codec action",
    )?;
    let first_action = rva_offset(first_action_rva, "native first codec action")?;
    let kind = read_u32(image, first_action)?;
    ensure!(
        kind & 0x0f == 1,
        "native first codec action is not a shift-three transform"
    );
    let transform_start = read_u32(image, first_action + 4)?;
    let transform_length = read_u32(image, first_action + 8)?;
    ensure!(
        transform_start != 0 && transform_length != 0,
        "native codec transform has an empty range"
    );
    let transform_end = transform_start
        .checked_add(transform_length)
        .context("native codec transform end overflows")?;
    let controller_end = controller_rva
        .checked_add(controller_length)
        .context("native controller span end overflows")?;
    ensure!(
        transform_start >= controller_rva && transform_end <= controller_end,
        "native codec transform lies outside the rooted KONN controller span"
    );
    range(
        image,
        transform_start,
        transform_length,
        "native codec transform range",
    )?;
    shared::transform_shift3_descriptor(image, first_action + 4, cancellation)?;

    let second_action_rva = codec_relative(
        codec_rva,
        codec_length,
        CODEC_ACTION_RELATIVE + STAGE_DESCRIPTOR_SIZE as u32,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native second codec action",
    )?;
    let second_action = rva_offset(second_action_rva, "native second codec action")?;
    ensure!(
        read_u32(image, second_action)? == 2,
        "native second codec action is not a rooted copy-list dispatch"
    );
    let copy_list_rva = read_u32(image, second_action + 4)?;
    let copy_list_end = copy_list_rva
        .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
        .context("native codec copy-list start range overflows")?;
    ensure!(
        copy_list_rva >= transform_start && copy_list_end <= transform_end,
        "native codec copy list lies outside the preceding rooted transform"
    );
    copy_rooted_codec_stage_list(image, copy_list_rva, transform_end, cancellation)
}

fn copy_rooted_codec_stage_list(
    image: &mut [u8],
    mut cursor: u32,
    list_end: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record_end = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("native codec copy-list cursor overflows")?;
        ensure!(
            record_end <= list_end,
            "native codec copy-list record lies outside the rooted transform"
        );
        shared::transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = descriptor(image, cursor, "native codec copy-list record")?;
        if record.source_length == 0 {
            return Ok(());
        }
        ensure!(
            record.source != 0
                && record.destination != 0
                && record.destination_length == record.source_length,
            "native codec copy-list record is malformed"
        );
        let source = range(
            image,
            record.source,
            record.source_length,
            "native codec copy-list source",
        )?;
        let destination = range(
            image,
            record.destination,
            record.destination_length,
            "native codec copy-list destination",
        )?;
        image.copy_within(source, destination.start);
        cursor = record_end;
    }
    bail!("native codec copy-list exceeds entry budget")
}

// The old terminal accepts either metadata placement only when decrypting the
// ImageBase-low word immediately after its entry reproduces the KONN-rooted
// image base. This distinguishes the transient layouts structurally.
fn select_image_base_metadata_relative(
    image: &mut [u8],
    info: &KonnInfo,
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut selected = None;
    for relative in IMAGE_BASE_METADATA_RELATIVES {
        let metadata_rva = add_rva(info[3], relative, "native image-base metadata")?;
        let sentinel = range(
            image,
            metadata_rva,
            IMAGE_BASE_METADATA_SENTINEL_LENGTH,
            "native image-base metadata ImageBase sentinel",
        )?;
        let mut original = [0u8; IMAGE_BASE_METADATA_SENTINEL_LENGTH as usize];
        original.copy_from_slice(&image[sentinel.clone()]);
        let decoded = (|| -> Result<u32> {
            shared::transform_shift2_range(
                image,
                metadata_rva,
                IMAGE_BASE_METADATA_SENTINEL_LENGTH,
                cancellation,
            )?;
            read_u32(
                image,
                sentinel.start + IMAGE_BASE_METADATA_IMAGE_BASE_RELATIVE,
            )
        })();
        image[sentinel].copy_from_slice(&original);
        if decoded? == info[3] {
            ensure!(
                selected.is_none(),
                "native image-base metadata placement is ambiguous"
            );
            selected = Some(relative);
        }
    }
    selected.context("native image-base metadata has no rooted ImageBase sentinel")
}

fn image_base_metadata(
    image: &mut [u8],
    info: &KonnInfo,
    cancellation: Option<&CancellationToken>,
) -> Result<HeaderMetadata> {
    let relative = select_image_base_metadata_relative(image, info, cancellation)?;
    let metadata_rva = add_rva(info[3], relative, "native image-base metadata")?;
    let metadata = range(
        image,
        metadata_rva,
        IMAGE_BASE_METADATA_LENGTH,
        "native image-base metadata",
    )?;
    let mut original = [0u8; IMAGE_BASE_METADATA_LENGTH as usize];
    original.copy_from_slice(&image[metadata.clone()]);
    let extracted = (|| -> Result<HeaderMetadata> {
        shared::transform_shift2_range(
            image,
            metadata_rva,
            IMAGE_BASE_METADATA_LENGTH,
            cancellation,
        )?;
        ensure!(
            read_u32(
                image,
                metadata.start + IMAGE_BASE_METADATA_IMAGE_BASE_RELATIVE
            )? == info[3],
            "native image-base metadata ImageBase sentinel changed after selection"
        );
        let entry = read_u32(image, metadata.start)?;
        let directories: [u8; 128] = image
            .get(metadata.start + 0x10..metadata.end)
            .context("native image-base metadata directories exceed image")?
            .try_into()
            .context("native image-base metadata directory span has an unexpected length")?;
        ensure!(entry != 0, "native image-base metadata has no entry point");
        range(image, entry, 1, "native image-base metadata entry point")?;
        Ok(HeaderMetadata { entry, directories })
    })();
    image[metadata].copy_from_slice(&original);
    extracted
}

fn parse_direct_payload_list_terminal_profile(
    image: &[u8],
    terminal_rva: u32,
    terminal_length: u32,
) -> Result<RootedNativeControllerTerminalProfile> {
    let marker_rva = stage_relative(
        terminal_rva,
        terminal_length,
        TERMINAL_MARKER_RELATIVE,
        DIRECT_PAYLOAD_LIST_TERMINAL_MARKER.len() as u32,
        "native direct-payload-list terminal marker",
    )?;
    let marker = range(
        image,
        marker_rva,
        DIRECT_PAYLOAD_LIST_TERMINAL_MARKER.len() as u32,
        "native direct-payload-list terminal marker",
    )?;
    ensure!(
        image[marker] == DIRECT_PAYLOAD_LIST_TERMINAL_MARKER,
        "native terminal marker does not match the rooted direct-payload-list grammar"
    );

    let kind_rva = stage_relative(
        terminal_rva,
        terminal_length,
        TERMINAL_KIND_MARKER_RELATIVE,
        8,
        "native direct-payload-list terminal kind marker",
    )?;
    let kind = rva_offset(kind_rva, "native direct-payload-list terminal kind marker")?;
    ensure!(
        read_u32(image, kind)? == DIRECT_PAYLOAD_LIST_TERMINAL_KIND[0]
            && read_u32(image, kind + 4)? == DIRECT_PAYLOAD_LIST_TERMINAL_KIND[1],
        "native terminal kind marker does not match the rooted direct-payload-list grammar"
    );
    Ok(RootedNativeControllerTerminalProfile::DirectPayloadList)
}

/// Recognizes only the six-member AMD64 executable grammar rooted at KONN info[6].
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
    let mut controller_image = bootstrap_image;
    let base_image = match materialize_payload_base(source) {
        Ok(image) => image,
        Err(_) => return Ok(None),
    };
    let root_rva = match add_rva(info[6], ROOT_FROM_KONN_SHELL_END, "native root") {
        Ok(root_rva) => root_rva,
        Err(_) => return Ok(None),
    };
    if !matches!(
        root_is_well_formed(&controller_image, &info, root_rva),
        Ok(true)
    ) {
        return Ok(None);
    }

    prepare_header(&mut controller_image, source, root_rva)?;
    let table = crc32_table();
    let header_checksum = header_checksum(&controller_image, root_rva, &table, cancellation)?;
    let primary_descriptor_rva = add_rva(
        root_rva,
        ROOT_PRIMARY_DESCRIPTOR_RELATIVE,
        "native root primary descriptor",
    )?;
    let primary_checksum = checksum(
        &controller_image,
        add_rva(
            root_rva,
            ROOT_PRIMARY_CHECKSUM_RELATIVE,
            "native root primary checksum",
        )?,
        &table,
        "native root primary checksum",
    )?;
    let primary_literal = read_u32(
        &controller_image,
        offset(
            root_rva,
            ROOT_PRIMARY_LITERAL_RELATIVE,
            "native root primary literal",
        )?,
    )?;
    let primary_key = header_checksum ^ primary_checksum ^ primary_literal;
    let primary = descriptor(
        &controller_image,
        primary_descriptor_rva,
        "native root primary descriptor",
    )?;
    shared::decrypt_rotating_dword_descriptor(
        &mut controller_image,
        usize::try_from(primary_descriptor_rva)
            .context("native root primary descriptor RVA does not fit usize")?,
        primary_key,
        21,
        cancellation,
    )?;
    validate_decoded_stage1(&controller_image, &info, primary.source)?;

    Ok(Some(Probe {
        info,
        root_rva,
        primary_descriptor_rva,
        stage1_rva: primary.source,
        base_image,
        controller_image,
        header_checksum,
    }))
}

/// Replays the Family-4 ROR19 codec dispatch and its rooted terminal producer.
pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<Proposal> {
    let Probe {
        info,
        root_rva,
        primary_descriptor_rva,
        stage1_rva,
        base_image,
        mut controller_image,
        header_checksum,
    } = probe;
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let table = crc32_table();
    let stage2_descriptor_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native stage-two descriptor",
    )?;
    let stage2 = descriptor(
        &controller_image,
        stage2_descriptor_rva,
        "native stage-two descriptor",
    )?;
    validate_stage2(&controller_image, &info, stage2)?;
    let stage2_key = read_u32(
        &controller_image,
        offset(
            stage1_rva,
            STAGE1_STAGE2_KEY_RELATIVE,
            "native stage-two key",
        )?,
    )?;
    shared::decrypt_rotating_dword_descriptor(
        &mut controller_image,
        usize::try_from(stage2_descriptor_rva)
            .context("native stage-two descriptor RVA does not fit usize")?,
        stage2_key,
        19,
        cancellation,
    )?;
    let stage2_rva = stage2.source;
    replay_codec_actions(
        &mut controller_image,
        stage2_rva,
        stage2.source_length,
        info[3],
        info[5],
        cancellation,
    )?;

    let parameter_base = codec_relative(
        stage2_rva,
        stage2.source_length,
        CODEC_PARAMETER_RELATIVE,
        CODEC_PARAMETER_DESCRIPTOR_RELATIVES[3] + STAGE_DESCRIPTOR_SIZE as u32,
        "native codec parameter table",
    )?;
    let mut key_rvas = [0u32; 4];
    for (slot, relative) in key_rvas
        .iter_mut()
        .zip(CODEC_PARAMETER_DESCRIPTOR_RELATIVES)
    {
        let parameter = add_rva(
            parameter_base,
            relative,
            "native codec parameter descriptor",
        )?;
        shared::transform_shift3_descriptor(
            &mut controller_image,
            usize::try_from(parameter)
                .context("native codec parameter descriptor RVA does not fit usize")?,
            cancellation,
        )?;
        *slot = read_u32(
            &controller_image,
            usize::try_from(parameter)
                .context("native codec parameter descriptor RVA does not fit usize")?,
        )?;
        ensure!(*slot != 0, "native codec parameter is null");
    }
    let file_decoder_table = shared::snapshot_decoder_table(&controller_image, key_rvas[0])?;
    let layer_decoder_table = shared::snapshot_decoder_table(&controller_image, key_rvas[1])?;
    let (file_raw_aes_key, _) = shared::recover_aes_context(&controller_image, key_rvas[2])?;
    let (layer_raw_aes_key, layer_aes) =
        shared::recover_aes_context(&controller_image, key_rvas[3])?;

    let checksum_base_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_CHECKSUM_BASE_RELATIVE,
        0x28,
        "native stage checksum descriptors",
    )?;
    let stage3_descriptor_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_STAGE3_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native stage-three descriptor",
    )?;
    let stage3 = descriptor(
        &controller_image,
        stage3_descriptor_rva,
        "native stage-three descriptor",
    )?;
    validate_compressed_in_place_stage(
        &controller_image,
        stage3,
        STAGE3_DESTINATION_LENGTH,
        "stage-three",
    )?;
    let stage3_key = header_checksum
        ^ checksum(
            &controller_image,
            add_rva(
                root_rva,
                ROOT_STAGE3_CHECKSUM_RELATIVE,
                "native stage-three checksum",
            )?,
            &table,
            "native stage-three checksum",
        )?
        ^ shared::advance_key(
            read_u32(
                &controller_image,
                offset(
                    stage1_rva,
                    STAGE1_STAGE3_ACCUMULATOR_RELATIVE,
                    "native stage-three accumulator",
                )?,
            )?,
            4,
        );
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(stage3_descriptor_rva)
            .context("native stage-three descriptor RVA does not fit usize")?,
        stage3_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )?;
    let stage3_rva = stage3.destination;

    let stage3b_descriptor_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_STAGE3B_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native stage-three-b descriptor",
    )?;
    let stage3b = descriptor(
        &controller_image,
        stage3b_descriptor_rva,
        "native stage-three-b descriptor",
    )?;
    validate_compressed_in_place_stage(
        &controller_image,
        stage3b,
        STAGE3B_DESTINATION_LENGTH,
        "stage-three-b",
    )?;
    let stage3_literal_rva = stage_relative(
        stage3_rva,
        stage3.destination_length,
        STAGE3_LITERAL_RELATIVE,
        4,
        "native stage-three literal",
    )?;
    let stage3_literal = read_u32(
        &controller_image,
        rva_offset(stage3_literal_rva, "native stage-three literal")?,
    )?;
    let stage3b_key = header_checksum
        ^ checksum(
            &controller_image,
            add_rva(checksum_base_rva, 0x18, "native stage-three-b checksum")?,
            &table,
            "native stage-three-b checksum",
        )?
        ^ stage3_literal;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(stage3b_descriptor_rva)
            .context("native stage-three-b descriptor RVA does not fit usize")?,
        stage3b_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )?;
    let stage3b_rva = stage3b.destination;

    let stage4_descriptor_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_STAGE4_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native stage-four descriptor",
    )?;
    let stage4 = descriptor(
        &controller_image,
        stage4_descriptor_rva,
        "native stage-four descriptor",
    )?;
    validate_compressed_in_place_stage(
        &controller_image,
        stage4,
        STAGE4_DESTINATION_LENGTH,
        "stage-four",
    )?;
    let stage3b_literal_rva = stage_relative(
        stage3b_rva,
        stage3b.destination_length,
        STAGE3B_LITERAL_RELATIVE,
        4,
        "native stage-three-b literal",
    )?;
    let stage3b_literal = read_u32(
        &controller_image,
        rva_offset(stage3b_literal_rva, "native stage-three-b literal")?,
    )?;
    let stage4_key = header_checksum
        ^ checksum(
            &controller_image,
            add_rva(checksum_base_rva, 0x10, "native stage-four checksum")?,
            &table,
            "native stage-four checksum",
        )?
        ^ !stage3b_literal;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(stage4_descriptor_rva)
            .context("native stage-four descriptor RVA does not fit usize")?,
        stage4_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )?;
    let stage4_rva = stage4.destination;

    let terminal_descriptor_rva = stage_relative(
        stage1_rva,
        ROOT_PRIMARY_LENGTH,
        STAGE1_TERMINAL_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native terminal descriptor",
    )?;
    let terminal_stage = descriptor(
        &controller_image,
        terminal_descriptor_rva,
        "native terminal descriptor",
    )?;
    validate_compressed_in_place_stage(
        &controller_image,
        terminal_stage,
        TERMINAL_DESTINATION_LENGTH,
        "terminal",
    )?;
    let terminal_rva = terminal_stage.destination;
    let layer_program_rva = stage_relative(
        stage4_rva,
        stage4.destination_length,
        STAGE4_LAYER_PROGRAM_RELATIVE,
        STAGE4_LAYER_PROGRAM_WINDOW_LENGTH,
        "native stage-four layer byte-map program",
    )?;
    let layer_program = shared::exact_lfsr_al_map(
        &controller_image,
        layer_program_rva,
        STAGE4_LAYER_PROGRAM_WINDOW_LENGTH,
        "native stage-four layer byte-map program",
    )?;
    let stage4_accumulator_rva = stage_relative(
        stage4_rva,
        stage4.destination_length,
        STAGE4_ACCUMULATOR_RELATIVE,
        4,
        "native stage-four accumulator",
    )?;
    let stage4_accumulator = shared::advance_key(
        read_u32(
            &controller_image,
            rva_offset(stage4_accumulator_rva, "native stage-four accumulator")?,
        )?,
        3,
    );
    let terminal_key = header_checksum
        ^ checksum(
            &controller_image,
            add_rva(
                checksum_base_rva,
                0x10,
                "native terminal stage-four checksum",
            )?,
            &table,
            "native terminal stage-four checksum",
        )?
        ^ checksum(
            &controller_image,
            add_rva(checksum_base_rva, 8, "native terminal checksum")?,
            &table,
            "native terminal checksum",
        )?
        ^ stage4_accumulator;
    shared::decrypt_stage(
        &mut controller_image,
        usize::try_from(terminal_descriptor_rva)
            .context("native terminal descriptor RVA does not fit usize")?,
        terminal_key,
        &layer_aes,
        &layer_decoder_table,
        Some(layer_program.map.as_ref()),
        cancellation,
    )?;
    let file_program_rva = stage_relative(
        terminal_rva,
        terminal_stage.destination_length,
        TERMINAL_FILE_PROGRAM_RELATIVE,
        TERMINAL_FILE_PROGRAM_WINDOW_LENGTH,
        "native terminal file byte-map program",
    )?;
    let file_program = shared::exact_lfsr_al_map(
        &controller_image,
        file_program_rva,
        TERMINAL_FILE_PROGRAM_WINDOW_LENGTH,
        "native terminal file byte-map program",
    )?;

    let terminal_profile = parse_direct_payload_list_terminal_profile(
        &controller_image,
        terminal_rva,
        terminal_stage.destination_length,
    )?;
    let payload_list_pointer_slot_rva = stage_relative(
        terminal_rva,
        terminal_stage.destination_length,
        TERMINAL_PAYLOAD_LIST_SLOT_RELATIVE,
        4,
        "native payload-list pointer",
    )?;
    let checksum_list_pointer_slot_rva = stage_relative(
        terminal_rva,
        terminal_stage.destination_length,
        TERMINAL_CHECKSUM_LIST_SLOT_RELATIVE,
        4,
        "native checksum-list pointer",
    )?;
    let checksum_list_rva = read_u32(
        &controller_image,
        rva_offset(
            checksum_list_pointer_slot_rva,
            "native checksum-list pointer",
        )?,
    )?;
    ensure!(
        checksum_list_rva != 0,
        "native checksum-list pointer is null"
    );
    range(
        &controller_image,
        checksum_list_rva,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native checksum-list head",
    )?;
    let import_list_pointer_slot_rva = stage_relative(
        terminal_rva,
        terminal_stage.destination_length,
        TERMINAL_IMPORT_LIST_SLOT_RELATIVE,
        4,
        "native import-list pointer",
    )?;
    let import_list_rva = read_u32(
        &controller_image,
        rva_offset(import_list_pointer_slot_rva, "native import-list pointer")?,
    )?;
    ensure!(import_list_rva != 0, "native import-list pointer is null");
    range(
        &controller_image,
        import_list_rva,
        20,
        "native import-list head",
    )?;
    let metadata_list_pointer_slot_rva = stage_relative(
        terminal_rva,
        terminal_stage.destination_length,
        TERMINAL_METADATA_LIST_SLOT_RELATIVE,
        4,
        "native metadata-list pointer",
    )?;
    let payload_list_rva = read_u32(
        &controller_image,
        rva_offset(payload_list_pointer_slot_rva, "native payload-list pointer")?,
    )?;
    ensure!(payload_list_rva != 0, "native payload-list pointer is null");
    range(
        &controller_image,
        payload_list_rva,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native payload-list head",
    )?;
    let metadata_list_rva = read_u32(
        &controller_image,
        rva_offset(
            metadata_list_pointer_slot_rva,
            "native metadata-list pointer",
        )?,
    )?;
    ensure!(
        metadata_list_rva != 0,
        "native metadata-list pointer is null"
    );
    range(
        &controller_image,
        metadata_list_rva,
        STAGE_DESCRIPTOR_SIZE as u32,
        "native metadata-list head",
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
            file_program,
            file_raw_aes_key,
            file_decoder_rva: key_rvas[0],
            file_decoder_table,
        },
        cancellation,
    )?;
    match terminal_profile {
        RootedNativeControllerTerminalProfile::DirectPayloadList => {
            image_base_metadata(&mut controller_image, &info, cancellation)?;
        }
        RootedNativeControllerTerminalProfile::NestedFinalDescriptor => {
            bail!("native terminal profile has no rooted metadata grammar")
        }
    }

    Ok(Proposal {
        base_image,
        block_table,
        candidate,
        finalizer: Finalizer {
            root_rva,
            primary_descriptor_rva,
            stage1_rva,
            stage2_descriptor_rva,
            stage2_rva,
            stage3_descriptor_rva,
            stage3_rva,
            stage3b_descriptor_rva,
            stage3b_rva,
            stage4_descriptor_rva,
            stage4_rva,
            terminal_descriptor_rva,
            terminal_rva,
            payload_list_rva,
            file_decoder_rva: key_rvas[0],
            layer_decoder_rva: key_rvas[1],
            file_aes_context_rva: key_rvas[2],
            layer_aes_context_rva: key_rvas[3],
            file_raw_aes_key,
            layer_raw_aes_key,
            layer_program,
            terminal_profile,
            terminal,
        },
    })
}

/// Applies the rooted DirectPayloadList terminal without inventing an unobserved teardown.
pub(super) fn finalize(
    _source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let selected_mapping = authenticated.plan().post_transform.mapping();
    ensure!(
        *finalizer.terminal.file_program.map == selected_mapping,
        "authenticated image-base-metadata-binding plan diverges from the rooted file-map program"
    );
    let mut image = match finalizer.terminal_profile {
        RootedNativeControllerTerminalProfile::DirectPayloadList => {
            terminal::finalize_post_stage5_as_authenticated_image(
                block_table,
                &finalizer.terminal,
                authenticated,
            )?
        }
        RootedNativeControllerTerminalProfile::NestedFinalDescriptor => {
            bail!("native terminal profile has no rooted finalization grammar")
        }
    };
    image.decryption_details.selected_controller = Some(
        SelectedController::ImageBaseMetadataBinding(SelectedRootedNativeController {
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
                    rva: finalizer.stage4_rva,
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
                    .context("native layer-program RVA does not fit u32")?,
            ),
            layer_program_length: Some(finalizer.layer_program.length),
            layer_byte_map: Some(finalizer.layer_program.map.to_vec()),
            file_program_rva: u32::try_from(finalizer.terminal.file_program.offset)
                .context("native file-program RVA does not fit u32")?,
            file_program_length: finalizer.terminal.file_program.length,
            file_byte_map: finalizer.terminal.file_program.map.to_vec(),
            terminal_profile: Some(finalizer.terminal_profile),
        }),
    );
    info!(
        root_rva = finalizer.root_rva,
        primary_descriptor_rva = finalizer.primary_descriptor_rva,
        stage1_rva = finalizer.stage1_rva,
        stage2_descriptor_rva = finalizer.stage2_descriptor_rva,
        stage2_rva = finalizer.stage2_rva,
        stage3_rva = finalizer.stage3_rva,
        stage3b_rva = finalizer.stage3b_rva,
        stage4_rva = finalizer.stage4_rva,
        terminal_rva = finalizer.terminal_rva,
        payload_list_rva = finalizer.payload_list_rva,
        file_decoder_rva = finalizer.file_decoder_rva,
        layer_decoder_rva = finalizer.layer_decoder_rva,
        file_aes_context_rva = finalizer.file_aes_context_rva,
        layer_aes_context_rva = finalizer.layer_aes_context_rva,
        metadata_records = finalizer.terminal.metadata_records,
        zero_records = finalizer.terminal.zero_ranges.len(),
        blocks = image.decryption_details.block_count,
        "selected PE64 EXE image-base-metadata-binding controller"
    );
    Ok(image)
}
