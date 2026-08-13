use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind, SelectedController,
    SelectedRootedNativeController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crackproof_checksum, crc32_table,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u16, read_u32, write_u32};

use super::super::replay::{
    AuthenticatedPayloadPlan, PayloadMaterializationPlan, PayloadPlanCandidate,
    PayloadPostTransform,
};
use super::super::source::BoundPayloadSource;
use super::super::{DecoderCandidate, DecryptedImage, PayloadBlock, PayloadBlockTable};
use super::codec_relocation::{
    HeaderMetadata, PostStage5Finalizer, finalize_post_stage5, prefill_managed_section,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};

// These slots are relative to the KONN-rooted controller graph. They are family
// grammar, not sample RVAs: the KONN descriptor supplies `anchor` and every
// subsequent pointer is decoded from a preceding controller-owned descriptor.
const ROOT_ANCHOR_RELATIVE: u32 = 0x18;
const PRIMARY_DESCRIPTOR_RELATIVE: u32 = 0x1650;
const PRIMARY_KEY_LITERAL_RELATIVE: u32 = 0x15e4;
const PRIMARY_CHECKSUM_RELATIVE: u32 = 0x1610;
const HEADER_CHECKSUM_LIST_RELATIVE: u32 = 0x1690;
const HEADER_CHECKSUM_ENTRY_COUNT: usize = 4;
const HEADER_CHECKSUM_RECORD_STRIDE: u32 = 8;
// The fixed checksum-list terminator is the farthest rooted probe-time read.
const ROOT_FIXED_PREFIX_LENGTH: u32 = ROOT_ANCHOR_RELATIVE
    + HEADER_CHECKSUM_LIST_RELATIVE
    + HEADER_CHECKSUM_ENTRY_COUNT as u32 * HEADER_CHECKSUM_RECORD_STRIDE
    + STAGE_DESCRIPTOR_SIZE as u32;

const PRIMARY_IMPORT_RELATIVE: u32 = 0x0d74;
const PRIMARY_STATE_KEY_RELATIVE: u32 = 0x0e0c;
const PRIMARY_STATE_DESCRIPTOR_RELATIVE: u32 = 0x0ec8;
const PRIMARY_STATE_SELECTOR_LIST_RELATIVE: u32 = 0x18;
const PRIMARY_STATE_SELECTOR_ENTRIES: usize = 14;
const PRIMARY_IMPORT_KEY_LITERAL: u32 = 0xc72b_0000;

const PRIMARY_CHECKSUM_RECORDS_RELATIVE: u32 = 0x0e20;
const PRIMARY_CHECKSUM_RECORD_COUNT: usize = 4;
const PRIMARY_CHECKSUM_RECORD_STRIDE: u32 = 8;
const PRIMARY_ROOT_CHECKSUM_LENGTH: u32 = 0x0e70;
const SELECTOR_STAGE_FOUR: usize = 4;
const SELECTOR_STAGE_FIVE: usize = 5;
const SELECTOR_STAGE_SEVEN: usize = 7;
const SELECTOR_STAGE_TWELVE: usize = 12;
const SELECTOR_STAGE_FOUR_SCALAR_RELATIVE: u32 = 0x0e74;
const SELECTOR_STAGE_FIVE_SCALAR_RELATIVE: u32 = 0x0830;
const SELECTOR_STAGE_SEVEN_SCALAR_RELATIVE: u32 = 0x0cf0;
const LAYER_MAP_PROGRAM_RELATIVE: u32 = 0x0d10;
// Only ordinal-zero payload records are supported by the observed terminal file-map binding.
// Other ordinals fail closed rather than select the adjacent program.
const FILE_MAP_PROGRAM_RELATIVE: u32 = 0x3210;
const AL_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;

const STATE_ROW_COUNT_RELATIVE: u32 = 0x2534;
const STATE_ROWS_RELATIVE: u32 = 0x25a0;
const STATE_ROW_STRIDE: u32 = 0x20;
const STATE_ROW_COUNT: usize = 4;
const STATE_ASSET_ROWS_RELATIVE: u32 = 0x26a0;
const STATE_B_HEADER_RELATIVE: u32 = 0x26f0;
const STATE_B_ROWS_RELATIVE: u32 = 0x2700;
const STATE_B_ROW_STRIDE: u32 = 0x10;
const STATE_B_ROW_COUNT: usize = 2;

const OUTER_PAYLOAD_RECORDS_RELATIVE: u32 = 0x320;
const MAX_PAYLOAD_REPLAY_WORK: usize = 512 << 20;
const MAX_ROOTED_SECURITY_DIRECTORY_BYTES: usize = 1 << 20;
const WIN_CERTIFICATE_HEADER_SIZE: usize = 8;

/// State established by the bounded KONN-root probe.
pub(in crate::pipeline::stages::payload::decrypt) struct Probe {
    info: KonnInfo,
    base_image: Vec<u8>,
    root_rva: u32,
    anchor_rva: u32,
    primary_descriptor_rva: u32,
    header_checksum: u32,
    primary_checksum: u32,
    primary_literal: u32,
}

pub(super) struct TerminalCodec {
    pub(super) file_decoder_rva: u32,
    pub(super) file_decoder_table: Vec<u8>,
    pub(super) file_aes_context_rva: u32,
    pub(super) file_raw_aes_key: [u8; 32],
    pub(super) file_program: LfsrAlMapCandidate,
    pub(super) layer_decoder_rva: u32,
    pub(super) layer_aes_context_rva: u32,
    pub(super) layer_raw_aes_key: [u8; 32],
    pub(super) layer_program: LfsrAlMapCandidate,
}

impl TerminalCodec {
    fn candidate(&self, block_table: &PayloadBlockTable) -> PayloadPlanCandidate {
        PayloadPlanCandidate::new(PayloadMaterializationPlan {
            block_table: block_table.clone(),
            aes_key: self.file_raw_aes_key,
            decoder: DecoderCandidate {
                source_file_offset: self.file_decoder_rva as usize,
                phase: 0,
                table: self.file_decoder_table.clone(),
            },
            post_transform: PayloadPostTransform::ByteMap(self.file_program.map.clone()),
        })
    }

    fn matches(&self, plan: &PayloadMaterializationPlan) -> bool {
        plan.aes_key == self.file_raw_aes_key
            && plan.decoder.source_file_offset == self.file_decoder_rva as usize
            && plan.decoder.phase == 0
            && plan.decoder.table == self.file_decoder_table
            && plan.post_transform.mapping() == *self.file_program.map
    }
}

/// Controller-owned data needed after shared full-table authentication.
pub(in crate::pipeline::stages::payload::decrypt) struct Finalizer {
    pub(super) metadata: HeaderMetadata,
    pub(super) root_rva: u32,
    pub(super) anchor_rva: u32,
    pub(super) primary_descriptor_rva: u32,
    pub(super) primary_rva: u32,
    pub(super) state_descriptor_rva: u32,
    pub(super) b0_descriptor_rva: u32,
    pub(super) payload_list_rva: u32,
    pub(super) terminal_codec: TerminalCodec,
}

/// Native-controller proposal before shared full-table authentication.
pub(super) struct Proposal {
    pub(super) base_image: Vec<u8>,
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: Finalizer,
}

struct StateReplay {
    b0_descriptor_rva: u32,
    b890_entry: Option<u32>,
    payload_list_rva: u32,
    block_table: PayloadBlockTable,
    terminal_codec: TerminalCodec,
}
struct RootedPayloadRecords {
    blocks: Vec<PayloadBlock>,
    file_ordinal: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootedSecurityDirectoryBinding {
    InternalNonCertificate,
    CertificateOrAmbiguous,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WinCertificateDirectory {
    Valid,
    NonCertificate,
    Ambiguous,
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn rva_offset(base: u32, relative: u32, label: &str) -> Result<usize> {
    usize::try_from(add_rva(base, relative, label)?)
        .with_context(|| format!("{label} RVA does not fit host address space"))
}

fn checked_dword_stage(image: &[u8], descriptor_rva: u32, label: &str) -> Result<StageDescriptor> {
    let stage = shared::read_stage_descriptor(
        image,
        usize::try_from(descriptor_rva)
            .with_context(|| format!("{label} descriptor RVA does not fit usize"))?,
    )?;
    ensure!(
        stage.source != 0
            && stage.source_length != 0
            && stage.source_length.is_multiple_of(4)
            && stage.destination == 0
            && stage.destination_length == 0,
        "{label} is not a source-only aligned dword stage"
    );
    checked_range(image.len(), stage.source, stage.source_length, label)?;
    Ok(stage)
}

fn checked_controller_stage(
    image: &[u8],
    descriptor_rva: u32,
    label: &str,
) -> Result<StageDescriptor> {
    let stage = shared::read_stage_descriptor(
        image,
        usize::try_from(descriptor_rva)
            .with_context(|| format!("{label} descriptor RVA does not fit usize"))?,
    )?;
    ensure!(
        stage.source != 0
            && stage.source_length != 0
            && stage.destination != 0
            && stage.destination_length != 0,
        "{label} is not a populated controller stage"
    );
    checked_range(image.len(), stage.source, stage.source_length, label)?;
    checked_range(
        image.len(),
        stage.destination,
        stage.destination_length,
        label,
    )?;
    Ok(stage)
}

fn validate_state_selector_list(image: &[u8], state_descriptor_rva: u32) -> Result<()> {
    let mut cursor = add_rva(
        state_descriptor_rva,
        PRIMARY_STATE_SELECTOR_LIST_RELATIVE,
        "state selector list",
    )?;
    for index in 0..PRIMARY_STATE_SELECTOR_ENTRIES {
        let stage = checked_controller_stage(image, cursor, "state selector stage")?;
        ensure!(
            stage.source == stage.destination,
            "state selector stage {index} is not in-place"
        );
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("state selector cursor overflows")?;
    }
    let terminator = shared::read_stage_descriptor(
        image,
        usize::try_from(cursor).context("state selector terminator does not fit usize")?,
    )?;
    ensure!(
        terminator.source == 0
            && terminator.source_length == 0
            && terminator.destination == 0
            && terminator.destination_length == 0,
        "state selector list has no rooted terminator"
    );
    Ok(())
}

fn validate_decoded_primary(image: &[u8], primary_rva: u32) -> Result<StageDescriptor> {
    let state_descriptor_rva = add_rva(
        primary_rva,
        PRIMARY_STATE_DESCRIPTOR_RELATIVE,
        "primary state descriptor",
    )?;
    let state = checked_controller_stage(image, state_descriptor_rva, "primary state descriptor")?;
    ensure!(
        state.source == state.destination
            && state.source_length.is_multiple_of(4)
            && state.destination_length <= state.source_length,
        "primary state descriptor is not an in-place ROR19 state service"
    );
    validate_state_selector_list(image, state_descriptor_rva)?;
    Ok(state)
}

fn checksum_at(
    image: &[u8],
    base: u32,
    relative: u32,
    table: &[u32; 256],
    label: &str,
) -> Result<u32> {
    shared::checksum_descriptor(image, rva_offset(base, relative, label)?, table)
}

fn prepare_checksum_header(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    anchor: u32,
) -> Result<()> {
    let pe_offset = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE optional-header base underflows")?;
    // `anchor` is `root + 0x18`; the native reads
    // `root + 0x10 + {0x15e0, 0x15dc, 0x1600, 0x1604}`.
    for (source_relative, pe_relative) in [
        (0x15d8, 0x90),
        (0x15d4, 0x94),
        (0x15f8, 0x98),
        (0x15fc, 0x9c),
    ] {
        let value = read_u32(
            image,
            rva_offset(anchor, source_relative, "root header-checksum source")?,
        )?;
        write_u32(image, pe_offset + pe_relative, value)?;
    }
    // The native controller authenticates the pre-payload header with the
    // packed relocation directory suppressed; terminal metadata restores it.
    write_u32(image, pe_offset + 0xb0, 0)?;
    write_u32(image, pe_offset + 0xb4, 0)?;
    Ok(())
}

fn bounded_header_checksum_list(
    image: &[u8],
    anchor: u32,
    table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut cursor = add_rva(
        anchor,
        HEADER_CHECKSUM_LIST_RELATIVE,
        "header-checksum list",
    )?;
    let mut checksum = 0u32;
    for index in 0..HEADER_CHECKSUM_ENTRY_COUNT {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        let at = usize::try_from(cursor).context("header-checksum cursor does not fit usize")?;
        let descriptor = shared::read_stage_descriptor(image, at)?;
        ensure!(
            descriptor.source != 0 && descriptor.source_length != 0,
            "PE64 DLL state-asset-selection header-checksum list terminates before entry {index}"
        );
        checksum ^= shared::checksum_descriptor(image, at, table)?;
        cursor = cursor
            .checked_add(HEADER_CHECKSUM_RECORD_STRIDE)
            .context("header-checksum cursor overflows")?;
    }
    let terminator = shared::read_stage_descriptor(
        image,
        usize::try_from(cursor).context("header-checksum terminator does not fit usize")?,
    )?;
    ensure!(
        terminator.source == 0
            && terminator.source_length == 0
            && terminator.destination == 0
            && terminator.destination_length == 0,
        "PE64 DLL state-asset-selection header-checksum list has no fixed zero terminator"
    );
    Ok(checksum)
}

fn validate_state_row(image: &[u8], row_rva: u32, index: usize) -> Result<(u32, u32, u32)> {
    let row = usize::try_from(row_rva).context("state row RVA does not fit usize")?;
    let flags = read_u32(image, row)?;
    let base = read_u32(image, row + 4)?;
    let span = read_u32(image, row + 8)?;
    let destination_length = read_u32(image, row + 12)?;
    let callback_relative = read_u32(image, row + 16)?;
    let import_relative = read_u32(image, row + 20)?;
    let import_length = read_u32(image, row + 24)?;
    ensure!(
        base != 0 && span != 0 && destination_length == span,
        "state materializer row {index} has an invalid target span"
    );
    let module = checked_range(image.len(), base, span, "state materializer target")?;
    if callback_relative != 0 {
        let callback = usize::try_from(add_rva(base, callback_relative, "state callback")?)
            .context("state callback RVA does not fit usize")?;
        ensure!(
            module.contains(&callback),
            "state materializer callback lies outside row {index}"
        );
    }
    if import_length != 0 {
        let import = add_rva(base, import_relative, "state import descriptor")?;
        let import = checked_range(
            image.len(),
            import,
            import_length,
            "state import descriptor",
        )?;
        ensure!(
            import.start >= module.start && import.end <= module.end,
            "state import descriptor lies outside row {index}"
        );
    } else {
        ensure!(
            import_relative == 0,
            "state materializer row {index} has a lengthless import descriptor"
        );
    }
    Ok((flags, base, span))
}

fn validate_state_rows(image: &[u8], state_rva: u32) -> Result<()> {
    let count = read_u32(
        image,
        rva_offset(state_rva, STATE_ROW_COUNT_RELATIVE, "state row count")?,
    )?;
    ensure!(
        count == STATE_ROW_COUNT as u32,
        "state service has an unsupported materializer row count {count}"
    );
    for index in 0..STATE_ROW_COUNT {
        let row_rva = add_rva(
            state_rva,
            STATE_ROWS_RELATIVE
                .checked_add(
                    u32::try_from(index)
                        .expect("fixed state row index fits u32")
                        .checked_mul(STATE_ROW_STRIDE)
                        .expect("fixed state row offset fits u32"),
                )
                .expect("fixed state row relative offset fits u32"),
            "state materializer row",
        )?;
        let (flags, _, _) = validate_state_row(image, row_rva, index)?;
        ensure!(
            flags & !0x1d9d == 0,
            "state materializer row {index} has unsupported dispatch flags {flags:#x}"
        );
    }
    // B500 materializes and import-resolves the four rooted modules, but no
    // rooted callback result has yet been tied to a selector row or map producer.
    Ok(())
}

fn replay_b1_copy_list(
    image: &mut [u8],
    mut cursor: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        shared::transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = shared::read_stage_descriptor(
            image,
            usize::try_from(cursor).context("B1 copy record RVA does not fit usize")?,
        )?;
        let next = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("B1 copy record cursor overflows")?;
        if record.source_length == 0 {
            ensure!(
                record.source == 0 && record.destination == 0 && record.destination_length == 0,
                "rooted B1 copy list has an invalid terminator"
            );
            return Ok(());
        }
        ensure!(
            record.source != 0
                && record.destination != 0
                && record.destination_length == record.source_length,
            "rooted B1 copy record is malformed"
        );
        let source = checked_range(
            image.len(),
            record.source,
            record.source_length,
            "B1 copy source",
        )?;
        let destination = checked_range(
            image.len(),
            record.destination,
            record.destination_length,
            "B1 copy destination",
        )?;
        image.copy_within(source, destination.start);
        cursor = next;
    }
    bail!("rooted B1 copy list exceeds its entry budget")
}

fn replay_b_services(
    image: &mut [u8],
    state_rva: u32,
    info: &KonnInfo,
    cancellation: Option<&CancellationToken>,
) -> Result<(u32, std::ops::Range<usize>, u32)> {
    let header_rva = add_rva(state_rva, STATE_B_HEADER_RELATIVE, "state B-service header")?;
    let header =
        usize::try_from(header_rva).context("state B-service header RVA does not fit usize")?;
    let count = read_u32(image, header)?;
    let outer_base = read_u32(image, header + 4)?;
    let outer_span = read_u32(image, header + 8)?;
    let reserved = read_u32(image, header + 12)?;
    ensure!(
        count == STATE_B_ROW_COUNT as u32 && outer_base == info[3] && outer_span != 0,
        "state B-service header does not bind the rooted outer controller"
    );
    let outer = checked_range(
        image.len(),
        outer_base,
        outer_span,
        "state B-service outer span",
    )?;

    let b0_row_rva = add_rva(state_rva, STATE_B_ROWS_RELATIVE, "state B0 service row")?;
    let b0_row =
        usize::try_from(b0_row_rva).context("state B0 service row RVA does not fit usize")?;
    let b0_flags = read_u32(image, b0_row)?;
    let descriptor_start = read_u32(image, b0_row + 4)?;
    let length = read_u32(image, b0_row + 8)?;
    let b0_reserved = read_u32(image, b0_row + 12)?;
    ensure!(
        descriptor_start == add_rva(outer_base, 0x10, "rooted B0 descriptor start")? && length != 0,
        "state B0 descriptor does not have the rooted grammar"
    );
    let (b0_range, transform_start, seed) = match b0_flags {
        // The complete two-entry B760 grammar has a statically established
        // zero R8 state. Its row's descriptor address is a suffix marker;
        // B3E0 operates on the rooted outer base instead.
        1 => {
            ensure!(
                reserved == 0 && b0_reserved == 0,
                "B760 B-service profile has nonzero reserved fields"
            );
            let range = checked_range(image.len(), outer_base, length, "state B760 transform")?;
            (range, outer_base, 0)
        }
        // The B890 service keeps its actual target in the B0 descriptor and
        // only admits the controller-owned callback-capable profile.
        0x11 => {
            let range = checked_range(
                image.len(),
                descriptor_start,
                length,
                "state B890 transform",
            )?;
            (
                range,
                descriptor_start,
                descriptor_start.wrapping_add(descriptor_start >> 8) as u8,
            )
        }
        flags => bail!("rooted B0 service has an unsupported dispatch flag {flags:#x}"),
    };
    ensure!(
        b0_range.start >= outer.start && b0_range.end <= outer.end,
        "state B0 transform lies outside the B-service outer span"
    );
    shared::transform_rotating_bytes(image, transform_start, length, 3, seed, cancellation)?;

    let b1_row_rva = add_rva(
        state_rva,
        STATE_B_ROWS_RELATIVE
            .checked_add(STATE_B_ROW_STRIDE)
            .expect("fixed B1 service row offset fits u32"),
        "state B1 service row",
    )?;
    let b1_row =
        usize::try_from(b1_row_rva).context("state B1 service row RVA does not fit usize")?;
    let b1_flags = read_u32(image, b1_row)?;
    let copy_list_rva = read_u32(image, b1_row + 4)?;
    let copy_record_size = read_u32(image, b1_row + 8)?;
    let b1_reserved = read_u32(image, b1_row + 12)?;
    ensure!(
        b1_flags == 2 && copy_list_rva != 0,
        "state B1 copy service does not have the rooted grammar"
    );
    if b0_flags == 1 {
        ensure!(
            copy_record_size == STAGE_DESCRIPTOR_SIZE as u32 && b1_reserved == 0,
            "B760 B1 copy service does not have the rooted grammar"
        );
    }
    replay_b1_copy_list(image, copy_list_rva, cancellation)?;
    Ok((b0_row_rva, b0_range, b0_flags))
}

fn validate_b890_metadata(
    image: &mut [u8],
    b0_start: u32,
    b0_range: &std::ops::Range<usize>,
    outer_base: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    const HEADER_LENGTH: u32 = 0x10;
    const FIRST_START: u32 = 0x10;
    const FIRST_END: u32 = 0x20;
    const SECTION_START: u32 = 0xa0;
    const MAX_METADATA_PREFIX: u32 = 0x1e0;
    const SECTION_RECORD_OFFSET: u32 = 0x24;
    const SECTION_RECORD_SIZE: u32 = 0x28;

    let prefix = checked_range(
        image.len(),
        b0_start,
        MAX_METADATA_PREFIX,
        "B890 rooted metadata prefix",
    )?;
    ensure!(
        prefix.start >= b0_range.start && prefix.end <= b0_range.end,
        "B890 metadata prefix lies outside the rooted B0 span"
    );
    let original = image[prefix.clone()].to_vec();
    let result = (|| -> Result<u32> {
        shared::transform_shift2_range(image, b0_start, HEADER_LENGTH, cancellation)?;
        let first_start = read_u32(image, rva_offset(b0_start, 0, "B890 first offset")?)?;
        let first_end = read_u32(image, rva_offset(b0_start, 4, "B890 first end")?)?;
        let section_start = read_u32(image, rva_offset(b0_start, 8, "B890 section offset")?)?;
        let section_end = read_u32(image, rva_offset(b0_start, 12, "B890 section end")?)?;
        let section_span = section_end
            .checked_sub(section_start)
            .context("B890 section metadata span underflows")?;
        let section_count = section_span / SECTION_RECORD_SIZE;
        let section_padding = section_span % SECTION_RECORD_SIZE;
        ensure!(
            first_start == FIRST_START
                && first_end == FIRST_END
                && section_start == SECTION_START
                && section_end > section_start
                && section_end <= MAX_METADATA_PREFIX
                && (1..=7).contains(&section_count)
                && (section_padding == 0 || section_padding == 8),
            "B890 metadata header has an unsupported rooted layout ({first_start:#x}, {first_end:#x}, {section_start:#x}, {section_end:#x})"
        );
        shared::transform_shift2_range(
            image,
            add_rva(b0_start, first_start, "B890 first metadata span")?,
            first_end - first_start,
            cancellation,
        )?;
        shared::transform_shift2_range(
            image,
            add_rva(b0_start, section_start, "B890 section metadata span")?,
            section_span,
            cancellation,
        )?;
        let entry = read_u32(image, rva_offset(b0_start, first_start, "B890 entry")?)?;
        ensure!(
            entry != 0
                && read_u32(
                    image,
                    rva_offset(b0_start, first_start + 4, "B890 outer bound")?,
                )? == outer_base,
            "B890 metadata header does not bind the rooted outer image"
        );
        for index in 0..section_count {
            let record = add_rva(
                b0_start,
                section_start
                    .checked_add(SECTION_RECORD_OFFSET)
                    .and_then(|offset| offset.checked_add(index * SECTION_RECORD_SIZE))
                    .context("B890 section record offset overflows")?,
                "B890 section record",
            )?;
            let record_prefix = record
                .checked_sub(0x1c)
                .context("B890 section record prefix underflows")?;
            checked_range(image.len(), record_prefix, 0x28, "B890 section record")?;
            let virtual_size = read_u32(
                image,
                usize::try_from(record_prefix)
                    .context("B890 section size RVA does not fit usize")?,
            )?;
            let virtual_rva = read_u32(
                image,
                usize::try_from(record_prefix + 4)
                    .context("B890 section RVA does not fit usize")?,
            )?;
            ensure!(
                virtual_size != 0
                    && virtual_rva != 0
                    && virtual_rva
                        .checked_add(virtual_size)
                        .is_some_and(|end| end <= outer_base),
                "B890 section record {index} is outside the rooted image bound"
            );
            let flags = read_u32(
                image,
                usize::try_from(record).context("B890 section flags RVA does not fit usize")?,
            )?;
            let selector =
                ((flags >> 30) & 1) | (2 * ((flags >> 31) & 1)) | (4 * ((flags >> 29) & 1));
            let callback_mode = [1u32, 2, 4, 4, 0x10, 0x20, 0x40, 0x40]
                [usize::try_from(selector).expect("three-bit B890 selector fits usize")];
            ensure!(
                callback_mode != 0,
                "B890 section record has an invalid callback mode"
            );
        }
        Ok(entry)
    })();
    image[prefix].copy_from_slice(&original);
    result
}

fn rooted_selector_stage(
    image: &[u8],
    state_descriptor_rva: u32,
    index: usize,
) -> Result<(u32, StageDescriptor)> {
    ensure!(
        index < PRIMARY_STATE_SELECTOR_ENTRIES,
        "rooted selector stage index {index} exceeds the fixed list"
    );
    let relative = PRIMARY_STATE_SELECTOR_LIST_RELATIVE
        .checked_add(
            u32::try_from(index)
                .context("rooted selector index exceeds u32")?
                .checked_mul(STAGE_DESCRIPTOR_SIZE as u32)
                .context("rooted selector descriptor offset overflows")?,
        )
        .context("rooted selector descriptor relative offset overflows")?;
    let descriptor_rva = add_rva(state_descriptor_rva, relative, "rooted selector descriptor")?;
    Ok((
        descriptor_rva,
        checked_controller_stage(image, descriptor_rva, "rooted selector stage")?,
    ))
}

fn rooted_selector_iteration_count(
    image: &[u8],
    state_descriptor_rva: u32,
    indices: Range<usize>,
    label: &str,
) -> Result<u32> {
    let mut count = 0usize;
    let mut canonical_lengths = None;
    let mut terminated = false;
    for index in indices {
        let (_, stage) = rooted_selector_stage(image, state_descriptor_rva, index)?;
        let lengths = (stage.source_length, stage.destination_length);
        match canonical_lengths {
            None => {
                ensure!(
                    stage.source_length > 3 && stage.destination_length > 4,
                    "{label} has no full selector iteration"
                );
                canonical_lengths = Some(lengths);
                count = 1;
            }
            Some(canonical) if !terminated && lengths == canonical => count += 1,
            Some(_) => {
                terminated = true;
                ensure!(
                    stage.source_length <= 3 && stage.destination_length <= 4,
                    "{label} has a noncanonical selector iteration after its terminator"
                );
            }
        }
    }
    u32::try_from(count).context("rooted selector iteration count exceeds u32")
}

fn rooted_checksum_range(
    image: &[u8],
    primary_rva: u32,
    index: usize,
    stage: &StageDescriptor,
) -> Result<Range<usize>> {
    ensure!(
        index < PRIMARY_CHECKSUM_RECORD_COUNT,
        "rooted checksum record index {index} exceeds the fixed list"
    );
    let relative = PRIMARY_CHECKSUM_RECORDS_RELATIVE
        .checked_add(
            u32::try_from(index)
                .context("rooted checksum index exceeds u32")?
                .checked_mul(PRIMARY_CHECKSUM_RECORD_STRIDE)
                .context("rooted checksum record offset overflows")?,
        )
        .context("rooted checksum record relative offset overflows")?;
    let record_rva = add_rva(primary_rva, relative, "rooted checksum record")?;
    let record = usize::try_from(record_rva).context("rooted checksum record exceeds usize")?;
    let start = read_u32(image, record)?;
    let length = read_u32(image, record + 4)?;
    ensure!(
        start == stage.destination && length != 0 && length <= stage.destination_length,
        "rooted checksum record {index} does not bind its selector output"
    );
    checked_range(image.len(), start, length, "rooted selector checksum span")
}

fn rooted_map_program(
    image: &[u8],
    stage: &StageDescriptor,
    relative: u32,
    label: &str,
) -> Result<LfsrAlMapCandidate> {
    let output = checked_range(
        image.len(),
        stage.destination,
        stage.destination_length,
        label,
    )?;
    let program_rva = add_rva(stage.destination, relative, label)?;
    let program = checked_range(image.len(), program_rva, AL_PROGRAM_WINDOW_LENGTH, label)?;
    ensure!(
        program.start >= output.start && program.end <= output.end,
        "{label} program slot {relative:#x} lies outside the selector output"
    );
    shared::exact_lfsr_al_map(image, program_rva, AL_PROGRAM_WINDOW_LENGTH, label)
}

fn replay_asset_rows(
    image: &mut [u8],
    state_rva: u32,
    primary_rva: u32,
    header_checksum: u32,
    file_ordinal: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<TerminalCodec> {
    let state_descriptor_rva = add_rva(
        primary_rva,
        PRIMARY_STATE_DESCRIPTOR_RELATIVE,
        "primary state descriptor",
    )?;
    let state_descriptor =
        checked_controller_stage(image, state_descriptor_rva, "primary state descriptor")?;
    ensure!(
        state_descriptor.source == state_rva && state_descriptor.destination == state_rva,
        "asset rows are detached from the rooted state descriptor"
    );
    ensure!(
        file_ordinal == 0,
        "rooted payload records use terminal asset ordinal {file_ordinal}, but only ordinal zero is supported by the observed terminal file-map binding"
    );

    let decoder_row_rva = add_rva(state_rva, STATE_ASSET_ROWS_RELATIVE, "decoder asset row")?;
    let aes_row_rva = add_rva(decoder_row_rva, STATE_ROW_STRIDE, "AES asset row")?;
    let decoder_row =
        usize::try_from(decoder_row_rva).context("decoder asset row RVA does not fit usize")?;
    let aes_row = usize::try_from(aes_row_rva).context("AES asset row RVA does not fit usize")?;
    let decoder_kind = read_u32(image, decoder_row)?;
    let decoder_service_rva = read_u32(image, decoder_row + 4)?;
    let aes_kind = read_u32(image, aes_row)?;
    let aes_service_rva = read_u32(image, aes_row + 4)?;
    ensure!(
        decoder_kind == 1 && aes_kind == 2 && decoder_service_rva != aes_service_rva,
        "state asset rows do not have the rooted decoder/AES service grammar"
    );
    checked_range(
        image.len(),
        decoder_service_rva,
        1,
        "rooted decoder service",
    )?;
    checked_range(image.len(), aes_service_rva, 1, "rooted AES service")?;

    let asset_descriptors = [decoder_row + 8, decoder_row + 16, aes_row + 8, aes_row + 16];
    let mut asset_rvas = [0u32; 4];
    for (index, &descriptor) in asset_descriptors.iter().enumerate() {
        let asset_rva = read_u32(image, descriptor)?;
        let asset_length = read_u32(image, descriptor + 4)?;
        ensure!(
            asset_rva != 0 && asset_length != 0,
            "rooted terminal asset descriptor {index} is empty"
        );
        checked_range(
            image.len(),
            asset_rva,
            asset_length,
            "rooted terminal asset",
        )?;
        asset_rvas[index] = asset_rva;
    }
    for descriptor in asset_descriptors {
        shared::transform_shift3_descriptor(image, descriptor, cancellation)?;
    }

    let layer_ordinal = file_ordinal ^ 1;
    let file_decoder_rva = asset_rvas[file_ordinal];
    let layer_decoder_rva = asset_rvas[layer_ordinal];
    let file_aes_context_rva = asset_rvas[2 + file_ordinal];
    let layer_aes_context_rva = asset_rvas[2 + layer_ordinal];
    let file_decoder_table = shared::snapshot_decoder_table(image, file_decoder_rva)?;
    let layer_decoder_table = shared::snapshot_decoder_table(image, layer_decoder_rva)?;
    let (file_raw_aes_key, _file_aes) = shared::recover_aes_context(image, file_aes_context_rva)?;
    let (layer_raw_aes_key, layer_aes) = shared::recover_aes_context(image, layer_aes_context_rva)?;
    tracing::debug!(
        file_ordinal,
        layer_ordinal,
        file_decoder_rva,
        layer_decoder_rva,
        file_aes_context_rva,
        layer_aes_context_rva,
        file_raw_key = %hex::encode(file_raw_aes_key),
        layer_raw_key = %hex::encode(layer_raw_aes_key),
        "selected rooted terminal assets"
    );

    let (stage_four_rva, stage_four) =
        rooted_selector_stage(image, state_descriptor_rva, SELECTOR_STAGE_FOUR)?;
    let (stage_five_rva, stage_five) =
        rooted_selector_stage(image, state_descriptor_rva, SELECTOR_STAGE_FIVE)?;
    let (stage_seven_rva, stage_seven) =
        rooted_selector_stage(image, state_descriptor_rva, SELECTOR_STAGE_SEVEN)?;
    let (stage_twelve_rva, stage_twelve) =
        rooted_selector_stage(image, state_descriptor_rva, SELECTOR_STAGE_TWELVE)?;
    let _r0 = rooted_checksum_range(image, primary_rva, 0, &stage_twelve)?;
    let r1 = rooted_checksum_range(image, primary_rva, 1, &stage_seven)?;
    let r2 = rooted_checksum_range(image, primary_rva, 2, &stage_five)?;
    let r3 = rooted_checksum_range(image, primary_rva, 3, &stage_four)?;
    let table = crc32_table();
    let primary_prefix = checked_range(
        image.len(),
        primary_rva,
        PRIMARY_ROOT_CHECKSUM_LENGTH,
        "rooted primary checksum prefix",
    )?;
    let stage_four_iterations = rooted_selector_iteration_count(
        image,
        state_descriptor_rva,
        0..SELECTOR_STAGE_FOUR,
        "rooted stage-four prelude",
    )?;
    let stage_four_scalar = read_u32(
        image,
        rva_offset(
            primary_rva,
            PRIMARY_STATE_KEY_RELATIVE + 4,
            "rooted stage-four scalar",
        )?,
    )?
    .wrapping_add(shared::advance_key(0, stage_four_iterations));
    let stage_four_key =
        stage_four_scalar ^ header_checksum ^ crackproof_checksum(&image[primary_prefix], &table);
    tracing::debug!(
        header_checksum,
        stage_four_scalar,
        stage_four_key,
        "derived rooted selector stage-four key"
    );
    shared::decrypt_stage(
        image,
        usize::try_from(stage_four_rva).context("stage-four descriptor exceeds usize")?,
        stage_four_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("replaying rooted selector stage four")?;

    let stage_five_scalar = read_u32(
        image,
        rva_offset(
            stage_four.destination,
            SELECTOR_STAGE_FOUR_SCALAR_RELATIVE,
            "rooted stage-five scalar",
        )?,
    )?;
    let stage_five_key =
        stage_five_scalar ^ header_checksum ^ crackproof_checksum(&image[r3], &table);
    shared::decrypt_stage(
        image,
        usize::try_from(stage_five_rva).context("stage-five descriptor exceeds usize")?,
        stage_five_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("replaying rooted selector stage five")?;

    let r2_checksum = crackproof_checksum(&image[r2], &table);
    let stage_seven_scalar = !read_u32(
        image,
        rva_offset(
            stage_five.destination,
            SELECTOR_STAGE_FIVE_SCALAR_RELATIVE,
            "rooted stage-seven scalar",
        )?,
    )?;
    let stage_seven_key = stage_seven_scalar ^ header_checksum ^ r2_checksum;
    shared::decrypt_stage(
        image,
        usize::try_from(stage_seven_rva).context("stage-seven descriptor exceeds usize")?,
        stage_seven_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("replaying rooted selector stage seven")?;
    let layer_program = rooted_map_program(
        image,
        &stage_seven,
        LAYER_MAP_PROGRAM_RELATIVE,
        "rooted layer-map output",
    )?;

    let stage_twelve_iterations = rooted_selector_iteration_count(
        image,
        state_descriptor_rva,
        SELECTOR_STAGE_SEVEN + 1..SELECTOR_STAGE_TWELVE,
        "rooted stage-twelve prelude",
    )?;
    let stage_twelve_scalar = read_u32(
        image,
        rva_offset(
            stage_seven.destination,
            SELECTOR_STAGE_SEVEN_SCALAR_RELATIVE,
            "rooted stage-twelve scalar",
        )?,
    )?
    .wrapping_add(shared::advance_key(0, stage_twelve_iterations));
    let stage_twelve_key = stage_twelve_scalar
        ^ header_checksum
        ^ crackproof_checksum(&image[r1], &table)
        ^ r2_checksum;
    shared::decrypt_stage(
        image,
        usize::try_from(stage_twelve_rva).context("stage-twelve descriptor exceeds usize")?,
        stage_twelve_key,
        &layer_aes,
        &layer_decoder_table,
        Some(&layer_program.map),
        cancellation,
    )
    .context("replaying rooted selector stage twelve")?;
    let file_program = rooted_map_program(
        image,
        &stage_twelve,
        FILE_MAP_PROGRAM_RELATIVE,
        "rooted terminal-map output",
    )?;

    Ok(TerminalCodec {
        file_decoder_rva,
        file_decoder_table,
        file_aes_context_rva,
        file_raw_aes_key,
        file_program,
        layer_decoder_rva,
        layer_aes_context_rva,
        layer_raw_aes_key,
        layer_program,
    })
}

fn packed_image_body_end(source: &BoundPayloadSource<'_>) -> Result<usize> {
    let mut body_end = usize::try_from(source.pe.size_of_headers)
        .context("PE header size does not fit host address space")?;
    ensure!(
        body_end <= source.packed.len(),
        "PE headers exceed the packed payload source"
    );
    for section in &source.pe.sections {
        if section.raw_size == 0 {
            continue;
        }
        let range = section.raw_range()?;
        ensure!(
            range.end <= source.packed.len(),
            "PE section {} exceeds the packed payload source",
            section.index
        );
        body_end = body_end.max(range.end);
    }
    Ok(body_end)
}

fn classify_win_certificate_directory(
    packed: &[u8],
    directory: &Range<usize>,
    cancellation: Option<&CancellationToken>,
) -> Result<WinCertificateDirectory> {
    let table = packed
        .get(directory.clone())
        .context("PE Security Directory exceeds the packed payload source")?;
    if table.len() < WIN_CERTIFICATE_HEADER_SIZE
        || table.len() > MAX_ROOTED_SECURITY_DIRECTORY_BYTES
    {
        return Ok(WinCertificateDirectory::Ambiguous);
    }

    let mut cursor = 0usize;
    for index in 0..table.len() / WIN_CERTIFICATE_HEADER_SIZE {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let Some(header_end) = cursor.checked_add(WIN_CERTIFICATE_HEADER_SIZE) else {
            return Ok(WinCertificateDirectory::Ambiguous);
        };
        let Some(header) = table.get(cursor..header_end) else {
            return Ok(WinCertificateDirectory::Ambiguous);
        };
        let revision = read_u16(header, 4)?;
        let certificate_type = read_u16(header, 6)?;
        let known_revision = matches!(revision, 0x0100 | 0x0200);
        let known_certificate_type = matches!(certificate_type, 0x0001..=0x0004);
        if !known_revision || !known_certificate_type {
            return Ok(
                if cursor == 0 && !known_revision && !known_certificate_type {
                    WinCertificateDirectory::NonCertificate
                } else {
                    WinCertificateDirectory::Ambiguous
                },
            );
        }

        let length = usize::try_from(read_u32(header, 0)?)
            .context("WIN_CERTIFICATE length does not fit host address space")?;
        if length < WIN_CERTIFICATE_HEADER_SIZE {
            return Ok(WinCertificateDirectory::Ambiguous);
        }
        let Some(padded_length) = length.checked_add(7).map(|value| value & !7) else {
            return Ok(WinCertificateDirectory::Ambiguous);
        };
        let Some(entry_end) = cursor.checked_add(padded_length) else {
            return Ok(WinCertificateDirectory::Ambiguous);
        };
        if entry_end > table.len() {
            return Ok(WinCertificateDirectory::Ambiguous);
        }
        cursor = entry_end;
        if cursor == table.len() {
            return Ok(WinCertificateDirectory::Valid);
        }
    }
    Ok(WinCertificateDirectory::Ambiguous)
}

fn rooted_security_directory_binding(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<RootedSecurityDirectoryBinding> {
    let Some(security) = source.source_security_range else {
        bail!("rooted Security Directory binding requested without a declaration");
    };
    if source.packed.len() != source.payload_source.len()
        || source.packed.as_ptr() != source.payload_source.as_ptr()
        || security.end > packed_image_body_end(source)?
        || security.start < source.stream.base_file_offset
        || security.end > source.payload_source.len()
    {
        return Ok(RootedSecurityDirectoryBinding::CertificateOrAmbiguous);
    }
    Ok(
        match classify_win_certificate_directory(source.packed, security, cancellation)? {
            WinCertificateDirectory::NonCertificate => {
                RootedSecurityDirectoryBinding::InternalNonCertificate
            }
            WinCertificateDirectory::Valid | WinCertificateDirectory::Ambiguous => {
                RootedSecurityDirectoryBinding::CertificateOrAmbiguous
            }
        },
    )
}

fn rooted_a_record_stream_range(
    source: &BoundPayloadSource<'_>,
    stream_displacement: u32,
    encoded_length: usize,
    security_binding: &mut Option<RootedSecurityDirectoryBinding>,
    cancellation: Option<&CancellationToken>,
) -> Result<Range<usize>> {
    let source_offset = source
        .stream
        .base_file_offset
        .checked_add(
            usize::try_from(stream_displacement)
                .context("rooted payload source displacement does not fit usize")?,
        )
        .context("rooted payload source offset overflows")?;
    let source_end = source_offset
        .checked_add(encoded_length)
        .context("rooted payload source end overflows")?;
    ensure!(
        source_end <= source.payload_source.len(),
        "rooted payload source exceeds the bound source"
    );
    let range = source_offset..source_end;
    let Some(security) = source.source_security_range else {
        return Ok(range);
    };
    if range.end <= security.start || range.start >= security.end {
        return Ok(range);
    }

    let binding = if let Some(binding) = *security_binding {
        binding
    } else {
        let binding = rooted_security_directory_binding(source, cancellation)?;
        *security_binding = Some(binding);
        binding
    };
    // The controller-authenticated stream can occupy an internal declaration
    // only after that entire declaration is proven not to be certificate data.
    ensure!(
        binding == RootedSecurityDirectoryBinding::InternalNonCertificate,
        "rooted payload source overlaps the PE Security Directory"
    );
    Ok(range)
}

fn parse_rooted_payload_records(
    image: &mut [u8],
    payload_list_rva: u32,
    b0_range: &std::ops::Range<usize>,
    outer_base: u32,
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<RootedPayloadRecords> {
    let mut cursor = payload_list_rva;
    let mut blocks = Vec::new();
    let mut work = 0usize;
    let mut file_ordinal = None;
    let mut security_binding = None;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record_end = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("rooted payload record cursor overflows")?;
        let record_range = checked_range(
            image.len(),
            cursor,
            STAGE_DESCRIPTOR_SIZE as u32,
            "rooted payload record",
        )?;
        ensure!(record_range.start >= b0_range.start && record_range.end <= b0_range.end,);
        shared::transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = shared::read_stage_descriptor(
            image,
            usize::try_from(cursor).context("rooted payload record RVA does not fit usize")?,
        )?;
        cursor = record_end;
        if record.source_length == 0 {
            ensure!(
                !blocks.is_empty()
                    && record.source == outer_base
                    && record.destination == 0
                    && record.destination_length == 0,
                "rooted payload record list has an invalid terminator"
            );
            let Some(file_ordinal) = file_ordinal else {
                bail!("rooted payload record list has no terminal asset selection");
            };
            return Ok(RootedPayloadRecords {
                blocks,
                file_ordinal,
            });
        }
        ensure!(
            record.destination_length != 0,
            "rooted payload record has an empty destination"
        );
        let record_file_ordinal = usize::from(record.destination >= outer_base);
        if let Some(file_ordinal) = file_ordinal {
            ensure!(
                record_file_ordinal == file_ordinal,
                "rooted payload records select mixed terminal asset ordinals"
            );
        } else {
            file_ordinal = Some(record_file_ordinal);
        }
        let encoded_length = usize::try_from(record.source_length)
            .context("rooted payload encoded length does not fit usize")?;
        let destination_length = usize::try_from(record.destination_length)
            .context("rooted payload destination length does not fit usize")?;
        let source_range = rooted_a_record_stream_range(
            source,
            record.source,
            encoded_length,
            &mut security_binding,
            cancellation,
        )?;
        let source_offset = source_range.start;
        checked_range(
            image.len(),
            record.destination,
            record.destination_length,
            "rooted payload destination",
        )?;
        work = work
            .checked_add(encoded_length)
            .and_then(|value| value.checked_add(destination_length))
            .context("rooted payload replay work overflows")?;
        ensure!(
            work <= MAX_PAYLOAD_REPLAY_WORK,
            "rooted payload replay exceeds its byte-work budget"
        );
        blocks.push(PayloadBlock {
            source_offset,
            encoded_length,
            destination_rva: usize::try_from(record.destination)
                .context("rooted payload destination RVA does not fit usize")?,
            destination_length,
        });
    }
    bail!("rooted payload record list exceeds its entry budget")
}

fn replay_state_service(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    info: &KonnInfo,
    primary_rva: u32,
    header_checksum: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<StateReplay> {
    let state_descriptor_rva = add_rva(
        primary_rva,
        PRIMARY_STATE_DESCRIPTOR_RELATIVE,
        "primary state descriptor",
    )?;
    let state = checked_controller_stage(image, state_descriptor_rva, "primary state descriptor")?;
    ensure!(
        state.source == state.destination
            && state.source_length.is_multiple_of(4)
            && state.destination_length <= state.source_length,
        "state service does not have the rooted in-place ROR19 grammar"
    );
    let state_key = read_u32(
        image,
        rva_offset(primary_rva, PRIMARY_STATE_KEY_RELATIVE, "state service key")?,
    )?;
    shared::decrypt_rotating_dword_descriptor(
        image,
        usize::try_from(state_descriptor_rva).context("state descriptor RVA does not fit usize")?,
        state_key,
        19,
        cancellation,
    )
    .context("decrypting rooted PE64 DLL state-asset-selection ROR19 state service")?;

    validate_state_rows(image, state.source)?;
    let (b0_descriptor_rva, b0_range, b0_flags) =
        replay_b_services(image, state.source, info, cancellation)?;
    let b890_entry = if b0_flags & 0x10 != 0 {
        Some(validate_b890_metadata(
            image,
            read_u32(image, rva_offset(b0_descriptor_rva, 4, "rooted B0 source")?)?,
            &b0_range,
            info[3],
            cancellation,
        )?)
    } else {
        None
    };
    let payload_list_rva = add_rva(
        info[3],
        OUTER_PAYLOAD_RECORDS_RELATIVE,
        "rooted B0 payload record list",
    )?;
    let RootedPayloadRecords {
        blocks,
        file_ordinal,
    } = parse_rooted_payload_records(
        image,
        payload_list_rva,
        &b0_range,
        info[3],
        source,
        cancellation,
    )?;
    let terminal_codec = replay_asset_rows(
        image,
        state.source,
        primary_rva,
        header_checksum,
        file_ordinal,
        cancellation,
    )?;
    Ok(StateReplay {
        b0_descriptor_rva,
        b890_entry,
        payload_list_rva,
        block_table: PayloadBlockTable {
            stream_base: 0,
            blocks,
        },
        terminal_codec,
    })
}

/// Recognizes the AMD64 DLL layout only through its KONN-rooted descriptors.
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
    let outer_end = info[3]
        .checked_add(info[5])
        .context("KONN outer range overflows")?;
    let root_prefix_end = info[6]
        .checked_add(ROOT_FIXED_PREFIX_LENGTH)
        .context("KONN root fixed prefix end overflows")?;
    ensure!(
        info[6] >= info[3] && root_prefix_end <= outer_end,
        "KONN root fixed prefix is outside the materialized outer range"
    );
    let root_rva = info[6];
    let mut base_image = shared::materialize_konn_bootstrap(source, &info, cancellation)?;
    let anchor_rva = add_rva(root_rva, ROOT_ANCHOR_RELATIVE, "controller control base")?;
    let table = crc32_table();
    prepare_checksum_header(&mut base_image, source, anchor_rva)?;
    let header_checksum =
        bounded_header_checksum_list(&base_image, anchor_rva, &table, cancellation)?;
    let primary_descriptor_rva = add_rva(
        anchor_rva,
        PRIMARY_DESCRIPTOR_RELATIVE,
        "root primary descriptor",
    )?;
    checked_dword_stage(&base_image, primary_descriptor_rva, "root primary stage")?;
    let primary_checksum = checksum_at(
        &base_image,
        anchor_rva,
        PRIMARY_CHECKSUM_RELATIVE,
        &table,
        "primary checksum",
    )?;
    let primary_literal = read_u32(
        &base_image,
        rva_offset(
            anchor_rva,
            PRIMARY_KEY_LITERAL_RELATIVE,
            "primary key literal",
        )?,
    )?;
    Ok(Some(Probe {
        info,
        base_image,
        root_rva,
        anchor_rva,
        primary_descriptor_rva,
        header_checksum,
        primary_checksum,
        primary_literal,
    }))
}

/// Replays the rooted state controller through its complete authenticated plan.
pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<Proposal> {
    let Probe {
        info,
        mut base_image,
        root_rva,
        anchor_rva,
        primary_descriptor_rva,
        header_checksum,
        primary_checksum,
        primary_literal,
    } = probe;
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }

    let primary_stage =
        checked_dword_stage(&base_image, primary_descriptor_rva, "root primary stage")?;
    let primary_rva = primary_stage.source;
    let primary_key = header_checksum ^ primary_checksum ^ primary_literal;
    let primary_seed = read_u32(
        &base_image,
        usize::try_from(primary_rva).context("primary start RVA does not fit usize")?,
    )?;
    ensure!(
        primary_seed == primary_key,
        "root primary seed does not bind the rooted checksum/key relation"
    );
    shared::decrypt_rotating_dword_descriptor(
        &mut base_image,
        usize::try_from(primary_descriptor_rva)
            .context("root primary descriptor RVA does not fit usize")?,
        primary_key,
        21,
        cancellation,
    )
    .context("decrypting rooted PE64 DLL state-asset-selection primary controller stage")?;
    ensure!(
        read_u32(
            &base_image,
            rva_offset(primary_rva, PRIMARY_IMPORT_RELATIVE, "primary import key")?,
        )? == PRIMARY_IMPORT_KEY_LITERAL,
        "primary import literal does not authenticate the rooted ROR21 relation"
    );
    validate_decoded_primary(&base_image, primary_rva)?;

    let StateReplay {
        b0_descriptor_rva,
        b890_entry,
        payload_list_rva,
        block_table,
        terminal_codec,
    } = replay_state_service(
        &mut base_image,
        source,
        &info,
        primary_rva,
        header_checksum,
        cancellation,
    )?;
    let (entry, directories) = shared::extract_metadata(&mut base_image, info[3], cancellation)?;
    let metadata = HeaderMetadata { entry, directories };
    if let Some(b890_entry) = b890_entry {
        ensure!(
            entry == b890_entry,
            "B890 entry metadata disagrees with the rooted finalizer metadata"
        );
    }
    prefill_managed_section(&mut base_image, source)?;

    let candidate = terminal_codec.candidate(&block_table);
    Ok(Proposal {
        base_image,
        block_table,
        candidate,
        finalizer: Finalizer {
            metadata,
            root_rva,
            anchor_rva,
            primary_descriptor_rva,
            primary_rva,
            state_descriptor_rva: add_rva(
                primary_rva,
                PRIMARY_STATE_DESCRIPTOR_RELATIVE,
                "primary state descriptor",
            )?,
            b0_descriptor_rva,
            payload_list_rva,
            terminal_codec,
        },
    })
}

impl Finalizer {
    /// Applies the authenticated rooted B0 plan and restores controller metadata.
    pub(super) fn finalize(
        self,
        source: &BoundPayloadSource<'_>,
        block_table: PayloadBlockTable,
        authenticated: AuthenticatedPayloadPlan,
    ) -> Result<DecryptedImage> {
        ensure!(
            self.terminal_codec.matches(authenticated.plan()),
            "authenticated plan does not match the rooted terminal codec"
        );
        let TerminalCodec {
            file_decoder_rva,
            file_decoder_table,
            file_aes_context_rva,
            file_raw_aes_key,
            file_program,
            layer_decoder_rva,
            layer_aes_context_rva,
            layer_raw_aes_key,
            layer_program,
        } = self.terminal_codec;
        let terminal = PostStage5Finalizer {
            file_raw_aes_key,
            file_decoder_table,
            file_program,
            metadata_records: 0,
            zero_ranges: Vec::new(),
        };
        let mut image = finalize_post_stage5(
            source,
            block_table,
            &terminal,
            &self.metadata,
            authenticated,
        )?;
        let file_program = &terminal.file_program;
        image.decryption_details.selected_controller = Some(
            SelectedController::StateAssetSelection(SelectedRootedNativeController {
                root_rva: self.root_rva,
                graph_nodes: vec![
                    RootedNativeControllerGraphNode {
                        kind: RootedNativeControllerNodeKind::Anchor,
                        rva: self.anchor_rva,
                    },
                    RootedNativeControllerGraphNode {
                        kind: RootedNativeControllerNodeKind::PrimaryDescriptor,
                        rva: self.primary_descriptor_rva,
                    },
                    RootedNativeControllerGraphNode {
                        kind: RootedNativeControllerNodeKind::Stage1,
                        rva: self.primary_rva,
                    },
                    RootedNativeControllerGraphNode {
                        kind: RootedNativeControllerNodeKind::Codec,
                        rva: self.state_descriptor_rva,
                    },
                    RootedNativeControllerGraphNode {
                        kind: RootedNativeControllerNodeKind::MapLayer,
                        rva: u32::try_from(file_program.offset)
                            .context("PE64 DLL state-asset-selection file map RVA exceeds u32")?,
                    },
                    RootedNativeControllerGraphNode {
                        kind: RootedNativeControllerNodeKind::Terminal,
                        rva: self.b0_descriptor_rva,
                    },
                ],
                payload_list_rva: self.payload_list_rva,
                file_decoder_rva,
                layer_decoder_rva: Some(layer_decoder_rva),
                file_aes_context_rva,
                layer_aes_context_rva: Some(layer_aes_context_rva),
                file_raw_key_hex: hex::encode(file_raw_aes_key),
                layer_raw_key_hex: Some(hex::encode(layer_raw_aes_key)),
                layer_program_rva: Some(
                    u32::try_from(layer_program.offset)
                        .context("1e958a97 layer program RVA exceeds u32")?,
                ),
                layer_program_length: Some(layer_program.length),
                layer_byte_map: Some(layer_program.map.to_vec()),
                file_program_rva: u32::try_from(file_program.offset)
                    .context("PE64 DLL state-asset-selection file program RVA exceeds u32")?,
                file_program_length: file_program.length,
                file_byte_map: file_program.map.to_vec(),
                terminal_profile: None,
            }),
        );
        Ok(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_classifier_recognizes_a_complete_known_chain() {
        let mut table = vec![0; WIN_CERTIFICATE_HEADER_SIZE];
        table[0..4].copy_from_slice(&(WIN_CERTIFICATE_HEADER_SIZE as u32).to_le_bytes());
        table[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        table[6..8].copy_from_slice(&0x0002u16.to_le_bytes());

        assert_eq!(
            classify_win_certificate_directory(&table, &(0..table.len()), None).unwrap(),
            WinCertificateDirectory::Valid
        );
    }

    #[test]
    fn certificate_classifier_rejects_a_truncated_plausible_header() {
        let mut table = vec![0; WIN_CERTIFICATE_HEADER_SIZE];
        table[0..4].copy_from_slice(&0x10u32.to_le_bytes());
        table[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        table[6..8].copy_from_slice(&0x0002u16.to_le_bytes());

        assert_eq!(
            classify_win_certificate_directory(&table, &(0..table.len()), None).unwrap(),
            WinCertificateDirectory::Ambiguous
        );
    }

    #[test]
    fn certificate_classifier_treats_a_partially_known_header_as_ambiguous() {
        let mut table = vec![0; WIN_CERTIFICATE_HEADER_SIZE];
        table[0..4].copy_from_slice(&(WIN_CERTIFICATE_HEADER_SIZE as u32).to_le_bytes());
        table[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        table[6..8].copy_from_slice(&0x7f7fu16.to_le_bytes());

        assert_eq!(
            classify_win_certificate_directory(&table, &(0..table.len()), None).unwrap(),
            WinCertificateDirectory::Ambiguous
        );
    }

    #[test]
    fn certificate_classifier_marks_an_invalid_leading_header_as_noncertificate() {
        let mut table = vec![0; WIN_CERTIFICATE_HEADER_SIZE];
        table[0..4].copy_from_slice(&0x10u32.to_le_bytes());
        table[4..6].copy_from_slice(&0x7f7fu16.to_le_bytes());
        table[6..8].copy_from_slice(&0x7f7fu16.to_le_bytes());

        assert_eq!(
            classify_win_certificate_directory(&table, &(0..table.len()), None).unwrap(),
            WinCertificateDirectory::NonCertificate
        );
    }

    #[test]
    fn nonzero_payload_ordinal_fails_before_terminal_map_selection() {
        let primary_rva = 0x100;
        let state_rva = 0x80u32;
        let descriptor_rva = primary_rva + PRIMARY_STATE_DESCRIPTOR_RELATIVE;
        let descriptor = usize::try_from(descriptor_rva).expect("test descriptor fits usize");
        let mut image = vec![0; descriptor + STAGE_DESCRIPTOR_SIZE];
        image[descriptor..descriptor + 4].copy_from_slice(&state_rva.to_le_bytes());
        image[descriptor + 4..descriptor + 8].copy_from_slice(&4u32.to_le_bytes());
        image[descriptor + 8..descriptor + 12].copy_from_slice(&state_rva.to_le_bytes());
        image[descriptor + 12..descriptor + 16].copy_from_slice(&4u32.to_le_bytes());

        let Err(error) = replay_asset_rows(&mut image, state_rva, primary_rva, 0, 1, None) else {
            panic!("an unbound payload ordinal must not select an adjacent terminal map");
        };

        assert!(
            error.to_string().contains("only ordinal zero"),
            "unexpected terminal-map binding error: {error:#}"
        );
    }
}
