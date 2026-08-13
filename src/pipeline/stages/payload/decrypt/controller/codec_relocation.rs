use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use super::super::aes::Aes256CbcDecryptor;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    DecryptionDetails, SelectedCodecRelocationController, SelectedController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crackproof_checksum, crc32_table,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::{
    AuthenticatedPayloadPlan, PayloadMaterializationPlan, PayloadPlanCandidate,
    PayloadPostTransform, ensure_terminal_zero_ranges_are_disjoint_from_payload_destinations,
};
use super::super::source::BoundPayloadSource;
use super::super::{
    DecoderCandidate, DecryptedImage, PayloadBlock, PayloadBlockTable,
    merged_payload_block_destination_ranges, payload_block_destination_range,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};
use super::{ControllerFinalizer, ControllerProposal};

const PRIMARY_DESCRIPTOR_RELATIVE: u32 = 5_712;
const PRIMARY_KEY_LITERAL_RELATIVE: u32 = 5_612;
const PRIMARY_CHECKSUM_RELATIVE: u32 = 5_648;
const HEADER_CHECKSUM_LIST_RELATIVE: u32 = 5_776;
const LAYER_CHECKSUM_RELATIVE: u32 = 5_640;
const PRIMARY_IMPORT_RELATIVE: u32 = 3_444;
const PRIMARY_TABLE_KEY_RELATIVE: u32 = 3_448;
const PRIMARY_CRC_DESCRIPTOR_RELATIVE: u32 = 3_488;
const PRIMARY_CHECKSUM3_RELATIVE: u32 = 3_480;
const PRIMARY_CHECKSUM4_RELATIVE: u32 = 3_472;
const PRIMARY_CODEC_DESCRIPTOR_RELATIVE: u32 = 3_632;
const PRIMARY_LAYER1_DESCRIPTOR_RELATIVE: u32 = 3_712;
const PRIMARY_LAYER2_DESCRIPTOR_RELATIVE: u32 = 3_728;
const PRIMARY_LAYER3_DESCRIPTOR_RELATIVE: u32 = 3_760;
const PRIMARY_FINAL_DESCRIPTOR_RELATIVE: u32 = 3_840;
const CODEC_PARAMETER_RELATIVE: u32 = 9_160;
const CODEC_RELOCATION_RELATIVE: u32 = 9_248;
const CODEC_RELOCATION_RECORD_SIZE: u32 = 16;
const CODEC_PARAMETER_DESCRIPTOR_RELATIVES: [u32; 4] = [0, 8, 32, 40];
const MAP_LAYER_KEY_RELATIVE: u32 = 3_160;
const DESCRIPTOR_LAYER_PROGRAM_RELATIVE: u32 = 0x0c80;
const DESCRIPTOR_FILE_PROGRAM_RELATIVE: u32 = 0x3070;
const FINAL_PAYLOAD_LIST_RELATIVE: u32 = 11_976;
const FINAL_METADATA_LIST_RELATIVE: u32 = 12_312;
const CONTROLLER_METADATA_RELATIVE: u32 = 16;
const CONTROLLER_METADATA_LENGTH: u32 = 656;
const CONTROLLER_DIRECTORIES_RELATIVE: u32 = 48;
const CONTROLLER_DIRECTORIES_LENGTH: usize = 128;
const MAX_FILE_REPLAY_WORK: usize = 512 << 20;
const MAX_ZERO_FILL_BYTES: usize = 512 << 20;
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

pub(crate) struct Probe {
    info: KonnInfo,
    base_image: Vec<u8>,
    pristine_outer_range: Range<usize>,
    pristine_outer_bytes: Vec<u8>,
    anchor_rva: u32,
    header_checksum: u32,
    primary_checksum: u32,
    primary_literal: u32,
    primary_key: u32,
}

/// The terminal descriptor graph is rooted by controller state already
/// materialized by its family-specific prefix.  `anchor_rva` is the logical
/// controller base, not necessarily the KONN bootstrap entry.
pub(super) struct RootedController {
    pub(super) info: KonnInfo,
    pub(super) image: Vec<u8>,
    pub(super) anchor_rva: u32,
}

pub(super) struct HeaderMetadata {
    pub(super) entry: u32,
    pub(super) directories: [u8; CONTROLLER_DIRECTORIES_LENGTH],
}

/// The file-codec and teardown state selected by a rooted terminal graph.
pub(super) struct PostStage5Finalizer {
    pub(super) file_raw_aes_key: [u8; 32],
    pub(super) file_decoder_table: Vec<u8>,
    pub(super) file_program: LfsrAlMapCandidate,
    pub(super) metadata_records: usize,
    pub(super) zero_ranges: Vec<Range<usize>>,
}

/// A single rooted file-map program supplied by a family-specific terminal.
pub(super) struct ExactPostStage5Input {
    pub(super) metadata_list_pointer_slot_rva: u32,
    pub(super) payload_list_pointer_slot_rva: u32,
    pub(super) file_program: LfsrAlMapCandidate,
    pub(super) file_raw_aes_key: [u8; 32],
    pub(super) file_decoder_rva: u32,
    pub(super) file_decoder_table: Vec<u8>,
}

/// Exact terminal replay with one controller-selected payload plan.
pub(super) struct ExactPostStage5Replay {
    pub(super) block_table: PayloadBlockTable,
    pub(super) payload_list_rva: u32,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: PostStage5Finalizer,
}

/// Rooted state required by the standard terminal sequence after a family has
/// decrypted its byte-map layer.
pub(super) struct StandardPostMapLayerInput<'a> {
    pub(super) primary_rva: u32,
    pub(super) map_layer_rva: u32,
    pub(super) metadata_controller_rva: u32,
    pub(super) header_checksum: u32,
    pub(super) checksum3: u32,
    pub(super) layer_aes: &'a Aes256CbcDecryptor,
    pub(super) layer_decoder_table: &'a [u8],
    pub(super) file_raw_aes_key: [u8; 32],
    pub(super) file_decoder_rva: u32,
    pub(super) file_decoder_table: Vec<u8>,
    pub(super) layer_program: LfsrAlMapCandidate,
}

/// Exact rooted output of the standard terminal sequence.
pub(super) struct StandardPostMapLayerReplay {
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) terminal: PostStage5Finalizer,
    pub(super) metadata: HeaderMetadata,
    pub(super) layer_program: LfsrAlMapCandidate,
    pub(super) final_controller_rva: u32,
    pub(super) payload_list_rva: u32,
}

pub(crate) struct Finalizer {
    pristine_outer_range: Range<usize>,
    pristine_outer_bytes: Vec<u8>,
    anchor_rva: u32,
    primary_rva: u32,
    codec_rva: u32,
    map_layer_rva: u32,
    final_controller_rva: u32,
    payload_list_rva: u32,
    file_decoder_rva: u32,
    layer_decoder_rva: u32,
    file_aes_context_rva: u32,
    layer_aes_context_rva: u32,
    layer_raw_aes_key: [u8; 32],
    layer_program: LfsrAlMapCandidate,
    terminal: PostStage5Finalizer,
    metadata: HeaderMetadata,
}
fn managed_com_descriptor(source: &BoundPayloadSource<'_>) -> Option<crate::pe::DataDirectory> {
    source
        .pe
        .directories
        .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .copied()
        .filter(|directory| !directory.is_empty())
}

pub(super) fn prefill_managed_section(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
) -> Result<()> {
    let Some(com_descriptor) = managed_com_descriptor(source) else {
        return Ok(());
    };
    let descriptor_size = usize::try_from(com_descriptor.size)
        .context("managed COM Descriptor size does not fit usize")?;
    // Section ownership includes virtual tail bytes; only a fully raw-backed
    // descriptor may authorize a packed-section copy.
    shared::packed_rva_range(
        source.pe,
        source.packed.len(),
        com_descriptor.virtual_address,
        com_descriptor.size,
    )?;
    let section = source
        .pe
        .section_for_rva_range(com_descriptor.virtual_address, descriptor_size)
        .context("managed COM Descriptor does not belong to one mapped section")?;
    let source_range = section.raw_range()?;
    let packed_section = source
        .packed
        .get(source_range)
        .context("managed section raw range exceeds the packed input")?;
    ensure!(
        !packed_section.is_empty(),
        "managed section has no file-backed bytes"
    );
    let destination = checked_range(
        image.len(),
        section.virtual_address,
        section.raw_size,
        "managed section destination",
    )?;
    image[destination].copy_from_slice(packed_section);
    Ok(())
}

fn restore_managed_header_state(image: &mut [u8], source: &BoundPayloadSource<'_>) -> Result<()> {
    let Some(com_descriptor) = managed_com_descriptor(source) else {
        return Ok(());
    };
    let source_range = shared::packed_rva_range(
        source.pe,
        source.packed.len(),
        com_descriptor.virtual_address,
        com_descriptor.size,
    )?;
    let destination = checked_range(
        image.len(),
        com_descriptor.virtual_address,
        com_descriptor.size,
        "managed COM Descriptor destination",
    )?;
    image[destination].copy_from_slice(&source.packed[source_range]);

    let directories_start = source.pe.data_directory_table_offset;
    let directories_end = directories_start
        .checked_add(CONTROLLER_DIRECTORIES_LENGTH)
        .context("managed directory table end overflows")?;
    let packed_directories = source
        .packed
        .get(directories_start..directories_end)
        .context("packed managed directory table is truncated")?;
    let mapped_directories = image
        .get_mut(directories_start..directories_end)
        .context("mapped managed directory table is truncated")?;
    mapped_directories.copy_from_slice(packed_directories);
    let packed_entry = read_u32(source.packed, source.pe.entry_rva_offset())
        .context("packed managed entry point is truncated")?;
    write_u32(image, source.pe.entry_rva_offset(), packed_entry)?;
    Ok(())
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn rva_offset(base: u32, relative: u32, label: &str) -> Result<usize> {
    usize::try_from(add_rva(base, relative, label)?)
        .with_context(|| format!("{label} RVA does not fit host address space"))
}

fn exact_descriptor_stage_program(
    image: &[u8],
    stage: StageDescriptor,
    producer_rva: u32,
    program_relative: u32,
    label: &str,
) -> Result<LfsrAlMapCandidate> {
    let program_rva = add_rva(producer_rva, program_relative, label)?;
    let program_offset = usize::try_from(program_rva)
        .with_context(|| format!("{label} RVA does not fit host address space"))?;
    let stage_output = checked_range(
        image.len(),
        stage.destination,
        stage.destination_length,
        "descriptor producer stage output",
    )?;
    ensure!(
        stage_output.contains(&program_offset),
        "{label} lies outside its rooted producer stage output"
    );
    let window = stage_output.end - program_offset;
    let window = u32::try_from(window.min(MAX_AL_PROGRAM_BYTES))
        .expect("bounded LFSR AL program window fits u32");
    shared::exact_lfsr_al_map(image, program_rva, window, label)
}

fn descriptor_at(image: &[u8], base: u32, relative: u32, label: &str) -> Result<StageDescriptor> {
    shared::read_stage_descriptor(image, rva_offset(base, relative, label)?)
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
    let pe_offset = source.pe.opt - 24;
    for (source_relative, pe_relative) in [(5_600, 144), (5_596, 148), (5_632, 152), (5_636, 156)] {
        let value = read_u32(
            image,
            rva_offset(anchor, source_relative, "header checksum source")?,
        )?;
        write_u32(image, pe_offset + pe_relative, value)?;
    }
    write_u32(image, pe_offset + 176, 0)?;
    write_u32(image, pe_offset + 180, 0)?;
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
        "header checksum list",
    )?;
    let mut checksum = 0u32;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let at = usize::try_from(cursor).context("header checksum cursor does not fit usize")?;
        let descriptor = shared::read_stage_descriptor(image, at)?;
        if descriptor.source_length == 0 {
            return Ok(checksum);
        }
        checksum ^= shared::checksum_descriptor(image, at, table)?;
        cursor = cursor
            .checked_add(8)
            .context("header checksum cursor overflows")?;
    }
    bail!("DLL controller header-checksum list exceeds its entry budget")
}

fn process_codec_relocation(
    image: &mut [u8],
    record_rva: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let record = usize::try_from(record_rva).context("codec relocation RVA does not fit usize")?;
    let kind = read_u32(image, record)?;
    if kind & 0x0f == 1 {
        shared::transform_shift3_descriptor(image, record + 4, cancellation)?;
    } else if kind == 2 {
        shared::copy_stage_list(image, read_u32(image, record + 4)?, cancellation)?;
    } else {
        ensure!(
            kind == 0,
            "unsupported DLL codec relocation action {kind:#x}"
        );
    }
    Ok(())
}

fn decrypt_metadata_records(
    image: &mut [u8],
    list_pointer_rva: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<usize> {
    let pointer = usize::try_from(list_pointer_rva)
        .context("controller metadata-list pointer RVA does not fit usize")?;
    let mut cursor = read_u32(image, pointer)?;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let at =
            usize::try_from(cursor).context("controller metadata cursor does not fit usize")?;
        if read_u32(image, at + 4)? == 0 {
            return Ok(index);
        }
        shared::transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("controller metadata cursor overflows")?;
    }
    bail!("DLL controller metadata list exceeds its entry budget")
}

fn parse_payload_and_zero_lists(
    image: &mut [u8],
    list_rva: u32,
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<(Vec<PayloadBlock>, Vec<Range<usize>>)> {
    let mut cursor = list_rva;
    let mut blocks = Vec::new();
    let mut replay_work = 0usize;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        shared::transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = shared::read_stage_descriptor(
            image,
            usize::try_from(cursor).context("payload descriptor RVA does not fit usize")?,
        )?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("payload descriptor cursor overflows")?;
        if record.source_length == 0 {
            ensure!(!blocks.is_empty(), "DLL payload descriptor list is empty");
            break;
        }
        ensure!(
            record.destination_length != 0,
            "DLL payload descriptor has an empty destination"
        );
        let source_offset = source
            .stream
            .base_file_offset
            .checked_add(
                usize::try_from(record.source)
                    .context("DLL payload source displacement does not fit usize")?,
            )
            .context("DLL payload source offset overflows")?;
        let source_length = usize::try_from(record.source_length)
            .context("DLL payload encoded length does not fit usize")?;
        let source_end = source_offset
            .checked_add(source_length)
            .context("DLL payload source end overflows")?;
        ensure!(
            source_end <= source.payload_source.len(),
            "DLL payload source exceeds the bound payload source"
        );
        if let Some(security) = source.source_security_range {
            ensure!(
                source_end <= security.start || source_offset >= security.end,
                "DLL payload source overlaps the PE Security Directory"
            );
        }
        checked_range(
            image.len(),
            record.destination,
            record.destination_length,
            "DLL payload destination",
        )?;
        let destination_length = usize::try_from(record.destination_length)
            .context("DLL payload destination length does not fit usize")?;
        replay_work = replay_work
            .checked_add(source_length)
            .and_then(|value| value.checked_add(destination_length))
            .context("DLL payload replay work overflows")?;
        ensure!(
            replay_work <= MAX_FILE_REPLAY_WORK,
            "DLL payload replay exceeds its byte-work budget"
        );
        blocks.push(PayloadBlock {
            source_offset,
            encoded_length: source_length,
            destination_rva: usize::try_from(record.destination)
                .context("DLL payload destination RVA does not fit usize")?,
            destination_length,
        });
        if index + 1 == MAX_STAGE_LIST_ENTRIES {
            bail!("DLL payload descriptor list exceeds its entry budget");
        }
    }

    let mut zero_bytes = 0usize;
    let mut zero_ranges = Vec::new();
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        shared::transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = shared::read_stage_descriptor(
            image,
            usize::try_from(cursor).context("zero descriptor RVA does not fit usize")?,
        )?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("zero descriptor cursor overflows")?;
        if record.source_length == 0 {
            return Ok((blocks, zero_ranges));
        }
        let range = checked_range(
            image.len(),
            record.source,
            record.source_length,
            "DLL zero-fill destination",
        )?;
        zero_bytes = zero_bytes
            .checked_add(range.len())
            .context("DLL zero-fill byte count overflows")?;
        ensure!(
            zero_bytes <= MAX_ZERO_FILL_BYTES,
            "DLL zero-fill list exceeds its byte-work budget"
        );
        zero_ranges.push(range);
    }
    bail!("DLL zero-fill list exceeds its entry budget")
}

fn controller_metadata(
    image: &mut [u8],
    controller_base: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<HeaderMetadata> {
    shared::transform_shift2_range(
        image,
        add_rva(
            controller_base,
            CONTROLLER_METADATA_RELATIVE,
            "controller metadata",
        )?,
        CONTROLLER_METADATA_LENGTH,
        cancellation,
    )?;
    let directories_start = rva_offset(
        controller_base,
        CONTROLLER_DIRECTORIES_RELATIVE,
        "controller directories",
    )?;
    let directories: [u8; CONTROLLER_DIRECTORIES_LENGTH] = image
        .get(directories_start..directories_start + CONTROLLER_DIRECTORIES_LENGTH)
        .context("DLL controller directories exceed the mapped image")?
        .try_into()
        .expect("controller directory span is fixed");
    Ok(HeaderMetadata {
        entry: 0,
        directories,
    })
}

/// Replays a terminal whose file program is already fixed by its rooted graph.
pub(super) fn replay_exact_post_stage5(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    input: ExactPostStage5Input,
    cancellation: Option<&CancellationToken>,
) -> Result<ExactPostStage5Replay> {
    let metadata_records =
        decrypt_metadata_records(image, input.metadata_list_pointer_slot_rva, cancellation)?;
    replay_exact_post_stage5_with_metadata_records(
        image,
        source,
        input,
        metadata_records,
        cancellation,
    )
}

/// Replays a terminal after a family has transiently validated and restored its
/// metadata/checksum chain.
pub(super) fn replay_exact_post_stage5_after_transient_metadata(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    input: ExactPostStage5Input,
    metadata_records: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<ExactPostStage5Replay> {
    replay_exact_post_stage5_with_metadata_records(
        image,
        source,
        input,
        metadata_records,
        cancellation,
    )
}

fn replay_exact_post_stage5_with_metadata_records(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    input: ExactPostStage5Input,
    metadata_records: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<ExactPostStage5Replay> {
    let ExactPostStage5Input {
        metadata_list_pointer_slot_rva: _,
        payload_list_pointer_slot_rva,
        file_program,
        file_raw_aes_key,
        file_decoder_rva,
        file_decoder_table,
    } = input;
    let payload_list_rva = read_u32(
        image,
        usize::try_from(payload_list_pointer_slot_rva)
            .context("controller payload-list pointer RVA does not fit usize")?,
    )?;
    let (blocks, zero_ranges) =
        parse_payload_and_zero_lists(image, payload_list_rva, source, cancellation)?;
    let block_table = PayloadBlockTable {
        stream_base: 0,
        blocks,
    };
    ensure_terminal_zero_ranges_are_disjoint_from_payload_destinations(&zero_ranges, &block_table)?;
    let candidate = PayloadPlanCandidate::new(PayloadMaterializationPlan {
        block_table: block_table.clone(),
        aes_key: file_raw_aes_key,
        decoder: DecoderCandidate {
            source_file_offset: usize::try_from(file_decoder_rva)
                .context("file decoder RVA does not fit usize")?,
            phase: 0,
            table: file_decoder_table.clone(),
        },
        post_transform: PayloadPostTransform::ByteMap(file_program.map.clone()),
    });
    Ok(ExactPostStage5Replay {
        block_table,
        payload_list_rva,
        candidate,
        finalizer: PostStage5Finalizer {
            file_raw_aes_key,
            file_decoder_table,
            file_program,
            metadata_records,
            zero_ranges,
        },
    })
}

struct RootedStandardFinalControllerInput<'a> {
    primary_rva: u32,
    header_checksum: u32,
    prior_checksum: u32,
    map_key: u32,
    layer_aes: &'a Aes256CbcDecryptor,
    layer_decoder_table: &'a [u8],
    layer_program: &'a LfsrAlMapCandidate,
}

fn decrypt_rooted_standard_final_controller(
    image: &mut [u8],
    input: RootedStandardFinalControllerInput<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<(u32, StageDescriptor)> {
    let RootedStandardFinalControllerInput {
        primary_rva,
        header_checksum,
        prior_checksum,
        map_key,
        layer_aes,
        layer_decoder_table,
        layer_program,
    } = input;
    let table = crc32_table();
    let checksum4 = checksum_at(
        image,
        primary_rva,
        PRIMARY_CHECKSUM4_RELATIVE,
        &table,
        "final controller checksum",
    )?;
    let final_descriptor = rva_offset(
        primary_rva,
        PRIMARY_FINAL_DESCRIPTOR_RELATIVE,
        "final controller descriptor",
    )?;
    let final_controller_rva = read_u32(image, final_descriptor)?;
    let final_stage = shared::read_stage_descriptor(image, final_descriptor)?;
    let final_stage_end = final_stage
        .destination
        .checked_add(final_stage.destination_length)
        .context("final controller output range overflows")?;
    checked_range(
        image.len(),
        final_stage.destination,
        final_stage.destination_length,
        "final controller output",
    )?;
    ensure!(
        final_controller_rva >= final_stage.destination && final_controller_rva < final_stage_end,
        "final controller pointer is outside its rooted output"
    );
    shared::decrypt_stage(
        image,
        final_descriptor,
        map_key ^ header_checksum ^ prior_checksum ^ checksum4,
        layer_aes,
        layer_decoder_table,
        Some(layer_program.map.as_ref()),
        cancellation,
    )
    .context("decrypting rooted standard final controller")?;
    Ok((final_controller_rva, final_stage))
}

/// Replays the exact shared terminal sequence after a family-specific byte-map
/// layer has been materialized from rooted controller state.
pub(super) fn replay_standard_post_map_layer(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    input: StandardPostMapLayerInput<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<StandardPostMapLayerReplay> {
    let layer_program = input.layer_program.clone();
    let map_key = shared::advance_key(
        read_u32(
            image,
            rva_offset(
                input.map_layer_rva,
                MAP_LAYER_KEY_RELATIVE,
                "final controller key",
            )?,
        )?,
        3,
    );
    let (final_controller_rva, final_stage) = decrypt_rooted_standard_final_controller(
        image,
        RootedStandardFinalControllerInput {
            primary_rva: input.primary_rva,
            header_checksum: input.header_checksum,
            prior_checksum: input.checksum3,
            map_key,
            layer_aes: input.layer_aes,
            layer_decoder_table: input.layer_decoder_table,
            layer_program: &layer_program,
        },
        cancellation,
    )?;
    let file_program = exact_descriptor_stage_program(
        image,
        final_stage,
        final_controller_rva,
        DESCRIPTOR_FILE_PROGRAM_RELATIVE,
        "ordinary descriptor file byte-map program",
    )?;
    let metadata_list_pointer_slot_rva = add_rva(
        final_controller_rva,
        FINAL_METADATA_LIST_RELATIVE,
        "controller metadata-list pointer",
    )?;
    let payload_list_pointer_slot_rva = add_rva(
        final_controller_rva,
        FINAL_PAYLOAD_LIST_RELATIVE,
        "payload-list pointer",
    )?;
    let ExactPostStage5Replay {
        block_table,
        payload_list_rva,
        candidate,
        finalizer: terminal,
    } = replay_exact_post_stage5(
        image,
        source,
        ExactPostStage5Input {
            metadata_list_pointer_slot_rva,
            payload_list_pointer_slot_rva,
            file_program,
            file_raw_aes_key: input.file_raw_aes_key,
            file_decoder_rva: input.file_decoder_rva,
            file_decoder_table: input.file_decoder_table,
        },
        cancellation,
    )?;
    let metadata = controller_metadata(image, input.metadata_controller_rva, cancellation)?;
    prefill_managed_section(image, source)?;
    Ok(StandardPostMapLayerReplay {
        block_table,
        candidate,
        terminal,
        metadata,
        layer_program,
        final_controller_rva,
        payload_list_rva,
    })
}

/// Applies authenticated terminal output with standard teardown/header restoration.
pub(super) fn finalize_post_stage5(
    source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: &PostStage5Finalizer,
    metadata: &HeaderMetadata,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let (plan, _selected_chain, mut image) = authenticated.into_parts();
    validate_authenticated_post_stage5_plan(&plan, finalizer)?;
    apply_standard_post_stage5_teardown(source, finalizer, metadata, &mut image)?;
    decrypted_image_from_authenticated_terminal(&block_table, image)
}

fn apply_standard_post_stage5_teardown(
    source: &BoundPayloadSource<'_>,
    finalizer: &PostStage5Finalizer,
    metadata: &HeaderMetadata,
    image: &mut [u8],
) -> Result<()> {
    // The rooted terminal list was checked against every authenticated
    // destination while constructing its payload plan.
    if managed_com_descriptor(source).is_none() {
        for range in &finalizer.zero_ranges {
            image[range.clone()].fill(0);
        }
    }
    shared::restore_common_mapped_header(image, source, metadata.entry, &metadata.directories)?;
    restore_managed_header_state(image, source)
}

/// Converts an authenticated post-stage-5 image without applying terminal
/// teardown or header reconstruction. A rooted terminal profile must establish
/// this ownership before selecting this path.
pub(super) fn finalize_post_stage5_as_authenticated_image(
    block_table: PayloadBlockTable,
    finalizer: &PostStage5Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let (plan, _selected_chain, image) = authenticated.into_parts();
    validate_authenticated_post_stage5_plan(&plan, finalizer)?;
    decrypted_image_from_authenticated_terminal(&block_table, image)
}

fn validate_authenticated_post_stage5_plan(
    plan: &PayloadMaterializationPlan,
    finalizer: &PostStage5Finalizer,
) -> Result<()> {
    ensure!(
        plan.aes_key == finalizer.file_raw_aes_key
            && plan.decoder.table == finalizer.file_decoder_table,
        "authenticated payload plan differs from the controller-selected file codec"
    );
    ensure!(
        plan.post_transform.mapping() == *finalizer.file_program.map,
        "authenticated payload plan differs from the controller-selected file byte map"
    );
    Ok(())
}

/// Restores the post-KONN controller outer around authenticated payload output.
fn restore_pristine_konn_outer_gaps(
    image: &mut [u8],
    outer_range: &Range<usize>,
    pristine_outer: &[u8],
    destination_ranges: &[Range<u32>],
) -> Result<()> {
    ensure!(
        outer_range.start <= outer_range.end && outer_range.end <= image.len(),
        "pristine KONN outer range exceeds authenticated image"
    );
    ensure!(
        pristine_outer.len() == outer_range.len(),
        "pristine KONN outer snapshot length does not match its range"
    );
    let outer_start =
        u32::try_from(outer_range.start).context("pristine KONN outer start exceeds u32")?;
    let outer_end =
        u32::try_from(outer_range.end).context("pristine KONN outer end exceeds u32")?;
    let mut cursor = outer_range.start;
    for destination in destination_ranges
        .iter()
        .skip_while(|destination| destination.end <= outer_start)
    {
        ensure!(
            destination.start <= destination.end,
            "authenticated payload destination range is inverted"
        );
        if destination.start >= outer_end {
            break;
        }
        let preserved_start = usize::try_from(destination.start)
            .context("authenticated payload destination start does not fit usize")?
            .max(outer_range.start);
        let preserved_end = usize::try_from(destination.end)
            .context("authenticated payload destination end does not fit usize")?
            .min(outer_range.end);
        if cursor < preserved_start {
            let snapshot_start = cursor - outer_range.start;
            let snapshot_end = preserved_start - outer_range.start;
            image[cursor..preserved_start]
                .copy_from_slice(&pristine_outer[snapshot_start..snapshot_end]);
        }
        cursor = cursor.max(preserved_end);
    }
    if cursor < outer_range.end {
        let snapshot_start = cursor - outer_range.start;
        image[cursor..outer_range.end].copy_from_slice(&pristine_outer[snapshot_start..]);
    }
    Ok(())
}

fn decrypted_image_from_authenticated_terminal(
    block_table: &PayloadBlockTable,
    image: Vec<u8>,
) -> Result<DecryptedImage> {
    let mut destination_record_ranges = block_table
        .blocks
        .iter()
        .map(payload_block_destination_range)
        .collect::<Result<Vec<Range<u32>>>>()?;
    destination_record_ranges.sort_unstable_by_key(|range| range.start);
    let destination_ranges = merged_payload_block_destination_ranges(&block_table.blocks)?;
    let copied_block_count = block_table
        .blocks
        .iter()
        .filter(|block| block.encoded_length == block.destination_length)
        .count();

    Ok(DecryptedImage {
        destination_record_ranges,
        destination_ranges,
        image,
        decryption_details: DecryptionDetails {
            block_count: block_table.blocks.len(),
            copied_block_count,
            decoded_block_count: block_table.blocks.len() - copied_block_count,
            aes_key_candidates: 1,
            decoder_candidates: 1,
            byte_transform_candidates: 1,
            selected_chain: None,
            ..DecryptionDetails::default()
        },
    })
}

pub(super) fn probe(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<Probe>> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let info = shared::decode_konn_info(source)
        .context("probing PE32+/AMD64 DLL descriptor-payload controller")?;
    let image = shared::materialize_konn_bootstrap(source, &info, cancellation)?;
    let probe = probe_rooted(
        source,
        RootedController {
            anchor_rva: info[6],
            info,
            image,
        },
        cancellation,
    )?;
    Ok(Some(probe))
}

/// Validates the shared terminal graph after a family prefix has materialized
/// its controller image and supplied its logical controller base.
pub(super) fn probe_rooted(
    source: &BoundPayloadSource<'_>,
    rooted: RootedController,
    cancellation: Option<&CancellationToken>,
) -> Result<Probe> {
    let RootedController {
        info,
        mut image,
        anchor_rva,
    } = rooted;
    let pristine_outer_range = checked_range(
        image.len(),
        info[3],
        info[5],
        "pristine KONN controller outer range",
    )?;
    let pristine_outer_bytes = image[pristine_outer_range.clone()].to_vec();
    let table = crc32_table();
    prepare_checksum_header(&mut image, source, anchor_rva)?;
    let header_checksum = bounded_header_checksum_list(&image, anchor_rva, &table, cancellation)?;
    let primary_descriptor = descriptor_at(
        &image,
        anchor_rva,
        PRIMARY_DESCRIPTOR_RELATIVE,
        "primary descriptor",
    )?;
    ensure!(
        primary_descriptor.source_length != 0 && primary_descriptor.source_length.is_multiple_of(4),
        "DLL primary descriptor is empty or unaligned"
    );
    checked_range(
        image.len(),
        primary_descriptor.source,
        primary_descriptor.source_length,
        "DLL primary descriptor source",
    )?;
    let primary_checksum = checksum_at(
        &image,
        anchor_rva,
        PRIMARY_CHECKSUM_RELATIVE,
        &table,
        "primary checksum",
    )?;
    let primary_literal = read_u32(
        &image,
        rva_offset(
            anchor_rva,
            PRIMARY_KEY_LITERAL_RELATIVE,
            "primary key literal",
        )?,
    )?;
    Ok(Probe {
        info,
        base_image: image,
        pristine_outer_range,
        pristine_outer_bytes,
        anchor_rva,
        header_checksum,
        primary_checksum,
        primary_literal,
        primary_key: header_checksum ^ primary_checksum ^ primary_literal,
    })
}

pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<ControllerProposal> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let Probe {
        info,
        base_image: mut image,
        pristine_outer_range,
        pristine_outer_bytes,
        anchor_rva: anchor,
        header_checksum,
        primary_checksum,
        primary_literal,
        primary_key,
    } = probe;
    let table = crc32_table();
    let primary_descriptor = rva_offset(anchor, PRIMARY_DESCRIPTOR_RELATIVE, "primary descriptor")?;
    let primary = read_u32(&image, primary_descriptor)?;
    shared::decrypt_rotating_dword_descriptor(
        &mut image,
        primary_descriptor,
        primary_key,
        21,
        cancellation,
    )
    .context("decrypting DLL primary descriptor")?;

    let import_key = read_u32(
        &image,
        rva_offset(primary, PRIMARY_IMPORT_RELATIVE, "primary import key")?,
    )?;
    let codec_descriptor = rva_offset(
        primary,
        PRIMARY_CODEC_DESCRIPTOR_RELATIVE,
        "codec descriptor",
    )?;
    let codec = read_u32(&image, codec_descriptor)?;
    shared::decrypt_rotating_dword_descriptor(
        &mut image,
        codec_descriptor,
        import_key,
        19,
        cancellation,
    )
    .with_context(|| {
        format!(
            "decrypting DLL codec descriptor (header_checksum={header_checksum:#x}, primary_checksum={primary_checksum:#x}, primary_literal={primary_literal:#x}, primary_key={primary_key:#x}, primary={primary:#x}, descriptor={codec_descriptor:#x}, codec={codec:#x}, source={:#x}, length={:#x})",
            read_u32(&image, codec_descriptor).unwrap_or_default(),
            read_u32(&image, codec_descriptor + 4).unwrap_or_default(),
        )
    })?;
    for relative in [
        CODEC_RELOCATION_RELATIVE,
        CODEC_RELOCATION_RELATIVE + CODEC_RELOCATION_RECORD_SIZE,
    ] {
        process_codec_relocation(
            &mut image,
            add_rva(codec, relative, "codec relocation")?,
            cancellation,
        )?;
    }

    let parameter_base = add_rva(codec, CODEC_PARAMETER_RELATIVE, "codec parameters")?;
    let mut key_rvas = [0u32; 4];
    for (slot, relative) in key_rvas
        .iter_mut()
        .zip(CODEC_PARAMETER_DESCRIPTOR_RELATIVES)
    {
        let descriptor = usize::try_from(add_rva(
            parameter_base,
            relative,
            "codec parameter descriptor",
        )?)
        .context("codec parameter descriptor RVA does not fit usize")?;
        shared::transform_shift3_descriptor(&mut image, descriptor, cancellation)?;
        *slot = read_u32(&image, descriptor)?;
    }
    let layer_decoder_table = shared::snapshot_decoder_table(&image, key_rvas[1])?;
    let file_decoder_table = shared::snapshot_decoder_table(&image, key_rvas[0])?;
    let (layer_raw_aes_key, layer_aes) = shared::recover_aes_context(&image, key_rvas[3])?;
    let (file_raw_aes_key, _) = shared::recover_aes_context(&image, key_rvas[2])?;

    let layer_checksum = checksum_at(
        &image,
        anchor,
        LAYER_CHECKSUM_RELATIVE,
        &table,
        "first layer checksum",
    )?;
    let table_key = shared::advance_key(
        read_u32(
            &image,
            rva_offset(primary, PRIMARY_TABLE_KEY_RELATIVE, "layer table key")?,
        )?,
        4,
    );
    shared::decrypt_stage(
        &mut image,
        rva_offset(
            primary,
            PRIMARY_LAYER1_DESCRIPTOR_RELATIVE,
            "first layer descriptor",
        )?,
        table_key ^ layer_checksum ^ header_checksum,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("decrypting DLL first layer")?;

    let crc_descriptor = descriptor_at(
        &image,
        primary,
        PRIMARY_CRC_DESCRIPTOR_RELATIVE,
        "CRC descriptor",
    )?;
    let crc_range = checked_range(
        image.len(),
        crc_descriptor.source,
        crc_descriptor.source_length,
        "DLL CRC input",
    )?;
    ensure!(
        crc_range.len() >= 4,
        "DLL CRC input is shorter than its trailing key"
    );
    let crc = crackproof_checksum(&image[crc_range.clone()], &table);
    let trailing = read_u32(&image, crc_range.end - 4)?;
    let layer2_descriptor = rva_offset(
        primary,
        PRIMARY_LAYER2_DESCRIPTOR_RELATIVE,
        "second layer descriptor",
    )?;
    let layer2 = read_u32(&image, layer2_descriptor)?;
    shared::decrypt_stage(
        &mut image,
        layer2_descriptor,
        crc ^ header_checksum ^ trailing,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("decrypting DLL second layer")?;

    let checksum3 = checksum_at(
        &image,
        primary,
        PRIMARY_CHECKSUM3_RELATIVE,
        &table,
        "third layer checksum",
    )?;
    let layer3_literal = !read_u32(
        &image,
        rva_offset(layer2, 1_968, "third layer key literal")?,
    )?;
    let layer3_descriptor = rva_offset(
        primary,
        PRIMARY_LAYER3_DESCRIPTOR_RELATIVE,
        "third layer descriptor",
    )?;
    let layer3 = shared::read_stage_descriptor(&image, layer3_descriptor)?;
    shared::decrypt_stage(
        &mut image,
        layer3_descriptor,
        layer3_literal ^ header_checksum ^ checksum3,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("decrypting DLL byte-map layer")?;
    let map_layer = read_u32(&image, layer3_descriptor)?;
    let layer_program = exact_descriptor_stage_program(
        &image,
        layer3,
        map_layer,
        DESCRIPTOR_LAYER_PROGRAM_RELATIVE,
        "ordinary descriptor layer byte-map program",
    )?;
    let StandardPostMapLayerReplay {
        block_table,
        candidate,
        terminal,
        metadata,
        layer_program,
        final_controller_rva: final_controller,
        payload_list_rva,
    } = replay_standard_post_map_layer(
        &mut image,
        source,
        StandardPostMapLayerInput {
            primary_rva: primary,
            map_layer_rva: map_layer,
            metadata_controller_rva: info[3],
            layer_program,
            header_checksum,
            checksum3,
            layer_aes: &layer_aes,
            layer_decoder_table: &layer_decoder_table,
            file_raw_aes_key,
            file_decoder_rva: key_rvas[0],
            file_decoder_table,
        },
        cancellation,
    )
    .context("replaying ordinary descriptor terminal")?;

    Ok(ControllerProposal {
        base_image: image,
        block_table,
        candidate,
        finalizer: ControllerFinalizer::CodecRelocation(Finalizer {
            pristine_outer_range,
            pristine_outer_bytes,
            anchor_rva: anchor,
            primary_rva: primary,
            codec_rva: codec,
            map_layer_rva: map_layer,
            final_controller_rva: final_controller,
            payload_list_rva,
            file_decoder_rva: key_rvas[0],
            layer_decoder_rva: key_rvas[1],
            file_aes_context_rva: key_rvas[2],
            layer_aes_context_rva: key_rvas[3],
            layer_raw_aes_key,
            layer_program,
            metadata,
            terminal,
        }),
    })
}

pub(super) fn finalize(
    source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let mut recovered = if managed_com_descriptor(source).is_some() {
        finalize_post_stage5(
            source,
            block_table,
            &finalizer.terminal,
            &finalizer.metadata,
            authenticated,
        )?
    } else {
        let mut recovered = finalize_post_stage5_as_authenticated_image(
            block_table,
            &finalizer.terminal,
            authenticated,
        )?;
        restore_pristine_konn_outer_gaps(
            &mut recovered.image,
            &finalizer.pristine_outer_range,
            &finalizer.pristine_outer_bytes,
            &recovered.destination_ranges,
        )?;
        recovered
    };
    recovered.decryption_details.selected_controller = Some(SelectedController::CodecRelocation(
        SelectedCodecRelocationController {
            anchor_rva: finalizer.anchor_rva,
            primary_rva: finalizer.primary_rva,
            codec_rva: finalizer.codec_rva,
            map_layer_rva: finalizer.map_layer_rva,
            final_controller_rva: finalizer.final_controller_rva,
            payload_list_rva: finalizer.payload_list_rva,
            file_decoder_rva: finalizer.file_decoder_rva,
            layer_decoder_rva: finalizer.layer_decoder_rva,
            file_aes_context_rva: finalizer.file_aes_context_rva,
            layer_aes_context_rva: finalizer.layer_aes_context_rva,
            file_raw_key_hex: hex::encode(finalizer.terminal.file_raw_aes_key),
            layer_raw_key_hex: hex::encode(finalizer.layer_raw_aes_key),
            layer_program_rva: u32::try_from(finalizer.layer_program.offset)
                .context("PE32+ layer program mapped-image RVA exceeds u32")?,
            layer_program_length: finalizer.layer_program.length,
            layer_byte_map: finalizer.layer_program.map.to_vec(),
            file_program_rva: u32::try_from(finalizer.terminal.file_program.offset)
                .context("PE32+ file program mapped-image RVA exceeds u32")?,
            file_program_length: finalizer.terminal.file_program.length,
            file_byte_map: finalizer.terminal.file_program.map.to_vec(),
            metadata_record_count: finalizer.terminal.metadata_records,
            zero_record_count: finalizer.terminal.zero_ranges.len(),
        },
    ));
    Ok(recovered)
}
