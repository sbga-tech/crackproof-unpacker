use anyhow::{Context, Result, bail, ensure};

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind, SelectedController,
    SelectedRootedNativeController,
};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, MAX_AL_PROGRAM_BYTES, crc32_table,
};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, write_u32};

use super::super::replay::AuthenticatedPayloadPlan;
use super::super::source::BoundPayloadSource;
use super::super::{DecryptedImage, PayloadBlockTable};
use super::codec_relocation::{
    ExactPostStage5Input, ExactPostStage5Replay, PostStage5Finalizer,
    finalize_post_stage5_as_authenticated_image, replay_exact_post_stage5,
};
use super::shared::{
    self, KonnInfo, MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor,
};
use super::{ControllerFinalizer, ControllerProposal};

const ROOT_CONTROL_LENGTH: usize = 0xc8;
const ROOT_PRIMARY_DESCRIPTOR: u32 = 0x78;
const ROOT_PRIMARY_SOURCE_RELATIVE: u32 = 0x6120;
// The generated entry treats `source + 8` as logical code base Q. Rooted
// descriptor offsets below deliberately remain relative to raw `source`.
const ROOT_PRIMARY_LITERAL: u32 = 0x14;
const ROOT_SECONDARY_CHECKSUM: u32 = 0x30;
const ROOT_PRIMARY_CHECKSUM: u32 = 0x38;
const ROOT_HEADER_LIST: u32 = 0xb8;
const ROOT_HEADER_EXTRA_RELATIVE: u32 = 0x28;
const ROOT_HEADER_RESOURCE_RELATIVE: u32 = 0x2c;
const ROOT_PRIMARY_ROTATION: u32 = 21;
const STAGE2_ROTATION: u32 = 19;
const STAGE1_CONTROLLER_LENGTH: u32 = 0x10d0;
const STAGE1_STAGE2_DESCRIPTOR_RELATIVE: u32 = 0xe38;
const STAGE1_CHECKSUM_PAIRS_RELATIVE: u32 = 0xd90;
const STAGE2_CODEC_TABLE_RELATIVE: u32 = 0x23b0;
const STAGE3_LITERAL_GRAMMAR_RELATIVE: u32 = 0xe38;
const STAGE3_LITERAL_RELATIVE: u32 = 0xe3c;
const STAGE3B_LITERAL_RELATIVE: u32 = 0x7a8;
const STAGE3B_VIRTUAL_RELATIVE: u32 = 0x7b0;
const STAGE4_ACCUMULATOR_EPILOGUE_RELATIVE: u32 = 0xc6a;
const STAGE4_ACCUMULATOR_SEED_RELATIVE: u32 = 0xc70;
const STAGE4_MAP_PROGRAM_RELATIVE: u32 = 0xc90;
const STAGE5_FILE_MAP_PROGRAM_RELATIVE: u32 = 0x2fe0;
const AL_PROGRAM_WINDOW_LENGTH: u32 = MAX_AL_PROGRAM_BYTES as u32;
const CODEC_TABLE_HEAD: u32 = 0x20;
const CODEC_KEY_TABLE_FROM_HEAD: u32 = 0x58;
const STAGE2_TO_STAGE3: u32 = 0x58;
const STAGE2_TO_STAGE3B: u32 = 0x68;
const STAGE2_TO_STAGE4: u32 = 0x88;
const STAGE2_TO_STAGE5: u32 = 0xd8;
const STAGE5_PAYLOAD_LIST: u32 = 0x2e30;
const STAGE5_METADATA_LIST: u32 = 0x2f88;
const ROOT_CONTROL_FROM_INFO6: u32 = 0x15b8;

/// Rooted structural state retained between the family probe and replay.
pub(crate) struct Probe {
    info: KonnInfo,
    image: Vec<u8>,
    base_image: Vec<u8>,
    root_rva: u32,
    root_checksum: u32,
    primary_checksum: u32,
    primary_literal: u32,
}
fn not_applicable(cancellation: Option<&CancellationToken>) -> Result<Option<Probe>> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    Ok(None)
}

/// Controller-owned terminal state retained after shared plan authentication.
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
    pub(super) stage5_descriptor_rva: u32,
    pub(super) stage5_rva: u32,
    pub(super) payload_list_rva: u32,
    pub(super) file_decoder_rva: u32,
    pub(super) layer_decoder_rva: u32,
    pub(super) file_aes_context_rva: u32,
    pub(super) layer_aes_context_rva: u32,
    pub(super) layer_raw_aes_key: [u8; 32],
    pub(super) layer_program: LfsrAlMapCandidate,
    pub(super) terminal: PostStage5Finalizer,
}

fn add_rva(base: u32, relative: u32, label: &str) -> Result<u32> {
    base.checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

fn rva_offset(rva: u32, label: &str) -> Result<usize> {
    usize::try_from(rva).with_context(|| format!("{label} RVA does not fit host address space"))
}
fn clean_mapped_outer_image(source: &BoundPayloadSource<'_>, info: &KonnInfo) -> Result<Vec<u8>> {
    let mut image = source
        .pe
        .map_image(source.packed)
        .context("mapping packed codec-control-metadata image for authenticated payload replay")?;
    let outer_length = u32::try_from(source.outer.len())
        .context("PE64 DLL stage5 bound outer source length exceeds u32")?;
    ensure!(
        outer_length == info[5],
        "PE64 DLL stage5 bound outer source length disagrees with the rooted KONN descriptor"
    );
    let outer_range = checked_range(
        image.len(),
        info[3],
        info[5],
        "PE64 DLL stage5 bound outer destination",
    )?;
    image[outer_range].copy_from_slice(&source.outer);
    Ok(image)
}

fn descriptor_at(image: &[u8], rva: u32, label: &str) -> Result<StageDescriptor> {
    shared::read_stage_descriptor(image, rva_offset(rva, label)?)
        .with_context(|| format!("{label} descriptor exceeds the controller image"))
}

fn checksum_at(image: &[u8], rva: u32, table: &[u32; 256], label: &str) -> Result<u32> {
    shared::checksum_descriptor(image, rva_offset(rva, label)?, table)
        .with_context(|| format!("{label} checksum descriptor is invalid"))
}

fn checked_source_dword_stage(image: &[u8], rva: u32, label: &str) -> Result<StageDescriptor> {
    let stage = descriptor_at(image, rva, label)?;
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

fn checked_controller_stage(image: &[u8], rva: u32, label: &str) -> Result<StageDescriptor> {
    let stage = descriptor_at(image, rva, label)?;
    ensure!(
        stage.source_length != 0 && stage.destination_length != 0,
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

fn checked_in_place_stage(image: &[u8], rva: u32, label: &str) -> Result<StageDescriptor> {
    let stage = checked_controller_stage(image, rva, label)?;
    ensure!(
        stage.source == stage.destination,
        "{label} is not an in-place controller stage"
    );
    Ok(stage)
}

fn root_matches(image: &[u8], info: &KonnInfo, root_rva: u32) -> Result<bool> {
    let root = rva_offset(root_rva, "PE64 DLL stage5 rooted control")?;
    let end = root
        .checked_add(ROOT_CONTROL_LENGTH)
        .context("PE64 DLL stage5 rooted control range overflows")?;
    let Some(control) = image.get(root..end) else {
        return Ok(false);
    };
    let import_size = read_u32(control, 4)?;
    let import_rva = read_u32(control, 8)?;
    let Some(import_end) = import_rva.checked_add(import_size) else {
        return Ok(false);
    };
    let import_range = match checked_range(
        image.len(),
        import_rva,
        import_size,
        "PE64 DLL stage5 import directory",
    ) {
        Ok(range) => range,
        Err(_) => return Ok(false),
    };
    let import_directory = &image[import_range];
    let import_directory_is_structural = import_size >= 40
        && import_size.is_multiple_of(20)
        && import_end <= info[6]
        && import_directory[..20].iter().any(|&byte| byte != 0)
        && import_directory[import_directory.len() - 20..]
            .iter()
            .all(|&byte| byte == 0);
    let primary_rva = match add_rva(
        root_rva,
        ROOT_PRIMARY_DESCRIPTOR,
        "PE64 DLL stage5 primary descriptor",
    ) {
        Ok(rva) => rva,
        Err(_) => return Ok(false),
    };
    let primary =
        match checked_source_dword_stage(image, primary_rva, "PE64 DLL stage5 primary stage") {
            Ok(stage) => stage,
            Err(_) => return Ok(false),
        };
    let expected_primary_source = match add_rva(
        root_rva,
        ROOT_PRIMARY_SOURCE_RELATIVE,
        "PE64 DLL stage5 primary source",
    ) {
        Ok(rva) => rva,
        Err(_) => return Ok(false),
    };
    Ok(read_u32(control, 0)? == info[3]
        && import_directory_is_structural
        && primary.source == expected_primary_source
        && primary.source_length == STAGE1_CONTROLLER_LENGTH)
}

fn prepare_header(image: &mut [u8], source: &BoundPayloadSource<'_>, root_rva: u32) -> Result<()> {
    let pe_header = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE header offset underflows")?;
    for (relative, pe_relative) in [
        (8u32, 0x90usize),
        (4, 0x94),
        (ROOT_HEADER_EXTRA_RELATIVE, 0x98),
        (ROOT_HEADER_RESOURCE_RELATIVE, 0x9c),
    ] {
        let value = read_u32(
            image,
            rva_offset(
                add_rva(root_rva, relative, "PE64 DLL stage5 root header field")?,
                "PE64 DLL stage5 root header field",
            )?,
        )?;
        write_u32(
            image,
            pe_header
                .checked_add(pe_relative)
                .context("PE directory header offset overflows")?,
            value,
        )?;
    }
    write_u32(
        image,
        pe_header
            .checked_add(0xb0)
            .context("PE security-directory offset overflows")?,
        0,
    )?;
    write_u32(
        image,
        pe_header
            .checked_add(0xb4)
            .context("PE security-directory size offset overflows")?,
        0,
    )?;
    Ok(())
}

fn root_checksum(
    image: &[u8],
    root_rva: u32,
    table: &[u32; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<u32> {
    let mut cursor = add_rva(
        root_rva,
        ROOT_HEADER_LIST,
        "PE64 DLL stage5 root checksum list",
    )?;
    let mut checksum = 0u32;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let record = descriptor_at(image, cursor, "PE64 DLL stage5 root checksum record")?;
        if record.source_length == 0 {
            ensure!(index != 0, "PE64 DLL stage5 root checksum list is empty");
            return Ok(checksum);
        }
        checksum ^= checksum_at(image, cursor, table, "PE64 DLL stage5 root checksum")?;
        cursor = cursor
            .checked_add(8)
            .context("PE64 DLL stage5 root checksum cursor overflows")?;
    }
    bail!("PE64 DLL stage5 root checksum list exceeds its entry budget")
}

fn raw_controller_end(info: &KonnInfo) -> Result<u32> {
    info[3]
        .checked_add(info[5])
        .context("PE64 DLL stage5 KONN controller range overflows")
}

fn stage_slot(
    image: &[u8],
    stage_base: u32,
    stage_length: u32,
    relative: u32,
    slot_length: u32,
    label: &str,
) -> Result<u32> {
    let stage_range = checked_range(image.len(), stage_base, stage_length, label)?;
    let slot_rva = add_rva(stage_base, relative, label)?;
    let slot_range = checked_range(image.len(), slot_rva, slot_length, label)?;
    ensure!(
        slot_range.start >= stage_range.start && slot_range.end <= stage_range.end,
        "{label} lies outside its rooted controller stage"
    );
    Ok(slot_rva)
}

fn stage_source_slot(
    image: &[u8],
    stage: &StageDescriptor,
    relative: u32,
    slot_length: u32,
    label: &str,
) -> Result<u32> {
    stage_slot(
        image,
        stage.source,
        stage.source_length,
        relative,
        slot_length,
        label,
    )
}

fn stage_output_slot(
    image: &[u8],
    stage: &StageDescriptor,
    relative: u32,
    slot_length: u32,
    label: &str,
) -> Result<u32> {
    stage_slot(
        image,
        stage.destination,
        stage.destination_length,
        relative,
        slot_length,
        label,
    )
}

fn checked_stage2(image: &[u8], descriptor_rva: u32, info: &KonnInfo) -> Result<StageDescriptor> {
    let stage = checked_in_place_stage(image, descriptor_rva, "PE64 DLL stage5 stage2")?;
    let raw_end = raw_controller_end(info)?;
    let source_end = stage
        .source
        .checked_add(stage.source_length)
        .context("PE64 DLL stage5 rooted stage2 source range overflows")?;
    ensure!(
        stage.source >= info[3]
            && source_end <= raw_end
            && stage.source_length > 0x1_0000
            && stage.destination_length < stage.source_length
            && stage.source_length.is_multiple_of(4),
        "PE64 DLL stage5 rooted stage2 descriptor has invalid controller bounds"
    );
    Ok(stage)
}

fn fixed_checksum_pairs(image: &[u8], info: &KonnInfo, stage1: &StageDescriptor) -> Result<u32> {
    let pairs_rva = stage_source_slot(
        image,
        stage1,
        STAGE1_CHECKSUM_PAIRS_RELATIVE,
        32,
        "PE64 DLL stage5 rooted checksum-pair table",
    )?;
    let raw_end = raw_controller_end(info)?;
    for index in 0..4u32 {
        let record_rva = add_rva(
            pairs_rva,
            index * 8,
            "PE64 DLL stage5 rooted checksum-pair record",
        )?;
        let source = read_u32(
            image,
            rva_offset(record_rva, "PE64 DLL stage5 rooted checksum-pair source")?,
        )?;
        let length_rva = add_rva(record_rva, 4, "PE64 DLL stage5 rooted checksum-pair length")?;
        let length = read_u32(
            image,
            rva_offset(length_rva, "PE64 DLL stage5 rooted checksum-pair length")?,
        )?;
        let source_end = source
            .checked_add(length)
            .context("PE64 DLL stage5 rooted checksum-pair source range overflows")?;
        ensure!(
            source >= info[3] && source_end <= raw_end && length != 0 && length < 0x1_0000,
            "PE64 DLL stage5 rooted checksum-pair record has invalid controller bounds"
        );
        checked_range(
            image.len(),
            source,
            length,
            "PE64 DLL stage5 rooted checksum-pair source",
        )?;
    }
    Ok(pairs_rva)
}

fn fixed_codec_table(image: &[u8], stage2: &StageDescriptor, info: &KonnInfo) -> Result<u32> {
    let table_rva = stage_source_slot(
        image,
        stage2,
        STAGE2_CODEC_TABLE_RELATIVE,
        16,
        "PE64 DLL stage5 rooted codec action table",
    )?;
    let table = checked_range(
        image.len(),
        table_rva,
        16,
        "PE64 DLL stage5 rooted codec action table",
    )?;
    let table = &image[table];
    ensure!(
        read_u32(table, 0)? == 1
            && read_u32(table, 4)? == 0
            && read_u32(table, 8)? == info[3]
            && read_u32(table, 12)? == 0,
        "PE64 DLL stage5 rooted codec action-table grammar is invalid"
    );
    Ok(table_rva)
}

fn replay_codec_controls(
    image: &mut [u8],
    codec_table_rva: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<[u32; 4]> {
    let head_rva = add_rva(
        codec_table_rva,
        CODEC_TABLE_HEAD,
        "PE64 DLL stage5 codec action head",
    )?;
    checked_range(
        image.len(),
        head_rva,
        (STAGE_DESCRIPTOR_SIZE * 2) as u32,
        "PE64 DLL stage5 codec actions",
    )?;
    for record_rva in [
        head_rva,
        add_rva(
            head_rva,
            STAGE_DESCRIPTOR_SIZE as u32,
            "PE64 DLL stage5 codec action",
        )?,
    ] {
        let record = rva_offset(record_rva, "PE64 DLL stage5 codec action")?;
        let kind = read_u32(image, record)?;
        if kind & 0x0f == 1 {
            shared::transform_shift3_descriptor(image, record + 4, cancellation)?;
        } else if kind == 2 {
            shared::copy_stage_list(image, read_u32(image, record + 4)?, cancellation)?;
        } else {
            bail!("PE64 DLL stage5 codec action is unsupported: {kind:#x}")
        }
    }

    let key_base = head_rva
        .checked_sub(CODEC_KEY_TABLE_FROM_HEAD)
        .context("PE64 DLL stage5 codec key-table base underflows")?;
    let mut key_rvas = [0u32; 4];
    for (slot, relative) in key_rvas.iter_mut().zip([0u32, 8, 32, 40]) {
        let descriptor_rva = add_rva(key_base, relative, "PE64 DLL stage5 codec key descriptor")?;
        let descriptor = rva_offset(descriptor_rva, "PE64 DLL stage5 codec key descriptor")?;
        shared::transform_shift3_descriptor(image, descriptor, cancellation)?;
        *slot = read_u32(image, descriptor)?;
    }
    Ok(key_rvas)
}

fn stage3_terminal_literal(image: &[u8], stage: &StageDescriptor) -> Result<u32> {
    let grammar_rva = stage_output_slot(
        image,
        stage,
        STAGE3_LITERAL_GRAMMAR_RELATIVE,
        4,
        "PE64 DLL stage5 stage3 RET/INT3 grammar",
    )?;
    let grammar = rva_offset(grammar_rva, "PE64 DLL stage5 stage3 RET/INT3 grammar")?;
    ensure!(
        image[grammar..grammar + 4] == [0xc3, 0xcc, 0xcc, 0xcc],
        "PE64 DLL stage5 stage3 terminal literal lacks its RET/INT3 grammar"
    );
    let literal_rva = stage_output_slot(
        image,
        stage,
        STAGE3_LITERAL_RELATIVE,
        4,
        "PE64 DLL stage5 stage3 terminal literal",
    )?;
    read_u32(
        image,
        rva_offset(literal_rva, "PE64 DLL stage5 stage3 terminal literal")?,
    )
}

fn stage3b_virtual_literal(image: &[u8], stage: &StageDescriptor) -> Result<u32> {
    let literal_rva = stage_output_slot(
        image,
        stage,
        STAGE3B_LITERAL_RELATIVE,
        4,
        "PE64 DLL stage5 stage3b Virtual hash slot",
    )?;
    let virtual_rva = stage_output_slot(
        image,
        stage,
        STAGE3B_VIRTUAL_RELATIVE,
        b"Virtual".len() as u32,
        "PE64 DLL stage5 stage3b Virtual API grammar",
    )?;
    ensure!(
        virtual_rva
            == add_rva(
                literal_rva,
                8,
                "PE64 DLL stage5 stage3b Virtual hash relation"
            )?,
        "PE64 DLL stage5 stage3b Virtual hash slot has an invalid relation"
    );
    let virtual_offset = rva_offset(virtual_rva, "PE64 DLL stage5 stage3b Virtual API grammar")?;
    ensure!(
        image[virtual_offset..virtual_offset + b"Virtual".len()] == *b"Virtual",
        "PE64 DLL stage5 stage3b Virtual API grammar is invalid"
    );
    Ok(!read_u32(
        image,
        rva_offset(literal_rva, "PE64 DLL stage5 stage3b Virtual hash slot")?,
    )?)
}

fn stage_output_map(
    image: &[u8],
    stage: &StageDescriptor,
    relative: u32,
    label: &str,
) -> Result<LfsrAlMapCandidate> {
    let program_rva = stage_output_slot(image, stage, relative, AL_PROGRAM_WINDOW_LENGTH, label)?;
    shared::exact_lfsr_al_map(image, program_rva, AL_PROGRAM_WINDOW_LENGTH, label)
}

fn stage4_map_program(image: &[u8], stage: &StageDescriptor) -> Result<LfsrAlMapCandidate> {
    let epilogue_rva = stage_output_slot(
        image,
        stage,
        STAGE4_ACCUMULATOR_EPILOGUE_RELATIVE,
        6,
        "PE64 DLL stage5 stage4 accumulator grammar",
    )?;
    let epilogue = rva_offset(epilogue_rva, "PE64 DLL stage5 stage4 accumulator grammar")?;
    ensure!(
        image[epilogue..epilogue + 6] == [0x48, 0xeb, 0x01, 0xb9, 0xcc, 0xcc],
        "PE64 DLL stage5 stage4 accumulator grammar is invalid"
    );
    stage_output_map(
        image,
        stage,
        STAGE4_MAP_PROGRAM_RELATIVE,
        "PE64 DLL stage5 stage4 byte-map program",
    )
}

fn stage5_file_map(image: &[u8], stage: &StageDescriptor) -> Result<LfsrAlMapCandidate> {
    stage_output_map(
        image,
        stage,
        STAGE5_FILE_MAP_PROGRAM_RELATIVE,
        "PE64 DLL stage5 terminal file byte-map program",
    )
}

fn stage4_accumulator_seed(image: &[u8], stage: &StageDescriptor) -> Result<u32> {
    let seed_rva = stage_output_slot(
        image,
        stage,
        STAGE4_ACCUMULATOR_SEED_RELATIVE,
        4,
        "PE64 DLL stage5 stage4 accumulator seed",
    )?;
    read_u32(
        image,
        rva_offset(seed_rva, "PE64 DLL stage5 stage4 accumulator seed")?,
    )
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
        Err(_) => return not_applicable(cancellation),
    };
    let mut image = match shared::materialize_konn_bootstrap(source, &info, cancellation) {
        Ok(image) => image,
        Err(_) => return not_applicable(cancellation),
    };
    let root_rva = match add_rva(
        info[6],
        ROOT_CONTROL_FROM_INFO6,
        "PE64 DLL stage5 rooted control",
    ) {
        Ok(root) => root,
        Err(_) => return not_applicable(cancellation),
    };
    let matches_root = match root_matches(&image, &info, root_rva) {
        Ok(matches) => matches,
        Err(_) => return not_applicable(cancellation),
    };
    if !matches_root {
        return not_applicable(cancellation);
    }
    let base_image = match clean_mapped_outer_image(source, &info) {
        Ok(image) => image,
        Err(_) => return not_applicable(cancellation),
    };
    if prepare_header(&mut image, source, root_rva).is_err() {
        return not_applicable(cancellation);
    }
    let table = crc32_table();
    let root_checksum = match root_checksum(&image, root_rva, &table, cancellation) {
        Ok(checksum) => checksum,
        Err(_) => return not_applicable(cancellation),
    };
    let primary_checksum_rva = match add_rva(
        root_rva,
        ROOT_PRIMARY_CHECKSUM,
        "PE64 DLL stage5 root primary checksum",
    ) {
        Ok(rva) => rva,
        Err(_) => return not_applicable(cancellation),
    };
    let primary_checksum = match checksum_at(
        &image,
        primary_checksum_rva,
        &table,
        "PE64 DLL stage5 root primary checksum",
    ) {
        Ok(checksum) => checksum,
        Err(_) => return not_applicable(cancellation),
    };
    let primary_literal_rva = match add_rva(
        root_rva,
        ROOT_PRIMARY_LITERAL,
        "PE64 DLL stage5 root primary literal",
    ) {
        Ok(rva) => rva,
        Err(_) => return not_applicable(cancellation),
    };
    let primary_literal =
        match rva_offset(primary_literal_rva, "PE64 DLL stage5 root primary literal")
            .and_then(|offset| read_u32(&image, offset))
        {
            Ok(literal) => literal,
            Err(_) => return not_applicable(cancellation),
        };
    let primary_descriptor = match add_rva(
        root_rva,
        ROOT_PRIMARY_DESCRIPTOR,
        "PE64 DLL stage5 primary descriptor",
    ) {
        Ok(descriptor) => descriptor,
        Err(_) => return not_applicable(cancellation),
    };
    let primary_stage = match checked_source_dword_stage(
        &image,
        primary_descriptor,
        "PE64 DLL stage5 primary stage",
    ) {
        Ok(stage) => stage,
        Err(_) => return not_applicable(cancellation),
    };
    if primary_stage.source_length != STAGE1_CONTROLLER_LENGTH {
        return not_applicable(cancellation);
    }
    Ok(Some(Probe {
        info,
        image,
        base_image,
        root_rva,
        root_checksum,
        primary_checksum,
        primary_literal,
    }))
}

pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: Probe,
    cancellation: Option<&CancellationToken>,
) -> Result<ControllerProposal> {
    let Probe {
        info,
        mut image,
        base_image,
        root_rva,
        root_checksum,
        primary_checksum,
        primary_literal,
    } = probe;
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let table = crc32_table();
    let primary_descriptor_rva = add_rva(
        root_rva,
        ROOT_PRIMARY_DESCRIPTOR,
        "PE64 DLL stage5 primary descriptor",
    )?;
    let stage1 = checked_source_dword_stage(
        &image,
        primary_descriptor_rva,
        "PE64 DLL stage5 primary stage",
    )?;
    ensure!(
        stage1.source_length == STAGE1_CONTROLLER_LENGTH,
        "PE64 DLL stage5 primary stage has an unexpected rooted controller length"
    );
    shared::decrypt_rotating_dword_descriptor(
        &mut image,
        rva_offset(primary_descriptor_rva, "PE64 DLL stage5 primary descriptor")?,
        root_checksum ^ primary_checksum ^ primary_literal,
        ROOT_PRIMARY_ROTATION,
        cancellation,
    )
    .context("replaying codec-control-metadata rooted primary dword stage")?;

    let stage2_descriptor_rva = stage_source_slot(
        &image,
        &stage1,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE,
        STAGE_DESCRIPTOR_SIZE as u32,
        "PE64 DLL stage5 rooted stage2 descriptor",
    )?;
    let stage2 = checked_stage2(&image, stage2_descriptor_rva, &info)?;
    let checksum_pairs_rva = fixed_checksum_pairs(&image, &info, &stage1)?;
    let stage2_key_relative = STAGE1_CHECKSUM_PAIRS_RELATIVE
        .checked_sub(0x14)
        .context("PE64 DLL stage5 stage2 key precedes its checksum table")?;
    let stage2_key_rva = stage_source_slot(
        &image,
        &stage1,
        stage2_key_relative,
        4,
        "PE64 DLL stage5 stage2 key",
    )?;
    let stage2_key = read_u32(
        &image,
        rva_offset(stage2_key_rva, "PE64 DLL stage5 stage2 key")?,
    )?;
    shared::decrypt_rotating_dword_descriptor(
        &mut image,
        rva_offset(stage2_descriptor_rva, "PE64 DLL stage5 stage2 descriptor")?,
        stage2_key,
        STAGE2_ROTATION,
        cancellation,
    )
    .context("replaying codec-control-metadata rooted stage2 dword stage")?;

    let codec_table_rva = fixed_codec_table(&image, &stage2, &info)?;
    let key_rvas = replay_codec_controls(&mut image, codec_table_rva, cancellation)?;
    let file_decoder_table = shared::snapshot_decoder_table(&image, key_rvas[0])?;
    let layer_decoder_table = shared::snapshot_decoder_table(&image, key_rvas[1])?;
    let (file_raw_aes_key, _) = shared::recover_aes_context(&image, key_rvas[2])?;
    let (layer_raw_aes_key, layer_aes) = shared::recover_aes_context(&image, key_rvas[3])?;

    let stage3_descriptor_rva = stage_source_slot(
        &image,
        &stage1,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE
            .checked_add(STAGE2_TO_STAGE3)
            .context("PE64 DLL stage5 stage3 descriptor offset overflows")?,
        STAGE_DESCRIPTOR_SIZE as u32,
        "PE64 DLL stage5 stage3 descriptor",
    )?;
    let stage3 = checked_controller_stage(&image, stage3_descriptor_rva, "PE64 DLL stage5 stage3")?;
    let stage3_checksum = checksum_at(
        &image,
        add_rva(
            root_rva,
            ROOT_SECONDARY_CHECKSUM,
            "PE64 DLL stage5 stage3 checksum",
        )?,
        &table,
        "PE64 DLL stage5 stage3 checksum",
    )?;
    let stage3_accumulator_relative = STAGE1_CHECKSUM_PAIRS_RELATIVE
        .checked_sub(0x10)
        .context("PE64 DLL stage5 stage3 accumulator precedes its checksum table")?;
    let stage3_accumulator_rva = stage_source_slot(
        &image,
        &stage1,
        stage3_accumulator_relative,
        4,
        "PE64 DLL stage5 stage3 accumulator",
    )?;
    let stage3_accumulator = shared::advance_key(
        read_u32(
            &image,
            rva_offset(stage3_accumulator_rva, "PE64 DLL stage5 stage3 accumulator")?,
        )?,
        4,
    );
    shared::decrypt_stage(
        &mut image,
        rva_offset(stage3_descriptor_rva, "PE64 DLL stage5 stage3 descriptor")?,
        root_checksum ^ stage3_checksum ^ stage3_accumulator,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("replaying codec-control-metadata stage3")?;
    let stage3_literal = stage3_terminal_literal(&image, &stage3)?;

    let stage3b_descriptor_rva = stage_source_slot(
        &image,
        &stage1,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE
            .checked_add(STAGE2_TO_STAGE3B)
            .context("PE64 DLL stage5 stage3b descriptor offset overflows")?,
        STAGE_DESCRIPTOR_SIZE as u32,
        "PE64 DLL stage5 stage3b descriptor",
    )?;
    let stage3b =
        checked_controller_stage(&image, stage3b_descriptor_rva, "PE64 DLL stage5 stage3b")?;
    let stage3b_checksum = checksum_at(
        &image,
        add_rva(checksum_pairs_rva, 0x18, "PE64 DLL stage5 stage3b checksum")?,
        &table,
        "PE64 DLL stage5 stage3b checksum",
    )?;
    shared::decrypt_stage(
        &mut image,
        rva_offset(stage3b_descriptor_rva, "PE64 DLL stage5 stage3b descriptor")?,
        root_checksum ^ stage3b_checksum ^ stage3_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("replaying codec-control-metadata stage3b")?;
    let stage3b_literal = stage3b_virtual_literal(&image, &stage3b)?;

    let stage4_descriptor_rva = stage_source_slot(
        &image,
        &stage1,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE
            .checked_add(STAGE2_TO_STAGE4)
            .context("PE64 DLL stage5 stage4 descriptor offset overflows")?,
        STAGE_DESCRIPTOR_SIZE as u32,
        "PE64 DLL stage5 stage4 descriptor",
    )?;
    let stage4 = checked_controller_stage(&image, stage4_descriptor_rva, "PE64 DLL stage5 stage4")?;
    let stage4_checksum = checksum_at(
        &image,
        add_rva(checksum_pairs_rva, 0x10, "PE64 DLL stage5 stage4 checksum")?,
        &table,
        "PE64 DLL stage5 stage4 checksum",
    )?;
    shared::decrypt_stage(
        &mut image,
        rva_offset(stage4_descriptor_rva, "PE64 DLL stage5 stage4 descriptor")?,
        root_checksum ^ stage4_checksum ^ stage3b_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("replaying codec-control-metadata byte-map stage")?;
    let stage5_accumulator = shared::advance_key(stage4_accumulator_seed(&image, &stage4)?, 3);

    let stage5_descriptor_rva = stage_source_slot(
        &image,
        &stage1,
        STAGE1_STAGE2_DESCRIPTOR_RELATIVE
            .checked_add(STAGE2_TO_STAGE5)
            .context("PE64 DLL stage5 stage5 descriptor offset overflows")?,
        STAGE_DESCRIPTOR_SIZE as u32,
        "PE64 DLL stage5 stage5 descriptor",
    )?;
    let stage5 = checked_in_place_stage(&image, stage5_descriptor_rva, "PE64 DLL stage5 stage5")?;
    let layer_program = stage4_map_program(&image, &stage4)?;
    let stage5_checksum = checksum_at(
        &image,
        add_rva(checksum_pairs_rva, 8, "PE64 DLL stage5 stage5 checksum")?,
        &table,
        "PE64 DLL stage5 stage5 checksum",
    )?;
    shared::decrypt_stage(
        &mut image,
        rva_offset(stage5_descriptor_rva, "PE64 DLL stage5 stage5 descriptor")?,
        root_checksum ^ stage4_checksum ^ stage5_checksum ^ stage5_accumulator,
        &layer_aes,
        &layer_decoder_table,
        Some(layer_program.map.as_ref()),
        cancellation,
    )
    .context("replaying codec-control-metadata terminal stage")?;
    let file_program = stage5_file_map(&image, &stage5)?;
    let ExactPostStage5Replay {
        block_table,
        payload_list_rva,
        candidate,
        finalizer: terminal,
    } = replay_exact_post_stage5(
        &mut image,
        source,
        ExactPostStage5Input {
            metadata_list_pointer_slot_rva: add_rva(
                stage5.destination,
                STAGE5_METADATA_LIST,
                "PE64 DLL stage5 metadata-list pointer slot",
            )?,
            payload_list_pointer_slot_rva: add_rva(
                stage5.destination,
                STAGE5_PAYLOAD_LIST,
                "PE64 DLL stage5 payload-list pointer slot",
            )?,
            file_program,
            file_raw_aes_key,
            file_decoder_rva: key_rvas[0],
            file_decoder_table,
        },
        cancellation,
    )?;

    Ok(ControllerProposal {
        base_image,
        block_table,
        candidate,
        finalizer: ControllerFinalizer::CodecControlMetadata(Finalizer {
            root_rva,
            primary_descriptor_rva,
            stage1_rva: stage1.source,
            stage2_descriptor_rva,
            stage2_rva: stage2.source,
            codec_table_rva,
            stage3_descriptor_rva,
            stage3_rva: stage3.destination,
            stage3b_descriptor_rva,
            stage3b_rva: stage3b.destination,
            stage4_descriptor_rva,
            map_layer_rva: stage4.destination,
            stage5_descriptor_rva,
            stage5_rva: stage5.destination,
            payload_list_rva,
            file_decoder_rva: key_rvas[0],
            layer_decoder_rva: key_rvas[1],
            file_aes_context_rva: key_rvas[2],
            layer_aes_context_rva: key_rvas[3],
            layer_raw_aes_key,
            layer_program,
            terminal,
        }),
    })
}

pub(super) fn finalize(
    _source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let mut image = finalize_post_stage5_as_authenticated_image(
        block_table,
        &finalizer.terminal,
        authenticated,
    )?;
    image.decryption_details.selected_controller = Some(SelectedController::CodecControlMetadata(
        SelectedRootedNativeController {
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
                    kind: RootedNativeControllerNodeKind::Stage5Descriptor,
                    rva: finalizer.stage5_descriptor_rva,
                },
                RootedNativeControllerGraphNode {
                    kind: RootedNativeControllerNodeKind::Terminal,
                    rva: finalizer.stage5_rva,
                },
            ],
            payload_list_rva: finalizer.payload_list_rva,
            file_decoder_rva: finalizer.file_decoder_rva,
            layer_decoder_rva: Some(finalizer.layer_decoder_rva),
            file_aes_context_rva: finalizer.file_aes_context_rva,
            layer_aes_context_rva: Some(finalizer.layer_aes_context_rva),
            file_raw_key_hex: hex::encode(finalizer.terminal.file_raw_aes_key),
            layer_raw_key_hex: Some(hex::encode(finalizer.layer_raw_aes_key)),
            layer_program_rva: Some(u32::try_from(finalizer.layer_program.offset).context(
                "native codec-control-metadata layer program mapped-image RVA exceeds u32",
            )?),
            layer_program_length: Some(finalizer.layer_program.length),
            layer_byte_map: Some(finalizer.layer_program.map.to_vec()),
            file_program_rva: u32::try_from(finalizer.terminal.file_program.offset).context(
                "native codec-control-metadata file program mapped-image RVA exceeds u32",
            )?,
            file_program_length: finalizer.terminal.file_program.length,
            file_byte_map: finalizer.terminal.file_program.map.to_vec(),
            terminal_profile: None,
        },
    ));
    Ok(image)
}
