use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use tracing::info;

use crate::pe::Pe;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{
    DecryptionDetails, SelectedController, SelectedShellDirectoryManifestController,
};
use crate::pipeline::stages::payload::nested::{LfsrAlMapCandidate, crc32_table};
use crate::util::bytes::{checked_u32_range as checked_range, read_u32, read_u32_opt, write_u32};

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
    MAX_STAGE_LIST_ENTRIES, STAGE_DESCRIPTOR_SIZE, StageDescriptor, advance_key,
    checksum_descriptor, copy_stage_list, decode_konn_info as decode_info,
    decrypt_rotating_dword_descriptor as decrypt_dword_descriptor, decrypt_stage,
    exact_lfsr_al_map, extract_metadata, materialize_konn_bootstrap as materialize_bootstrap,
    packed_rva_range, read_stage_descriptor as descriptor, recover_aes_context as recover_aes,
    restore_common_mapped_header, snapshot_decoder_table, transform_shift2_range,
    transform_shift3_descriptor,
};
use super::{ControllerProposal, shell_directory_manifest_proposal};

const CONTROLLER_DIRECTORY_BASE_LENGTH: u32 = 0xbc0;
const CODEC_DESCRIPTOR_RELATIVE: u32 = 0xb8c;
const CODEC_KEY_RELATIVE: u32 = 0x968;
const MAPPED_KEY_RELATIVE: u32 = 0x964;
const CHECKSUM_BASE_RELATIVE: u32 = 0x96c;
const DESCRIPTOR_BASE_RELATIVE: u32 = 0xa9c;
const CODEC_ASSET_TABLE_BACK: usize = 0x58;
const PAYLOAD_MANIFEST_DESCRIPTOR_RELATIVE: usize = 0xc0;
const TERMINAL_CONFIG_MAGIC: u32 = 0x7679;
const MAX_FILE_REPLAY_WORK: usize = 512 << 20;
const MAX_ZERO_FILL_BYTES: usize = 512 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManifestProfile {
    Direct,
    Compact,
}

impl ManifestProfile {
    const fn shell_table_from_root(self) -> u32 {
        match self {
            Self::Direct => 0x1670,
            Self::Compact => 0x1590,
        }
    }

    const fn controller_layout_shift(self) -> u32 {
        match self {
            Self::Direct => 0x10,
            Self::Compact => 0x28,
        }
    }

    const fn codec_operation_relative(self) -> u32 {
        match self {
            Self::Direct => 0x15e0,
            Self::Compact => 0x13d8,
        }
    }

    const fn byte_map_layer_length(self) -> u32 {
        match self {
            Self::Direct => 0xad0,
            Self::Compact => 0xf70,
        }
    }

    const fn byte_map_program_relative(self) -> u32 {
        match self {
            Self::Direct => 0xa70,
            Self::Compact => 0xf00,
        }
    }

    const fn byte_map_program_window_length(self) -> u32 {
        self.byte_map_layer_length() - self.byte_map_program_relative()
    }

    const fn payload_manifest_key_relative(self) -> u32 {
        match self {
            Self::Direct => 0xa00,
            Self::Compact => 0xe20,
        }
    }

    const fn payload_manifest_length(self) -> u32 {
        match self {
            Self::Direct => 0x42a0,
            Self::Compact => 0x4fc0,
        }
    }

    const fn file_program_relative(self) -> u32 {
        match self {
            Self::Direct => 0x40dc,
            Self::Compact => 0x4de0,
        }
    }

    const fn file_program_window_length(self) -> u32 {
        self.payload_manifest_length() - self.file_program_relative()
    }

    const fn manifest_config_relative(self) -> u32 {
        match self {
            Self::Direct => 0x3c48,
            Self::Compact => 0x48b8,
        }
    }

    const fn checksum_list_from_info(self) -> u32 {
        match self {
            Self::Direct => 0x210,
            Self::Compact => 0x1a0,
        }
    }

    const fn compressed_list_from_info(self) -> u32 {
        match self {
            Self::Direct => 0x350,
            Self::Compact => 0x270,
        }
    }

    fn validate_shell(self, image: &[u8], table: usize, root: u32) -> Result<()> {
        ensure!(
            read_u32(image, table + 0x88)? == root,
            "rooted PE32 shell marker does not name the KONN shell"
        );
        let shell_length = read_u32(image, table + 0x8c)?;
        let mode = read_u32(image, table + 0x4c)?;
        let controls = (
            read_u32(image, table + 0x58)?,
            read_u32(image, table + 0x60)?,
            read_u32(image, table + 0x68)?,
        );
        match self {
            Self::Direct => {
                ensure!(
                    shell_length == 0x1cf0
                        && matches!(
                            (mode, controls),
                            (0x0001_0000, (0x178, 0x1d4, 0x218))
                                | (0x0003_0000, (0x180, 0x1dc, 0x220))
                        ),
                    "rooted PE32 shell has a neighboring controller dispatch"
                );
            }
            Self::Compact => {
                ensure!(
                    shell_length == 0x1c04
                        && (mode, controls) == (0x0000_6000, (0x128, 0x184, 0x1c8)),
                    "rooted compact PE32 shell has the wrong dispatch geometry"
                );
            }
        }

        let list = read_u32(image, table + 0x58)?;
        ensure!(list != 0, "rooted PE32 shell list is null");
        checked_range(image.len(), list, 8, "rooted PE32 shell list")?;

        let controller = descriptor(image, table + 0x98)?;
        ensure!(
            controller.source_length
                == CONTROLLER_DIRECTORY_BASE_LENGTH + self.controller_layout_shift(),
            "rooted PE32 controller directory has the wrong profile length"
        );
        checked_range(
            image.len(),
            controller.source,
            controller.source_length,
            "rooted PE32 controller directory",
        )?;
        Ok(())
    }
}

/// Terminal fields reached through one profile-specific manifest operand.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PayloadManifestLayout {
    config_rva: u32,
    file_checksums_rva: u32,
    file_checksums_size: u32,
    compressed_info_rva: u32,
    zero_list_rva: u32,
}

fn rooted_stage_program_rva(
    stage: StageDescriptor,
    relative: u32,
    window_length: u32,
    label: &str,
) -> Result<u32> {
    let end = relative
        .checked_add(window_length)
        .with_context(|| format!("{label} relative range overflows"))?;
    ensure!(
        end <= stage.destination_length,
        "{label} lies outside its rooted stage"
    );
    stage
        .destination
        .checked_add(relative)
        .with_context(|| format!("{label} RVA overflows"))
}

pub(crate) struct Probe {
    info_words: [u32; 8],
    base_image: Vec<u8>,
    shell_table: usize,
    profile: ManifestProfile,
}

pub(crate) struct Finalizer {
    metadata_entry: u32,
    metadata_directories: [u8; 128],
    shell_table: usize,
    byte_map_layer_rva: u32,
    payload_manifest_rva: u32,
    manifest_layout: PayloadManifestLayout,
    key_offsets: [u32; 4],
    file_raw_aes_key: [u8; 32],
    layer_raw_aes_key: [u8; 32],
    custom_program: LfsrAlMapCandidate,
    file_program: LfsrAlMapCandidate,
}

fn rooted_shell_marker_table(image: &[u8], root: u32, profile: ManifestProfile) -> Option<usize> {
    let table = usize::try_from(root.checked_add(profile.shell_table_from_root())?).ok()?;
    let marker = table.checked_add(0x88)?;
    if read_u32_opt(image, marker) == Some(root) {
        Some(table)
    } else {
        None
    }
}

fn rooted_shell_table(image: &[u8], info: &[u32; 8]) -> Result<Option<(ManifestProfile, usize)>> {
    let root = info[6];

    if let Some(table) = rooted_shell_marker_table(image, root, ManifestProfile::Direct) {
        ManifestProfile::Direct.validate_shell(image, table, root)?;
        return Ok(Some((ManifestProfile::Direct, table)));
    }

    let Some(table) = rooted_shell_marker_table(image, root, ManifestProfile::Compact) else {
        return Ok(None);
    };
    ManifestProfile::Compact.validate_shell(image, table, root)?;
    Ok(Some((ManifestProfile::Compact, table)))
}

fn rooted_header_checksum(
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
            .context("rooted PE32 header-checksum cursor overflows")?;
    }
    bail!("rooted PE32 header-checksum list exceeds entry budget")
}

fn rooted_manifest_layout(
    image: &[u8],
    payload_manifest_start: u32,
    payload_manifest_length: u32,
    info_base: u32,
    profile: ManifestProfile,
) -> Result<PayloadManifestLayout> {
    let config_relative = profile.manifest_config_relative();
    ensure!(
        config_relative
            .checked_add(0x50)
            .is_some_and(|end| end <= payload_manifest_length),
        "rooted payload-manifest configuration exceeds its decoded stage"
    );
    let config_rva = payload_manifest_start
        .checked_add(config_relative)
        .context("rooted payload-manifest configuration RVA overflows")?;
    let config = usize::try_from(config_rva)
        .context("rooted payload-manifest configuration RVA does not fit usize")?;
    checked_range(
        image.len(),
        config_rva,
        0x50,
        "rooted payload-manifest configuration",
    )?;
    if profile == ManifestProfile::Direct {
        ensure!(
            read_u32(image, config)? == TERMINAL_CONFIG_MAGIC,
            "rooted payload-manifest terminal marker is invalid"
        );
    }

    let file_checksums_rva = read_u32(image, config + 0x30)?;
    let file_checksums_size = read_u32(image, config + 0x34)?;
    let compressed_info_rva = read_u32(image, config + 0x40)?;
    let zero_list_rva = read_u32(image, config + 0x48)?;
    ensure!(
        file_checksums_rva
            == info_base
                .checked_add(profile.checksum_list_from_info())
                .context("rooted file-checksum list RVA overflows")?
            && file_checksums_size == 0x20,
        "rooted payload-manifest checksum list disagrees with its controller profile"
    );
    ensure!(
        compressed_info_rva
            == info_base
                .checked_add(profile.compressed_list_from_info())
                .context("rooted compressed-info list RVA overflows")?,
        "rooted payload-manifest block list disagrees with its controller profile"
    );
    ensure!(
        zero_list_rva != 0,
        "rooted payload-manifest has a null zero-fill list"
    );
    checked_range(
        image.len(),
        file_checksums_rva,
        file_checksums_size,
        "rooted file-checksum list",
    )?;
    checked_range(
        image.len(),
        compressed_info_rva,
        16,
        "rooted compressed-info list",
    )?;
    checked_range(image.len(), zero_list_rva, 16, "rooted zero-fill list")?;
    Ok(PayloadManifestLayout {
        config_rva,
        file_checksums_rva,
        file_checksums_size,
        compressed_info_rva,
        zero_list_rva,
    })
}

fn decode_file_checksum_records(
    image: &mut [u8],
    cursor: u32,
    size: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
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
    Ok(())
}

fn parse_zero_ranges(
    image: &mut [u8],
    mut cursor: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<Range<usize>>> {
    let mut total = 0usize;
    let mut ranges = Vec::new();
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = descriptor(
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
            "rooted zero-fill range",
        )?;
        total = total
            .checked_add(range.len())
            .context("rooted zero-fill byte count overflows")?;
        ensure!(
            total <= MAX_ZERO_FILL_BYTES,
            "rooted zero-fill list exceeds byte budget"
        );
        ranges.push(range);
    }
    bail!("rooted zero-fill list exceeds entry budget")
}

fn parse_payload_blocks(
    image: &mut [u8],
    mut cursor: u32,
    payload_length: usize,
    source_base: u32,
    security_range: Option<&Range<usize>>,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<PayloadBlock>> {
    let mut blocks = Vec::new();
    let mut replay_work = 0usize;
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = descriptor(
            image,
            usize::try_from(cursor).context("rooted compressed-info cursor does not fit usize")?,
        )?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("rooted compressed-info cursor overflows")?;
        if record.source_length == 0 {
            ensure!(
                !blocks.is_empty(),
                "rooted compressed-info list contains no payload blocks"
            );
            return Ok(blocks);
        }
        ensure!(
            record.destination_length != 0,
            "rooted compressed-info record has an empty destination"
        );
        let file_start = source_base
            .checked_add(record.source)
            .context("rooted payload-block source offset overflows")?;
        let file_range = checked_range(
            payload_length,
            file_start,
            record.source_length,
            "rooted payload-block source",
        )?;
        if let Some(security) = security_range {
            ensure!(
                file_range.end <= security.start || file_range.start >= security.end,
                "rooted payload-block source overlaps the PE Security Directory"
            );
        }
        checked_range(
            image.len(),
            record.destination,
            record.destination_length,
            "rooted payload-block destination",
        )?;
        replay_work = replay_work
            .checked_add(file_range.len())
            .and_then(|value| value.checked_add(record.destination_length as usize))
            .context("rooted payload-block replay work overflows")?;
        ensure!(
            replay_work <= MAX_FILE_REPLAY_WORK,
            "rooted payload-block replay exceeds byte budget"
        );
        blocks.push(PayloadBlock {
            source_offset: usize::try_from(file_start)
                .context("rooted payload-block source offset does not fit usize")?,
            encoded_length: usize::try_from(record.source_length)
                .context("rooted payload-block encoded length does not fit usize")?,
            destination_rva: usize::try_from(record.destination)
                .context("rooted payload-block destination RVA does not fit usize")?,
            destination_length: usize::try_from(record.destination_length)
                .context("rooted payload-block destination length does not fit usize")?,
        });
    }
    bail!("rooted compressed-info list exceeds entry budget")
}

fn restore_tls_from_stub(
    image: &mut [u8],
    packed: &[u8],
    pe: &Pe,
    tls_rva: u32,
    tls_size: u32,
) -> Result<bool> {
    if tls_rva == 0 || tls_size < 24 {
        return Ok(false);
    }
    let destination = checked_range(image.len(), tls_rva, 24, "TLS directory")?;
    if image[destination.clone()].iter().any(|byte| *byte != 0) {
        return Ok(true);
    }
    let source = match packed_rva_range(pe, packed.len(), tls_rva, 24) {
        Ok(range) => range,
        Err(_) => return Ok(false),
    };
    let start_va = read_u32(packed, source.start)?;
    let end_va = read_u32(packed, source.start + 4)?;
    let index_va = read_u32(packed, source.start + 8)?;
    let callbacks_va = read_u32(packed, source.start + 12)?;
    let image_base = u32::try_from(pe.image_base).context("PE32 image base exceeds u32")?;
    let image_end = image_base
        .checked_add(pe.size_of_image)
        .context("PE32 image end overflows")?;
    let in_image = |value: u32| value > image_base && value < image_end;
    if !in_image(start_va)
        || !in_image(index_va)
        || !in_image(callbacks_va)
        || end_va < start_va
        || end_va - start_va > 0x10_0000
    {
        return Ok(false);
    }
    let template_length = end_va - start_va;
    if template_length != 0 {
        let template_rva = start_va - image_base;
        let template_source =
            match packed_rva_range(pe, packed.len(), template_rva, template_length) {
                Ok(range) => range,
                Err(_) => return Ok(false),
            };
        let template_destination = checked_range(
            image.len(),
            template_rva,
            template_length,
            "TLS template destination",
        )?;
        image[template_destination].copy_from_slice(&packed[template_source]);
    }
    image[destination].copy_from_slice(&packed[source]);
    Ok(true)
}

fn finalize_header(
    image: &mut [u8],
    source: &BoundPayloadSource<'_>,
    metadata_entry: u32,
    metadata_directories: &[u8; 128],
) -> Result<()> {
    restore_common_mapped_header(image, source, metadata_entry, metadata_directories)?;
    let directory_offset = source.pe.data_directory_table_offset;
    let tls_rva = read_u32(image, directory_offset + 9 * 8)?;
    let tls_size = read_u32(image, directory_offset + 9 * 8 + 4)?;
    if tls_rva != 0
        && !restore_tls_from_stub(image, source.packed, source.pe, tls_rva, tls_size)?
        && checked_range(image.len(), tls_rva, 24, "TLS directory")?
            .into_iter()
            .all(|offset| image[offset] == 0)
    {
        write_u32(image, directory_offset + 9 * 8, 0)?;
        write_u32(image, directory_offset + 9 * 8 + 4, 0)?;
    }
    Ok(())
}
pub(super) fn probe(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<Option<Probe>> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let Ok(info_words) = decode_info(source) else {
        return Ok(None);
    };
    let base_image = materialize_bootstrap(source, &info_words, cancellation)?;
    let Some((profile, shell_table)) = rooted_shell_table(&base_image, &info_words)? else {
        return Ok(None);
    };
    Ok(Some(Probe {
        info_words,
        base_image,
        shell_table,
        profile,
    }))
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
        info_words,
        base_image: mut image,
        shell_table: table,
        profile,
    } = probe;
    let crc_table = crc32_table();
    let pe_header = source
        .pe
        .opt
        .checked_sub(24)
        .context("PE header offset underflows")?;

    let import_rva = read_u32(&image, table + 0xbc)?;
    let resource_rva = read_u32(&image, table + 0xc8)?;
    let resource_size = read_u32(&image, table + 0xcc)?;
    write_u32(&mut image, pe_header + 0x80, import_rva)?;
    write_u32(&mut image, pe_header + 0x88, resource_rva)?;
    write_u32(&mut image, pe_header + 0x8c, resource_size)?;
    write_u32(&mut image, pe_header + 0xa0, 0)?;
    write_u32(&mut image, pe_header + 0xa4, 0)?;
    write_u32(&mut image, pe_header + 0xb0, 0)?;
    write_u32(&mut image, pe_header + 0xb4, 0)?;

    let header_checksum = rooted_header_checksum(&image, table, &crc_table, cancellation)?;
    let bootstrap_checksum = checksum_descriptor(&image, table + 0xa8, &crc_table)?;
    let controller_key_literal = read_u32(&image, table + 0x40)?;
    let controller_descriptor = table + 0x98;
    let controller = descriptor(&image, controller_descriptor)?;
    ensure!(
        controller.source_length
            == CONTROLLER_DIRECTORY_BASE_LENGTH + profile.controller_layout_shift(),
        "rooted PE32 controller directory length changed after probe"
    );
    decrypt_dword_descriptor(
        &mut image,
        controller_descriptor,
        header_checksum ^ bootstrap_checksum ^ controller_key_literal,
        21,
        cancellation,
    )?;

    let controller_start = usize::try_from(controller.source)
        .context("rooted PE32 controller RVA does not fit usize")?;
    let layout_shift = profile.controller_layout_shift();
    let codec_descriptor = controller_start
        .checked_add((CODEC_DESCRIPTOR_RELATIVE + layout_shift) as usize)
        .context("rooted PE32 codec descriptor overflows")?;
    let codec = descriptor(&image, codec_descriptor)?;
    checked_range(
        image.len(),
        codec.source,
        codec.source_length,
        "rooted PE32 codec stage",
    )?;
    let codec_key = read_u32(
        &image,
        controller_start + (CODEC_KEY_RELATIVE + layout_shift) as usize,
    )?;
    decrypt_dword_descriptor(&mut image, codec_descriptor, codec_key, 19, cancellation)?;

    let operation_table = usize::try_from(codec.source)
        .context("rooted PE32 codec RVA does not fit usize")?
        .checked_add(profile.codec_operation_relative() as usize)
        .context("rooted PE32 operation-table RVA overflows")?;
    ensure!(
        operation_table
            .checked_add(32)
            .is_some_and(|end| end <= image.len()),
        "rooted PE32 operation table exceeds the image"
    );
    ensure!(
        matches!(read_u32(&image, operation_table)?, 1 | 0x11)
            && read_u32(&image, operation_table + 16)? == 2,
        "rooted PE32 operation table has the wrong action sequence"
    );
    transform_shift3_descriptor(&mut image, operation_table + 4, cancellation)?;
    let copy_list = read_u32(&image, operation_table + 20)?;
    copy_stage_list(&mut image, copy_list, cancellation)?;
    ensure!(
        operation_table >= CODEC_ASSET_TABLE_BACK,
        "rooted PE32 codec asset table underflows"
    );
    let asset_table = operation_table - CODEC_ASSET_TABLE_BACK;
    let mut key_offsets = [0u32; 4];
    for group in 0..2usize {
        for index in 0..2usize {
            let at = asset_table + group * 32 + index * 8;
            transform_shift3_descriptor(&mut image, at, cancellation)?;
            key_offsets[group * 2 + index] = read_u32(&image, at)?;
        }
    }
    let file_decoder_table = snapshot_decoder_table(&image, key_offsets[0])?;
    let layer_decoder_table = snapshot_decoder_table(&image, key_offsets[1])?;
    let (file_raw_aes_key, _) = recover_aes(&image, key_offsets[2])?;
    let (layer_raw_aes_key, layer_aes) = recover_aes(&image, key_offsets[3])?;

    let checksum_base = controller_start
        .checked_add((CHECKSUM_BASE_RELATIVE + layout_shift) as usize)
        .context("rooted PE32 checksum-table RVA overflows")?;
    let descriptor_base = controller_start
        .checked_add((DESCRIPTOR_BASE_RELATIVE + layout_shift) as usize)
        .context("rooted PE32 stage-descriptor RVA overflows")?;
    let controller_checksum = checksum_descriptor(&image, table + 0xb0, &crc_table)?;
    let mapped_key = advance_key(
        read_u32(
            &image,
            controller_start + (MAPPED_KEY_RELATIVE + layout_shift) as usize,
        )?,
        4,
    );
    decrypt_stage(
        &mut image,
        descriptor_base + 0x40,
        header_checksum ^ controller_checksum ^ mapped_key,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("rooted PE32 mapped-layer replay")?;

    let mapped_checksum = checksum_descriptor(&image, checksum_base, &crc_table)?;
    let mapped_record = descriptor(&image, checksum_base)?;
    ensure!(
        mapped_record.source_length >= 4,
        "rooted PE32 mapped-layer checksum range is too short"
    );
    let transformed_literal_rva = mapped_record
        .source
        .checked_add(mapped_record.source_length)
        .and_then(|value| value.checked_sub(4))
        .context("rooted PE32 transformed-layer literal underflows")?;
    let transformed_literal = read_u32(
        &image,
        usize::try_from(transformed_literal_rva)
            .context("rooted PE32 transformed-layer literal does not fit usize")?,
    )?;
    decrypt_stage(
        &mut image,
        descriptor_base + 0x50,
        header_checksum ^ mapped_checksum ^ transformed_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("rooted PE32 transformed-layer replay")?;

    let transformed_checksum = checksum_descriptor(&image, checksum_base + 8, &crc_table)?;
    let transformed_record = descriptor(&image, checksum_base + 8)?;
    ensure!(
        transformed_record.source_length >= 0x10,
        "rooted PE32 transformed-layer checksum range is too short"
    );
    let byte_map_literal_rva = transformed_record
        .source
        .checked_add(transformed_record.source_length)
        .and_then(|value| value.checked_sub(0x10))
        .context("rooted PE32 byte-map-layer literal underflows")?;
    let byte_map_literal = !read_u32(
        &image,
        usize::try_from(byte_map_literal_rva)
            .context("rooted PE32 byte-map-layer literal does not fit usize")?,
    )?;
    let byte_map_descriptor = descriptor_base + 0x70;
    let byte_map_layer = descriptor(&image, byte_map_descriptor)?;
    ensure!(
        byte_map_layer.source == byte_map_layer.destination
            && byte_map_layer.destination_length == profile.byte_map_layer_length(),
        "rooted PE32 byte-map layer has the wrong profile geometry"
    );
    decrypt_stage(
        &mut image,
        byte_map_descriptor,
        header_checksum ^ transformed_checksum ^ byte_map_literal,
        &layer_aes,
        &layer_decoder_table,
        None,
        cancellation,
    )
    .context("rooted PE32 byte-map-layer replay")?;
    let custom_program_rva = rooted_stage_program_rva(
        byte_map_layer,
        profile.byte_map_program_relative(),
        profile.byte_map_program_window_length(),
        "rooted PE32 byte-map program",
    )?;
    let custom_program = exact_lfsr_al_map(
        &image,
        custom_program_rva,
        profile.byte_map_program_window_length(),
        "rooted PE32 byte-map program",
    )?;

    let byte_map_checksum = checksum_descriptor(&image, checksum_base + 0x10, &crc_table)?;
    let payload_manifest_descriptor = descriptor_base + PAYLOAD_MANIFEST_DESCRIPTOR_RELATIVE;
    let payload_manifest = descriptor(&image, payload_manifest_descriptor)?;
    ensure!(
        payload_manifest.source == payload_manifest.destination
            && payload_manifest.destination_length == profile.payload_manifest_length(),
        "rooted PE32 payload manifest has the wrong profile geometry"
    );
    let payload_manifest_literal_rva = byte_map_layer
        .source
        .checked_add(profile.payload_manifest_key_relative())
        .context("rooted PE32 payload-manifest literal RVA overflows")?;
    let payload_manifest_literal = read_u32(
        &image,
        usize::try_from(payload_manifest_literal_rva)
            .context("rooted PE32 payload-manifest literal does not fit usize")?,
    )?;
    let compression_key_offset = source
        .bootstrap
        .descriptor_file_offset
        .checked_add(0x80)
        .context("compressed-data key offset overflows")?;
    let source_base = (!read_u32(source.payload_source, compression_key_offset)?).wrapping_add(
        u32::try_from(source.bootstrap.descriptor_file_offset)
            .context("descriptor file offset exceeds u32")?,
    );
    decrypt_stage(
        &mut image,
        payload_manifest_descriptor,
        header_checksum
            ^ transformed_checksum
            ^ byte_map_checksum
            ^ advance_key(payload_manifest_literal, 3),
        &layer_aes,
        &layer_decoder_table,
        Some(custom_program.map.as_ref()),
        cancellation,
    )
    .context("rooted PE32 payload-manifest replay")?;
    let manifest_layout = rooted_manifest_layout(
        &image,
        payload_manifest.source,
        payload_manifest.destination_length,
        info_words[3],
        profile,
    )?;
    let file_program_rva = rooted_stage_program_rva(
        payload_manifest,
        profile.file_program_relative(),
        profile.file_program_window_length(),
        "rooted PE32 file byte-map program",
    )?;
    let file_program = exact_lfsr_al_map(
        &image,
        file_program_rva,
        profile.file_program_window_length(),
        "rooted PE32 file byte-map program",
    )?;
    let (metadata_entry, metadata_directories) =
        extract_metadata(&mut image, info_words[3], cancellation)?;
    decode_file_checksum_records(
        &mut image,
        manifest_layout.file_checksums_rva,
        manifest_layout.file_checksums_size,
        cancellation,
    )?;
    let zero_ranges = parse_zero_ranges(&mut image, manifest_layout.zero_list_rva, cancellation)?;
    let blocks = parse_payload_blocks(
        &mut image,
        manifest_layout.compressed_info_rva,
        source.payload_source.len(),
        source_base,
        source.source_security_range,
        cancellation,
    )?;
    let block_table = PayloadBlockTable {
        stream_base: 0,
        blocks,
    };
    ensure_terminal_zero_ranges_are_disjoint_from_payload_destinations(&zero_ranges, &block_table)?;
    for range in zero_ranges {
        image[range].fill(0);
    }
    let candidate = PayloadPlanCandidate::new(PayloadMaterializationPlan {
        block_table: block_table.clone(),
        aes_key: file_raw_aes_key,
        decoder: DecoderCandidate {
            source_file_offset: usize::try_from(key_offsets[0])
                .expect("validated rooted PE32 file decoder RVA fits usize"),
            phase: 0,
            table: file_decoder_table,
        },
        post_transform: PayloadPostTransform::ByteMap(file_program.map.clone()),
    });
    Ok(shell_directory_manifest_proposal(
        image,
        block_table,
        candidate,
        Finalizer {
            metadata_entry,
            metadata_directories,
            shell_table: table,
            byte_map_layer_rva: byte_map_layer.source,
            payload_manifest_rva: payload_manifest.source,
            manifest_layout,
            key_offsets,
            file_raw_aes_key,
            layer_raw_aes_key,
            custom_program,
            file_program,
        },
    ))
}

pub(super) fn finalize(
    source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: Finalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let selected_mapping = authenticated.plan().post_transform.mapping();
    ensure!(
        finalizer.file_program.map.as_ref() == &selected_mapping,
        "authenticated PE32 manifest plan differs from the rooted file byte map"
    );
    let (_plan, _selected_chain, mut image) = authenticated.into_parts();
    finalize_header(
        &mut image,
        source,
        finalizer.metadata_entry,
        &finalizer.metadata_directories,
    )?;
    let mut destination_record_ranges = block_table
        .blocks
        .iter()
        .map(payload_block_destination_range)
        .collect::<Result<Vec<_>>>()?;
    destination_record_ranges.sort_unstable_by_key(|range| range.start);
    let destination_ranges = merged_payload_block_destination_ranges(&block_table.blocks)?;
    let copied_block_count = block_table
        .blocks
        .iter()
        .filter(|block| block.encoded_length == block.destination_length)
        .count();
    info!(
        table_rva = finalizer.shell_table,
        byte_map_layer_rva = finalizer.byte_map_layer_rva,
        payload_manifest_rva = finalizer.payload_manifest_rva,
        custom_program_rva = finalizer.custom_program.offset,
        file_program_rva = finalizer.file_program.offset,
        file_program_length = finalizer.file_program.length,
        byte_map_candidates = 1,
        blocks = block_table.blocks.len(),
        "selected PE32 shell-directory-manifest controller"
    );
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
            selected_controller: Some(SelectedController::ShellDirectoryManifest(
                SelectedShellDirectoryManifestController {
                    shell_table_rva: u32::try_from(finalizer.shell_table)
                        .context("shell table RVA exceeds u32")?,
                    byte_map_layer_rva: finalizer.byte_map_layer_rva,
                    payload_manifest_rva: finalizer.payload_manifest_rva,
                    manifest_config_rva: finalizer.manifest_layout.config_rva,
                    file_checksum_list_rva: finalizer.manifest_layout.file_checksums_rva,
                    compressed_info_list_rva: finalizer.manifest_layout.compressed_info_rva,
                    zero_list_rva: finalizer.manifest_layout.zero_list_rva,
                    file_decoder_rva: finalizer.key_offsets[0],
                    layer_decoder_rva: finalizer.key_offsets[1],
                    file_aes_context_rva: finalizer.key_offsets[2],
                    layer_aes_context_rva: finalizer.key_offsets[3],
                    file_raw_key_hex: hex::encode(finalizer.file_raw_aes_key),
                    layer_raw_key_hex: hex::encode(finalizer.layer_raw_aes_key),
                    custom_program_rva: u32::try_from(finalizer.custom_program.offset)
                        .context("custom program RVA exceeds u32")?,
                    custom_program_length: finalizer.custom_program.length,
                    custom_byte_map: finalizer.custom_program.map.to_vec(),
                    file_program_rva: u32::try_from(finalizer.file_program.offset)
                        .context("file program RVA exceeds u32")?,
                    file_program_length: finalizer.file_program.length,
                    file_byte_map: finalizer.file_program.map.to_vec(),
                },
            )),
            ..DecryptionDetails::default()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: u32 = 0x100;

    fn info_words() -> [u32; 8] {
        [0, 0, 0, 0, 0, 0, ROOT, 0]
    }

    #[test]
    fn rooted_shell_table_returns_none_without_a_profile_marker() {
        let image = vec![0; 0x2000];

        assert_eq!(rooted_shell_table(&image, &info_words()).unwrap(), None);
    }

    #[test]
    fn rooted_shell_table_rejects_a_malformed_direct_profile_after_marker_match() {
        let mut image = vec![0; 0x2000];
        let table =
            usize::try_from(ROOT + ManifestProfile::Direct.shell_table_from_root()).unwrap();
        write_u32(&mut image, table + 0x88, ROOT).unwrap();

        assert!(rooted_shell_table(&image, &info_words()).is_err());
    }

    #[test]
    fn rooted_shell_table_rejects_a_malformed_compact_profile_after_marker_match() {
        let mut image = vec![0; 0x2000];
        let table =
            usize::try_from(ROOT + ManifestProfile::Compact.shell_table_from_root()).unwrap();
        write_u32(&mut image, table + 0x88, ROOT).unwrap();

        assert!(rooted_shell_table(&image, &info_words()).is_err());
    }
}
