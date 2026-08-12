use std::collections::HashSet;
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};
use tracing::{debug, info};

use crate::pe::{Machine, Pe};
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::{DecryptionDetails, SelectedStagedTable};
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, crackproof_checksum, crc32_table, lfsr_al_map_candidates,
};

use super::DecryptedImage;
use super::aes::{
    AES_CONTEXT_HEADER, AES_DECRYPT_SCHEDULE_SIZE, Aes256CbcDecryptor,
    make_openssl_decrypt_schedule, recover_raw_key,
};
use super::decoder::decode_custom_stream_with_history;
use super::grammar::BoundPayloadSource;

const KONN_MAGIC: u32 = u32::from_le_bytes(*b"KONN");
const HEADER_COPY_SIZE: usize = 0x1000;
const STAGE_DESCRIPTOR_SIZE: usize = 16;
const MAX_STAGE_LIST_ENTRIES: usize = 1 << 20;
const MAX_EIGHTH_STAGE_ATTEMPTS: usize = 16_384;
const MAX_FILE_REPLAY_WORK: usize = 512 << 20;
const MAX_ZERO_FILL_BYTES: usize = 512 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StageDescriptor {
    source: u32,
    source_length: u32,
    destination: u32,
    destination_length: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileBlock {
    source_offset: u32,
    source_length: u32,
    destination: u32,
    destination_length: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EighthLayout {
    base: u32,
    import_table: u32,
    file_checksums: u32,
    compressed_info: u32,
    zero_list: u32,
}

fn checked_range(total: usize, start: u32, length: u32, label: &str) -> Result<Range<usize>> {
    let start =
        usize::try_from(start).with_context(|| format!("{label} start does not fit usize"))?;
    let length =
        usize::try_from(length).with_context(|| format!("{label} length does not fit usize"))?;
    let end = start
        .checked_add(length)
        .with_context(|| format!("{label} end overflows"))?;
    ensure!(
        end <= total,
        "{label} range {start:#x}..{end:#x} exceeds {total:#x} bytes"
    );
    Ok(start..end)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    let bytes = data
        .get(offset..offset.checked_add(2).context("u16 offset overflows")?)
        .context("u16 read exceeds buffer")?;
    Ok(u16::from_le_bytes(
        bytes.try_into().expect("two-byte slice"),
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset.checked_add(4).context("u32 offset overflows")?)
        .context("u32 read exceeds buffer")?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("four-byte slice"),
    ))
}

fn write_u16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    let destination = data
        .get_mut(offset..offset.checked_add(2).context("u16 offset overflows")?)
        .context("u16 write exceeds buffer")?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let destination = data
        .get_mut(offset..offset.checked_add(4).context("u32 offset overflows")?)
        .context("u32 write exceeds buffer")?;
    destination.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn descriptor(data: &[u8], offset: usize) -> Result<StageDescriptor> {
    let _ = data
        .get(
            offset
                ..offset
                    .checked_add(STAGE_DESCRIPTOR_SIZE)
                    .context("descriptor end overflows")?,
        )
        .context("stage descriptor exceeds image")?;
    Ok(StageDescriptor {
        source: read_u32(data, offset)?,
        source_length: read_u32(data, offset + 4)?,
        destination: read_u32(data, offset + 8)?,
        destination_length: read_u32(data, offset + 12)?,
    })
}

fn decode_info(source: &BoundPayloadSource<'_>) -> Result<[u32; 8]> {
    let offset = source.bootstrap.descriptor_file_offset;
    let words = source
        .payload_source
        .get(offset..offset.checked_add(32).context("KONN table end overflows")?)
        .context("payload source does not contain the KONN key table")?;
    let mut info = [0u32; 8];
    info[0] = u32::from_le_bytes(words[..4].try_into().expect("first KONN word"));
    let mut state = info[0];
    for index in 0..7usize {
        let cell_offset = (index + 1) * 4;
        let cell = u32::from_le_bytes(
            words[cell_offset..cell_offset + 4]
                .try_into()
                .expect("bounded KONN word"),
        );
        info[index + 1] = state ^ cell;
        let index = index as u32;
        state = index.wrapping_mul(index) ^ state.wrapping_add(cell).wrapping_sub(index);
    }
    ensure!(info[1] == KONN_MAGIC, "staged table key header is not KONN");
    ensure!(
        info[2] == source.pe.entry_rva
            && info[3] == source.bootstrap.destination_rva
            && info[4] == source.bootstrap.source_offset
            && info[5] == source.bootstrap.length,
        "staged table header disagrees with the selected KONN descriptor"
    );
    Ok(info)
}

fn materialize_bootstrap(source: &BoundPayloadSource<'_>, info: &[u32; 8]) -> Result<Vec<u8>> {
    let image_length = usize::try_from(source.pe.size_of_image)
        .context("staged image size does not fit host address space")?;
    let mut image = vec![0u8; image_length];
    let decrypt_length = info[6]
        .checked_sub(info[3])
        .context("staged shell end precedes destination")?
        .checked_add(0x2000)
        .context("staged bootstrap decrypt length overflows")?;
    ensure!(
        decrypt_length <= info[5] && decrypt_length.is_multiple_of(4),
        "staged bootstrap decrypt span is invalid"
    );

    let source_start = source
        .bootstrap
        .descriptor_file_offset
        .checked_add(usize::try_from(info[4]).context("staged source offset does not fit usize")?)
        .context("staged source start overflows")?;
    let source_range = source
        .payload_source
        .get(
            source_start
                ..source_start
                    .checked_add(
                        usize::try_from(info[5])
                            .context("staged source length does not fit usize")?,
                    )
                    .context("staged source end overflows")?,
        )
        .context("staged bootstrap source exceeds payload source")?;
    let destination = usize::try_from(info[3]).context("staged destination does not fit usize")?;
    let destination_end = destination
        .checked_add(source_range.len())
        .context("staged destination end overflows")?;
    ensure!(
        destination_end <= image.len(),
        "staged bootstrap destination exceeds image"
    );

    let encrypted_length =
        usize::try_from(decrypt_length).context("staged decrypt length does not fit usize")?;
    let mut state = info[0].wrapping_sub(decrypt_length).wrapping_sub(1);
    for (index, ciphertext) in source_range[..encrypted_length].chunks_exact(4).enumerate() {
        let ciphertext = u32::from_le_bytes(ciphertext.try_into().expect("dword bootstrap chunk"));
        let output = ciphertext ^ state;
        let at = destination + index * 4;
        image[at..at + 4].copy_from_slice(&output.to_le_bytes());
        let index = u32::try_from(index).context("staged bootstrap word index exceeds u32")?;
        state = state.wrapping_add(ciphertext).wrapping_add(index) ^ index.wrapping_mul(index);
    }
    image[destination + encrypted_length..destination_end]
        .copy_from_slice(&source_range[encrypted_length..]);

    let header_length = HEADER_COPY_SIZE.min(source.packed.len()).min(image.len());
    ensure!(
        header_length == HEADER_COPY_SIZE,
        "staged PE lacks a complete 4 KiB header"
    );
    image[..header_length].copy_from_slice(&source.packed[..header_length]);
    write_u32(
        &mut image,
        destination,
        u32::try_from(source.bootstrap.descriptor_file_offset)
            .context("KONN descriptor offset exceeds u32")?,
    )?;
    Ok(image)
}

fn find_table(image: &[u8], info: &[u32; 8]) -> Result<usize> {
    let shell = usize::try_from(info[6]).context("staged shell RVA does not fit usize")?;
    let upper = shell
        .checked_add(0x3000)
        .context("staged table scan end overflows")?
        .min(image.len().saturating_sub(0x100));
    for offset in (shell..upper).step_by(4) {
        if read_u32(image, offset)? != info[6] || offset < 0x88 {
            continue;
        }
        let shell_length = read_u32(image, offset + 4)?;
        if !(0x1001..0x10_0000).contains(&shell_length) {
            continue;
        }
        let candidate = offset - 0x88;
        let pointed = read_u32(image, candidate + 0x58)?;
        if pointed != 0 && usize::try_from(pointed).is_ok_and(|value| value < image.len()) {
            return Ok(candidate);
        }
    }
    bail!("PE32 staged table was not found")
}

fn checksum_descriptor(image: &[u8], offset: usize, table: &[u32; 256]) -> Result<u32> {
    let start = read_u32(image, offset)?;
    let length = read_u32(image, offset + 4)?;
    let range = checked_range(image.len(), start, length, "checksum input")?;
    Ok(crackproof_checksum(&image[range], table))
}

fn decrypt_dword_descriptor(
    image: &mut [u8],
    descriptor_offset: usize,
    mut key: u32,
    rotation: u32,
) -> Result<()> {
    let stage = descriptor(image, descriptor_offset)?;
    ensure!(
        stage.source_length.is_multiple_of(4),
        "staged dword span is not aligned"
    );
    let range = checked_range(
        image.len(),
        stage.source,
        stage.source_length,
        "dword stage",
    )?;
    for (index, word) in image[range].chunks_exact_mut(4).enumerate() {
        let ciphertext = u32::from_le_bytes(word.try_into().expect("dword stage chunk"));
        let index = u32::try_from(index).context("dword stage index exceeds u32")?;
        let plaintext = (ciphertext ^ key)
            .rotate_right(rotation)
            .wrapping_sub(index);
        word.copy_from_slice(&plaintext.to_le_bytes());
        key = key.wrapping_add(index);
    }
    Ok(())
}

fn transform_rotating_bytes(
    image: &mut [u8],
    start: u32,
    length: u32,
    rotation: u32,
    seed: u8,
) -> Result<()> {
    let range = checked_range(image.len(), start, length, "rotating byte transform")?;
    let mut first_key = seed;
    let mut second_key = seed.wrapping_add(1);
    for value in &mut image[range] {
        let first = value.rotate_left(rotation) ^ second_key;
        let second = first.rotate_left(rotation) ^ first_key;
        *value = second.rotate_left(rotation);
        first_key = first_key.wrapping_add(1);
        second_key = second_key.wrapping_add(1);
    }
    Ok(())
}

fn transform_shift3_descriptor(image: &mut [u8], offset: usize) -> Result<()> {
    let start = read_u32(image, offset)?;
    let length = read_u32(image, offset + 4)?;
    let seed = start.wrapping_add(start >> 8) as u8;
    transform_rotating_bytes(image, start, length, 3, seed)
}

fn transform_shift2_range(image: &mut [u8], start: u32, length: u32) -> Result<()> {
    transform_rotating_bytes(image, start, length, 2, start as u8)
}

fn copy_stage_list(image: &mut [u8], mut offset: u32) -> Result<()> {
    for _ in 0..MAX_STAGE_LIST_ENTRIES {
        transform_shift2_range(image, offset, STAGE_DESCRIPTOR_SIZE as u32)?;
        let record = descriptor(
            image,
            usize::try_from(offset).context("copy record offset does not fit usize")?,
        )?;
        offset = offset
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("copy record cursor overflows")?;
        if record.source_length == 0 {
            return Ok(());
        }
        ensure!(
            record.source != 0
                && record.destination != 0
                && record.destination_length == record.source_length,
            "staged copy record is malformed"
        );
        let source = checked_range(
            image.len(),
            record.source,
            record.source_length,
            "copy source",
        )?;
        let destination = checked_range(
            image.len(),
            record.destination,
            record.destination_length,
            "copy destination",
        )?;
        image.copy_within(source, destination.start);
    }
    bail!("staged copy list exceeds entry budget")
}

fn recover_aes(image: &[u8], offset: u32) -> Result<([u8; 32], Aes256CbcDecryptor)> {
    let offset = usize::try_from(offset).context("AES context RVA does not fit usize")?;
    let context_length = AES_CONTEXT_HEADER.len() + AES_DECRYPT_SCHEDULE_SIZE;
    let context = image
        .get(
            offset
                ..offset
                    .checked_add(context_length)
                    .context("AES context end overflows")?,
        )
        .context("AES context exceeds staged image")?;
    ensure!(
        context[..AES_CONTEXT_HEADER.len()] == AES_CONTEXT_HEADER,
        "staged AES context has the wrong header"
    );
    let schedule: [u8; AES_DECRYPT_SCHEDULE_SIZE] = context[AES_CONTEXT_HEADER.len()..]
        .try_into()
        .expect("bounded AES schedule");
    let raw_key = recover_raw_key(&schedule);
    ensure!(
        make_openssl_decrypt_schedule(&raw_key) == schedule,
        "staged AES schedule does not invert to a valid AES-256 key"
    );
    Ok((raw_key, Aes256CbcDecryptor::new(&raw_key)))
}

fn snapshot_decoder_table(image: &[u8], offset: u32) -> Result<Vec<u8>> {
    let base = usize::try_from(offset).context("decoder table RVA does not fit usize")?;
    let mut visited = vec![false; 1 << 16];
    let mut pending = (0u32..256).collect::<Vec<_>>();
    let mut maximum = 255u32;
    while let Some(index) = pending.pop() {
        ensure!(
            index < 1 << 16,
            "decoder table node exceeds 16-bit index space"
        );
        if visited[index as usize] {
            continue;
        }
        visited[index as usize] = true;
        let node = base
            .checked_add(usize::try_from(index).expect("u32 node index fits usize") * 3)
            .context("decoder table node offset overflows")?;
        let tag = read_u16(image, node)?;
        let child = u32::from(tag & 0x7fff);
        if tag & 0x8000 == 0 {
            ensure!(
                child < (1 << 16) - 1,
                "decoder child pair exceeds table index space"
            );
            maximum = maximum.max(child + 1);
            pending.push(child);
            pending.push(child + 1);
        }
    }
    let length = usize::try_from(maximum + 1)
        .expect("decoder node count fits usize")
        .checked_mul(3)
        .context("decoder table size overflows")?;
    Ok(image
        .get(
            base..base
                .checked_add(length)
                .context("decoder table end overflows")?,
        )
        .context("decoder table exceeds staged image")?
        .to_vec())
}

fn decrypt_stage(
    image: &mut [u8],
    descriptor_offset: usize,
    key: u32,
    aes: &Aes256CbcDecryptor,
    decoder: &[u8],
    map: Option<&[u8; 256]>,
) -> Result<()> {
    let stage = descriptor(image, descriptor_offset)?;
    let source_range = checked_range(
        image.len(),
        stage.source,
        stage.source_length,
        "stage source",
    )?;
    aes.decrypt_full_blocks_in_place(&mut image[source_range.clone()]);
    let mut rolling_key = key;
    for (index, word) in image[source_range.clone()].chunks_exact_mut(4).enumerate() {
        let ciphertext = u32::from_le_bytes(word.try_into().expect("stage dword"));
        let index = u32::try_from(index).context("stage dword index exceeds u32")?;
        let plaintext = (ciphertext ^ rolling_key)
            .rotate_right(19)
            .wrapping_sub(index);
        word.copy_from_slice(&plaintext.to_le_bytes());
        rolling_key = rolling_key.wrapping_add(index);
    }
    if let Some(map) = map {
        for byte in &mut image[source_range.clone()] {
            *byte = map[usize::from(*byte)];
        }
    }

    let destination_range = checked_range(
        image.len(),
        stage.destination,
        stage.destination_length,
        "stage destination",
    )?;
    if stage.source_length == stage.destination_length {
        if source_range != destination_range {
            let payload = image[source_range].to_vec();
            image[destination_range].copy_from_slice(&payload);
        }
        return Ok(());
    }

    let payload = image[source_range].to_vec();
    let history_start = destination_range.start.saturating_sub(4);
    let history = image[history_start..destination_range.start].to_vec();
    decode_custom_stream_with_history(decoder, &payload, &history, &mut image[destination_range])
        .context("decoding staged Huffman/LZ stream")?;
    Ok(())
}

fn stage_backups(image: &[u8], descriptor_offset: usize) -> Result<Vec<(Range<usize>, Vec<u8>)>> {
    let stage = descriptor(image, descriptor_offset)?;
    let mut ranges = vec![
        checked_range(
            image.len(),
            stage.source,
            stage.source_length,
            "stage source backup",
        )?,
        checked_range(
            image.len(),
            stage.destination,
            stage.destination_length,
            "stage destination backup",
        )?,
    ];
    ranges.sort_unstable_by_key(|range| range.start);
    ranges.dedup();
    Ok(ranges
        .into_iter()
        .map(|range| {
            let bytes = image[range.clone()].to_vec();
            (range, bytes)
        })
        .collect())
}

fn restore_backups(image: &mut [u8], backups: &[(Range<usize>, Vec<u8>)]) {
    for (range, bytes) in backups {
        image[range.clone()].copy_from_slice(bytes);
    }
}

fn advance_key(mut key: u32, iterations: u32) -> u32 {
    for iteration in 0..iterations {
        let bound = (iteration + 1).wrapping_mul(25) << 2;
        for value in 1..=bound {
            key = key.wrapping_add(value);
        }
    }
    key
}

fn non_string_key(value: u32) -> bool {
    value != 0
        && value != 0xcccc_cccc
        && !(0..4).all(|shift| (0x20..0x7f).contains(&((value >> (shift * 8)) & 0xff)))
}

fn eighth_key_offsets(
    image: &[u8],
    stage_start: u32,
    stage_length: u32,
    programs: &[LfsrAlMapCandidate],
) -> Result<Vec<u32>> {
    let stage_start_usize =
        usize::try_from(stage_start).context("seven-stage RVA does not fit usize")?;
    let mut offsets = Vec::new();
    let mut push = |offset: u32| -> Result<()> {
        if offset.checked_add(4).is_some_and(|end| end <= stage_length) {
            let value = read_u32(image, stage_start_usize + offset as usize)?;
            if non_string_key(value) && !offsets.contains(&offset) {
                offsets.push(offset);
            }
        }
        Ok(())
    };
    for gap in [0xd0u32, 0xc0, 0xe0, 0xb0, 0xa0, 0xf0, 0x100] {
        if let Some(offset) = stage_length.checked_sub(gap) {
            push(offset)?;
        }
    }
    for program in programs {
        let program_offset =
            u32::try_from(program.offset).context("AL program offset exceeds u32")?;
        for gap in [
            0x70u32, 0xd0, 0x28, 0x50, 0x48, 0x30, 0x40, 0x58, 0x60, 0x20, 0x38, 0x80, 0x90, 0xa0,
            0xb0,
        ] {
            if let Some(offset) = program_offset.checked_sub(gap) {
                push(offset)?;
            }
        }
        let scan_start = program_offset.saturating_sub(0x100) & !3;
        for offset in (scan_start..program_offset).step_by(4) {
            push(offset)?;
        }
    }
    Ok(offsets)
}

fn cluster_at(
    image: &[u8],
    stage_start: u32,
    stage_length: u32,
    info_base: u32,
    base: u32,
) -> Result<Option<EighthLayout>> {
    let required_end = base
        .checked_add(0x50)
        .context("eighth cluster end overflows")?;
    if required_end > stage_length {
        return Ok(None);
    }
    let absolute = stage_start
        .checked_add(base)
        .context("eighth cluster RVA overflows")?;
    let absolute = usize::try_from(absolute).context("eighth cluster RVA does not fit usize")?;
    let checksum_rva = read_u32(image, absolute + 0x30)?;
    let checksum_size = read_u32(image, absolute + 0x34)?;
    if checksum_rva <= info_base
        || checksum_rva > info_base.saturating_add(0x2000)
        || !(0x10..=0x200).contains(&checksum_size)
        || !checksum_size.is_multiple_of(16)
    {
        return Ok(None);
    }
    let compressed_info = read_u32(image, absolute + 0x40)?;
    let zero_list = read_u32(image, absolute + 0x48)?;
    if compressed_info == 0
        || zero_list == 0
        || usize::try_from(compressed_info).map_or(true, |value| value >= image.len())
        || usize::try_from(zero_list).map_or(true, |value| value >= image.len())
    {
        return Ok(None);
    }
    Ok(Some(EighthLayout {
        base,
        import_table: base + 0x18,
        file_checksums: base + 0x30,
        compressed_info: base + 0x40,
        zero_list: base + 0x48,
    }))
}

fn find_eighth_layout(
    image: &[u8],
    stage_start: u32,
    stage_length: u32,
    info_base: u32,
) -> Result<EighthLayout> {
    let stage_range = checked_range(image.len(), stage_start, stage_length, "eighth stage")?;
    for offset in (0..stage_range.len().saturating_sub(0x50)).step_by(4) {
        if read_u32(image, stage_range.start + offset)? == 0x7679
            && let Some(layout) = cluster_at(
                image,
                stage_start,
                stage_length,
                info_base,
                u32::try_from(offset).expect("stage offset fits u32"),
            )?
        {
            return Ok(layout);
        }
    }

    let mut candidates = Vec::new();
    for checksum_offset in (0x30..stage_range.len().saturating_sub(8)).step_by(4) {
        let base = u32::try_from(checksum_offset - 0x30).expect("stage offset fits u32");
        if let Some(layout) = cluster_at(image, stage_start, stage_length, info_base, base)? {
            let absolute = stage_range.start + checksum_offset;
            let distance = read_u32(image, absolute)? - info_base;
            candidates.push((distance, layout));
        }
    }
    candidates.sort_unstable_by_key(|(distance, layout)| (*distance, layout.base));
    candidates
        .into_iter()
        .next()
        .map(|(_, layout)| layout)
        .context("eighth-stage config cluster was not found")
}

fn extract_metadata(image: &mut [u8], info_base: u32) -> Result<(u32, [u8; 128])> {
    let info_base = usize::try_from(info_base).context("metadata base does not fit usize")?;
    let layout_b = read_u32(image, info_base + 0x10)? > 0x10000;
    let (start, length, entry_offset, directory_offset) = if layout_b {
        (
            info_base + 0x10,
            0x290usize,
            info_base + 0x20,
            info_base + 0x30,
        )
    } else {
        (
            info_base + 0x40,
            144usize,
            info_base + 0x40,
            info_base + 0x50,
        )
    };
    let original = image
        .get(
            start
                ..start
                    .checked_add(length)
                    .context("metadata end overflows")?,
        )
        .context("metadata record exceeds image")?
        .to_vec();
    transform_shift2_range(
        image,
        u32::try_from(start).context("metadata start exceeds u32")?,
        u32::try_from(length).context("metadata length exceeds u32")?,
    )?;
    let entry = read_u32(image, entry_offset)?;
    let directories: [u8; 128] = image
        .get(directory_offset..directory_offset + 128)
        .context("metadata directories exceed image")?
        .try_into()
        .expect("128-byte metadata directory slice");
    image[start..start + length].copy_from_slice(&original);
    Ok((entry, directories))
}

fn decrypt_file_checksums(image: &mut [u8], stage_start: u32, layout: EighthLayout) -> Result<()> {
    let slot = usize::try_from(
        stage_start
            .checked_add(layout.file_checksums)
            .context("file-checksum slot overflows")?,
    )
    .context("file-checksum slot does not fit usize")?;
    let mut cursor = read_u32(image, slot)?;
    let size = read_u32(image, slot + 4)?;
    if size != 0 {
        ensure!(
            size.is_multiple_of(16),
            "file-checksum table is not record aligned"
        );
        let end = cursor
            .checked_add(size)
            .context("file-checksum table end overflows")?;
        while cursor < end {
            transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32)?;
            cursor += STAGE_DESCRIPTOR_SIZE as u32;
        }
        return Ok(());
    }
    for _ in 0..MAX_STAGE_LIST_ENTRIES {
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32)?;
        if read_u32(
            image,
            usize::try_from(cursor).context("checksum cursor does not fit usize")? + 4,
        )? == 0
        {
            return Ok(());
        }
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("file-checksum cursor overflows")?;
    }
    bail!("file-checksum list exceeds entry budget")
}

fn apply_zero_list(image: &mut [u8], stage_start: u32, layout: EighthLayout) -> Result<()> {
    let slot = usize::try_from(
        stage_start
            .checked_add(layout.zero_list)
            .context("zero-list slot overflows")?,
    )
    .context("zero-list slot does not fit usize")?;
    let mut cursor = read_u32(image, slot)?;
    let mut total = 0usize;
    for _ in 0..MAX_STAGE_LIST_ENTRIES {
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32)?;
        let record = descriptor(
            image,
            usize::try_from(cursor).context("zero-list cursor does not fit usize")?,
        )?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("zero-list cursor overflows")?;
        if record.source_length == 0 {
            return Ok(());
        }
        let range = checked_range(
            image.len(),
            record.source,
            record.source_length,
            "zero-fill range",
        )?;
        total = total
            .checked_add(range.len())
            .context("zero-fill byte count overflows")?;
        ensure!(
            total <= MAX_ZERO_FILL_BYTES,
            "zero-fill list exceeds byte budget"
        );
        image[range].fill(0);
    }
    bail!("zero-fill list exceeds entry budget")
}

fn parse_file_blocks(
    image: &mut [u8],
    stage_start: u32,
    layout: EighthLayout,
    payload_length: usize,
    source_base: u32,
    security_range: Option<&Range<usize>>,
) -> Result<Vec<FileBlock>> {
    let slot = usize::try_from(
        stage_start
            .checked_add(layout.compressed_info)
            .context("compressed-info slot overflows")?,
    )
    .context("compressed-info slot does not fit usize")?;
    let mut cursor = read_u32(image, slot)?;
    let mut blocks = Vec::new();
    let mut replay_work = 0usize;
    for _ in 0..MAX_STAGE_LIST_ENTRIES {
        transform_shift2_range(image, cursor, STAGE_DESCRIPTOR_SIZE as u32)?;
        let record = descriptor(
            image,
            usize::try_from(cursor).context("compressed-info cursor does not fit usize")?,
        )?;
        cursor = cursor
            .checked_add(STAGE_DESCRIPTOR_SIZE as u32)
            .context("compressed-info cursor overflows")?;
        if record.source_length == 0 {
            ensure!(
                !blocks.is_empty(),
                "compressed-info list contains no file blocks"
            );
            return Ok(blocks);
        }
        ensure!(
            record.destination_length != 0,
            "compressed-info record has an empty destination"
        );
        let file_start = source_base
            .checked_add(record.source)
            .context("file-block source offset overflows")?;
        let file_range = checked_range(
            payload_length,
            file_start,
            record.source_length,
            "file-block source",
        )?;
        if let Some(security) = security_range {
            ensure!(
                file_range.end <= security.start || file_range.start >= security.end,
                "file-block source overlaps the PE Security Directory"
            );
        }
        checked_range(
            image.len(),
            record.destination,
            record.destination_length,
            "file-block destination",
        )?;
        replay_work = replay_work
            .checked_add(file_range.len())
            .and_then(|value| value.checked_add(record.destination_length as usize))
            .context("file-block replay work overflows")?;
        ensure!(
            replay_work <= MAX_FILE_REPLAY_WORK,
            "file-block replay exceeds byte budget"
        );
        blocks.push(FileBlock {
            source_offset: file_start,
            source_length: record.source_length,
            destination: record.destination,
            destination_length: record.destination_length,
        });
    }
    bail!("compressed-info list exceeds entry budget")
}

fn replay_file_blocks(
    image: &mut [u8],
    payload_source: &[u8],
    blocks: &[FileBlock],
    aes: &Aes256CbcDecryptor,
    decoder: &[u8],
    map: &[u8; 256],
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let mut payload = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        if index & 0xff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let source = checked_range(
            payload_source.len(),
            block.source_offset,
            block.source_length,
            "file-block source",
        )?;
        payload.clear();
        payload.extend_from_slice(&payload_source[source]);
        aes.decrypt_full_blocks_in_place(&mut payload);
        for byte in &mut payload {
            *byte = map[usize::from(*byte)];
        }
        let destination = checked_range(
            image.len(),
            block.destination,
            block.destination_length,
            "file-block destination",
        )?;
        if block.source_length == block.destination_length {
            image[destination].copy_from_slice(&payload);
        } else {
            let history_start = destination.start.saturating_sub(4);
            let history = image[history_start..destination.start].to_vec();
            decode_custom_stream_with_history(decoder, &payload, &history, &mut image[destination])
                .with_context(|| format!("decoding file block {index}"))?;
        }
    }
    Ok(())
}

struct DestinationCoverage {
    records: Vec<Range<u32>>,
    merged: Vec<Range<u32>>,
}

fn merged_destination_ranges(blocks: &[FileBlock]) -> Result<DestinationCoverage> {
    let mut records = blocks
        .iter()
        .map(|block| {
            let end = block
                .destination
                .checked_add(block.destination_length)
                .context("file-block destination end overflows")?;
            Ok(block.destination..end)
        })
        .collect::<Result<Vec<_>>>()?;
    records.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Range<u32>> = Vec::new();
    for range in &records {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range.clone());
    }
    Ok(DestinationCoverage { records, merged })
}

fn packed_rva_range(pe: &Pe, packed_len: usize, rva: u32, length: u32) -> Result<Range<usize>> {
    if rva < pe.size_of_headers {
        return checked_range(packed_len, rva, length, "packed header RVA");
    }
    let end = rva
        .checked_add(length)
        .context("packed RVA range overflows")?;
    let section = pe
        .sections
        .iter()
        .find(|section| {
            let span = section.virtual_size.max(section.raw_size);
            rva >= section.virtual_address && end <= section.virtual_address.saturating_add(span)
        })
        .context("packed RVA range is not file-backed")?;
    let delta = rva - section.virtual_address;
    let start = section
        .raw_pointer
        .checked_add(delta)
        .context("packed RVA file offset overflows")?;
    checked_range(packed_len, start, length, "packed RVA file range")
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
    let header_length =
        usize::try_from(source.pe.size_of_headers).context("PE header size does not fit usize")?;
    ensure!(
        header_length <= source.packed.len() && header_length <= image.len(),
        "packed PE header exceeds input or mapped image"
    );
    image[..header_length].copy_from_slice(&source.packed[..header_length]);

    for section in &source.pe.sections {
        write_u32(image, section.header_offset + 16, section.virtual_size)?;
        write_u32(image, section.header_offset + 20, section.virtual_address)?;
        if section.name_bytes.starts_with(b".idata") {
            write_u32(image, section.header_offset + 36, 0xc000_0040)?;
        }
    }

    if let Some(export) = source.pe.directories.first().copied()
        && !export.is_empty()
        && let Ok(source_range) = packed_rva_range(
            source.pe,
            source.packed.len(),
            export.virtual_address,
            export.size,
        )
    {
        let destination = checked_range(
            image.len(),
            export.virtual_address,
            export.size,
            "export directory destination",
        )?;
        image[destination].copy_from_slice(&source.packed[source_range]);
    }

    let directory_offset = source.pe.data_directory_table_offset;
    let directory_end = directory_offset
        .checked_add(metadata_directories.len())
        .context("metadata directory table end overflows")?;

    ensure!(
        directory_end <= image.len(),
        "metadata directory table exceeds image"
    );
    image[directory_offset..directory_end].copy_from_slice(metadata_directories);
    if metadata_entry != 0 {
        write_u32(image, source.pe.entry_rva_offset(), metadata_entry)?;
    }

    if !source.pe.is_dll() {
        write_u32(image, directory_offset + 5 * 8, 0)?;
        write_u32(image, directory_offset + 5 * 8 + 4, 0)?;
        write_u16(image, source.pe.opt + 0x46, 0)?;
    }

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
pub(super) fn recognizes_staged_table_payload(source: &BoundPayloadSource<'_>) -> bool {
    decode_info(source)
        .and_then(|info| {
            let image = materialize_bootstrap(source, &info)?;
            find_table(&image, &info)
        })
        .is_ok()
}

pub(super) fn recover_staged_table_payload(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<DecryptedImage> {
    ensure!(
        source.pe.machine_kind() == Machine::I386,
        "staged-table grammar only applies to PE32/I386 images"
    );
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }

    let info_words = decode_info(source)?;
    let mut image = materialize_bootstrap(source, &info_words)?;
    let table = find_table(&image, &info_words)?;
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
    write_u32(&mut image, pe_header + 0xb0, 0)?;
    write_u32(&mut image, pe_header + 0xb4, 0)?;

    let first_stage_checksum = checksum_descriptor(&image, table + 0xa8, &crc_table)?;
    let second_stage_literal = read_u32(&image, table + 0x40)?;
    let second_descriptor = table + 0x98;
    let second = descriptor(&image, second_descriptor)?;
    ensure!(
        second.source_length >= 0xbc0,
        "second-stage length is below the PE32 layout baseline"
    );
    let layout_shift = second.source_length - 0xbc0;
    ensure!(
        layout_shift <= 0x1000,
        "second-stage layout shift is implausible"
    );
    let second_range = checked_range(
        image.len(),
        second.source,
        second.source_length,
        "second-stage ciphertext",
    )?;
    let second_ciphertext = image[second_range.clone()].to_vec();
    let reloc_offset = pe_header + 0xa0;
    let original_reloc = (
        read_u32(&image, reloc_offset)?,
        read_u32(&image, reloc_offset + 4)?,
    );
    let third_pair_relative = 0xb8c_u32
        .checked_add(layout_shift)
        .context("third-stage pair offset overflows")?;
    let mut selected_header_checksum = None;
    for clear_relocations in [false, true] {
        image[second_range.clone()].copy_from_slice(&second_ciphertext);
        write_u32(&mut image, reloc_offset, original_reloc.0)?;
        write_u32(&mut image, reloc_offset + 4, original_reloc.1)?;
        if clear_relocations {
            write_u32(&mut image, reloc_offset, 0)?;
            write_u32(&mut image, reloc_offset + 4, 0)?;
        }
        let mut header_checksum = 0u32;
        let mut cursor = table + 0x58;
        for _ in 0..MAX_STAGE_LIST_ENTRIES {
            if read_u32(&image, cursor + 4)? == 0 {
                break;
            }
            header_checksum ^= checksum_descriptor(&image, cursor, &crc_table)?;
            cursor += 8;
        }
        let key = header_checksum ^ first_stage_checksum ^ second_stage_literal;
        decrypt_dword_descriptor(&mut image, second_descriptor, key, 21)?;
        let pair_offset = usize::try_from(second.source)
            .context("second-stage RVA does not fit usize")?
            .checked_add(third_pair_relative as usize)
            .context("third-stage descriptor offset overflows")?;
        let third = descriptor(&image, pair_offset)?;
        if third.source > 0x1000
            && third.source_length >= 4
            && checked_range(
                image.len(),
                third.source,
                third.source_length,
                "third-stage candidate",
            )
            .is_ok()
        {
            selected_header_checksum = Some(header_checksum);
            break;
        }
    }
    let header_checksum =
        selected_header_checksum.context("no header checksum decrypts the second stage")?;

    let third_key_offset = 0x968_u32 + layout_shift;
    let fourth_key_offset = 0x964_u32 + layout_shift;
    let checksum_base_offset = 0x96c_u32 + layout_shift;
    let descriptor_base_offset = 0xa9c_u32 + layout_shift;
    let second_start =
        usize::try_from(second.source).context("second-stage RVA does not fit usize")?;
    let third_descriptor = second_start + third_pair_relative as usize;
    let third = descriptor(&image, third_descriptor)?;
    let third_ciphertext_range = checked_range(
        image.len(),
        third.source,
        third.source_length,
        "third-stage ciphertext",
    )?;
    let third_ciphertext = image[third_ciphertext_range.clone()].to_vec();
    let third_key = read_u32(&image, second_start + third_key_offset as usize)?;
    let mut info_table = None;
    for rotation in [19u32, 21, 17, 23, 15, 25, 13, 11] {
        image[third_ciphertext_range.clone()].copy_from_slice(&third_ciphertext);
        decrypt_dword_descriptor(&mut image, third_descriptor, third_key, rotation)?;
        for relative in (0..third.source_length.saturating_sub(32) as usize).step_by(4) {
            let at = third_ciphertext_range.start + relative;
            let first_kind = read_u32(&image, at)?;
            let second_kind = read_u32(&image, at + 16)?;
            let pointed = read_u32(&image, at + 4)?;
            if matches!(first_kind, 1 | 0x11)
                && second_kind == 2
                && pointed > 0x1000
                && usize::try_from(pointed).is_ok_and(|value| value < image.len())
            {
                info_table = Some(at);
                break;
            }
        }
        if info_table.is_some() {
            break;
        }
    }
    let info_table = info_table.context("no rotate profile reveals the PE32 third-stage table")?;
    ensure!(info_table >= 0x58, "third-stage key table underflows");
    let keys_address = info_table - 0x58;

    for index in 0..2usize {
        let at = info_table + index * 16;
        match read_u32(&image, at)? {
            1 | 0x11 => transform_shift3_descriptor(&mut image, at + 4)?,
            2 => {
                let list = read_u32(&image, at + 4)?;
                copy_stage_list(&mut image, list)?;
            }
            kind => bail!("unsupported third-stage table operation {kind:#x}"),
        }
    }

    let mut key_offsets = [0u32; 4];
    for group in 0..2usize {
        for index in 0..2usize {
            let at = keys_address + group * 32 + index * 8;
            transform_shift3_descriptor(&mut image, at)?;
            key_offsets[group * 2 + index] = read_u32(&image, at)?;
        }
    }
    let file_decoder_table = snapshot_decoder_table(&image, key_offsets[0])?;
    let stage_decoder_table = snapshot_decoder_table(&image, key_offsets[1])?;
    let (file_raw_aes_key, file_aes) = recover_aes(&image, key_offsets[2])?;
    let (stage_raw_aes_key, stage_aes) = recover_aes(&image, key_offsets[3])?;

    let second_checksum = checksum_descriptor(&image, table + 0xb0, &crc_table)?;
    let checksum_base = second_start + checksum_base_offset as usize;
    let descriptor_base = second_start + descriptor_base_offset as usize;
    let fourth_key = advance_key(
        read_u32(&image, second_start + fourth_key_offset as usize)?,
        4,
    );
    decrypt_stage(
        &mut image,
        descriptor_base + 0x40,
        header_checksum ^ second_checksum ^ fourth_key,
        &stage_aes,
        &stage_decoder_table,
        None,
    )?;

    let fourth_checksum = checksum_descriptor(&image, checksum_base, &crc_table)?;
    let fourth_checksum_record = descriptor(&image, checksum_base)?;
    ensure!(
        fourth_checksum_record.source_length >= 4,
        "fourth-stage checksum range is too short"
    );
    let fifth_literal_offset = fourth_checksum_record
        .source
        .checked_add(fourth_checksum_record.source_length)
        .and_then(|value| value.checked_sub(4))
        .context("fifth-stage literal address underflows")?;
    let fifth_literal = read_u32(
        &image,
        usize::try_from(fifth_literal_offset)
            .context("fifth-stage literal RVA does not fit usize")?,
    )?;
    decrypt_stage(
        &mut image,
        descriptor_base + 0x50,
        header_checksum ^ fourth_checksum ^ fifth_literal,
        &stage_aes,
        &stage_decoder_table,
        None,
    )?;

    let fifth_checksum = checksum_descriptor(&image, checksum_base + 8, &crc_table)?;
    let fifth_checksum_record = descriptor(&image, checksum_base + 8)?;
    ensure!(
        fifth_checksum_record.source_length >= 0x10,
        "fifth-stage checksum range is too short"
    );
    let seven_literal_offset = fifth_checksum_record
        .source
        .checked_add(fifth_checksum_record.source_length)
        .and_then(|value| value.checked_sub(0x10))
        .context("seven-stage literal address underflows")?;
    let seven_literal = !read_u32(
        &image,
        usize::try_from(seven_literal_offset)
            .context("seven-stage literal RVA does not fit usize")?,
    )?;
    let seven_descriptor = descriptor_base + 0x70;
    let seven = descriptor(&image, seven_descriptor)?;
    decrypt_stage(
        &mut image,
        seven_descriptor,
        header_checksum ^ fifth_checksum ^ seven_literal,
        &stage_aes,
        &stage_decoder_table,
        None,
    )?;

    let seven_range = checked_range(
        image.len(),
        seven.source,
        seven.destination_length,
        "decoded seven stage",
    )?;
    let custom_programs = lfsr_al_map_candidates(&image[seven_range.clone()]);
    ensure!(
        !custom_programs.is_empty(),
        "seven stage contains no LFSR AL programs"
    );
    let key_offsets_in_stage = eighth_key_offsets(
        &image,
        seven.source,
        seven.destination_length,
        &custom_programs,
    )?;
    ensure!(
        !key_offsets_in_stage.is_empty(),
        "seven stage contains no eighth-stage key candidates"
    );

    let seven_checksum = checksum_descriptor(&image, checksum_base + 0x10, &crc_table)?;
    let eighth_descriptor = descriptor_base + 0xc0;
    let eighth = descriptor(&image, eighth_descriptor)?;
    let eighth_backups = stage_backups(&image, eighth_descriptor)?;
    let mut attempts = 0usize;
    let mut seen = HashSet::new();
    let mut winners = Vec::new();
    for (map_index, program) in custom_programs.iter().enumerate() {
        for &relative_key in &key_offsets_in_stage {
            attempts = attempts
                .checked_add(1)
                .context("eighth-stage attempt count overflows")?;
            ensure!(
                attempts <= MAX_EIGHTH_STAGE_ATTEMPTS,
                "eighth-stage replay exceeds attempt budget"
            );
            let key_offset = usize::try_from(seven.source)
                .context("seven-stage RVA does not fit usize")?
                + relative_key as usize;
            let key = header_checksum
                ^ fifth_checksum
                ^ seven_checksum
                ^ advance_key(read_u32(&image, key_offset)?, 3);
            if !seen.insert((map_index, key)) {
                continue;
            }
            restore_backups(&mut image, &eighth_backups);
            if decrypt_stage(
                &mut image,
                eighth_descriptor,
                key,
                &stage_aes,
                &stage_decoder_table,
                Some(program.map.as_ref()),
            )
            .is_ok()
                && find_eighth_layout(
                    &image,
                    eighth.source,
                    eighth.destination_length,
                    info_words[3],
                )
                .is_ok()
            {
                winners.push((map_index, key));
            }
        }
    }
    restore_backups(&mut image, &eighth_backups);
    winners.sort_unstable();
    winners.dedup();
    ensure!(
        winners.len() == 1,
        "expected one authenticated eighth-stage replay, found {}",
        winners.len()
    );
    let (custom_map_index, eighth_key) = winners[0];
    decrypt_stage(
        &mut image,
        eighth_descriptor,
        eighth_key,
        &stage_aes,
        &stage_decoder_table,
        Some(custom_programs[custom_map_index].map.as_ref()),
    )?;

    let layout = find_eighth_layout(
        &image,
        eighth.source,
        eighth.destination_length,
        info_words[3],
    )?;
    let eighth_range = checked_range(
        image.len(),
        eighth.source,
        eighth.destination_length,
        "decoded eighth stage",
    )?;
    let file_programs = lfsr_al_map_candidates(&image[eighth_range.clone()])
        .into_iter()
        .filter(|candidate| candidate.offset >= layout.zero_list as usize)
        .collect::<Vec<_>>();
    ensure!(
        !file_programs.is_empty(),
        "eighth stage contains no file byte-map programs"
    );
    let (metadata_entry, metadata_directories) = extract_metadata(&mut image, info_words[3])?;
    decrypt_file_checksums(&mut image, eighth.source, layout)?;
    apply_zero_list(&mut image, eighth.source, layout)?;

    let compression_key_offset = source
        .bootstrap
        .descriptor_file_offset
        .checked_add(0x80)
        .context("compressed-data key offset overflows")?;
    let source_base = (!read_u32(source.payload_source, compression_key_offset)?).wrapping_add(
        u32::try_from(source.bootstrap.descriptor_file_offset)
            .context("descriptor file offset exceeds u32")?,
    );
    let blocks = parse_file_blocks(
        &mut image,
        eighth.source,
        layout,
        source.payload_source.len(),
        source_base,
        source.source_security_range,
    )?;
    let replay_base = image.clone();
    let mut selected_file_map = None;
    let mut rejection_evidence = Vec::new();
    for (index, program) in file_programs.iter().enumerate() {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        let mut trial = replay_base.clone();
        match replay_file_blocks(
            &mut trial,
            source.payload_source,
            &blocks,
            &file_aes,
            &file_decoder_table,
            program.map.as_ref(),
            cancellation,
        ) {
            Ok(()) => {
                ensure!(
                    selected_file_map.is_none(),
                    "multiple staged file byte maps replay every block"
                );
                selected_file_map = Some(index);
            }
            Err(error) => {
                let reason = format!("{error:#}");
                debug!(
                    program_offset = program.offset,
                    program_length = program.length,
                    reason,
                    "rejected staged file byte map"
                );
                if rejection_evidence.len() < 8 {
                    rejection_evidence.push(format!(
                        "+{:#x}/{}: {reason}",
                        program.offset, program.length
                    ));
                }
            }
        }
    }
    let selected_file_map = selected_file_map.with_context(|| {
        format!(
            "no staged file byte map replays every block ({} candidates: {})",
            file_programs.len(),
            rejection_evidence.join("; ")
        )
    })?;
    image = replay_base;
    replay_file_blocks(
        &mut image,
        source.payload_source,
        &blocks,
        &file_aes,
        &file_decoder_table,
        file_programs[selected_file_map].map.as_ref(),
        cancellation,
    )?;
    finalize_header(&mut image, source, metadata_entry, &metadata_directories)?;

    let DestinationCoverage {
        records: destination_record_ranges,
        merged: destination_ranges,
    } = merged_destination_ranges(&blocks)?;
    let copied_chunk_count = blocks
        .iter()
        .filter(|block| block.source_length == block.destination_length)
        .count();
    info!(
        table_rva = table,
        seven_stage_rva = seven.source,
        eighth_stage_rva = eighth.source,
        custom_program_offset = custom_programs[custom_map_index].offset,
        file_program_offset = file_programs[selected_file_map].offset,
        file_program_length = file_programs[selected_file_map].length,
        byte_map_candidates = file_programs.len(),
        chunks = blocks.len(),
        "selected static PE32 staged byte-map pipeline"
    );
    debug!(
        stage_raw_aes_key = %hex::encode(stage_raw_aes_key),
        file_raw_aes_key = %hex::encode(file_raw_aes_key),
        "recovered staged AES-256 keys"
    );
    Ok(DecryptedImage {
        destination_record_ranges,
        destination_ranges,
        image,
        decryption_details: DecryptionDetails {
            payload_grammar: None,
            selected_stream: None,
            chunk_count: blocks.len(),
            copied_chunk_count,
            decoded_chunk_count: blocks.len() - copied_chunk_count,
            aes_key_candidates: 1,
            decoder_candidates: 1,
            byte_transform_candidates: file_programs.len(),
            selected_chain: None,
            selected_staged_table: Some(SelectedStagedTable {
                shell_table_rva: u32::try_from(table).context("shell table RVA exceeds u32")?,
                seven_stage_rva: seven.source,
                eighth_stage_rva: eighth.source,
                file_decoder_rva: key_offsets[0],
                stage_decoder_rva: key_offsets[1],
                file_aes_context_rva: key_offsets[2],
                stage_aes_context_rva: key_offsets[3],
                file_raw_key_hex: hex::encode(file_raw_aes_key),
                stage_raw_key_hex: hex::encode(stage_raw_aes_key),
                custom_program_offset: custom_programs[custom_map_index].offset,
                custom_program_length: custom_programs[custom_map_index].length,
                custom_byte_map: custom_programs[custom_map_index].map.to_vec(),
                file_program_offset: file_programs[selected_file_map].offset,
                file_program_length: file_programs[selected_file_map].length,
                file_byte_map: file_programs[selected_file_map].map.to_vec(),
            }),
        },
    })
}
