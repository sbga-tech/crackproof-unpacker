use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pe::Pe;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::stages::payload::nested::{
    LfsrAlMapCandidate, crackproof_checksum, lfsr_al_map_at_start,
};
use crate::util::bytes::{
    checked_u32_range as checked_range, read_u16, read_u32, write_u16, write_u32,
};

use super::super::aes::{
    AES_CONTEXT_HEADER, AES_DECRYPT_SCHEDULE_SIZE, Aes256CbcDecryptor,
    make_openssl_decrypt_schedule, recover_raw_key,
};
use super::super::decoder::decode_custom_stream_with_history;
use super::super::source::BoundPayloadSource;

pub(super) const KONN_MAGIC: u32 = u32::from_le_bytes(*b"KONN");
pub(super) const STAGE_DESCRIPTOR_SIZE: usize = 16;
pub(super) const MAX_STAGE_LIST_ENTRIES: usize = 1 << 20;
const HEADER_COPY_SIZE: usize = 0x1000;

pub(super) type KonnInfo = [u32; 8];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StageDescriptor {
    pub(super) source: u32,
    pub(super) source_length: u32,
    pub(super) destination: u32,
    pub(super) destination_length: u32,
}

pub(super) fn read_stage_descriptor(data: &[u8], offset: usize) -> Result<StageDescriptor> {
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

pub(super) fn decode_konn_info(source: &BoundPayloadSource<'_>) -> Result<[u32; 8]> {
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
    ensure!(
        info[1] == KONN_MAGIC,
        "PE32 payload-manifest controller table key header is not KONN"
    );
    ensure!(
        info[2] == source.pe.entry_rva
            && info[3] == source.bootstrap.destination_rva
            && info[4] == source.bootstrap.source_offset
            && info[5] == source.bootstrap.length,
        "PE32 payload-manifest controller header disagrees with the selected KONN descriptor"
    );
    Ok(info)
}

pub(super) fn materialize_konn_bootstrap(
    source: &BoundPayloadSource<'_>,
    info: &[u32; 8],
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<u8>> {
    let image_length = usize::try_from(source.pe.size_of_image)
        .context("controller image size does not fit host address space")?;
    let mut image = vec![0u8; image_length];
    let decrypt_length = info[6]
        .checked_sub(info[3])
        .context("controller shell end precedes destination")?
        .checked_add(0x2000)
        .context("controller bootstrap decrypt length overflows")?;
    ensure!(
        decrypt_length <= info[5] && decrypt_length.is_multiple_of(4),
        "controller bootstrap decrypt span is invalid"
    );

    let source_start = source
        .bootstrap
        .descriptor_file_offset
        .checked_add(
            usize::try_from(info[4]).context("controller source offset does not fit usize")?,
        )
        .context("controller source start overflows")?;
    let source_range = source
        .payload_source
        .get(
            source_start
                ..source_start
                    .checked_add(
                        usize::try_from(info[5])
                            .context("controller source length does not fit usize")?,
                    )
                    .context("controller source end overflows")?,
        )
        .context("controller bootstrap source exceeds payload source")?;
    let destination =
        usize::try_from(info[3]).context("controller destination does not fit usize")?;
    let destination_end = destination
        .checked_add(source_range.len())
        .context("controller destination end overflows")?;
    ensure!(
        destination_end <= image.len(),
        "controller bootstrap destination exceeds image"
    );

    let encrypted_length =
        usize::try_from(decrypt_length).context("controller decrypt length does not fit usize")?;
    let mut state = info[0].wrapping_sub(decrypt_length).wrapping_sub(1);
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    for (index, ciphertext) in source_range[..encrypted_length].chunks_exact(4).enumerate() {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let ciphertext = u32::from_le_bytes(ciphertext.try_into().expect("dword bootstrap chunk"));
        let output = ciphertext ^ state;
        let at = destination + index * 4;
        image[at..at + 4].copy_from_slice(&output.to_le_bytes());
        let index = u32::try_from(index).context("controller bootstrap word index exceeds u32")?;
        state = state.wrapping_add(ciphertext).wrapping_add(index) ^ index.wrapping_mul(index);
    }
    image[destination + encrypted_length..destination_end]
        .copy_from_slice(&source_range[encrypted_length..]);

    let header_length = HEADER_COPY_SIZE.min(source.packed.len()).min(image.len());
    ensure!(
        header_length == HEADER_COPY_SIZE,
        "controller PE lacks a complete 4 KiB header"
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

pub(super) fn checksum_descriptor(image: &[u8], offset: usize, table: &[u32; 256]) -> Result<u32> {
    let start = read_u32(image, offset)?;
    let length = read_u32(image, offset + 4)?;
    let range = checked_range(image.len(), start, length, "checksum input")?;
    Ok(crackproof_checksum(&image[range], table))
}

pub(super) fn decrypt_rotating_dword_descriptor(
    image: &mut [u8],
    descriptor_offset: usize,
    mut key: u32,
    rotation: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let stage = read_stage_descriptor(image, descriptor_offset)?;
    let range = checked_range(
        image.len(),
        stage.source,
        stage.source_length,
        "dword stage",
    )?;
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    for (index, word) in image[range].chunks_exact_mut(4).enumerate() {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let ciphertext = u32::from_le_bytes(word.try_into().expect("dword stage chunk"));
        let index = u32::try_from(index).context("dword stage index exceeds u32")?;
        let plaintext = (ciphertext ^ key)
            .rotate_right(rotation)
            .wrapping_sub(index);
        key = key.wrapping_add(index);
        word.copy_from_slice(&plaintext.to_le_bytes());
    }
    Ok(())
}

pub(super) fn transform_rotating_bytes(
    image: &mut [u8],
    start: u32,
    length: u32,
    rotation: u32,
    seed: u8,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let range = checked_range(image.len(), start, length, "rotating byte transform")?;
    let mut first_key = seed;
    let mut second_key = seed.wrapping_add(1);
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    for (index, value) in image[range].iter_mut().enumerate() {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let first = value.rotate_left(rotation) ^ second_key;
        let second = first.rotate_left(rotation) ^ first_key;
        *value = second.rotate_left(rotation);
        first_key = first_key.wrapping_add(1);
        second_key = second_key.wrapping_add(1);
    }
    Ok(())
}

pub(super) fn transform_shift3_descriptor(
    image: &mut [u8],
    offset: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let start = read_u32(image, offset)?;
    let length = read_u32(image, offset + 4)?;
    let seed = start.wrapping_add(start >> 8) as u8;
    transform_rotating_bytes(image, start, length, 3, seed, cancellation)
}

pub(super) fn transform_shift2_range(
    image: &mut [u8],
    start: u32,
    length: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    transform_rotating_bytes(image, start, length, 2, start as u8, cancellation)
}

pub(super) fn copy_stage_list(
    image: &mut [u8],
    mut offset: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    for index in 0..MAX_STAGE_LIST_ENTRIES {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        transform_shift2_range(image, offset, STAGE_DESCRIPTOR_SIZE as u32, cancellation)?;
        let record = read_stage_descriptor(
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
            "controller copy record is malformed"
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
    bail!("controller copy list exceeds entry budget")
}

pub(super) fn recover_aes_context(
    image: &[u8],
    offset: u32,
) -> Result<([u8; 32], Aes256CbcDecryptor)> {
    let offset = usize::try_from(offset).context("AES context RVA does not fit usize")?;
    let context_length = AES_CONTEXT_HEADER.len() + AES_DECRYPT_SCHEDULE_SIZE;
    let context = image
        .get(
            offset
                ..offset
                    .checked_add(context_length)
                    .context("AES context end overflows")?,
        )
        .context("AES context exceeds controller image")?;
    ensure!(
        context[..AES_CONTEXT_HEADER.len()] == AES_CONTEXT_HEADER,
        "controller AES context has the wrong header"
    );
    let schedule: [u8; AES_DECRYPT_SCHEDULE_SIZE] = context[AES_CONTEXT_HEADER.len()..]
        .try_into()
        .expect("bounded AES schedule");
    let raw_key = recover_raw_key(&schedule);
    ensure!(
        make_openssl_decrypt_schedule(&raw_key) == schedule,
        "controller AES schedule does not invert to a valid AES-256 key"
    );
    Ok((raw_key, Aes256CbcDecryptor::new(&raw_key)))
}

pub(super) fn snapshot_decoder_table(image: &[u8], offset: u32) -> Result<Vec<u8>> {
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
        .context("decoder table exceeds controller image")?
        .to_vec())
}

pub(super) fn decrypt_stage(
    image: &mut [u8],
    descriptor_offset: usize,
    key: u32,
    aes: &Aes256CbcDecryptor,
    decoder: &[u8],
    map: Option<&[u8; 256]>,
    cancellation: Option<&CancellationToken>,
) -> Result<()> {
    let stage = read_stage_descriptor(image, descriptor_offset)?;
    let source_range = checked_range(
        image.len(),
        stage.source,
        stage.source_length,
        "stage source",
    )?;
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    aes.decrypt_full_blocks_in_place(&mut image[source_range.clone()]);
    let mut rolling_key = key;
    for (index, word) in image[source_range.clone()].chunks_exact_mut(4).enumerate() {
        if index & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let ciphertext = u32::from_le_bytes(word.try_into().expect("stage dword"));
        let index = u32::try_from(index).context("stage dword index exceeds u32")?;
        let plaintext = (ciphertext ^ rolling_key)
            .rotate_right(19)
            .wrapping_sub(index);
        word.copy_from_slice(&plaintext.to_le_bytes());
        rolling_key = rolling_key.wrapping_add(index);
    }
    if let Some(map) = map {
        for (index, byte) in image[source_range.clone()].iter_mut().enumerate() {
            if index & 0x3fff == 0
                && let Some(cancellation) = cancellation
            {
                cancellation.checkpoint()?;
            }
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
        .context("decoding controller Huffman/LZ stream")?;
    Ok(())
}

pub(super) fn advance_key(mut key: u32, iterations: u32) -> u32 {
    for iteration in 0..iterations {
        let bound = (iteration + 1).wrapping_mul(25) << 2;
        for value in 1..=bound {
            key = key.wrapping_add(value);
        }
    }
    key
}

pub(super) fn extract_metadata(
    image: &mut [u8],
    info_base: u32,
    cancellation: Option<&CancellationToken>,
) -> Result<(u32, [u8; 128])> {
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
        cancellation,
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

pub(super) fn packed_rva_range(
    pe: &Pe,
    packed_len: usize,
    rva: u32,
    length: u32,
) -> Result<Range<usize>> {
    let end = rva
        .checked_add(length)
        .context("packed RVA range overflows")?;
    if rva < pe.size_of_headers {
        ensure!(
            end <= pe.size_of_headers,
            "packed header RVA range is not fully header-backed"
        );
        return checked_range(packed_len, rva, length, "packed header RVA");
    }
    let section = pe
        .sections
        .iter()
        .find(|section| {
            section
                .virtual_address
                .checked_add(section.raw_size)
                .is_some_and(|raw_end| rva >= section.virtual_address && end <= raw_end)
        })
        .context("packed RVA range is not fully raw-file-backed")?;
    let delta = rva - section.virtual_address;
    let start = section
        .raw_pointer
        .checked_add(delta)
        .context("packed RVA file offset overflows")?;
    checked_range(packed_len, start, length, "packed RVA file range")
}

pub(super) fn restore_common_mapped_header(
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
    Ok(())
}

pub(super) fn exact_lfsr_al_map(
    image: &[u8],
    program_rva: u32,
    window_length: u32,
    label: &str,
) -> Result<LfsrAlMapCandidate> {
    let range = checked_range(image.len(), program_rva, window_length, label)?;
    let program_start = range.start;
    let program_window_length = range.len();
    let mut candidate = lfsr_al_map_at_start(&image[range])
        .with_context(|| format!("{label} does not begin with an LFSR AL byte-map program"))?;
    ensure!(
        candidate.offset == 0,
        "{label} exact parser returned an unrooted LFSR AL byte-map program"
    );
    ensure!(
        candidate.length <= program_window_length,
        "{label} LFSR AL byte-map program exceeds its producer-owned span"
    );
    candidate.offset = program_start;
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PointerWidth;
    use crate::pipeline::stages::imports::test_support::{section, synthetic_pe};
    use crate::pipeline::stages::payload::nested::{MAX_AL_PROGRAM_BYTES, lfsr_decode_program};

    #[test]
    fn packed_rva_range_rejects_virtual_zero_fill() {
        let mut mapped_section = section(0, 0x1000, 0x1000);
        mapped_section.raw_size = 0x100;
        mapped_section.raw_pointer = 0x400;
        let pe = synthetic_pe(0x2000, vec![mapped_section], PointerWidth::U32);

        assert!(packed_rva_range(&pe, 0x1000, 0x1100, 1).is_err());
    }

    #[test]
    fn packed_rva_range_rejects_header_to_section_span() {
        let pe = synthetic_pe(0x2000, vec![section(0, 0x1000, 0x100)], PointerWidth::U32);

        assert!(packed_rva_range(&pe, 0x2000, 0x3ff, 2).is_err());
    }

    #[test]
    fn exact_lfsr_al_map_rejects_a_program_before_the_rooted_start() {
        let mut decoded = [0u8; MAX_AL_PROGRAM_BYTES];
        decoded[..8].copy_from_slice(&[0x04, 1, 0x2c, 2, 0x34, 3, 0x90, 0xc3]);
        let encoded = lfsr_decode_program(&decoded);
        let mut image = vec![0u8; MAX_AL_PROGRAM_BYTES + 1];
        image[0] = lfsr_decode_program(&[0])[0] ^ 0xff;
        image[1..].copy_from_slice(&encoded);

        assert!(
            exact_lfsr_al_map(&image, 0, MAX_AL_PROGRAM_BYTES as u32, "wrong rooted span").is_err()
        );
    }

    #[test]
    fn exact_lfsr_al_map_reports_the_producer_rooted_rva() {
        let mut decoded = [0u8; MAX_AL_PROGRAM_BYTES];
        decoded[..8].copy_from_slice(&[0x04, 1, 0x2c, 2, 0x34, 3, 0x90, 0xc3]);
        let encoded = lfsr_decode_program(&decoded);
        let mut image = vec![0u8; MAX_AL_PROGRAM_BYTES + 3];
        image[3..].copy_from_slice(&encoded);

        let candidate =
            exact_lfsr_al_map(&image, 3, MAX_AL_PROGRAM_BYTES as u32, "rooted span").unwrap();

        assert_eq!(candidate.offset, 3);
    }

    #[test]
    fn exact_lfsr_al_map_rejects_a_program_truncated_by_its_rooted_window() {
        let mut decoded = [0u8; MAX_AL_PROGRAM_BYTES];
        decoded[..8].copy_from_slice(&[0x04, 1, 0x2c, 2, 0x34, 3, 0x90, 0xc3]);
        let encoded = lfsr_decode_program(&decoded);

        assert!(exact_lfsr_al_map(&encoded, 0, 7, "truncated rooted span").is_err());
    }
}
