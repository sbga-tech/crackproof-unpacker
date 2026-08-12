use std::ops::Range;

use super::decoder::CustomDecoderSource;
use super::grammar::{
    BoundPayloadSource, derive_payload_stream_provenance, select_payload_grammar,
};
use super::replay::NestedTransformedSource;
use super::*;
use crate::pe::{DataDirectory, Machine, Pe, Section};
use crate::pipeline::stages::payload::bootstrap::{
    MAX_OUTER_SOURCE_BYTES, OUTER_ENCRYPTED_PREFIX_RVA_BIAS, PackedBootstrap,
    bootstrap_source_file_range, derive_outer_source,
};
use crate::pipeline::stages::payload::nested::{
    MAX_AL_PROGRAM_BYTES, amd64_runtime_header_checksums, crackproof_checksum, crc32_table,
    lfsr_al_map_candidates, lfsr_al_maps, lfsr_decode_program, nested_transform_dwords_into,
    parse_al_byte_map,
};
use crate::pipeline::stages::startup::{
    SparsePageKey, decode_sparse_text_pages_in_place, unique_sparse_page_keys,
};
use ::aes::Aes256;
use ::aes::cipher::{Block, BlockEncrypt, KeyInit};
use libmwemu::{emu32, maps::mem64::Permission};
const SPARSE_PAGE_SIZE: usize = 0x1000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
fn lfsr_encode_program(program: &[u8]) -> [u8; MAX_AL_PROGRAM_BYTES] {
    let mut plaintext = [0u8; MAX_AL_PROGRAM_BYTES];
    plaintext[..program.len()].copy_from_slice(program);
    lfsr_decode_program(&plaintext)
}

fn bound_fixture_source<'a>(packed: &'a [u8], pe: &'a Pe) -> BoundPayloadSource<'a> {
    let family = crate::pipeline::stages::detect::detect_family(packed, pe).unwrap();
    let bootstrap = PackedBootstrap::from(&family.descriptor);
    let source_file_range = bootstrap_source_file_range(packed, bootstrap).unwrap();
    let (source_start, outer) = derive_outer_source(packed, bootstrap).unwrap();
    let stream =
        derive_payload_stream_provenance(packed, bootstrap, &source_file_range, None).unwrap();
    BoundPayloadSource {
        packed,
        pe,
        payload_source: packed,
        bootstrap,
        source_security_range: None,
        source_file_range,
        source_start,
        stream,
        outer,
    }
}

#[test]
fn shallow_staged_shape_does_not_preempt_a_record_authentication() {
    let packed = include_bytes!("../../../../../packed/chusanApp_2.25.exe");
    let pe = Pe::parse(packed).unwrap();
    let source = bound_fixture_source(packed, &pe);
    assert!(super::staged::recognizes_staged_table_payload(&source));

    let recovered = select_payload_grammar(&source, None).unwrap();
    assert_eq!(
        recovered.decryption_details.payload_grammar,
        Some(crate::pipeline::outcome::PayloadGrammar::ARecord)
    );
    assert_eq!(recovered.decryption_details.chunk_count, 7_485);
    assert!(recovered.decryption_details.selected_staged_table.is_none());
}

#[test]
fn complete_staged_table_replay_remains_authoritative() {
    let packed = include_bytes!("../../../../../packed/maimai_SDEY_1.99.exe");
    let pe = Pe::parse(packed).unwrap();
    let source = bound_fixture_source(packed, &pe);
    assert!(super::staged::recognizes_staged_table_payload(&source));

    let recovered = select_payload_grammar(&source, None).unwrap();
    assert_eq!(
        recovered.decryption_details.payload_grammar,
        Some(crate::pipeline::outcome::PayloadGrammar::StagedTable)
    );
    assert_eq!(recovered.decryption_details.chunk_count, 2_264);
    assert!(recovered.decryption_details.selected_staged_table.is_some());
}

#[test]
fn complete_staged_table_replay_wins_a_record_overlap() {
    let packed = include_bytes!("../../../../../packed/chusanApp_2.50.exe");
    let pe = Pe::parse(packed).unwrap();
    let source = bound_fixture_source(packed, &pe);
    assert!(super::staged::recognizes_staged_table_payload(&source));

    let recovered = select_payload_grammar(&source, None).unwrap();
    assert_eq!(
        recovered.decryption_details.payload_grammar,
        Some(crate::pipeline::outcome::PayloadGrammar::StagedTable)
    );
    assert!(recovered.decryption_details.selected_staged_table.is_some());
}

#[test]
fn sparse_text_page_decoder_matches_all_key_profiles_and_is_involutive() {
    let text = Section {
        index: 0,
        header_offset: 0,
        name_bytes: *b".text\0\0\0",
        virtual_size: SPARSE_PAGE_SIZE as u32,
        virtual_address: SPARSE_PAGE_SIZE as u32,
        raw_size: SPARSE_PAGE_SIZE as u32,
        raw_pointer: 0,
        characteristics: IMAGE_SCN_MEM_EXECUTE,
    };
    let pe = Pe {
        opt: 0,
        machine: Machine::Amd64,
        coff_characteristics: 0,
        section_count: 1,
        entry_rva: text.virtual_address,
        image_base: 0x0000_0001_4000_0000,
        section_alignment: SPARSE_PAGE_SIZE as u32,
        file_alignment: 0x200,
        size_of_image: (2 * SPARSE_PAGE_SIZE) as u32,
        size_of_headers: 0x200,
        checksum_offset: 0,
        data_directory_table_offset: 0,
        directories: vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ],
        sections: vec![text],
        file_len: 0,
    };
    let original = (0..2 * SPARSE_PAGE_SIZE)
        .map(|offset| offset as u8)
        .collect::<Vec<_>>();

    let mut page_index = original.clone();
    decode_sparse_text_pages_in_place(&mut page_index, &pe, SparsePageKey::PageIndex).unwrap();
    assert_eq!(page_index[0x1015], original[0x1015] ^ 0x06);
    assert_eq!(page_index[0x1022], original[0x1022] ^ 0x04);
    assert_eq!(&page_index[..0x1000], &original[..0x1000]);
    decode_sparse_text_pages_in_place(&mut page_index, &pe, SparsePageKey::PageIndex).unwrap();
    assert_eq!(page_index, original);

    let mut masked_page_rva = original.clone();
    decode_sparse_text_pages_in_place(
        &mut masked_page_rva,
        &pe,
        SparsePageKey::PageRvaOrTextSizeMask,
    )
    .unwrap();
    assert_eq!(masked_page_rva[0x101d], original[0x101d] ^ 0xfe);
    assert_eq!(masked_page_rva[0x1022], original[0x1022] ^ 0x04);
    decode_sparse_text_pages_in_place(
        &mut masked_page_rva,
        &pe,
        SparsePageKey::PageRvaOrTextSizeMask,
    )
    .unwrap();
    assert_eq!(masked_page_rva, original);

    let mut rotated_page_rva = original.clone();
    decode_sparse_text_pages_in_place(&mut rotated_page_rva, &pe, SparsePageKey::PageRvaRol(3))
        .unwrap();
    assert_eq!(rotated_page_rva[0x1001], original[0x1001]);
    assert_eq!(rotated_page_rva[0x1011], original[0x1011] ^ 0x02);
    assert_eq!(rotated_page_rva[0x1026], original[0x1026] ^ 0x08);
    decode_sparse_text_pages_in_place(&mut rotated_page_rva, &pe, SparsePageKey::PageRvaRol(3))
        .unwrap();
    assert_eq!(rotated_page_rva, original);

    let profiles = unique_sparse_page_keys(&pe).unwrap();
    assert!(profiles.contains(&SparsePageKey::PageIndex));
    assert!(!profiles.contains(&SparsePageKey::PageRvaRol(20)));
    let mut rotated_twenty = original.clone();
    decode_sparse_text_pages_in_place(&mut rotated_twenty, &pe, SparsePageKey::PageRvaRol(20))
        .unwrap();
    let mut indexed_once = original.clone();
    decode_sparse_text_pages_in_place(&mut indexed_once, &pe, SparsePageKey::PageIndex).unwrap();
    assert_eq!(rotated_twenty, indexed_once);
}

#[test]
fn amd64_runtime_header_checksum_comes_from_nested_metadata() {
    let mut directories = vec![
        DataDirectory {
            virtual_address: 0,
            size: 0,
        };
        16
    ];
    directories[1] = DataDirectory {
        virtual_address: 0x5000,
        size: 0x28,
    };
    directories[2] = DataDirectory {
        virtual_address: 0x6000,
        size: 0x1d8,
    };
    directories[5] = DataDirectory {
        virtual_address: 0x7000,
        size: 8,
    };
    let pe = Pe {
        opt: 0x140,
        machine: Machine::Amd64,
        coff_characteristics: 0,
        section_count: 1,
        entry_rva: 0x1000,
        image_base: 0x0000_0001_4000_0000,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: 0x8000,
        size_of_headers: 0x400,
        checksum_offset: 0x180,
        data_directory_table_offset: 0x1b0,
        directories,
        sections: vec![Section {
            index: 0,
            header_offset: 0x240,
            name_bytes: *b".data\0\0\0",
            virtual_size: 0x5000,
            virtual_address: 0x2000,
            raw_size: 0x5000,
            raw_pointer: 0x400,
            characteristics: 0,
        }],
        file_len: 0,
    };
    let mut mapped = (0..usize::try_from(pe.size_of_image).unwrap())
        .map(|offset| offset.wrapping_mul(37) as u8)
        .collect::<Vec<_>>();
    let directory_base = pe.number_of_rva_and_sizes_offset() + 4;
    for (index, directory) in pe.directories.iter().enumerate() {
        let offset = directory_base + index * 8;
        mapped[offset..offset + 4].copy_from_slice(&directory.virtual_address.to_le_bytes());
        mapped[offset + 4..offset + 8].copy_from_slice(&directory.size.to_le_bytes());
    }

    let mut stage = vec![0; 0x200];
    for (index, value) in [0x28u32, 0x3000, 0x5000, 5].into_iter().enumerate() {
        stage[0x80 + index * 4..0x84 + index * 4].copy_from_slice(&value.to_le_bytes());
    }
    stage[0xa0..0xa4].copy_from_slice(&0x4000u32.to_le_bytes());
    stage[0xa4..0xa8].copy_from_slice(&0x1e0u32.to_le_bytes());
    let ranges = [
        (0x128u32, 0x30u32),
        (0x160, 0x20),
        (0x184, 0x4c),
        (0x1d8, 0x58),
        (0x240, 0x20),
    ];
    for (index, (start, length)) in ranges.into_iter().enumerate() {
        let offset = 0x100 + index * 8;
        stage[offset..offset + 4].copy_from_slice(&start.to_le_bytes());
        stage[offset + 4..offset + 8].copy_from_slice(&length.to_le_bytes());
    }

    let table = crc32_table();
    let checksums =
        amd64_runtime_header_checksums(&mapped, &pe, &stage, 0..stage.len(), &table).unwrap();
    let mut expected_header = mapped[..pe.size_of_headers as usize].to_vec();
    expected_header[directory_base + 8..directory_base + 12]
        .copy_from_slice(&0x3000u32.to_le_bytes());
    expected_header[directory_base + 16..directory_base + 20]
        .copy_from_slice(&0x4000u32.to_le_bytes());
    expected_header[directory_base + 20..directory_base + 24]
        .copy_from_slice(&0x1e0u32.to_le_bytes());
    expected_header[directory_base + 40..directory_base + 48].fill(0);
    let expected = ranges.iter().fold(0u32, |checksum, (start, length)| {
        let start = usize::try_from(*start).unwrap();
        let end = start + usize::try_from(*length).unwrap();
        checksum ^ crackproof_checksum(&expected_header[start..end], &table)
    });
    assert!(checksums.contains(&expected));
}

#[test]
fn discovers_every_semantic_al_program_without_marker_bytes() {
    const FIRST: [u8; 16] = [
        0x04, 0x11, 0x34, 0x22, 0xc0, 0xc0, 0x03, 0xfe, 0xc8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xc3,
    ];
    const SECOND: [u8; 18] = [
        0x2c, 0x37, 0xc0, 0xc8, 0x05, 0xfe, 0xc0, 0x34, 0xa5, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0x90, 0xc3,
    ];
    let mut source = vec![0u8; 2 * MAX_AL_PROGRAM_BYTES];
    source[..MAX_AL_PROGRAM_BYTES].copy_from_slice(&lfsr_encode_program(&FIRST));
    source[MAX_AL_PROGRAM_BYTES..].copy_from_slice(&lfsr_encode_program(&SECOND));

    let first_map = parse_al_byte_map(&FIRST).unwrap().1;
    let second_map = parse_al_byte_map(&SECOND).unwrap().1;
    let candidates = lfsr_al_maps(&source);
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().any(|(_, map)| map == &first_map));
    assert!(candidates.iter().any(|(_, map)| map == &second_map));
    assert_ne!(usize::from(source[MAX_AL_PROGRAM_BYTES - 1]), FIRST.len());
    assert_ne!(
        usize::from(source[2 * MAX_AL_PROGRAM_BYTES - 1]),
        SECOND.len()
    );
}

#[test]
fn discovers_short_semantic_al_program() {
    const PROGRAM: [u8; 11] = [
        0xfe, 0xc0, 0xfe, 0xc0, 0xc0, 0xc0, 0x07, 0xc0, 0xc0, 0x03, 0xc3,
    ];
    let encoded = lfsr_encode_program(&PROGRAM);
    let expected = parse_al_byte_map(&PROGRAM).unwrap().1;

    let candidates = lfsr_al_maps(&encoded);

    assert!(
        candidates
            .iter()
            .any(|(length, map)| { *length == PROGRAM.len() && map == &expected })
    );
}

#[test]
fn retains_lfsr_program_offset_with_generated_map() {
    const PROGRAM: [u8; 11] = [
        0xfe, 0xc0, 0xfe, 0xc0, 0xc0, 0xc0, 0x07, 0xc0, 0xc0, 0x03, 0xc3,
    ];
    const PROGRAM_OFFSET: usize = 37;
    let encoded = lfsr_encode_program(&PROGRAM);
    let expected = parse_al_byte_map(&PROGRAM).unwrap().1;
    let mut source = vec![0x5a; PROGRAM_OFFSET + MAX_AL_PROGRAM_BYTES + 17];
    source[PROGRAM_OFFSET..PROGRAM_OFFSET + MAX_AL_PROGRAM_BYTES].copy_from_slice(&encoded);

    let matching = lfsr_al_map_candidates(&source)
        .into_iter()
        .filter(|candidate| candidate.map == expected)
        .collect::<Vec<_>>();

    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].offset, PROGRAM_OFFSET);
    assert_eq!(matching[0].length, PROGRAM.len());
}

fn mwemu_al_map(program: &[u8], static_map: &[u8; 256]) -> [u8; 256] {
    const CODE: u64 = 0x0010_0000;
    const STACK: u64 = 0x0020_0000;
    const STACK_TOP: u64 = STACK + 0x800;
    const RETURN_SENTINEL: u64 = 0x0030_0000;

    assert!(!program.is_empty() && program.last() == Some(&0xc3));
    let mut emulator = emu32();
    emulator
        .maps
        .create_map("al-code", CODE, 0x1000, Permission::READ_WRITE_EXECUTE)
        .expect("map callback code");
    emulator
        .maps
        .create_map("al-stack", STACK, 0x1000, Permission::READ_WRITE)
        .expect("map callback stack");
    emulator
        .maps
        .create_map(
            "al-return",
            RETURN_SENTINEL,
            0x1000,
            Permission::READ_EXECUTE,
        )
        .expect("map callback return sentinel");
    assert!(emulator.maps.write_bytes(CODE, program));

    let mut observed = [0u8; 256];
    for input in 0u16..=u8::MAX.into() {
        emulator.regs_mut().set_eax(0);
        emulator.regs_mut().set_al(u64::from(input));
        emulator.regs_mut().set_esp(STACK_TOP - 4);
        assert!(
            emulator
                .maps
                .write_dword(STACK_TOP - 4, RETURN_SENTINEL as u32)
        );
        emulator.regs_mut().set_eip(CODE);

        let mut returned = false;
        for _ in 0..program.len() {
            assert!(emulator.step(), "callback faulted for input {input:#04x}");
            if emulator.regs().get_eip() == RETURN_SENTINEL {
                returned = true;
                break;
            }
        }
        assert!(returned, "callback did not return for input {input:#04x}");
        assert_eq!(emulator.regs().get_esp(), STACK_TOP);
        observed[usize::from(input)] = emulator.regs().get_al() as u8;
        assert_eq!(
            emulator.regs().get_eax(),
            u64::from(observed[usize::from(input)])
        );
    }
    assert_eq!(&observed, static_map);
    observed
}

#[test]
fn mwemu_executes_recovered_polymorphic_callback_map() {
    const PROGRAM: [u8; 75] = [
        0xc0, 0xc8, 0x9a, 0xc0, 0xc8, 0x45, 0x04, 0x4d, 0x04, 0xaa, 0xfe, 0xc8, 0x34, 0x1a, 0x2c,
        0xa8, 0x34, 0x49, 0xc0, 0xc8, 0x97, 0xfe, 0xc0, 0xc0, 0xc0, 0xf8, 0xfe, 0xc8, 0xfe, 0xc0,
        0xc0, 0xc8, 0x74, 0x2c, 0x20, 0xc0, 0xc8, 0x8e, 0x2c, 0x3f, 0xc0, 0xc0, 0xae, 0xc0, 0xc8,
        0x93, 0xfe, 0xc0, 0xfe, 0xc8, 0xc0, 0xc0, 0x6a, 0xc0, 0xc8, 0xd7, 0xfe, 0xc0, 0xc0, 0xc8,
        0xef, 0xfe, 0xc0, 0xc0, 0xc8, 0xdd, 0x04, 0x44, 0x2c, 0xee, 0x04, 0xc8, 0xfe, 0xc0, 0xc3,
    ];
    let (length, static_map) = parse_al_byte_map(&PROGRAM).unwrap();
    assert_eq!(length, PROGRAM.len());
    let observed = mwemu_al_map(&PROGRAM, &static_map);
    assert_eq!(
        [
            observed[0x00],
            observed[0x01],
            observed[0x02],
            observed[0x7f],
            observed[0x80],
            observed[0xfe],
            observed[0xff],
        ],
        [0x53, 0x20, 0x1b, 0x57, 0x51, 0x59, 0x55]
    );
    let mut seen = [false; 256];
    for value in observed {
        seen[usize::from(value)] = true;
    }
    assert!(seen.into_iter().all(|present| present));
}

#[test]
fn mwemu_executes_recovered_dword_transform_helper() {
    const PROGRAM: [u8; 83] = [
        0x55, 0x8b, 0xec, 0x53, 0x56, 0x57, 0xe8, 0x02, 0x00, 0x00, 0x00, 0x59, 0x68, 0x83, 0xc4,
        0x04, 0x8b, 0x45, 0x08, 0x8b, 0x48, 0x04, 0x8b, 0x45, 0x0c, 0x8b, 0x51, 0x58, 0x8b, 0x30,
        0x33, 0xc9, 0x8b, 0x12, 0x03, 0xd6, 0x8b, 0x70, 0x04, 0xc1, 0xee, 0x02, 0x85, 0xf6, 0x7e,
        0x20, 0x8b, 0x7d, 0x10, 0x8b, 0x02, 0x83, 0xc2, 0x04, 0x33, 0xc7, 0x03, 0xf9, 0x8b, 0xd8,
        0xc1, 0xeb, 0x13, 0xc1, 0xe0, 0x0d, 0x0b, 0xd8, 0x2b, 0xd9, 0x41, 0x89, 0x5a, 0xfc, 0x3b,
        0xce, 0x7c, 0xe3, 0x5f, 0x5e, 0x5b, 0x5d, 0xc3,
    ];
    const CODE: u64 = 0x0010_0000;
    const DATA: u64 = 0x0020_0000;
    const STACK: u64 = 0x0030_0000;
    const STACK_TOP: u64 = STACK + 0x800;
    const RETURN_SENTINEL: u64 = 0x0040_0000;
    const CONTEXT: u64 = DATA + 0x100;
    const NODE: u64 = DATA + 0x200;
    const BASE_SLOT: u64 = DATA + 0x300;
    const DESCRIPTOR: u64 = DATA + 0x400;
    const INPUT: u64 = DATA + 0x800;
    const KEY: u32 = 0x1d8b_cbf7;
    const INPUT_DWORDS: [u32; 4] = [0x0123_4567, 0xffff_ffff, 0x8000_0000, 0];
    const EXPECTED: [u32; 4] = [0x11d2_0395, 0x8681_1c4d, 0x797f_13af, 0x797f_43ae];

    let mut emulator = emu32();
    emulator
        .maps
        .create_map("dword-code", CODE, 0x1000, Permission::READ_WRITE_EXECUTE)
        .expect("map dword helper code");
    emulator
        .maps
        .create_map("dword-data", DATA, 0x1000, Permission::READ_WRITE)
        .expect("map dword helper data");
    emulator
        .maps
        .create_map("dword-stack", STACK, 0x1000, Permission::READ_WRITE)
        .expect("map dword helper stack");
    emulator
        .maps
        .create_map(
            "dword-return",
            RETURN_SENTINEL,
            0x1000,
            Permission::READ_EXECUTE,
        )
        .expect("map dword helper return sentinel");
    assert!(emulator.maps.write_bytes(CODE, &PROGRAM));
    assert!(emulator.maps.write_dword(CONTEXT + 4, NODE as u32));
    assert!(emulator.maps.write_dword(NODE + 0x58, BASE_SLOT as u32));
    assert!(emulator.maps.write_dword(BASE_SLOT, INPUT as u32));
    assert!(emulator.maps.write_dword(DESCRIPTOR, 0));
    assert!(emulator.maps.write_dword(
        DESCRIPTOR + 4,
        (INPUT_DWORDS.len() * size_of::<u32>()) as u32
    ));
    for (index, value) in INPUT_DWORDS.into_iter().enumerate() {
        assert!(
            emulator
                .maps
                .write_dword(INPUT + (index * size_of::<u32>()) as u64, value)
        );
    }
    let entry_sp = STACK_TOP - 16;
    for (offset, value) in [
        RETURN_SENTINEL as u32,
        CONTEXT as u32,
        DESCRIPTOR as u32,
        KEY,
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            emulator
                .maps
                .write_dword(entry_sp + (offset * size_of::<u32>()) as u64, value)
        );
    }
    emulator.regs_mut().set_esp(entry_sp);
    emulator.regs_mut().set_eip(CODE);
    let mut returned = false;
    for _ in 0..(32 + 16 * INPUT_DWORDS.len()) {
        assert!(emulator.step(), "dword helper faulted");
        if emulator.regs().get_eip() == RETURN_SENTINEL {
            returned = true;
            break;
        }
    }
    assert!(returned, "dword helper did not return");
    assert_eq!(emulator.regs().get_esp(), entry_sp + 4);
    let observed = std::array::from_fn(|index| {
        emulator
            .maps
            .read_dword(INPUT + (index * size_of::<u32>()) as u64)
            .unwrap()
    });
    assert_eq!(observed, EXPECTED);

    let static_source = INPUT_DWORDS
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let mut static_output = vec![0; static_source.len()];
    nested_transform_dwords_into(&static_source, &mut static_output, KEY, 19);
    assert_eq!(
        static_output,
        EXPECTED
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>()
    );
}

#[test]
fn nested_dword_transform_copies_a_partial_tail() {
    let source = [1, 2, 3, 4, 0xaa, 0xbb, 0xcc];
    let mut destination = [0x55; 7];

    nested_transform_dwords_into(&source, &mut destination, 0, 0);

    assert_eq!(destination, source);
}

#[test]
fn lazy_nested_transform_matches_materialized_bytes() {
    let mut byte_map = [0u8; 256];
    for (index, byte) in byte_map.iter_mut().enumerate() {
        *byte = (index as u8).rotate_left(3) ^ 0xa5;
    }

    for length in [1, 3, 4, 5, 7, 8, 17, 65] {
        let source = (0..length)
            .map(|index| (index as u8).wrapping_mul(0x3d).wrapping_add(0x17))
            .collect::<Vec<_>>();
        let mut materialized = vec![0; source.len()];
        nested_transform_dwords_into(&source, &mut materialized, 0x89ab_cdef, 19);

        for map in [None, Some(&byte_map)] {
            let mut lazy = NestedTransformedSource::new(&source, 0x89ab_cdef, map);
            for index in (0..source.len()).chain((0..source.len()).rev()) {
                let expected = map.map_or(materialized[index], |map| {
                    map[usize::from(materialized[index])]
                });
                assert_eq!(lazy.byte(index), expected, "length {length}, byte {index}");
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FixtureOptions {
    descriptor_file_offset: usize,
    source_offset: u32,
    stream_gap: usize,
    destination_rva: u32,
    key: u32,
    prefix_length: usize,
    source_length: usize,
    records: usize,
    table_offset: usize,
    precursor_offset: usize,
    precursor_phase: u8,
    context_source_offset: usize,
    context_seed: u8,
    aes_key: [u8; AES_256_KEY_SIZE],
}

struct Fixture {
    packed: Vec<u8>,
    bootstrap: PackedBootstrap,
    direct_output: Vec<u8>,
    custom_output: u8,
    direct_destination: usize,
    custom_destination: usize,
    source_start: usize,
    table_offset: usize,
    stream_base: usize,
    context_range: Range<usize>,
    encoded_context: [u8; AES_CONTEXT_SIZE],
}

fn inverse_byte(value: u8, transform: impl Fn(u8) -> u8) -> u8 {
    (u8::MIN..=u8::MAX)
        .find(|&candidate| transform(candidate) == value)
        .expect("test transform is bijective")
}

fn inverse_f2a0(bytes: &mut [u8], initial: u8) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let state = initial.wrapping_add(index as u8);
        *byte = inverse_byte(*byte, |value| f2a0_byte(value, state));
    }
}

fn inverse_f710(bytes: &mut [u8], seed: u32) {
    for (index, byte) in bytes.iter_mut().enumerate() {
        let state = (seed as u8).wrapping_add(index as u8);
        *byte = inverse_byte(*byte, |value| {
            let dl = state.wrapping_add(1);
            let value = value.rotate_left(2) ^ dl;
            let value = value.rotate_left(2) ^ state;
            value.rotate_left(2)
        });
    }
}

fn inverse_f8(value: u8) -> u8 {
    inverse_byte(value, f8_byte)
}

fn encrypt_cbc_full_blocks_in_place(bytes: &mut [u8], key: &[u8; AES_256_KEY_SIZE]) {
    let cipher = Aes256::new_from_slice(key).expect("fixed AES key");
    let mut previous = [0u8; 16];
    let complete_length = bytes.len() & !0x0f;
    for block in bytes[..complete_length].chunks_exact_mut(16) {
        for (byte, previous_byte) in block.iter_mut().zip(previous) {
            *byte ^= previous_byte;
        }
        cipher.encrypt_block(Block::<Aes256>::from_mut_slice(block));
        previous.copy_from_slice(block);
    }
}

fn encode_context(key: &[u8; AES_256_KEY_SIZE], seed: u8) -> [u8; AES_CONTEXT_SIZE] {
    let mut context = [0u8; AES_CONTEXT_SIZE];
    context[..AES_CONTEXT_HEADER.len()].copy_from_slice(&AES_CONTEXT_HEADER);
    context[AES_CONTEXT_HEADER.len()..].copy_from_slice(&make_openssl_decrypt_schedule(key));
    for (index, byte) in context.iter_mut().enumerate() {
        *byte = inverse_byte(*byte, |value| transform_context_byte(value, seed, index));
    }
    context
}

fn put_record(bytes: &mut [u8], index: usize, words: [u32; 4]) {
    let offset = index * A_RECORD_SIZE;
    for (word_index, word) in words.into_iter().enumerate() {
        bytes[offset + word_index * 4..offset + word_index * 4 + 4]
            .copy_from_slice(&word.to_le_bytes());
    }
}

fn encode_a_record_run(
    record_count: usize,
    bootstrap: PackedBootstrap,
    initial_phase: u8,
) -> Vec<u8> {
    encode_a_record_run_at(record_count, bootstrap, initial_phase, 0)
}

fn encode_a_record_run_at(
    record_count: usize,
    bootstrap: PackedBootstrap,
    initial_phase: u8,
    start_offset: usize,
) -> Vec<u8> {
    assert!(record_count >= 2);
    let mut bytes = vec![0; record_count * A_RECORD_SIZE];
    for index in 0..record_count - 1 {
        put_record(&mut bytes, index, [0, 1, 0, 1]);
    }
    put_record(
        &mut bytes,
        record_count - 1,
        [bootstrap.destination_rva, 0, 0, 0],
    );
    for (index, record) in bytes.chunks_exact_mut(A_RECORD_SIZE).enumerate() {
        let record_offset = start_offset
            .checked_add(index * A_RECORD_SIZE)
            .expect("test A record offset");
        inverse_f710(
            record,
            bootstrap
                .destination_rva
                .checked_add(u32::try_from(record_offset).expect("test A record offset fits u32"))
                .expect("test A record target RVA"),
        );
    }
    inverse_f2a0(&mut bytes, initial_phase);
    bytes
}

fn root_literal_table(literal: u8) -> Vec<u8> {
    let mut table = vec![0; CUSTOM_DECODER_ROOT_NODES * CUSTOM_DECODER_NODE_SIZE];
    for node in table.chunks_exact_mut(CUSTOM_DECODER_NODE_SIZE) {
        node[..2].copy_from_slice(&(0x8000u16 | u16::from(literal)).to_le_bytes());
        node[2] = 4;
    }
    table
}

fn encode_decoder_precursor_table(table: &[u8], phase: u8) -> Vec<u8> {
    let mut encoded = table.to_vec();
    inverse_f2a0(&mut encoded, phase);
    encoded
}

fn root_table_for_tokens(source: &[u8], symbols: &[u16]) -> Vec<u8> {
    assert!(symbols.len() * 4 <= source.len() * 8);
    let mut table = root_literal_table(0);
    let mut assigned = [None; CUSTOM_DECODER_ROOT_NODES];
    for (token_index, &symbol) in symbols.iter().enumerate() {
        let bit_offset = token_index * 4;
        let source_byte = bit_offset / 8;
        let shift = bit_offset % 8;
        let window = u16::from(source[source_byte])
            | (u16::from(source.get(source_byte + 1).copied().unwrap_or(0)) << 8);
        let root_index = usize::from(((window >> shift) & 0xff) as u8);
        if let Some(previous) = assigned[root_index] {
            assert_eq!(previous, symbol, "test token root collision");
        }
        assigned[root_index] = Some(symbol);
        let node = &mut table
            [root_index * CUSTOM_DECODER_NODE_SIZE..(root_index + 1) * CUSTOM_DECODER_NODE_SIZE];
        node[..2].copy_from_slice(&(0x8000 | symbol).to_le_bytes());
        node[2] = 4;
    }
    table
}

fn encrypt_outer_source(
    plaintext: &[u8],
    bootstrap: PackedBootstrap,
    prefix_length: usize,
    forced_ciphertext: &[(usize, Vec<u8>)],
) -> Vec<u8> {
    let mut forced = vec![None; prefix_length];
    for (offset, bytes) in forced_ciphertext {
        for (index, byte) in bytes.iter().copied().enumerate() {
            forced[offset + index] = Some(byte);
        }
    }
    let mut ciphertext = plaintext.to_vec();
    let mut state = bootstrap
        .key
        .wrapping_sub(u32::try_from(prefix_length).expect("test prefix fits u32"))
        .wrapping_sub(1);
    for (word_index, block) in ciphertext[..prefix_length].chunks_exact_mut(4).enumerate() {
        let force = forced[word_index * 4..word_index * 4 + 4]
            .iter()
            .copied()
            .collect::<Option<Vec<_>>>();
        let word = match force {
            Some(bytes) => u32::from_le_bytes(bytes.try_into().expect("forced dword")),
            None => {
                let plain = u32::from_le_bytes(
                    plaintext[word_index * 4..word_index * 4 + 4]
                        .try_into()
                        .expect("plaintext dword"),
                );
                plain ^ state
            }
        };
        block.copy_from_slice(&word.to_le_bytes());
        let index = word_index as u32;
        state = state.wrapping_add(word).wrapping_add(index) ^ index.wrapping_mul(index);
    }
    ciphertext
}

fn build_fixture(options: FixtureOptions) -> Fixture {
    assert!(options.prefix_length.is_multiple_of(4));
    assert!(options.prefix_length <= options.source_length);
    assert!(options.records >= 2);
    let source_start = options.descriptor_file_offset + options.source_offset as usize;
    let source_rva = options
        .destination_rva
        .checked_add((options.prefix_length - OUTER_ENCRYPTED_PREFIX_RVA_BIAS as usize) as u32)
        .expect("test source RVA");
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: options.descriptor_file_offset,
        key: options.key,
        destination_rva: options.destination_rva,
        source_offset: options.source_offset,
        length: options.source_length as u32,
        source_rva,
    };
    let direct_output = (0..16)
        .map(|index| 0x30u8.wrapping_add(index as u8))
        .collect::<Vec<_>>();
    let custom_output = 0x5a;
    let direct_destination = 0x180;
    let custom_destination = 0x240;
    let mut records = vec![0; options.records * A_RECORD_SIZE];
    put_record(
        &mut records,
        0,
        [
            0,
            direct_output.len() as u32,
            direct_destination as u32,
            direct_output.len() as u32,
        ],
    );
    put_record(&mut records, 1, [16, 1, custom_destination as u32, 2]);
    for index in 2..options.records - 1 {
        let destination = 0x300 + index * 0x20;
        put_record(&mut records, index, [17, 1, destination as u32, 1]);
    }
    put_record(
        &mut records,
        options.records - 1,
        [options.destination_rva, 0, 0, 0],
    );
    for (index, record) in records.chunks_exact_mut(A_RECORD_SIZE).enumerate() {
        inverse_f710(
            record,
            options.destination_rva + options.table_offset as u32 + (index * A_RECORD_SIZE) as u32,
        );
    }
    inverse_f2a0(&mut records, 0x6d);

    let mut plaintext = vec![0; options.source_length];
    plaintext[options.table_offset..options.table_offset + records.len()].copy_from_slice(&records);

    let table = root_literal_table(custom_output);
    let mut precursor = table.clone();
    inverse_f2a0(&mut precursor, options.precursor_phase);
    let source = encrypt_outer_source(
        &plaintext,
        bootstrap,
        options.prefix_length,
        &[(options.precursor_offset, precursor)],
    );

    let stream_base = source_start + options.source_length + options.stream_gap;
    let context_start = source_start
        .checked_add(options.context_source_offset)
        .expect("test context start");
    let context_end = context_start
        .checked_add(AES_CONTEXT_SIZE)
        .expect("test context end");
    assert!(context_end <= stream_base);
    let context_range = context_start..context_end;
    let packed_length = stream_base
        .checked_add(18)
        .expect("test stream length")
        .max(context_end);
    let mut packed = vec![0; packed_length];
    let source_end = source_start + options.source_length;
    packed[source_start..source_end].copy_from_slice(&source);
    let locator_offset = options.descriptor_file_offset + 0x80;
    let descriptor_offset =
        u32::try_from(options.descriptor_file_offset).expect("test descriptor offset");
    let relative_stream_base = u32::try_from(stream_base)
        .expect("test stream base")
        .wrapping_sub(descriptor_offset);
    packed[locator_offset..locator_offset + 4]
        .copy_from_slice(&(!relative_stream_base).to_le_bytes());
    let mut direct_encoded = direct_output
        .iter()
        .copied()
        .map(inverse_f8)
        .collect::<Vec<_>>();
    encrypt_cbc_full_blocks_in_place(&mut direct_encoded, &options.aes_key);
    packed[stream_base..stream_base + direct_encoded.len()].copy_from_slice(&direct_encoded);
    packed[stream_base + 16] = inverse_f8(0);
    packed[stream_base + 17] = inverse_f8(0);
    let encoded_context = encode_context(&options.aes_key, options.context_seed);
    packed[context_range.clone()].copy_from_slice(&encoded_context);

    Fixture {
        packed,
        bootstrap,
        direct_output,
        custom_output,
        direct_destination,
        custom_destination,
        source_start,
        stream_base,
        table_offset: options.table_offset,
        context_range,
        encoded_context,
    }
}

fn options_a() -> FixtureOptions {
    FixtureOptions {
        descriptor_file_offset: 0x40,
        source_offset: 0x100,
        stream_gap: 0,
        destination_rva: 0x4100,
        key: 0x91a2_b3c4,
        prefix_length: 0x2000,
        source_length: 0x2100,
        records: 3,
        table_offset: 0x120,
        precursor_offset: 0x1500,
        precursor_phase: 0x53,
        context_source_offset: 0x200c,
        context_seed: 0x39,
        aes_key: std::array::from_fn(|index| index as u8 ^ 0xa5),
    }
}

fn options_b() -> FixtureOptions {
    FixtureOptions {
        descriptor_file_offset: 0x180,
        source_offset: 0x100,
        stream_gap: 0x280,
        destination_rva: 0x6200,
        key: 0x1726_35e4,
        prefix_length: 0x2040,
        source_length: 0x2180,
        records: 4,
        table_offset: 0x2a0,
        precursor_offset: 0x1724,
        precursor_phase: 0xc7,
        context_source_offset: 0x208c,
        context_seed: 0x8e,
        aes_key: std::array::from_fn(|index| 0x3cu8.wrapping_add((index * 11) as u8)),
    }
}
#[test]
fn payload_stream_provenance_uses_the_descriptor_locator_gap() {
    let fixture = build_fixture(options_b());
    let source_file_range =
        bootstrap_source_file_range(&fixture.packed, fixture.bootstrap).unwrap();

    let provenance = derive_payload_stream_provenance(
        &fixture.packed,
        fixture.bootstrap,
        &source_file_range,
        None,
    )
    .unwrap();

    assert_eq!(
        provenance,
        super::grammar::PayloadStreamProvenance {
            locator_file_offset: fixture.bootstrap.descriptor_file_offset + 0x80,
            base_file_offset: fixture.stream_base,
            gap_after_outer_source: options_b().stream_gap,
        }
    );
}

#[test]
fn payload_stream_provenance_rejects_a_locator_overlapping_the_outer_source() {
    let fixture = build_fixture(options_a());
    let bootstrap = PackedBootstrap {
        source_offset: 0x80,
        ..fixture.bootstrap
    };
    let source_file_range = bootstrap_source_file_range(&fixture.packed, bootstrap).unwrap();

    assert!(
        derive_payload_stream_provenance(&fixture.packed, bootstrap, &source_file_range, None)
            .is_err()
    );
}

#[test]
fn payload_stream_provenance_rejects_a_base_before_the_outer_source_end() {
    let mut fixture = build_fixture(options_a());
    let source_file_range =
        bootstrap_source_file_range(&fixture.packed, fixture.bootstrap).unwrap();
    let invalid_base = source_file_range.end - 1;
    let descriptor_offset = u32::try_from(fixture.bootstrap.descriptor_file_offset).unwrap();
    let encoded = !(u32::try_from(invalid_base)
        .unwrap()
        .wrapping_sub(descriptor_offset));
    let locator = fixture.bootstrap.descriptor_file_offset + 0x80;
    fixture.packed[locator..locator + 4].copy_from_slice(&encoded.to_le_bytes());

    assert!(
        derive_payload_stream_provenance(
            &fixture.packed,
            fixture.bootstrap,
            &source_file_range,
            None,
        )
        .is_err()
    );
}

#[test]
fn payload_stream_provenance_rejects_a_locator_in_the_security_directory() {
    let fixture = build_fixture(options_a());
    let source_file_range =
        bootstrap_source_file_range(&fixture.packed, fixture.bootstrap).unwrap();
    let locator = fixture.bootstrap.descriptor_file_offset + 0x80;
    let security = locator..locator + 4;

    assert!(
        derive_payload_stream_provenance(
            &fixture.packed,
            fixture.bootstrap,
            &source_file_range,
            Some(&security),
        )
        .is_err()
    );
}

#[test]
fn primitives_round_trip_and_custom_decoder_consumes_exact_stream() {
    let mut f2 = [0x10, 0x22, 0x33, 0x44];
    let original = f2;
    inverse_f2a0(&mut f2, 0x91);
    f2a0_transform_from_dl(&mut f2, 0x91);
    assert_eq!(f2, original);

    let mut f710 = [0x91, 0x82, 0x73, 0x64];
    let original = f710;
    inverse_f710(&mut f710, 0x1234_5678);
    f710_record_transform(&mut f710, 0x1234_5678);
    assert_eq!(f710, original);

    let table = root_literal_table(b'Q');
    let mut destination = [0];
    let stats = decode_custom_stream(&table, &[0x3f], &mut destination).expect("decode literal");
    assert_eq!(destination, [b'Q']);
    assert_eq!(stats.source_bytes_consumed, 1);
    assert!(decode_custom_stream(&table, &[], &mut destination).is_err());
}

#[test]
fn custom_decoder_prefix_filter_never_rejects_a_successful_stream() {
    let token_table = |symbol: u16| {
        let mut table = root_literal_table(0);
        for node in table.chunks_exact_mut(CUSTOM_DECODER_NODE_SIZE) {
            node[..2].copy_from_slice(&(0x8000 | symbol).to_le_bytes());
        }
        table
    };

    let literal_source = [0x3f];
    let literal_table = root_literal_table(b'Q');
    assert!(custom_decoder_prefix_is_viable(
        &literal_table,
        &literal_source,
        literal_source.len(),
        0,
        2,
        false,
    ));

    let pending_source = [0x10];
    let pending_table = root_table_for_tokens(&pending_source, &[0x101, 0x201]);
    let mut pending_output = [0];
    decode_custom_stream_with_history_mode(
        &pending_table,
        &pending_source,
        b"A",
        &mut pending_output,
        false,
    )
    .expect("prefix followed by a valid repeat");
    assert!(custom_decoder_prefix_is_viable(
        &pending_table,
        &pending_source,
        pending_source.len(),
        1,
        pending_output.len(),
        false,
    ));

    for rejected in [0x203, 0x301] {
        assert!(!custom_decoder_prefix_is_viable(
            &token_table(rejected),
            &[0],
            1,
            4,
            4,
            false,
        ));
    }

    for symbol in 0..=0x3ff {
        let table = token_table(symbol);
        let source = [0];
        let history = [0xa5; 4];
        let mut destination = [0; 2];
        let successful = decode_custom_stream_with_history_mode(
            &table,
            &source,
            &history,
            &mut destination,
            false,
        )
        .is_ok();
        assert!(
            !successful
                || custom_decoder_prefix_is_viable(
                    &table,
                    &source,
                    source.len(),
                    history.len(),
                    destination.len(),
                    false,
                ),
            "successful initial token {symbol:#x} was filtered"
        );
    }
}

#[test]
fn custom_decoder_rejects_unsupported_repeat_widths_and_pending_prefixes() {
    let source = [0x21];
    let table = root_table_for_tokens(&source, &[0x203]);
    let mut destination = [0xa5; 3];
    assert_eq!(
        decode_custom_stream(&table, &source, &mut destination),
        Err(CustomDecodeError::InvalidRepeatWidth { width: 3 })
    );
    assert_eq!(destination, [0xa5; 3]);

    let source = [0x10];
    let table = root_table_for_tokens(&source, &[0x101, u16::from(b'Z')]);
    let mut destination = [0];
    assert_eq!(
        decode_custom_stream(&table, &source, &mut destination),
        Err(CustomDecodeError::PendingPrefix { pending: 1 })
    );
    assert_eq!(destination, [b'Z']);
}

#[test]
fn custom_decoder_can_reuse_a_dirty_destination_after_failure() {
    let failing_source = [0x10];
    let failing_table = root_table_for_tokens(&failing_source, &[0x101, u16::from(b'Z')]);
    let mut destination = [0xa5; 4];
    assert!(
        decode_custom_stream_with_history_mode(
            &failing_table,
            &failing_source,
            &[],
            &mut destination,
            false,
        )
        .is_err()
    );
    assert_eq!(destination[0], b'Z');

    let successful_source = [0x21, 0x43];
    let successful_table = root_table_for_tokens(
        &successful_source,
        &[
            u16::from(b'W'),
            u16::from(b'X'),
            u16::from(b'Y'),
            u16::from(b'Z'),
        ],
    );
    decode_custom_stream_with_history_mode(
        &successful_table,
        &successful_source,
        &[],
        &mut destination,
        false,
    )
    .expect("successful replay into dirty destination");
    assert_eq!(destination, *b"WXYZ");
}

#[test]
fn custom_decoder_consumes_zero_width_control_tokens_without_output() {
    let source = [0x10];
    for token in [0x100, 0x200, 0x300] {
        let table = root_table_for_tokens(&source, &[token, u16::from(b'Z')]);
        let mut strict_destination = [0xa5];
        assert_eq!(
            decode_custom_stream_with_history_mode(
                &table,
                &source,
                &[],
                &mut strict_destination,
                false,
            ),
            Err(CustomDecodeError::InvalidRepeatWidth { width: 0 })
        );
        assert_eq!(strict_destination, [0xa5]);
        let mut destination = [0xa5];
        decode_custom_stream(&table, &source, &mut destination)
            .expect("zero-width control token followed by a literal");
        assert_eq!(destination, [b'Z']);
    }
}

#[test]
fn custom_decoder_repeats_only_the_three_implemented_periods() {
    let source = [0x21];
    let table = root_table_for_tokens(&source, &[u16::from(b'A'), 0x201]);
    let mut destination = [0; 2];
    decode_custom_stream(&table, &source, &mut destination).expect("width-one repeat");
    assert_eq!(destination, *b"AA");

    let source = [0x21, 0x03];
    let table = root_table_for_tokens(&source, &[u16::from(b'A'), u16::from(b'B'), 0x202]);
    let mut destination = [0; 4];
    decode_custom_stream(&table, &source, &mut destination).expect("width-two repeat");
    assert_eq!(destination, *b"ABAB");

    let source = [0x21, 0x43, 0x05];
    let table = root_table_for_tokens(
        &source,
        &[
            u16::from(b'A'),
            u16::from(b'B'),
            u16::from(b'C'),
            u16::from(b'D'),
            0x204,
        ],
    );
    let mut destination = [0; 8];
    decode_custom_stream(&table, &source, &mut destination).expect("width-four repeat");
    assert_eq!(destination, *b"ABCDABCD");
}

#[test]
fn decoder_validation_reuses_scratch_for_normal_candidates() {
    let source = encode_decoder_precursor_table(&root_literal_table(b'Q'), 0);
    let mut scratch =
        DecoderValidationScratch::new(CUSTOM_DECODER_ROOT_NODES).expect("test scratch");
    let seen_storage = scratch.seen_generations.as_ptr();
    let mut validation_budget = DecoderValidationBudget::default();

    for _ in 0..2 {
        assert_eq!(
            validate_decoder_candidate(&source, 0, 0, &mut scratch, &mut validation_budget)
                .expect("normal candidate validation"),
            Some(CUSTOM_DECODER_ROOT_NODES)
        );
        assert_eq!(scratch.seen_generations.as_ptr(), seen_storage);
    }
    assert_eq!(validation_budget.full_attempts, 2);
    assert_eq!(validation_budget.node_work, 2 * CUSTOM_DECODER_ROOT_NODES);
}

#[test]
fn decoder_validation_attempt_budget_rejects_many_late_invalid_roots() {
    let mut table = root_literal_table(0);
    let last_root = (CUSTOM_DECODER_ROOT_NODES - 1) * CUSTOM_DECODER_NODE_SIZE;
    table[last_root..last_root + 2].copy_from_slice(&(0x8000u16 | 0x0400).to_le_bytes());
    let source = encode_decoder_precursor_table(&table, 0);
    let mut scratch =
        DecoderValidationScratch::new(CUSTOM_DECODER_ROOT_NODES).expect("test scratch");
    let mut validation_budget = DecoderValidationBudget::with_limits(8, usize::MAX);

    for _ in 0..8 {
        assert_eq!(
            validate_decoder_candidate(&source, 0, 0, &mut scratch, &mut validation_budget)
                .expect("late invalid root is structurally rejected"),
            None
        );
    }
    assert_eq!(validation_budget.full_attempts, 8);
    assert_eq!(validation_budget.node_work, 8 * CUSTOM_DECODER_ROOT_NODES);

    let error = validate_decoder_candidate(&source, 0, 0, &mut scratch, &mut validation_budget)
        .expect_err("ninth late-invalid candidate must exhaust the shared attempt budget");
    assert!(
        error.to_string().contains("8-attempt work cap"),
        "unexpected decoder validation budget error: {error:#}"
    );
}

#[test]
fn decoder_validation_node_budget_rejects_cyclic_roots_deterministically() {
    let table = vec![0; CUSTOM_DECODER_ROOT_NODES * CUSTOM_DECODER_NODE_SIZE];
    let source = encode_decoder_precursor_table(&table, 0);
    let reject_cyclic_candidate = || {
        let mut scratch =
            DecoderValidationScratch::new(CUSTOM_DECODER_ROOT_NODES).expect("test scratch");
        let mut validation_budget =
            DecoderValidationBudget::with_limits(1, CUSTOM_DECODER_ROOT_NODES + 6);
        let error = validate_decoder_candidate(&source, 0, 0, &mut scratch, &mut validation_budget)
            .expect_err("cyclic candidate must exhaust node work");
        assert_eq!(validation_budget.full_attempts, 1);
        assert_eq!(validation_budget.node_work, CUSTOM_DECODER_ROOT_NODES + 6);
        error.to_string()
    };

    let first_error = reject_cyclic_candidate();
    let second_error = reject_cyclic_candidate();
    assert_eq!(first_error, second_error);
    assert!(
        first_error.contains("262-node work cap"),
        "unexpected cyclic validation budget error: {first_error}"
    );
}

#[test]
fn decoder_validation_seen_generation_rollover_clears_old_marks() {
    let table = vec![0; CUSTOM_DECODER_ROOT_NODES * CUSTOM_DECODER_NODE_SIZE];
    let source = encode_decoder_precursor_table(&table, 0);
    let mut scratch =
        DecoderValidationScratch::new(CUSTOM_DECODER_ROOT_NODES).expect("test scratch");
    scratch.seen_generations.fill(1);
    scratch.generation = u16::MAX;
    let mut validation_budget = DecoderValidationBudget::with_limits(1, CUSTOM_DECODER_ROOT_NODES);

    let error = validate_decoder_candidate(&source, 0, 0, &mut scratch, &mut validation_budget)
        .expect_err("a wrapped generation must not reuse stale seen marks");
    assert!(
        error.to_string().contains("256-node work cap"),
        "unexpected rollover validation error: {error:#}"
    );
    assert_eq!(scratch.generation, 1);
    assert_eq!(
        scratch.seen_generations[CUSTOM_DECODER_MAX_CODE_BITS + 2],
        1
    );
}

#[test]
fn discovers_long_a_run_without_cumulative_suffix_rescans() {
    const RECORD_COUNT: usize = 8_000;
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0x4000,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let outer = encode_a_record_run(RECORD_COUNT, bootstrap, 0x6d);
    let candidate_count = RECORD_COUNT
        .checked_mul(A_RECORD_PHASES)
        .expect("test candidate count");
    assert!(candidate_count <= MAX_A_DISCOVERY_CANDIDATES);
    let old_cumulative_record_work = candidate_count
        .checked_add(
            RECORD_COUNT
                .checked_mul(RECORD_COUNT - 1)
                .expect("test suffix work")
                / 2,
        )
        .expect("test cumulative work");
    assert!(old_cumulative_record_work > MAX_A_RECORD_CHECKS);

    let run = discover_a_record_run(&outer, bootstrap, 0, 1, 1, None)
        .expect("linear state propagation finds the unique long run");
    assert_eq!(run.records.len(), RECORD_COUNT - 1);
    assert!(run.records.iter().all(|record| record.source_offset == 0
        && record.encoded_length == 1
        && record.destination_rva == 0
        && record.destination_length == 1));
}
#[test]
fn rejects_a_record_sources_overlapping_the_security_directory() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0x4000,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let outer = encode_a_record_run(5, bootstrap, 0x6d);
    assert!(discover_a_record_run(&outer, bootstrap, 0, 1, 1, None).is_ok());
    let security_range = 0..1;

    let error = discover_a_record_run(&outer, bootstrap, 0, 1, 1, Some(&security_range))
        .expect_err("certificate bytes cannot authenticate an A-record source");
    assert!(
        error
            .to_string()
            .contains("no structurally valid A descriptor run"),
        "unexpected Security Directory overlap error: {error:#}"
    );
}

#[test]
fn rejects_descriptor_source_ranges_overlapping_the_security_directory() {
    assert!(ensure_source_excludes_security(&(0x100..0x200), None).is_ok());
    assert!(ensure_source_excludes_security(&(0x100..0x200), Some(&(0x200..0x220))).is_ok());
    assert!(ensure_source_excludes_security(&(0x100..0x200), Some(&(0x1ff..0x220))).is_err());
}

#[test]
fn accepts_shorter_a_record_runs_that_are_exact_suffixes() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0x4000,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let outer = encode_a_record_run(5, bootstrap, 0x6d);

    let run = discover_a_record_run(&outer, bootstrap, 0, 1, 1, None)
        .expect("all shorter structural runs are true suffixes");
    assert_eq!(run.records.len(), 4);
}

#[test]
fn rejects_an_independent_shorter_a_record_run() {
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0x4000,
        source_offset: 0,
        length: 0,
        source_rva: 0,
    };
    let mut outer = encode_a_record_run(5, bootstrap, 0x6d);
    let decoy_offset = outer.len();
    outer.extend(encode_a_record_run_at(3, bootstrap, 0x91, decoy_offset));

    let error = discover_a_record_run(&outer, bootstrap, 0, 1, 1, None)
        .expect_err("independent shorter structural run must be rejected");
    assert!(
        error.to_string().contains("independent shorter"),
        "unexpected A-record ambiguity error: {error:#}"
    );
}

#[test]
fn decrypts_structurally_discovered_direct_and_custom_records() {
    for options in [options_a(), options_b()] {
        let fixture = build_fixture(options);
        let mut mapped = vec![0xcc; 0x7000];
        decrypt_bootstrap_into(&fixture.packed, fixture.bootstrap, &mut mapped)
            .expect("unique structural decryption");
        assert_eq!(
            &mapped[fixture.direct_destination
                ..fixture.direct_destination + fixture.direct_output.len()],
            fixture.direct_output.as_slice()
        );
        assert_eq!(mapped[fixture.custom_destination], fixture.custom_output);
    }
}

#[test]
fn decryption_preserves_native_ordered_destination_overlaps() {
    let records = vec![
        ARecord {
            source_offset: 0,
            encoded_length: 2,
            destination_rva: 0,
            destination_length: 2,
        },
        ARecord {
            source_offset: 2,
            encoded_length: 2,
            destination_rva: 1,
            destination_length: 2,
        },
    ];
    assert_eq!(
        merged_a_record_destination_ranges(&records).expect("merged coverage"),
        vec![0..3]
    );

    let packed = [
        inverse_f8(b'A'),
        inverse_f8(b'B'),
        inverse_f8(b'C'),
        inverse_f8(b'D'),
    ];
    let plan = DecryptionPlan {
        records,
        aes_key: [0; AES_256_KEY_SIZE],
        decoder: DecoderCandidate {
            source_file_offset: 0,
            phase: 0,
            table: root_literal_table(0),
        },
        post_transform: PayloadPostTransform::F8,
    };
    let mut mapped = [0; 3];
    apply_decryption_plan(&packed, 0, &mut mapped, plan).expect("ordered direct writes");
    assert_eq!(mapped, *b"ACD");
}

#[test]
fn decryption_rejects_a_direct_only_chain_before_mutation() {
    let direct = ARecord {
        source_offset: 0,
        encoded_length: 1,
        destination_rva: 0,
        destination_length: 1,
    };
    assert!(
        select_decryption_plan(
            &[],
            0..0,
            0,
            &[],
            &[direct],
            Vec::new(),
            &[PayloadPostTransform::F8],
        )
        .is_err()
    );
}

#[test]
fn decryption_work_bound_includes_direct_records_once() {
    let oversized_half = MAX_DECRYPTION_REPLAY_WORK / 2 + 1;
    let direct = ARecord {
        source_offset: 0,
        encoded_length: oversized_half,
        destination_rva: 0,
        destination_length: oversized_half,
    };
    let error = ensure_decryption_work_bound(&[direct])
        .expect_err("direct decryption work must remain bounded")
        .to_string();
    assert!(error.contains("bounded work"), "{error}");
}

#[test]
fn aggregate_replay_work_is_bounded_before_candidate_loops() {
    let encoded_length = MAX_DECRYPTION_REPLAY_WORK / 4;
    let custom = ARecord {
        source_offset: 0,
        encoded_length,
        destination_rva: 0,
        destination_length: encoded_length + 1,
    };
    assert!(ensure_decryption_work_bound(std::slice::from_ref(&custom)).is_ok());
    let record_work = custom.encoded_length + custom.destination_length;
    let candidate_pairs = MAX_DECRYPTION_AGGREGATE_REPLAY_WORK / record_work + 1;
    let error = ensure_aggregate_replay_work_bound(&[custom], candidate_pairs)
        .expect_err("candidate-pair replay amplification must be rejected")
        .to_string();
    assert!(error.contains("aggregate work cap"), "{error}");
}
#[test]
fn decryption_replay_budget_is_independent_per_candidate_chain() {
    let direct_length = MAX_DECRYPTION_REPLAY_WORK / 4;
    let key = [0x3c; AES_256_KEY_SIZE];
    let encoded_context = encode_context(&key, 0x39);
    let stream_base = AES_CONTEXT_SIZE;
    let mut packed = vec![0; stream_base + direct_length + 1];
    packed[..stream_base].copy_from_slice(&encoded_context);
    packed[stream_base + direct_length] = inverse_f8(0);

    let records = [
        ARecord {
            source_offset: 0,
            encoded_length: direct_length,
            destination_rva: 0,
            destination_length: direct_length,
        },
        ARecord {
            source_offset: direct_length,
            encoded_length: 1,
            destination_rva: 0,
            destination_length: 2,
        },
    ];
    let accepting_table = root_literal_table(0);
    let mapped = vec![0; direct_length];
    let (plan, decryption_details) = select_decryption_plan(
        &packed,
        0..stream_base,
        stream_base,
        &mapped,
        &records,
        vec![
            DecoderCandidate {
                source_file_offset: 0,
                phase: 0,
                table: root_table_for_tokens(&[0], &[0x203]),
            },
            DecoderCandidate {
                source_file_offset: 0,
                phase: 0,
                table: accepting_table.clone(),
            },
        ],
        &[PayloadPostTransform::F8],
    )
    .expect("a rejected chain cannot consume the succeeding chain's replay budget");

    assert_eq!(plan.aes_key, key);
    assert_eq!(plan.decoder.table, accepting_table);
    assert_eq!(plan.post_transform, PayloadPostTransform::F8);
    assert_eq!(decryption_details.chunk_count, 2);
    assert_eq!(decryption_details.copied_chunk_count, 1);
    assert_eq!(decryption_details.decoded_chunk_count, 1);
    assert_eq!(decryption_details.aes_key_candidates, 1);
    assert_eq!(decryption_details.decoder_candidates, 2);
    assert_eq!(decryption_details.byte_transform_candidates, 1);
    let selected = decryption_details
        .selected_chain
        .expect("successful replay records the selected chain");
    assert_eq!(selected.aes.file_offset, 0);
    assert_eq!(selected.aes.seed, 0x39);
    assert_eq!(selected.aes.raw_key_hex, hex::encode(key));
    assert_eq!(selected.decoder.source_file_offset, 0);
    assert_eq!(selected.decoder.phase, 0);
    assert_eq!(
        selected.byte_transform,
        crate::pipeline::outcome::ByteTransform::FixedF8
    );
    assert_eq!(selected.byte_map.len(), 256);
}

#[test]
fn parallel_candidate_replay_matches_single_thread_selection() {
    let key = [0x3c; AES_256_KEY_SIZE];
    let stream_base = AES_CONTEXT_SIZE;
    let mut packed = vec![0; stream_base + 2];
    packed[..stream_base].copy_from_slice(&encode_context(&key, 0x39));
    packed[stream_base] = inverse_f8(b'D');
    packed[stream_base + 1] = inverse_f8(0);
    let records = [
        ARecord {
            source_offset: 0,
            encoded_length: 1,
            destination_rva: 0,
            destination_length: 1,
        },
        ARecord {
            source_offset: 1,
            encoded_length: 1,
            destination_rva: 1,
            destination_length: 2,
        },
    ];
    let mapped = [0; 3];
    let accepting_table = root_literal_table(0);
    let select = |threads| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .unwrap()
            .install(|| {
                select_decryption_plan(
                    &packed,
                    0..stream_base,
                    stream_base,
                    &mapped,
                    &records,
                    vec![
                        DecoderCandidate {
                            source_file_offset: 1,
                            phase: 0,
                            table: root_table_for_tokens(&[0], &[0x203]),
                        },
                        DecoderCandidate {
                            source_file_offset: 2,
                            phase: 0,
                            table: accepting_table.clone(),
                        },
                    ],
                    &[PayloadPostTransform::F8],
                )
            })
            .unwrap()
    };

    let (single_plan, single_details) = select(1);
    let (parallel_plan, parallel_details) = select(4);
    assert_eq!(parallel_plan.aes_key, single_plan.aes_key);
    assert_eq!(
        parallel_plan.decoder.source_file_offset,
        single_plan.decoder.source_file_offset
    );
    assert_eq!(parallel_plan.decoder.phase, single_plan.decoder.phase);
    assert_eq!(parallel_plan.decoder.table, single_plan.decoder.table);
    assert_eq!(parallel_plan.post_transform, single_plan.post_transform);
    assert_eq!(parallel_details, single_details);
}

#[test]
fn decryption_selection_failure_reports_bounded_custom_rejections() {
    let key = [0x3c; AES_256_KEY_SIZE];
    let stream_base = AES_CONTEXT_SIZE;
    let mut packed = vec![0; stream_base + 2];
    packed[..stream_base].copy_from_slice(&encode_context(&key, 0x39));
    packed[stream_base] = inverse_f8(b'D');
    packed[stream_base + 1] = inverse_f8(0);
    let records = [
        ARecord {
            source_offset: 0,
            encoded_length: 1,
            destination_rva: 0,
            destination_length: 1,
        },
        ARecord {
            source_offset: 1,
            encoded_length: 1,
            destination_rva: 1,
            destination_length: 2,
        },
    ];
    let rejecting_table = root_table_for_tokens(&[0], &[0x203]);
    let decoder_candidates = (0..9)
        .map(|candidate| DecoderCandidate {
            source_file_offset: candidate,
            phase: 0,
            table: rejecting_table.clone(),
        })
        .collect::<Vec<_>>();

    let error = select_decryption_plan(
        &packed,
        0..stream_base,
        stream_base,
        &[0; 3],
        &records,
        decoder_candidates,
        &[PayloadPostTransform::F8],
    )
    .err()
    .expect("all candidate chains reject the custom record");
    let failure = error
        .downcast_ref::<DecryptionSelectionError>()
        .expect("no-winner failure exposes decryption evidence");
    let decryption_details = &failure.decryption_details;

    assert_eq!(decryption_details.chunk_count, 2);
    assert_eq!(decryption_details.copied_chunk_count, 1);
    assert_eq!(decryption_details.decoded_chunk_count, 1);
    assert_eq!(decryption_details.aes_key_candidates, 1);
    assert_eq!(decryption_details.decoder_candidates, 9);
    assert_eq!(decryption_details.byte_transform_candidates, 1);
    assert_eq!(decryption_details.selected_chain, None);
}

#[test]
fn decryption_rejects_excess_candidate_pairs_before_replay() {
    let key = [0x3c; AES_256_KEY_SIZE];
    let packed = encode_context(&key, 0x39).to_vec();
    let record = ARecord {
        source_offset: 0,
        encoded_length: 1,
        destination_rva: 0,
        destination_length: 2,
    };
    let decoder_candidates = (0..=MAX_DECRYPTION_REPLAY_PAIRS)
        .map(|_| DecoderCandidate {
            source_file_offset: 0,
            phase: 0,
            table: root_literal_table(0),
        })
        .collect();

    let mapped = [0; 2];
    let error = select_decryption_plan(
        &packed,
        0..AES_CONTEXT_SIZE,
        AES_CONTEXT_SIZE,
        &mapped,
        &[record],
        decoder_candidates,
        &[PayloadPostTransform::F8],
    )
    .err()
    .expect("over-cap candidate pairs must fail before replay");
    assert!(
        error.to_string().contains("candidate pairs"),
        "unexpected replay-pair error: {error:#}"
    );
}

#[test]
fn aes_context_validation_budget_rejects_many_invalid_prefixes_deterministically() {
    const VALIDATION_LIMIT: usize = 8;
    let mut invalid_context = encode_context(&[0xa5; AES_256_KEY_SIZE], 0x39);
    invalid_context[AES_CONTEXT_HEADER.len()] ^= 0x80;
    let data = invalid_context.repeat(VALIDATION_LIMIT + 1);
    assert!(data.len() <= MAX_AES_CONTEXT_SCAN_BYTES);

    let reject_invalid_prefixes = || {
        let mut validation_budget = AesContextValidationBudget::with_limit(VALIDATION_LIMIT);
        let error =
            scan_aes_contexts_in_range_with_budget(&data, 0..data.len(), &mut validation_budget)
                .expect_err(
                    "invalid encoded header candidates must exhaust the shared validation cap",
                );
        assert_eq!(validation_budget.candidates, VALIDATION_LIMIT);
        error.to_string()
    };

    let first_error = reject_invalid_prefixes();
    let second_error = reject_invalid_prefixes();
    assert_eq!(first_error, second_error);
    assert!(
        first_error.contains("8-candidate validation work cap"),
        "unexpected AES-context validation budget error: {first_error}"
    );
}

#[test]
fn decryption_ignores_aes_contexts_outside_descriptor_source() {
    let mut fixture = build_fixture(options_a());
    fixture.packed[fixture.context_range.clone()].fill(0);
    let overlay_offset = fixture.packed.len();
    fixture.packed.extend_from_slice(&fixture.encoded_context);
    assert_eq!(
        scan_aes_contexts_in_range(&fixture.packed, 0..fixture.packed.len())
            .expect("bounded diagnostic scan")
            .iter()
            .map(|context| context.file_offset)
            .collect::<Vec<_>>(),
        [overlay_offset]
    );

    let mut mapped = vec![0x5a; 0x7000];
    let original = mapped.clone();
    assert!(decrypt_bootstrap_into(&fixture.packed, fixture.bootstrap, &mut mapped).is_err());
    assert_eq!(mapped, original);

    assert!(ensure_aes_context_scan_bound(MAX_AES_CONTEXT_SCAN_BYTES + 1).is_err());
}

#[test]
fn derive_outer_source_rejects_an_oversized_descriptor_before_cloning() {
    let source_length = MAX_OUTER_SOURCE_BYTES + 1;
    let packed = vec![0; source_length];
    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0,
        source_offset: 0,
        length: u32::try_from(source_length).expect("test source length fits u32"),
        source_rva: 0,
    };

    let error = derive_outer_source(&packed, bootstrap)
        .expect_err("oversized descriptor source must fail before cloning");
    assert!(
        error.to_string().contains("per-descriptor cap"),
        "unexpected outer-source error: {error:#}"
    );
}

#[test]
fn rejects_corruption_truncation_and_missing_a_candidate_without_mutation() {
    let mut fixture = build_fixture(options_a());
    let mut mapped = vec![0x6d; 0x7000];
    let original = mapped.clone();
    fixture.packed[fixture.source_start + fixture.table_offset] ^= 0x80;
    assert!(decrypt_bootstrap_into(&fixture.packed, fixture.bootstrap, &mut mapped).is_err());
    assert_eq!(mapped, original);

    let fixture = build_fixture(options_b());
    let mut mapped = vec![0x6d; 0x7000];
    let original = mapped.clone();
    let stream_base = fixture.stream_base;
    let truncated = &fixture.packed[..stream_base + 16];
    assert!(decrypt_bootstrap_into(truncated, fixture.bootstrap, &mut mapped).is_err());
    assert_eq!(mapped, original);

    let bootstrap = PackedBootstrap {
        descriptor_file_offset: 0,
        key: 0,
        destination_rva: 0x2000,
        source_offset: 0,
        length: 0x2000,
        source_rva: 0x2000,
    };
    let packed = vec![0; 0x2200];
    let mut mapped = vec![0x6d; 0x4000];
    let original = mapped.clone();
    assert!(decrypt_bootstrap_into(&packed, bootstrap, &mut mapped).is_err());
    assert_eq!(mapped, original);
}

#[test]
fn rejects_equal_length_descriptor_ambiguity_without_mutation() {
    let options = options_a();
    let mut fixture = build_fixture(options);
    let source_start = fixture.source_start;
    let mut outer = derive_outer_source(&fixture.packed, fixture.bootstrap)
        .expect("fixture outer source")
        .1;
    let first = options.table_offset;
    let second = 0x500;
    let span = options.records * A_RECORD_SIZE;
    let mut duplicate = outer[first..first + span].to_vec();
    f2a0_transform_from_dl(&mut duplicate, 0x6d);
    for (index, record) in duplicate.chunks_exact_mut(A_RECORD_SIZE).enumerate() {
        f710_record_transform(
            record,
            options.destination_rva + first as u32 + (index * A_RECORD_SIZE) as u32,
        );
        inverse_f710(
            record,
            options.destination_rva + second as u32 + (index * A_RECORD_SIZE) as u32,
        );
    }
    inverse_f2a0(&mut duplicate, 0x6d);
    outer[second..second + span].copy_from_slice(&duplicate);

    let prefix = options.prefix_length;
    let source = encrypt_outer_source(&outer, fixture.bootstrap, prefix, &[]);
    fixture.packed[source_start..source_start + source.len()].copy_from_slice(&source);
    fixture.packed[fixture.context_range.clone()].copy_from_slice(&fixture.encoded_context);
    let mut mapped = vec![0x5a; 0x7000];
    let original = mapped.clone();
    assert!(decrypt_bootstrap_into(&fixture.packed, fixture.bootstrap, &mut mapped).is_err());
    assert_eq!(mapped, original);
}
