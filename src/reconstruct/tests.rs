use super::*;
use crate::pe::{Machine, Section};

fn test_pe() -> Pe {
    Pe {
        opt: 0x98,
        machine: Machine::I386,
        coff_characteristics: 0x102,
        section_count: 1,
        entry_rva: 0x1000,
        image_base: 0x400000,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: 0x2000,
        size_of_headers: 0x200,
        checksum_offset: 0xd8,
        data_directory_table_offset: 0xf8,
        directories: vec![
            DataDirectory {
                virtual_address: 0,
                size: 0
            };
            16
        ],
        sections: vec![Section {
            index: 0,
            header_offset: 0x178,
            name_bytes: *b".data\0\0\0",
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_size: 0x1000,
            raw_pointer: 0x200,
            characteristics: 0xc0000040,
        }],
        file_len: 0x1200,
    }
}

fn put_u32(image: &mut [u8], rva: usize, value: u32) {
    image[rva..rva + 4].copy_from_slice(&value.to_le_bytes());
}

fn standard_import(image: &mut [u8], start: usize, suffix: u8) {
    put_u32(image, start, (start + 0x40) as u32);
    put_u32(image, start + 12, (start + 0x60) as u32);
    put_u32(image, start + 16, (start + 0x80) as u32);
    put_u32(image, start + 0x40, (start + 0xa0) as u32);
    image[start + 0x60..start + 0x68].copy_from_slice(b"mod.dll\0");
    image[start + 0xa2..start + 0xa7].copy_from_slice(b"Func\0");
    image[start + 0xa0] = suffix;
}

fn standard_export(image: &mut [u8], start: usize) {
    put_u32(image, start + 12, (start + 0x40) as u32);
    put_u32(image, start + 16, 1);
    put_u32(image, start + 20, 1);
    put_u32(image, start + 24, 1);
    put_u32(image, start + 28, (start + 0x50) as u32);
    put_u32(image, start + 32, (start + 0x60) as u32);
    put_u32(image, start + 36, (start + 0x64) as u32);
    image[start + 0x40..start + 0x46].copy_from_slice(b"x.dll\0");
    put_u32(image, start + 0x50, 0x1400);
    put_u32(image, start + 0x60, (start + 0x70) as u32);
    image[start + 0x70..start + 0x75].copy_from_slice(b"Func\0");
}

#[test]
fn import_scanner_ignores_directory_values_and_rejects_competing_graphs() {
    let mut pe = test_pe();
    let mut image = vec![0; 0x2000];
    standard_import(&mut image, 0x1100, 0);
    pe.directories[IMPORT_DIRECTORY] = DataDirectory {
        virtual_address: 0x1abc,
        size: 1,
    };
    let selected = select_import_candidate(scan_import_candidates(&image, &pe).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(selected.start, 0x1100);
    assert_eq!(selected.graph.functions, 1);

    standard_import(&mut image, 0x1200, 1);
    assert!(select_import_candidate(scan_import_candidates(&image, &pe).unwrap()).is_err());
}

#[test]
fn candidate_cleanup_removes_proven_metadata_without_touching_unrelated_bytes() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    standard_import(&mut image, 0x1100, 0);
    image[0x1700..0x1709].copy_from_slice(b"unrelated");
    let candidate = select_import_candidate(scan_import_candidates(&image, &pe).unwrap())
        .unwrap()
        .unwrap();
    clear_candidate(&mut image, &pe, &candidate).unwrap();
    assert!(
        image
            .windows(b"mod.dll".len())
            .all(|window| window != b"mod.dll")
    );
    assert!(image.windows(b"Func".len()).all(|window| window != b"Func"));
    assert_eq!(&image[0x1700..0x1709], b"unrelated");
}

fn two_module_import(image: &mut [u8], start: usize) {
    for (descriptor, lookup, dll, iat, hint_name, module, api) in [
        (
            start,
            start + 0x40,
            start + 0x60,
            start + 0x80,
            start + 0xa0,
            b"one.dll\0".as_slice(),
            b"One\0".as_slice(),
        ),
        (
            start + 20,
            start + 0xc0,
            start + 0xe0,
            start + 0x100,
            start + 0x120,
            b"two.dll\0".as_slice(),
            b"Two\0".as_slice(),
        ),
    ] {
        put_u32(image, descriptor, lookup as u32);
        put_u32(image, descriptor + 12, dll as u32);
        put_u32(image, descriptor + 16, iat as u32);
        put_u32(image, lookup, hint_name as u32);
        image[dll..dll + module.len()].copy_from_slice(module);
        image[hint_name + 2..hint_name + 2 + api.len()].copy_from_slice(api);
    }
}

#[test]
fn selected_import_winner_coalesces_suffixes_and_rejects_disjoint_graphs_without_mutation() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    two_module_import(&mut image, 0x1100);
    image[0x1700..0x1709].copy_from_slice(b"untouched");
    let winner = select_import_candidate(scan_import_candidates(&image, &pe).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(winner.graph.modules.len(), 2);
    clear_selected_import_candidate(&mut image, &pe).unwrap();
    assert!(
        image
            .windows(b"one.dll".len())
            .all(|window| window != b"one.dll")
    );
    assert!(
        image
            .windows(b"two.dll".len())
            .all(|window| window != b"two.dll")
    );
    assert_eq!(&image[0x1700..0x1709], b"untouched");
    let mut competing = vec![0; 0x2000];
    two_module_import(&mut competing, 0x1100);
    standard_import(&mut competing, 0x1400, 0);
    let before = competing.clone();
    assert!(clear_selected_import_candidate(&mut competing, &pe).is_err());
    assert_eq!(competing, before);
}
#[test]
fn import_scanner_rejects_invalid_ordinal_encoding() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    standard_import(&mut image, 0x1100, 0);
    put_u32(&mut image, 0x1140, 0x8001_0001);
    assert!(scan_import_candidates(&image, &pe).unwrap().is_empty());
}

#[test]
fn export_scanner_ignores_directory_values_and_rejects_invalid_target() {
    let mut pe = test_pe();
    let mut image = vec![0; 0x2000];
    standard_export(&mut image, 0x1300);
    pe.directories[EXPORT_DIRECTORY] = DataDirectory {
        virtual_address: 0,
        size: 0,
    };
    let selected = scan_export(&image, &pe).unwrap().unwrap();
    assert_eq!(selected.rva, 0x1300);
    assert_eq!(selected.functions, 1);
    assert_eq!(selected.names, 1);

    put_u32(&mut image, 0x1350, 0x3000);
    assert!(scan_export(&image, &pe).unwrap().is_none());
}

#[test]
fn resource_closure_includes_contiguous_payload_and_rejects_cross_section_payload() {
    let mut pe = test_pe();
    let mut image = vec![0; 0x3000];
    let root = 0x1100usize;
    // Root -> type -> name -> language -> IMAGE_RESOURCE_DATA_ENTRY.
    image[root + 14..root + 16].copy_from_slice(&1u16.to_le_bytes());
    put_u32(&mut image, root + 20, 0x8000_0018);
    image[root + 0x18 + 14..root + 0x18 + 16].copy_from_slice(&1u16.to_le_bytes());
    put_u32(&mut image, root + 0x18 + 20, 0x8000_0030);
    image[root + 0x30 + 14..root + 0x30 + 16].copy_from_slice(&1u16.to_le_bytes());
    put_u32(&mut image, root + 0x30 + 20, 0x48);
    put_u32(&mut image, root + 0x48, (root + 0x58) as u32);
    put_u32(&mut image, root + 0x4c, 0x17d);
    let mut nodes = 0;
    assert_eq!(
        resource_node(&image, &pe, root as u32, root as u32, 0, &mut nodes).unwrap(),
        Some((root + 0x1d5) as u32)
    );
    pe.sections.push(Section {
        index: 1,
        header_offset: 0x1a0,
        name_bytes: *b".next\0\0\0",
        virtual_size: 0x1000,
        virtual_address: 0x2000,
        raw_size: 0x1000,
        raw_pointer: 0x1200,
        characteristics: 0xc0000040,
    });
    pe.section_count = 2;
    pe.size_of_image = 0x3000;
    put_u32(&mut image, root + 0x48, 0x2000);
    put_u32(&mut image, root + 0x4c, 1);
    let mut nodes = 0;
    assert_eq!(
        resource_node(&image, &pe, root as u32, root as u32, 0, &mut nodes).unwrap(),
        None
    );
}

#[test]
fn forwarder_grammar_rejects_non_decimal_ordinals() {
    assert!(valid_forwarder("other.RealName"));
    assert!(valid_forwarder("other.#12"));
    assert!(!valid_forwarder("other.#abc"));
}

#[test]
fn retained_directory_validators_reject_unsupported_and_malformed_metadata() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    assert!(
        validate_retained_directory(
            &image,
            &pe,
            7,
            DataDirectory {
                virtual_address: 0x1100,
                size: 4
            }
        )
        .is_err()
    );
    put_u32(&mut image, 0x1100, 72);
    put_u32(&mut image, 0x1108, 0x1200);
    put_u32(&mut image, 0x110c, 16);
    assert!(
        validate_clr_directory(
            &image,
            &pe,
            DataDirectory {
                virtual_address: 0x1100,
                size: 72
            }
        )
        .is_err()
    );
    put_u32(&mut image, 0x1100 + 16, 1);
    put_u32(&mut image, 0x1100 + 20, 0);
    put_u32(&mut image, 0x1100 + 24, 0x1234);
    assert!(
        validate_debug_directory(
            &image,
            &pe,
            DataDirectory {
                virtual_address: 0x1100,
                size: 28
            }
        )
        .is_err()
    );
}

#[test]
fn export_forwarder_after_initial_closure_extends_directory_size() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    standard_export(&mut image, 0x1300);
    put_u32(&mut image, 0x1350, 0x1500);
    image[0x1500..0x150a].copy_from_slice(b"other.#12\0");
    let export = scan_export(&image, &pe).unwrap().unwrap();
    assert_eq!(export.size, 0x20a);
}

#[test]
fn cloned_import_graph_at_disjoint_rva_is_rejected() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    standard_import(&mut image, 0x1100, 0);
    let descriptor = image[0x1100..0x1114].to_vec();
    image[0x1500..0x1514].copy_from_slice(&descriptor);
    assert!(select_import_candidate(scan_import_candidates(&image, &pe).unwrap()).is_err());
}

#[test]
fn tls_callback_array_must_terminate() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    // PE32 AddressOfCallbacks points to a non-terminated array of valid VAs.
    put_u32(&mut image, 0x1100 + 12, 0x401180);
    for cell in (0x1180..0x2000).step_by(4) {
        put_u32(&mut image, cell, 0x401100);
    }
    assert!(
        validate_tls_directory(
            &image,
            &pe,
            DataDirectory {
                virtual_address: 0x1100,
                size: 24
            }
        )
        .is_err()
    );
}

#[test]
fn serializer_preserves_executable_section_protection() {
    let mut pe = test_pe();
    pe.sections[0].characteristics = 0x6000_0020;
    let mut mapped = vec![0; 0x2000];
    mapped[..0x200].fill(0);
    let output = serialize_sections(
        &mapped,
        &pe,
        0x2000,
        0x1000,
        &[],
        0x1000,
        None,
        0,
        0x3000,
        &[],
        DataDirectory {
            virtual_address: 0x1100,
            size: 4,
        },
    )
    .unwrap();
    let characteristics = u32::from_le_bytes(output[0x178 + 36..0x178 + 40].try_into().unwrap());
    assert_eq!(characteristics, 0x6000_0020);
    assert_eq!(characteristics & 0x8000_0000, 0);
}

#[test]
fn serializer_translates_debug_pointer_for_nonidentity_raw_layout() {
    let pe = test_pe();
    let mut mapped = vec![0; 0x2000];
    // IMAGE_DEBUG_DIRECTORY at RVA 0x1100: SizeOfData=4, AddressOfRawData=0x1180,
    // deliberately stale PointerToRawData=0xdeadbeef.
    put_u32(&mut mapped, 0x1100 + 16, 4);
    put_u32(&mut mapped, 0x1100 + 20, 0x1180);
    put_u32(&mut mapped, 0x1100 + 24, 0xdead_beef);
    let debug = DataDirectory {
        virtual_address: 0x1100,
        size: 28,
    };
    let output = serialize_sections(
        &mapped,
        &pe,
        0x2000,
        0x1000,
        &[],
        0x1000,
        None,
        0,
        0x3000,
        &[(6, debug)],
        DataDirectory {
            virtual_address: 0x1100,
            size: 4,
        },
    )
    .unwrap();
    // Headers take 0x200 bytes; the section is laid out at raw 0x200, so RVA 0x1100 maps to 0x300.
    assert_eq!(
        u32::from_le_bytes(output[0x300 + 24..0x300 + 28].try_into().unwrap()),
        0x380
    );
}

#[test]
fn iat_envelope_covers_holes_within_one_owner_section() {
    let pe = test_pe();
    let discovery = LoaderDiscovery {
        table_rva: 0,
        metadata_ranges: Vec::new(),
        image_size: pe.size_of_image,
        modules: vec![
            ImportModule {
                dll: "a.dll".into(),
                destination_rva: 0x1100,
                symbols: vec![ImportSymbol::Ordinal(1)],
            },
            ImportModule {
                dll: "b.dll".into(),
                destination_rva: 0x1180,
                symbols: vec![ImportSymbol::Ordinal(2)],
            },
        ],
        function_count: 2,
        named_count: 0,
        ordinal_count: 2,
    };
    assert_eq!(
        iat_directory(&pe, &discovery).unwrap(),
        DataDirectory {
            virtual_address: 0x1100,
            size: 0x88
        }
    );
}

#[test]
fn iat_envelope_rejects_cross_section_and_missing_slot() {
    let mut pe = test_pe();
    pe.sections.push(Section {
        index: 1,
        header_offset: 0x1a0,
        name_bytes: *b".next\0\0\0",
        virtual_size: 0x1000,
        virtual_address: 0x2000,
        raw_size: 0x1000,
        raw_pointer: 0x1200,
        characteristics: 0xc0000040,
    });
    pe.section_count = 2;
    pe.size_of_image = 0x3000;
    let discovery = LoaderDiscovery {
        table_rva: 0,
        metadata_ranges: Vec::new(),
        image_size: pe.size_of_image,
        modules: vec![
            ImportModule {
                dll: "a.dll".into(),
                destination_rva: 0x1100,
                symbols: vec![ImportSymbol::Ordinal(1)],
            },
            ImportModule {
                dll: "b.dll".into(),
                destination_rva: 0x2000,
                symbols: vec![ImportSymbol::Ordinal(2)],
            },
        ],
        function_count: 2,
        named_count: 0,
        ordinal_count: 2,
    };
    assert!(iat_directory(&pe, &discovery).is_err());
    pe.directories.truncate(IAT_DIRECTORY);
    assert!(
        serialize_sections(
            &vec![0; 0x3000],
            &pe,
            0x3000,
            0x1000,
            &[],
            0x1000,
            None,
            0,
            0x4000,
            &[],
            DataDirectory {
                virtual_address: 0x1100,
                size: 4
            }
        )
        .is_err()
    );
}

#[test]
fn section_aggregate_sizes_sum_mixed_flags_by_pe_rules() {
    let actual = section_aggregate_sizes([
        Ok((
            0x200,
            0x100,
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA,
        )),
        Ok((
            0x400,
            0x300,
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA,
        )),
        Ok((0x800, 0x500, IMAGE_SCN_CNT_UNINITIALIZED_DATA)),
    ])
    .unwrap();
    assert_eq!(actual, (0x200, 0x600, 0x800));
}

#[test]
fn section_aggregate_sizes_reject_overflow() {
    assert!(
        section_aggregate_sizes([
            Ok((u32::MAX, 0, IMAGE_SCN_CNT_CODE)),
            Ok((1, 0, IMAGE_SCN_CNT_CODE))
        ])
        .is_err()
    );
}

#[test]
fn compact_raw_layout_trims_nonzero_prefix_to_file_alignment() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    image[0x1357] = 1;
    let layout = compact_raw_layout(&image, &pe, &[]).unwrap();
    assert_eq!(layout[0].raw_size, 0x400);
}

#[test]
fn compact_raw_layout_allows_zero_raw_sections_and_keeps_late_data() {
    let pe = test_pe();
    let mut image = vec![0; 0x2000];
    assert_eq!(compact_raw_layout(&image, &pe, &[]).unwrap()[0].raw_size, 0);
    image[0x1fff] = 0x7f;
    assert_eq!(
        compact_raw_layout(&image, &pe, &[]).unwrap()[0].raw_size,
        0x1000
    );
}

#[test]
fn compact_raw_layout_keeps_zeroed_debug_payload_in_the_raw_prefix() {
    let mut pe = test_pe();
    let mut image = vec![0; 0x2000];
    pe.directories[6] = DataDirectory {
        virtual_address: 0x1100,
        size: 28,
    };
    put_u32(&mut image, 0x1100 + 16, 0x20);
    put_u32(&mut image, 0x1100 + 20, 0x1800);
    assert_eq!(
        compact_raw_layout(&image, &pe, &[(6, pe.directories[6])]).unwrap()[0].raw_size,
        0xa00
    );
}

#[test]
fn serializer_maps_trimmed_zero_tail_back_to_the_original_image() {
    let pe = test_pe();
    let mut mapped = vec![0; 0x2000];
    mapped[0x1357] = 1;
    mapped[..2].copy_from_slice(b"MZ");
    put_u32(&mut mapped, 0x3c, 0x80);
    mapped[0x80..0x84].copy_from_slice(b"PE\0\0");
    mapped[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
    mapped[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    mapped[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
    mapped[0x96..0x98].copy_from_slice(&0x102u16.to_le_bytes());
    mapped[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
    put_u32(&mut mapped, 0x98 + 16, 0x1000);
    put_u32(&mut mapped, 0x98 + 28, 0x400000);
    put_u32(&mut mapped, 0x98 + 32, 0x1000);
    put_u32(&mut mapped, 0x98 + 36, 0x200);
    put_u32(&mut mapped, 0x98 + 56, 0x3000);
    put_u32(&mut mapped, 0x98 + 60, 0x200);
    put_u32(&mut mapped, 0x98 + 92, 16);
    let output = serialize_sections(
        &mapped,
        &pe,
        0x2000,
        0x1000,
        &[],
        0x1000,
        None,
        0,
        0x3000,
        &[],
        DataDirectory {
            virtual_address: 0x1100,
            size: 4,
        },
    )
    .unwrap();
    assert_eq!(
        u32::from_le_bytes(output[0x178 + 8..0x178 + 12].try_into().unwrap()),
        0x1000
    );
    assert_eq!(
        u32::from_le_bytes(output[0x178 + 16..0x178 + 20].try_into().unwrap()),
        0x400
    );
    assert_eq!(&output[0x200..0x600], &mapped[0x1000..0x1400]);
    let emitted = Pe::parse(&output).unwrap();
    let remapped = emitted.map_image(&output).unwrap();
    assert_eq!(&remapped[0x1000..0x2000], &mapped[0x1000..0x2000]);
}
