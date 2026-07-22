use super::{
    DESCRIPTOR_SIZE, DiscoveryBudget, ImportModule, ImportProfile, ImportSymbol, MAX_API_NAME_LEN,
    MAX_ATTEMPTED_LOADER_STRING_BYTES, MAX_PARSED_DESCRIPTORS, MAX_PARSED_FUNCTIONS,
    MAX_REFERENCED_METADATA_BYTES, MAX_SCANNED_DESCRIPTOR_STARTS, MAX_VALID_CANDIDATES,
    discover_imports_in_image, named_thunk_rva, ordinal_flag, pointer_size_rva,
};
use crate::pe::{DataDirectory, PointerWidth};
use crate::unpack::imports::test_support::*;

#[test]
fn named_pe32_plus_thunks_accept_only_plain_or_exact_bit32_tag() {
    assert_eq!(named_thunk_rva(PointerWidth::U32, 0x1234), Some(0x1234));
    assert_eq!(named_thunk_rva(PointerWidth::U32, 0x1_0000_1234), None);
    assert_eq!(named_thunk_rva(PointerWidth::U64, 0x1234), Some(0x1234));
    assert_eq!(
        named_thunk_rva(PointerWidth::U64, 0x1_0000_1234),
        Some(0x1234)
    );
    assert_eq!(named_thunk_rva(PointerWidth::U64, 0x2_0000_1234), None);
    assert_eq!(named_thunk_rva(PointerWidth::U64, 0x1_0000_0000_1234), None);
}
#[test]
fn loader_discovery_finds_shifted_graphs_and_exact_metadata_ranges() {
    for pointer_width in [PointerWidth::U32, PointerWidth::U64] {
        let first = fixture_for_width(pointer_width, 0x21_000, 0x34, &graph_specs());
        let second = fixture_for_width(pointer_width, 0x4b_000, 0xbc, &graph_specs());
        let first_discovery =
            discover_imports_in_image(&first.mapped, &first.pe, ImportProfile::EncodedLoader)
                .unwrap();
        let second_discovery =
            discover_imports_in_image(&second.mapped, &second.pe, ImportProfile::EncodedLoader)
                .unwrap();
        assert_eq!(first_discovery.table_rva, first.run.table_rva);
        assert_eq!(second_discovery.table_rva, second.run.table_rva);
        assert_eq!(first_discovery.modules, first.run.expected_modules);
        assert_eq!(second_discovery.modules, second.run.expected_modules);
        assert_eq!(
            first_discovery.metadata_ranges,
            merged_ranges(first.run.referenced_ranges.clone())
        );
        assert_eq!(
            second_discovery.metadata_ranges,
            merged_ranges(second.run.referenced_ranges.clone())
        );
    }
}

#[test]
fn standard_discovery_accepts_tagged_pe32_plus_shared_iat() {
    let mut pe = synthetic_pe(0x4000, vec![section(0, 0x1000, 0x2000)], PointerWidth::U64);
    let mut mapped = vec![0u8; 0x4000];
    let descriptor_rva = 0x1100u32;
    let iat_rva = 0x1204u32;
    let dll_rva = 0x1280u32;
    let record_rva = 0x12a0u32;
    put(&mut mapped, descriptor_rva, 0);
    put(&mut mapped, descriptor_rva + 12, dll_rva);
    put(&mut mapped, descriptor_rva + 16, iat_rva);
    put_pointer_cell(
        &pe,
        &mut mapped,
        iat_rva,
        (1u64 << 32) | u64::from(record_rva),
    );
    put_pointer_cell(&pe, &mut mapped, iat_rva + 8, 0);
    mapped[usize::try_from(dll_rva).unwrap()..][..13].copy_from_slice(b"kernel32.dll\0");
    mapped[usize::try_from(record_rva).unwrap()..][..2].copy_from_slice(&7u16.to_le_bytes());
    mapped[usize::try_from(record_rva + 2).unwrap()..][..6].copy_from_slice(b"Sleep\0");
    pe.directories[1] = DataDirectory {
        virtual_address: descriptor_rva,
        size: 2 * DESCRIPTOR_SIZE as u32,
    };
    let discovery = discover_imports_in_image(&mapped, &pe, ImportProfile::Standard).unwrap();
    assert_eq!(
        discovery.modules,
        vec![ImportModule {
            dll: "kernel32.dll".to_owned(),
            destination_rva: iat_rva,
            symbols: vec![ImportSymbol::Name {
                hint: 7,
                name: "Sleep".to_owned()
            }],
        }]
    );
    assert!(
        discovery
            .metadata_ranges
            .iter()
            .all(|range| range.end <= iat_rva || iat_rva + 16 <= range.start)
    );
}

#[test]
fn loader_discovery_rejects_ambiguous_and_malformed_graphs() {
    let first_base = 0x12_000;

    let second_base = 0x28_000;
    let image_size = second_base + TABLE_SECTION_SIZE;
    let mut mapped = vec![0xa5; usize::try_from(image_size).unwrap()];
    let pe = synthetic_pe(
        image_size,
        vec![
            section(0, IAT_SECTION_RVA, IAT_SECTION_SIZE),
            section(1, first_base, TABLE_SECTION_SIZE),
            section(2, second_base, TABLE_SECTION_SIZE),
        ],
        PointerWidth::U32,
    );
    mapped[usize::try_from(IAT_SECTION_RVA).unwrap()
        ..usize::try_from(IAT_SECTION_RVA + IAT_SECTION_SIZE).unwrap()]
        .fill(0);
    let specs = [ModuleSpec {
        dll: "one",
        symbols: vec![named("Open", 0)],
        destination_rva: IAT_SECTION_RVA + 0x100,
    }];
    write_run(&pe, &mut mapped, first_base, 0x20, &specs);
    write_run(&pe, &mut mapped, second_base, 0xa0, &specs);
    let error = discover_imports_in_image(&mapped, &pe, ImportProfile::EncodedLoader)
        .unwrap_err()
        .to_string();
    assert!(error.contains("ambiguous"), "{error}");

    let mut invalid = fixture(
        0x41_000,
        0x30,
        &[ModuleSpec {
            dll: "valid",
            symbols: vec![named("Open", 0)],
            destination_rva: IAT_SECTION_RVA + 0x100,
        }],
    );
    let dll_rva = invalid.run.dll_rvas[0];
    invalid.mapped[usize::try_from(dll_rva + 5).unwrap()] = 0xa5;
    assert!(
        discover_imports_in_image(&invalid.mapped, &invalid.pe, ImportProfile::EncodedLoader)
            .is_err()
    );
}

#[test]
fn loader_discovery_preserves_pe32_plus_thunk_address_checks() {
    let mut named_thunk = fixture_for_width(
        PointerWidth::U64,
        0x4d_000,
        0x30,
        &[ModuleSpec {
            dll: "valid",
            symbols: vec![named("Open", 0)],
            destination_rva: IAT_SECTION_RVA + 0x100,
        }],
    );
    put_pointer_cell(
        &named_thunk.pe,
        &mut named_thunk.mapped,
        named_thunk.run.source_rvas[0],
        0x0000_0001_0000_1000,
    );
    assert!(
        discover_imports_in_image(
            &named_thunk.mapped,
            &named_thunk.pe,
            ImportProfile::EncodedLoader
        )
        .is_err()
    );

    for pointer_width in [PointerWidth::U32, PointerWidth::U64] {
        let mut ordinal_thunk = fixture_for_width(
            pointer_width,
            0x4f_000,
            0x30,
            &[ModuleSpec {
                dll: "valid",
                symbols: vec![ImportSymbol::Ordinal(1)],
                destination_rva: IAT_SECTION_RVA + 0x100,
            }],
        );
        put_pointer_cell(
            &ordinal_thunk.pe,
            &mut ordinal_thunk.mapped,
            ordinal_thunk.run.source_rvas[0],
            ordinal_flag(pointer_width) | 0x0001_0000,
        );
        assert!(
            discover_imports_in_image(
                &ordinal_thunk.mapped,
                &ordinal_thunk.pe,
                ImportProfile::EncodedLoader
            )
            .is_err()
        );
    }
}

#[test]
fn discovery_work_budgets_fail_closed() {
    let mut scan = DiscoveryBudget {
        scanned_descriptor_starts: MAX_SCANNED_DESCRIPTOR_STARTS,
        ..DiscoveryBudget::default()
    };
    assert!(scan.scanned_descriptor_start().is_err());

    let mut descriptor = DiscoveryBudget {
        parsed_descriptors: MAX_PARSED_DESCRIPTORS,
        ..DiscoveryBudget::default()
    };
    assert!(descriptor.parsed_descriptor().is_err());

    let mut function = DiscoveryBudget {
        parsed_functions: MAX_PARSED_FUNCTIONS,
        ..DiscoveryBudget::default()
    };
    assert!(function.parsed_function().is_err());

    let mut candidate = DiscoveryBudget {
        valid_candidates: MAX_VALID_CANDIDATES,
        ..DiscoveryBudget::default()
    };
    assert!(candidate.valid_candidate().is_err());

    let mut metadata = DiscoveryBudget {
        referenced_metadata_bytes: MAX_REFERENCED_METADATA_BYTES,
        ..DiscoveryBudget::default()
    };
    assert!(metadata.referenced_metadata(1).is_err());

    let mut loader_string = DiscoveryBudget {
        attempted_loader_string_bytes: MAX_ATTEMPTED_LOADER_STRING_BYTES,
        ..DiscoveryBudget::default()
    };
    assert!(loader_string.attempted_loader_string_byte().is_err());
}

#[test]
fn many_invalid_loader_strings_exhaust_the_global_byte_budget() {
    let string_bytes = MAX_API_NAME_LEN + 1;
    let descriptor_count = MAX_ATTEMPTED_LOADER_STRING_BYTES / string_bytes + 1;
    let descriptor_bytes = (descriptor_count + 1) * DESCRIPTOR_SIZE;
    let table_rva = 0x80_000;
    let source_offset = descriptor_bytes + 0x20;
    let record_offset = source_offset + 0x10;
    let name_offset = record_offset + 2;
    let dll_offset = name_offset + string_bytes + 0x10;
    let table_size = u32::try_from(dll_offset + 0x20).unwrap();
    let image_size = table_rva + table_size;
    let mut mapped = vec![0xa5; usize::try_from(image_size).unwrap()];
    let pe = synthetic_pe(
        image_size,
        vec![
            section(0, IAT_SECTION_RVA, IAT_SECTION_SIZE),
            section(1, table_rva, table_size),
        ],
        PointerWidth::U32,
    );
    mapped[usize::try_from(IAT_SECTION_RVA).unwrap()
        ..usize::try_from(IAT_SECTION_RVA + IAT_SECTION_SIZE).unwrap()]
        .fill(0);

    let source_rva = table_rva + u32::try_from(source_offset).unwrap();
    let record_rva = table_rva + u32::try_from(record_offset).unwrap();
    let name_rva = table_rva + u32::try_from(name_offset).unwrap();
    let dll_rva = table_rva + u32::try_from(dll_offset).unwrap();
    mapped[usize::try_from(record_rva).unwrap()..usize::try_from(name_rva).unwrap()].fill(0);
    put_pointer_cell(&pe, &mut mapped, source_rva, u64::from(record_rva));
    put_pointer_cell(
        &pe,
        &mut mapped,
        source_rva + pointer_size_rva(pe.pointer_width()),
        0,
    );

    let mut name_key = record_rva as u8;
    for offset in 0..string_bytes {
        let character = if b'A'.wrapping_add(name_key) == 0 {
            b'B'
        } else {
            b'A'
        };
        mapped[usize::try_from(name_rva).unwrap() + offset] =
            character.wrapping_add(name_key).rotate_right(4);
        name_key = name_key.wrapping_add(0x43);
    }
    let mut dll_key = dll_rva as u8;
    let mut dll = Vec::with_capacity(3);
    for _ in 0..3 {
        let character = if b'A'.wrapping_add(dll_key) == 0 {
            b'B'
        } else {
            b'A'
        };
        dll.push(character);
        dll_key = dll_key.wrapping_add(0x43);
    }
    let dll = String::from_utf8(dll).unwrap();
    encode_string(&mut mapped, dll_rva, dll_rva, &dll);

    for index in 0..descriptor_count {
        let descriptor_rva =
            table_rva + u32::try_from(index.checked_mul(DESCRIPTOR_SIZE).unwrap()).unwrap();
        put(&mut mapped, descriptor_rva, source_rva);
        put(&mut mapped, descriptor_rva + 4, 0);
        put(&mut mapped, descriptor_rva + 8, 0);
        put(&mut mapped, descriptor_rva + 12, dll_rva);
        put(&mut mapped, descriptor_rva + 16, IAT_SECTION_RVA + 0x100);
    }
    let null_descriptor_rva =
        table_rva + u32::try_from(descriptor_count * DESCRIPTOR_SIZE).unwrap();
    mapped[usize::try_from(null_descriptor_rva).unwrap()
        ..usize::try_from(null_descriptor_rva + DESCRIPTOR_SIZE as u32).unwrap()]
        .fill(0);

    let error = discover_imports_in_image(&mapped, &pe, ImportProfile::EncodedLoader)
        .unwrap_err()
        .to_string();
    assert!(error.contains("loader string byte budget"), "{error}");
}
