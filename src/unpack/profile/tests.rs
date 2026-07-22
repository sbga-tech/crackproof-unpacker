use super::{
    native::{
        amd64::{amd64_crt_startup_evidence, authenticate_amd64_sparse_entry},
        i386::{SemanticVeneer, authenticate_i386_sparse_entry, executable_jumps},
    },
    *,
};
use crate::pe::{DataDirectory, Machine, Section};

const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const AMD64_DEFAULT_SECURITY_COOKIE: u64 = 0x0000_2b99_2ddf_a232;
const MAX_EXECUTABLE_JUMPS: usize = 65_536;

const TEST_IMAGE_BASE: u64 = 0x0040_0000;

const FIRST_EXECUTABLE_RVA: u32 = 0x1000;
const FIRST_EXECUTABLE_SIZE: u32 = 0x400;
const SECOND_EXECUTABLE_RVA: u32 = 0x3000;
const SECOND_EXECUTABLE_SIZE: u32 = 0x400;
const NON_EXECUTABLE_RVA: u32 = 0x5000;
const IMAGE_END_RVA: u32 = 0x6000;
const SHIFTS: [u32; 2] = [0, 0x8000];

#[derive(Clone, Copy)]
struct Layout {
    first_executable: u32,
    second_executable: u32,
    non_executable: u32,
    image_end: u32,
    entry: u32,
    predecessor: u32,
    call_target: u32,
    veneer_helper_target: u32,
    crt_startup: u32,
    crt_call_target: u32,
    crt_helper_target: u32,
    startup_data: u32,
}

impl Layout {
    fn new(shift: u32) -> Self {
        let shifted = |rva| shift.checked_add(rva).unwrap();
        Self {
            first_executable: shifted(FIRST_EXECUTABLE_RVA),
            second_executable: shifted(SECOND_EXECUTABLE_RVA),
            non_executable: shifted(NON_EXECUTABLE_RVA),
            image_end: shifted(IMAGE_END_RVA),
            entry: shifted(0x1100),
            predecessor: shifted(0x1200),
            call_target: shifted(0x1300),
            veneer_helper_target: shifted(0x1340),
            crt_startup: shifted(0x3000),
            crt_call_target: shifted(0x1320),
            crt_helper_target: shifted(0x1360),
            startup_data: shifted(NON_EXECUTABLE_RVA),
        }
    }
}

fn section(index: usize, virtual_address: u32, virtual_size: u32, characteristics: u32) -> Section {
    Section {
        index,
        header_offset: 0,
        name_bytes: [0; 8],
        virtual_size,
        virtual_address,
        raw_size: 0,
        raw_pointer: 0,
        characteristics,
    }
}

fn fixture(shift: u32) -> (Vec<u8>, Pe, Layout) {
    let layout = Layout::new(shift);
    let sections = vec![
        section(
            0,
            layout.first_executable,
            FIRST_EXECUTABLE_SIZE,
            IMAGE_SCN_MEM_EXECUTE,
        ),
        section(
            1,
            layout.second_executable,
            SECOND_EXECUTABLE_SIZE,
            IMAGE_SCN_MEM_EXECUTE,
        ),
        section(
            2,
            layout.non_executable,
            0x400,
            IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
        ),
    ];
    let pe = Pe {
        opt: 0,
        machine: Machine::I386,
        coff_characteristics: 0,
        section_count: sections.len(),
        entry_rva: layout.entry,
        image_base: TEST_IMAGE_BASE,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: layout.image_end,
        size_of_headers: 0x400,
        checksum_offset: 0,
        data_directory_table_offset: 0,
        directories: vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ],
        sections,
        file_len: 0,
    };
    let image_len = usize::try_from(layout.image_end).unwrap();
    (vec![0; image_len], pe, layout)
}

fn offset(rva: u32) -> usize {
    usize::try_from(rva).unwrap()
}

fn write_rel32(image: &mut [u8], rva: u32, opcode: u8, target: u32) {
    let next_rva = rva.checked_add(DIRECT_REL32_LEN as u32).unwrap();
    let displacement = i64::from(target) - i64::from(next_rva);
    let displacement = i32::try_from(displacement).unwrap();
    let start = offset(rva);
    image[start] = opcode;
    image[start + 1..start + DIRECT_REL32_LEN].copy_from_slice(&displacement.to_le_bytes());
}

fn place_veneer(
    image: &mut [u8],
    entry: u32,
    call_target: u32,
    crt_startup: u32,
    crt_call_target: u32,
) {
    write_rel32(image, entry, 0xe8, call_target);
    write_rel32(
        image,
        entry.checked_add(DIRECT_REL32_LEN as u32).unwrap(),
        0xe9,
        crt_startup,
    );

    let startup = offset(crt_startup);
    image[startup] = 0x6a;
    image[startup + 1] = 4;
    image[startup + 2] = 0x68;
    let startup_data = crt_startup
        .checked_sub(SECOND_EXECUTABLE_RVA)
        .and_then(|shift| shift.checked_add(NON_EXECUTABLE_RVA))
        .unwrap();
    let startup_data_va = u32::try_from(
        TEST_IMAGE_BASE
            .checked_add(u64::from(startup_data))
            .unwrap(),
    )
    .unwrap();
    image[startup + 3..startup + 7].copy_from_slice(&startup_data_va.to_le_bytes());
    write_rel32(
        image,
        crt_startup.checked_add(7).unwrap(),
        0xe8,
        crt_call_target,
    );
    write_rel32(
        image,
        call_target,
        0xe9,
        call_target.checked_add(0x40).unwrap(),
    );
    write_rel32(
        image,
        crt_call_target,
        0xe9,
        crt_call_target.checked_add(0x40).unwrap(),
    );
}

fn place_handoff(image: &mut [u8], layout: Layout) {
    place_veneer(
        image,
        layout.entry,
        layout.call_target,
        layout.crt_startup,
        layout.crt_call_target,
    );
    write_rel32(image, layout.predecessor, 0xe9, layout.entry);
}

fn expected_entry(layout: Layout) -> SemanticEntry {
    SemanticEntry::i386_for_test(
        layout.entry,
        layout.predecessor,
        layout.call_target,
        layout.veneer_helper_target,
        layout.crt_startup,
        layout.crt_call_target,
        layout.crt_helper_target,
        layout.startup_data,
        4,
    )
}

const AMD64_IMAGE_BASE: u64 = 0x0000_0001_4000_0000;

#[derive(Clone, Copy)]
struct Amd64Layout {
    header_aep: u32,
    predecessor: u32,
    entry: u32,
    import_thunk: u32,
    startup: u32,
    helper_thunk: u32,
    helper_target: u32,
    iat_cell: u32,
    startup_state: u32,
    runtime_function: u32,
    unwind_info: u32,
}

fn amd64_layout() -> Amd64Layout {
    Amd64Layout {
        header_aep: 0x1010,
        predecessor: 0x1200,
        entry: 0x1300,
        import_thunk: 0x1400,
        // The E9 from the veneer reaches this lower RVA through a
        // negative rel32 displacement.
        startup: 0x1100,
        helper_thunk: 0x1500,
        helper_target: 0x1540,
        iat_cell: 0x3000,
        startup_state: 0x3020,
        runtime_function: 0x4000,
        unwind_info: 0x4020,
    }
}

fn amd64_fixture() -> (Vec<u8>, Pe, Amd64Layout) {
    let layout = amd64_layout();
    let sections = vec![
        section(
            0,
            0x1000,
            0x1000,
            IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
        ),
        section(1, 0x3000, 0x400, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        section(2, 0x4000, 0x400, IMAGE_SCN_MEM_READ),
    ];
    let mut pe = Pe {
        opt: 0,
        machine: Machine::Amd64,
        coff_characteristics: 0,
        section_count: sections.len(),
        entry_rva: layout.header_aep,
        image_base: AMD64_IMAGE_BASE,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: 0x5000,
        size_of_headers: 0x400,
        checksum_offset: 0,
        data_directory_table_offset: 0,
        directories: vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ],
        sections,
        file_len: 0,
    };
    pe.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = DataDirectory {
        virtual_address: layout.runtime_function,
        size: AMD64_RUNTIME_FUNCTION_LEN as u32,
    };

    let mut image = vec![0; usize::try_from(pe.size_of_image).unwrap()];
    image[offset(layout.header_aep)] = 0x90;
    place_amd64_candidate(
        &mut image,
        layout.predecessor,
        layout.entry,
        layout.import_thunk,
        layout.startup,
        layout.helper_thunk,
        layout.helper_target,
        layout.iat_cell,
        layout.startup_state,
    );
    let import_target_va = pe.rva_to_va(layout.header_aep).unwrap();
    image[offset(layout.iat_cell)..offset(layout.iat_cell) + AMD64_POINTER_CELL_LEN]
        .copy_from_slice(&import_target_va.to_le_bytes());
    let startup_state_va = pe.rva_to_va(layout.entry).unwrap();
    image[offset(layout.startup_state)..offset(layout.startup_state) + AMD64_POINTER_CELL_LEN]
        .copy_from_slice(&startup_state_va.to_le_bytes());
    write_amd64_runtime_function(
        &mut image,
        layout.runtime_function,
        layout.startup,
        layout.startup + 0x20,
        layout.unwind_info,
    );
    image[offset(layout.unwind_info)] = 1;
    (image, pe, layout)
}

fn write_rip_relative_displacement(
    image: &mut [u8],
    rva: u32,
    instruction_len: usize,
    displacement_offset: usize,
    target: u32,
) {
    let next_rva = rva
        .checked_add(u32::try_from(instruction_len).unwrap())
        .unwrap();
    let displacement = i32::try_from(i64::from(target) - i64::from(next_rva)).unwrap();
    let start = offset(rva) + displacement_offset;
    image[start..start + 4].copy_from_slice(&displacement.to_le_bytes());
}

fn place_amd64_candidate(
    image: &mut [u8],
    predecessor: u32,
    entry: u32,
    import_thunk: u32,
    startup: u32,
    helper_thunk: u32,
    helper_target: u32,
    iat_cell: u32,
    startup_state: u32,
) {
    write_rel32(image, predecessor, 0xe9, entry);
    write_rel32(image, entry, 0xe8, import_thunk);
    write_rel32(image, entry + DIRECT_REL32_LEN as u32, 0xe9, startup);

    let import_offset = offset(import_thunk);
    image[import_offset..import_offset + 2].copy_from_slice(&[0xff, 0x25]);
    write_rip_relative_displacement(image, import_thunk, AMD64_IMPORT_THUNK_LEN, 2, iat_cell);

    let startup_offset = offset(startup);
    image[startup_offset..startup_offset + 3].copy_from_slice(&[0x48, 0x8d, 0x0d]);
    write_rip_relative_displacement(image, startup, 7, 3, startup_state);
    write_rel32(image, startup + 7, 0xe8, helper_thunk);
    image[startup_offset + 12] = 0xc3;

    write_rel32(image, helper_thunk, 0xe9, helper_target);
    image[offset(helper_target)..offset(helper_target) + AMD64_HELPER_TARGET_LEN]
        .copy_from_slice(&[0x90, 0x90, 0x90, 0x90, 0xc3]);
}

fn write_amd64_runtime_function(
    image: &mut [u8],
    record_rva: u32,
    begin_rva: u32,
    end_rva: u32,
    unwind_rva: u32,
) {
    let start = offset(record_rva);
    image[start..start + 4].copy_from_slice(&begin_rva.to_le_bytes());
    image[start + 4..start + 8].copy_from_slice(&end_rva.to_le_bytes());
    image[start + 8..start + AMD64_RUNTIME_FUNCTION_LEN].copy_from_slice(&unwind_rva.to_le_bytes());
}

#[test]
fn discovers_standard_amd64_msvc_startup_from_cookie_and_runtime_evidence() {
    let (mut image, mut pe, _) = amd64_fixture();
    image[offset(FIRST_EXECUTABLE_RVA)..offset(FIRST_EXECUTABLE_RVA + 0x1000)].fill(0xcc);
    let entry_rva = 0x1600;
    let cookie_initializer_rva = 0x1700;
    let startup_rva = 0x1800;
    let cookie_rva = 0x3020;
    let unwind_rva = 0x4100;

    image[offset(entry_rva)..offset(entry_rva) + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
    write_rel32(&mut image, entry_rva + 4, 0xe8, cookie_initializer_rva);
    image[offset(entry_rva) + 9..offset(entry_rva) + 13].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
    write_rel32(&mut image, entry_rva + 13, 0xe9, startup_rva);

    image[offset(cookie_initializer_rva)..offset(cookie_initializer_rva) + 7]
        .copy_from_slice(&[0x48, 0x8b, 0x05, 0, 0, 0, 0]);
    write_rip_relative_displacement(&mut image, cookie_initializer_rva, 7, 3, cookie_rva);
    image[offset(cookie_initializer_rva) + 7..offset(cookie_initializer_rva) + 9]
        .copy_from_slice(&[0x48, 0xbb]);
    image[offset(cookie_initializer_rva) + 9..offset(cookie_initializer_rva) + 17]
        .copy_from_slice(&AMD64_DEFAULT_SECURITY_COOKIE.to_le_bytes());
    image[offset(cookie_initializer_rva) + 17] = 0xc3;
    image[offset(cookie_rva)..offset(cookie_rva) + AMD64_POINTER_CELL_LEN]
        .copy_from_slice(&AMD64_DEFAULT_SECURITY_COOKIE.to_le_bytes());

    image[offset(startup_rva)..offset(startup_rva) + AMD64_CRT_EVIDENCE_LEN].fill(0x90);
    image[offset(startup_rva)..offset(startup_rva) + 9]
        .copy_from_slice(&[0x65, 0x48, 0x8b, 0x04, 0x25, 0x30, 0, 0, 0]);
    image[offset(startup_rva) + 9..offset(startup_rva) + 18]
        .copy_from_slice(&[0xf0, 0x48, 0x0f, 0xb1, 0x15, 0, 0, 0, 0]);
    image[offset(startup_rva) + 18] = 0xc3;

    pe.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size = (3 * AMD64_RUNTIME_FUNCTION_LEN) as u32;
    for (index, (begin, end)) in [
        (entry_rva, entry_rva + AMD64_MSVC_ENTRY_LEN as u32),
        (
            cookie_initializer_rva,
            cookie_initializer_rva + AMD64_COOKIE_EVIDENCE_LEN as u32,
        ),
        (startup_rva, startup_rva + AMD64_CRT_EVIDENCE_LEN as u32),
    ]
    .into_iter()
    .enumerate()
    {
        write_amd64_runtime_function(
            &mut image,
            0x4000 + (index * AMD64_RUNTIME_FUNCTION_LEN) as u32,
            begin,
            end,
            unwind_rva,
        );
    }
    image[offset(unwind_rva)] = 1;

    let entry = discover_semantic_entry(&image, &pe).unwrap();
    assert_eq!(entry.entry_rva, entry_rva);
    assert_eq!(entry.veneer_call_target_rva, cookie_initializer_rva);
    assert_eq!(entry.startup_rva, startup_rva);
    assert_eq!(entry.startup_data_rva, cookie_rva);
    assert_eq!(
        entry.protected_ranges().unwrap(),
        vec![
            entry_rva..entry_rva + AMD64_MSVC_ENTRY_LEN as u32,
            cookie_initializer_rva..cookie_initializer_rva + AMD64_COOKIE_EVIDENCE_LEN as u32,
            startup_rva..startup_rva + AMD64_CRT_EVIDENCE_LEN as u32,
            cookie_rva..cookie_rva + AMD64_POINTER_CELL_LEN as u32,
            0x4000..0x4000 + AMD64_RUNTIME_FUNCTION_LEN as u32,
            0x400c..0x400c + AMD64_RUNTIME_FUNCTION_LEN as u32,
            0x4018..0x4018 + AMD64_RUNTIME_FUNCTION_LEN as u32,
        ]
    );
}

#[test]
fn recognizes_legacy_amd64_crt_pe_header_validation() {
    let startup_rva = 0x40;
    let mut image = vec![0x90; 0x100];
    image[0x50..0x54].copy_from_slice(&[0x4d, 0x5a, 0x00, 0x00]);
    image[0x60..0x64].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
    image[0x70..0x74].copy_from_slice(&[0x0b, 0x02, 0x00, 0x00]);

    assert!(amd64_crt_startup_evidence(&image, startup_rva).unwrap());

    image[0x60..0x64].fill(0);
    assert!(!amd64_crt_startup_evidence(&image, startup_rva).unwrap());
}

#[test]
fn discovers_amd64_input_derived_handoff_and_preserves_exact_evidence() {
    let (image, pe, layout) = amd64_fixture();

    let entry = discover_semantic_entry(&image, &pe).unwrap();
    assert_eq!(entry.entry_rva, layout.entry);
    assert_ne!(entry.entry_rva, pe.entry_rva);
    assert_eq!(entry.predecessor_rva, Some(layout.predecessor));
    assert_eq!(entry.veneer_call_target_rva, layout.import_thunk);
    assert_eq!(entry.startup_rva, layout.startup);
    assert_eq!(entry.startup_data_rva, layout.startup_state);
    assert_eq!(entry.startup_data_len, AMD64_POINTER_CELL_LEN as u32);
    assert_eq!(
        entry.executable_rvas(),
        vec![
            layout.predecessor,
            layout.entry,
            layout.import_thunk,
            layout.helper_thunk,
            layout.helper_target,
            layout.startup,
        ]
    );
    assert_eq!(
        entry.protected_ranges().unwrap(),
        vec![
            layout.predecessor..layout.predecessor + 5,
            layout.entry..layout.entry + 10,
            layout.startup..layout.startup + AMD64_STARTUP_LEN as u32,
            layout.import_thunk..layout.import_thunk + AMD64_IMPORT_THUNK_LEN as u32,
            layout.helper_thunk..layout.helper_thunk + 5,
            layout.helper_target..layout.helper_target + AMD64_HELPER_TARGET_LEN as u32,
            layout.startup_state..layout.startup_state + AMD64_POINTER_CELL_LEN as u32,
            layout.iat_cell..layout.iat_cell + AMD64_POINTER_CELL_LEN as u32,
            layout.runtime_function..layout.runtime_function + AMD64_RUNTIME_FUNCTION_LEN as u32,
        ]
    );
}

#[test]
fn accepts_negative_amd64_veneer_jump_displacement() {
    let (image, pe, layout) = amd64_fixture();
    assert!(layout.startup < layout.entry);
    assert_eq!(
        discover_semantic_entry(&image, &pe).unwrap().entry_rva,
        layout.entry
    );
}

#[test]
fn ignores_unreferenced_amd64_veneer_shaped_decoys() {
    let (mut image, pe, layout) = amd64_fixture();
    let decoy_entry = 0x1600;
    write_rel32(&mut image, decoy_entry, 0xe8, layout.import_thunk);
    write_rel32(
        &mut image,
        decoy_entry + DIRECT_REL32_LEN as u32,
        0xe9,
        layout.startup,
    );

    assert_eq!(
        discover_semantic_entry(&image, &pe).unwrap().entry_rva,
        layout.entry
    );
}

#[test]
fn ignores_reachable_incomplete_amd64_decoy_when_one_full_handoff_exists() {
    let (mut image, pe, layout) = amd64_fixture();
    let decoy_predecessor = 0x1600;
    let decoy_entry = 0x1700;
    write_rel32(&mut image, decoy_predecessor, 0xe9, decoy_entry);
    write_rel32(&mut image, decoy_entry, 0xe8, layout.iat_cell);
    write_rel32(
        &mut image,
        decoy_entry + DIRECT_REL32_LEN as u32,
        0xe9,
        layout.startup,
    );

    assert_eq!(
        discover_semantic_entry(&image, &pe).unwrap().entry_rva,
        layout.entry
    );
}

#[test]
fn rejects_unknown_instruction_on_reachable_amd64_candidate_path() {
    let (mut image, pe, layout) = amd64_fixture();
    image[offset(layout.startup)] = 0x49;

    let error = discover_semantic_entry(&image, &pe)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("incomplete or unknown instruction evidence"),
        "{error}"
    );
}

#[test]
fn rejects_amd64_veneer_call_target_outside_executable_sections() {
    let (mut image, pe, layout) = amd64_fixture();
    write_rel32(&mut image, layout.entry, 0xe8, layout.iat_cell);

    let error = discover_semantic_entry(&image, &pe)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("incomplete or unknown instruction evidence"),
        "{error}"
    );
}

#[test]
fn rejects_ambiguous_amd64_semantic_handoffs() {
    let (mut image, mut pe, layout) = amd64_fixture();
    let second_predecessor = 0x1600;
    let second_entry = 0x1700;
    let second_import_thunk = 0x1780;
    let second_startup = 0x1800;
    place_amd64_candidate(
        &mut image,
        second_predecessor,
        second_entry,
        second_import_thunk,
        second_startup,
        layout.helper_thunk,
        layout.helper_target,
        layout.iat_cell,
        layout.startup_state,
    );
    pe.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION].size = (AMD64_RUNTIME_FUNCTION_LEN * 2) as u32;
    write_amd64_runtime_function(
        &mut image,
        layout.runtime_function + AMD64_RUNTIME_FUNCTION_LEN as u32,
        second_startup,
        second_startup + 0x20,
        layout.unwind_info,
    );

    let error = discover_semantic_entry(&image, &pe)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("2 structurally valid AMD64 semantic entries"),
        "{error}"
    );
}

#[test]
fn rejects_malformed_amd64_runtime_function_boundaries() {
    let (mut image, pe, layout) = amd64_fixture();
    write_amd64_runtime_function(
        &mut image,
        layout.runtime_function,
        layout.startup,
        layout.startup,
        layout.unwind_info,
    );

    let error = discover_semantic_entry(&image, &pe)
        .unwrap_err()
        .to_string();
    assert!(error.contains("invalid"), "{error}");
}

#[test]
fn merges_contiguous_executable_sections() {
    let (image, mut pe, layout) = fixture(0);
    pe.sections[1].virtual_address = layout.first_executable + FIRST_EXECUTABLE_SIZE;

    assert_eq!(
        executable_section_ranges(&image, &pe).unwrap(),
        vec![
            layout.first_executable
                ..layout.first_executable + FIRST_EXECUTABLE_SIZE + SECOND_EXECUTABLE_SIZE
        ]
    );
}

#[test]
fn rejects_nonexecutable_crt_call_target() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_veneer(
            &mut image,
            layout.entry,
            layout.call_target,
            layout.crt_startup,
            layout.non_executable,
        );
        write_rel32(&mut image, layout.predecessor, 0xe9, layout.entry);

        assert!(discover_semantic_entry(&image, &pe).is_err());
    }
}

#[test]
fn semantic_veneer_range_covers_both_instructions() {
    let (_, _, layout) = fixture(0);
    assert_eq!(
        expected_entry(layout).veneer_range().unwrap(),
        layout.entry..layout.entry + SEMANTIC_VENEER_LEN as u32
    );
}

#[test]
fn discovers_shifted_structural_handoff() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);

        assert_eq!(
            discover_semantic_entry(&image, &pe).unwrap(),
            expected_entry(layout)
        );
    }
}

#[test]
fn discovers_all_direct_i386_callee_profile() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.call_target)..offset(layout.call_target) + DIRECT_REL32_LEN]
            .copy_from_slice(&[0x55, 0x8b, 0xec, 0x90, 0x90]);
        image[offset(layout.crt_call_target)..offset(layout.crt_call_target) + DIRECT_REL32_LEN]
            .copy_from_slice(&[0x53, 0x56, 0x57, 0x90, 0x90]);

        let mut expected = expected_entry(layout);
        expected.veneer_helper_target_rva = layout.call_target;
        expected.crt_helper_target_rva = layout.crt_call_target;
        assert_eq!(discover_semantic_entry(&image, &pe).unwrap(), expected);
    }
}

#[test]
fn rejects_mixed_i386_callee_profiles() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.call_target)..offset(layout.call_target) + DIRECT_REL32_LEN]
            .copy_from_slice(&[0x55, 0x8b, 0xec, 0x90, 0x90]);

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no structurally valid semantic entry"),
            "{error}"
        );
    }
}

#[test]
fn ignores_unreferenced_veneer_shaped_decoys() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        place_veneer(
            &mut image,
            layout.entry.checked_add(0x40).unwrap(),
            layout.call_target,
            layout.crt_startup.checked_add(0x40).unwrap(),
            layout.crt_call_target,
        );

        assert_eq!(
            discover_semantic_entry(&image, &pe).unwrap(),
            expected_entry(layout)
        );
    }
}

#[test]
fn rejects_malformed_handoff() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.entry.checked_add(DIRECT_REL32_LEN as u32).unwrap())] = 0x90;

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no structurally valid semantic entry"),
            "{error}"
        );
    }
}

#[test]
fn rejects_truncated_executable_sections() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image.truncate(offset(
            layout
                .crt_startup
                .checked_add(CRT_STARTUP_PROLOGUE_LEN as u32 - 1)
                .unwrap(),
        ));

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(error.contains("exceeds mapped image length"), "{error}");
    }
}

#[test]
fn rejects_call_targets_outside_executable_sections() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_veneer(
            &mut image,
            layout.entry,
            layout.non_executable,
            layout.crt_startup,
            layout.crt_call_target,
        );
        write_rel32(&mut image, layout.predecessor, 0xe9, layout.entry);

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no structurally valid semantic entry"),
            "{error}"
        );
    }
}

#[test]
fn rejects_veneers_crossing_executable_section_boundaries() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        let first_end = layout
            .first_executable
            .checked_add(FIRST_EXECUTABLE_SIZE)
            .unwrap();
        let edge_entry = first_end.checked_sub(DIRECT_REL32_LEN as u32).unwrap();
        place_veneer(
            &mut image,
            edge_entry,
            layout.call_target,
            layout.crt_startup,
            layout.crt_call_target,
        );
        write_rel32(&mut image, layout.predecessor, 0xe9, edge_entry);

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no structurally valid semantic entry"),
            "{error}"
        );
    }
}

#[test]
fn rejects_wrong_crt_startup_prologue() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.crt_startup.checked_add(2).unwrap())] = 0x90;

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("no structurally valid semantic entry"),
            "{error}"
        );
    }
}

#[test]
fn rejects_multiple_structural_entries() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        place_veneer(
            &mut image,
            layout.entry.checked_add(0x40).unwrap(),
            layout.call_target,
            layout.crt_startup.checked_add(0x40).unwrap(),
            layout.crt_call_target,
        );
        write_rel32(
            &mut image,
            layout.predecessor.checked_add(0x40).unwrap(),
            0xe9,
            layout.entry.checked_add(0x40).unwrap(),
        );

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("2 structurally valid semantic entries"),
            "{error}"
        );
    }
}

#[test]
fn rejects_multiple_predecessors() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        write_rel32(
            &mut image,
            layout.predecessor.checked_add(0x20).unwrap(),
            0xe9,
            layout.entry,
        );

        let error = discover_semantic_entry(&image, &pe)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("2 executable E9 rel32 predecessors"),
            "{error}"
        );
    }
}

#[test]
fn startup_operands_and_helper_thunks_are_required_evidence() {
    for shift in SHIFTS {
        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.crt_startup + 1)] = 0;
        assert!(discover_semantic_entry(&image, &pe).is_err());

        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.crt_startup + 3)..offset(layout.crt_startup + 7)]
            .copy_from_slice(&layout.entry.to_le_bytes());
        assert!(discover_semantic_entry(&image, &pe).is_err());

        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        image[offset(layout.call_target)] = 0x90;
        assert!(discover_semantic_entry(&image, &pe).is_err());

        let (mut image, pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        write_rel32(
            &mut image,
            layout.crt_call_target,
            0xe9,
            layout.non_executable,
        );
        assert!(discover_semantic_entry(&image, &pe).is_err());
    }
}
#[test]
fn startup_data_immediate_is_an_absolute_readable_va() {
    for shift in SHIFTS {
        let (mut image, mut pe, layout) = fixture(shift);
        place_handoff(&mut image, layout);
        pe.sections[2].characteristics = IMAGE_SCN_MEM_READ;
        assert_eq!(
            discover_semantic_entry(&image, &pe).unwrap(),
            expected_entry(layout)
        );

        image[offset(layout.crt_startup + 3)..offset(layout.crt_startup + 7)]
            .copy_from_slice(&layout.startup_data.to_le_bytes());
        assert!(discover_semantic_entry(&image, &pe).is_err());
    }
}

#[test]
fn semantic_entry_scan_has_a_total_executable_byte_cap() {
    let at_cap = 0..MAX_SEMANTIC_EXECUTABLE_SCAN_BYTES as u32;
    ensure_executable_scan_bound(std::slice::from_ref(&at_cap)).unwrap();
    let over_cap = 0..MAX_SEMANTIC_EXECUTABLE_SCAN_BYTES as u32 + 1;
    assert!(ensure_executable_scan_bound(std::slice::from_ref(&over_cap)).is_err());
}

#[test]
fn semantic_protected_ranges_cover_all_handoff_provenance() {
    let (_, _, layout) = fixture(0);
    assert_eq!(
        expected_entry(layout).protected_ranges().unwrap(),
        vec![
            layout.predecessor..layout.predecessor + 5,
            layout.entry..layout.entry + 10,
            layout.crt_startup..layout.crt_startup + 12,
            layout.call_target..layout.call_target + 5,
            layout.crt_call_target..layout.crt_call_target + 5,
            layout.veneer_helper_target..layout.veneer_helper_target + 5,
            layout.crt_helper_target..layout.crt_helper_target + 5,
            layout.startup_data..layout.startup_data + 4,
        ]
    );
}

#[test]
fn rejects_executable_jump_candidate_budget_exhaustion() {
    let count = MAX_EXECUTABLE_JUMPS + 1;
    let mut image = vec![0; count * DIRECT_REL32_LEN];
    for index in 0..count {
        write_rel32(
            &mut image,
            u32::try_from(index * DIRECT_REL32_LEN).unwrap(),
            0xe9,
            0,
        );
    }
    let range = 0..u32::try_from(image.len()).unwrap();
    let veneers = [SemanticVeneer {
        entry_rva: 0,
        veneer_call_target_rva: 0,
        veneer_helper_target_rva: 0,
        startup_rva: 0,
        crt_call_target_rva: 0,
        crt_helper_target_rva: 0,
        startup_data_rva: 0,
        startup_data_len: 1,
    }];
    let error = executable_jumps(&image, std::slice::from_ref(&range), &veneers)
        .unwrap_err()
        .to_string();
    assert!(error.contains("predecessor budget"), "{error}");
}

#[test]
fn native_dll_entry_profile_preserves_native_bootstrap_without_crt_inference() {
    let (image, mut pe, layout) = fixture(0);
    pe.coff_characteristics |= crate::pe::IMAGE_FILE_DLL;

    let profile = discover_output_entry(&image, &pe).unwrap();

    assert_eq!(
        profile,
        OutputEntry::NativeDll {
            entry_rva: layout.entry
        }
    );
    assert_eq!(
        profile.protected_ranges(&pe).unwrap(),
        vec![layout.first_executable..layout.first_executable + FIRST_EXECUTABLE_SIZE]
    );
}

#[test]
fn native_dll_entry_profile_rejects_non_executable_bootstrap() {
    let (image, mut pe, layout) = fixture(0);
    pe.coff_characteristics |= crate::pe::IMAGE_FILE_DLL;
    pe.entry_rva = layout.non_executable;

    let error = discover_output_entry(&image, &pe).unwrap_err().to_string();

    assert!(
        error.contains("belongs to non-executable section"),
        "{error}"
    );
}

#[test]
fn managed_dll_entry_profile_discards_protector_native_bootstrap() {
    let (mut image, mut pe, layout) = fixture(0);
    pe.coff_characteristics |= crate::pe::IMAGE_FILE_DLL;
    pe.directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = DataDirectory {
        virtual_address: layout.non_executable,
        size: 0x48,
    };
    let header_offset = usize::try_from(layout.non_executable).unwrap();
    image[header_offset..header_offset + 4].copy_from_slice(&0x48u32.to_le_bytes());

    let profile = discover_output_entry(&image, &pe).unwrap();

    assert_eq!(profile, OutputEntry::Managed { entry_rva: 0 });
    assert!(profile.protected_ranges(&pe).unwrap().is_empty());
}

#[test]
fn managed_entry_profile_rejects_non_dll_images() {
    let (image, mut pe, layout) = fixture(0);
    pe.directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = DataDirectory {
        virtual_address: layout.non_executable,
        size: 0x48,
    };

    let error = discover_output_entry(&image, &pe).unwrap_err().to_string();
    assert!(
        error.contains("managed EXE output profiles are unsupported"),
        "{error}"
    );
}

#[derive(Clone, Copy)]
struct StandaloneI386Layout {
    entry: u32,
    cookie_initializer: u32,
    seh_helper: u32,
    startup_data: u32,
    cookie: u32,
    cookie_complement: u32,
}

fn standalone_i386_fixture() -> (Vec<u8>, Pe, StandaloneI386Layout) {
    let layout = StandaloneI386Layout {
        entry: 0x1800,
        cookie_initializer: 0x1a00,
        seh_helper: 0x1c00,
        startup_data: 0x4000,
        cookie: 0x4020,
        cookie_complement: 0x4024,
    };
    let mut text = section(
        0,
        0x1000,
        0x2000,
        IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    );
    text.name_bytes = *b".text\0\0\0";
    let pe = Pe {
        opt: 0,
        machine: Machine::I386,
        coff_characteristics: 0,
        section_count: 2,
        entry_rva: layout.entry,
        image_base: TEST_IMAGE_BASE,
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: 0x5000,
        size_of_headers: 0x400,
        checksum_offset: 0,
        data_directory_table_offset: 0,
        directories: vec![
            DataDirectory {
                virtual_address: 0,
                size: 0,
            };
            16
        ],
        sections: vec![
            text,
            section(1, 0x4000, 0x1000, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        ],
        file_len: 0,
    };
    let mut image = vec![0; usize::try_from(pe.size_of_image).unwrap()];
    place_standalone_i386_entry(&mut image, &pe, layout, layout.entry);
    (image, pe, layout)
}

fn write_u32_at(image: &mut [u8], rva: u32, value: u32) {
    image[offset(rva)..offset(rva) + 4].copy_from_slice(&value.to_le_bytes());
}

fn place_standalone_i386_entry(
    image: &mut [u8],
    pe: &Pe,
    layout: StandaloneI386Layout,
    entry_rva: u32,
) {
    const DEFAULT_COOKIE: u32 = 0xbb40_e64e;

    write_rel32(image, entry_rva, 0xe8, layout.cookie_initializer);
    let startup_rva = entry_rva + SEMANTIC_VENEER_LEN as u32;
    write_rel32(
        image,
        entry_rva + DIRECT_REL32_LEN as u32,
        0xe9,
        startup_rva,
    );
    let startup = offset(startup_rva);
    image[startup] = 0x6a;
    image[startup + 1] = 0x14;
    image[startup + 2] = 0x68;
    let startup_data_va = u32::try_from(pe.rva_to_va(layout.startup_data).unwrap()).unwrap();
    image[startup + 3..startup + 7].copy_from_slice(&startup_data_va.to_le_bytes());
    write_rel32(image, startup_rva + 7, 0xe8, layout.seh_helper);

    let cookie_va = u32::try_from(pe.rva_to_va(layout.cookie).unwrap()).unwrap();
    let complement_va = u32::try_from(pe.rva_to_va(layout.cookie_complement).unwrap()).unwrap();
    let initializer = offset(layout.cookie_initializer);
    image[initializer..initializer + 5].copy_from_slice(&[0x55, 0x8b, 0xec, 0x83, 0xec]);
    image[initializer + 6] = 0xa1;
    image[initializer + 7..initializer + 11].copy_from_slice(&cookie_va.to_le_bytes());
    image[initializer + 11..initializer + 16].copy_from_slice(&[0xbf, 0x4e, 0xe6, 0x40, 0xbb]);
    image[initializer + 16..initializer + 21].copy_from_slice(&[0xbe, 0x00, 0x00, 0xff, 0xff]);
    image[initializer + 0x20..initializer + 0x26].copy_from_slice(&[
        0x89,
        0x0d,
        cookie_va.to_le_bytes()[0],
        cookie_va.to_le_bytes()[1],
        cookie_va.to_le_bytes()[2],
        cookie_va.to_le_bytes()[3],
    ]);
    image[initializer + 0x30..initializer + 0x37].copy_from_slice(&[
        0xf7,
        0xd0,
        0xa3,
        complement_va.to_le_bytes()[0],
        complement_va.to_le_bytes()[1],
        complement_va.to_le_bytes()[2],
        complement_va.to_le_bytes()[3],
    ]);
    image[initializer + 0x40..initializer + 0x48].copy_from_slice(&[
        0xf7,
        0xd1,
        0x89,
        0x0d,
        complement_va.to_le_bytes()[0],
        complement_va.to_le_bytes()[1],
        complement_va.to_le_bytes()[2],
        complement_va.to_le_bytes()[3],
    ]);
    write_u32_at(image, layout.cookie, DEFAULT_COOKIE);
    write_u32_at(image, layout.cookie_complement, !DEFAULT_COOKIE);

    let helper = offset(layout.seh_helper);
    image[helper..helper + 12].copy_from_slice(&[0x68, 1, 2, 3, 4, 0x64, 0xff, 0x35, 0, 0, 0, 0]);
    image[helper + 0x20..helper + 0x2a].copy_from_slice(&[
        0xa1,
        cookie_va.to_le_bytes()[0],
        cookie_va.to_le_bytes()[1],
        cookie_va.to_le_bytes()[2],
        cookie_va.to_le_bytes()[3],
        0x31,
        0x45,
        0xfc,
        0x33,
        0xc5,
    ]);
}

#[test]
fn recognizes_standalone_i386_msvc_oep_without_predecessor() {
    let (image, pe, layout) = standalone_i386_fixture();

    let entry = discover_semantic_entry(&image, &pe).unwrap();

    assert_eq!(entry.entry_rva, layout.entry);
    assert_eq!(entry.predecessor_rva, None);
    assert!(matches!(
        entry.evidence,
        SemanticEvidence::I386MsvcStandalone { .. }
    ));
    let ranges = entry.protected_ranges().unwrap();
    assert!(ranges.contains(&(layout.entry..layout.entry + SEMANTIC_VENEER_LEN as u32)));
    assert!(ranges.contains(&(layout.cookie..layout.cookie + I386_COOKIE_CELL_LEN as u32)));
    assert!(ranges.contains(
        &(layout.cookie_complement..layout.cookie_complement + I386_COOKIE_CELL_LEN as u32)
    ));
    assert!(!ranges.iter().any(|range| range.start == 0x1200));
}

#[test]
fn legacy_i386_sparse_authentication_rejects_veneer_only_false_hits() {
    let (image, pe, layout) = standalone_i386_fixture();
    let entry = SemanticEntry::i386_for_test(
        layout.entry,
        0x1200,
        layout.cookie_initializer,
        layout.cookie_initializer,
        layout.entry + SEMANTIC_VENEER_LEN as u32,
        layout.seh_helper,
        layout.seh_helper,
        layout.startup_data,
        0x14,
    );
    authenticate_i386_sparse_entry(&image, &pe, entry).unwrap();

    let mut false_hit = image;
    false_hit[offset(layout.cookie_initializer)] = 0xcc;
    let error = authenticate_i386_sparse_entry(&false_hit, &pe, entry)
        .unwrap_err()
        .to_string();
    assert!(error.contains("security-cookie initializer"), "{error}");
}

#[test]
fn amd64_sparse_authentication_matches_unwind_program_to_prologue() {
    let (mut image, _, _) = amd64_fixture();
    let function_rva = 0x1600;
    let runtime_function_rva = 0x4000;
    let unwind_rva = 0x4100;
    image[offset(function_rva)..offset(function_rva) + 13].copy_from_slice(&[
        0x48, 0x89, 0x5c, 0x24, 0x20, 0x55, 0x48, 0x8b, 0xec, 0x48, 0x83, 0xec, 0x20,
    ]);
    write_amd64_runtime_function(
        &mut image,
        runtime_function_rva,
        function_rva,
        function_rva + 0x100,
        unwind_rva,
    );
    image[offset(unwind_rva)..offset(unwind_rva) + 12].copy_from_slice(&[
        0x01, 0x0d, 0x04, 0x00, 0x0d, 0x34, 0x09, 0x00, 0x0d, 0x32, 0x06, 0x50,
    ]);
    let entry = SemanticEntry {
        entry_rva: function_rva,
        predecessor_rva: Some(0x1500),
        veneer_call_target_rva: function_rva,
        veneer_helper_target_rva: function_rva,
        startup_rva: function_rva,
        crt_call_target_rva: function_rva,
        crt_helper_target_rva: function_rva,
        startup_data_rva: 0x3000,
        startup_data_len: AMD64_POINTER_CELL_LEN as u32,
        evidence: SemanticEvidence::Amd64 {
            iat_cell_rva: 0x3000,
            runtime_function_rva: Some(runtime_function_rva),
        },
    };
    authenticate_amd64_sparse_entry(&image, entry).unwrap();

    image[offset(function_rva) + 4] = 0xe5;
    let error = authenticate_amd64_sparse_entry(&image, entry)
        .unwrap_err()
        .to_string();
    assert!(error.contains("does not match unwind prologue"), "{error}");

    image[offset(function_rva)..offset(function_rva) + 25].copy_from_slice(&[
        0x48, 0x8b, 0xc4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18,
        0x4c, 0x89, 0x70, 0x20, 0x41, 0x57, 0x48, 0x83, 0xec, 0x30,
    ]);
    image[offset(unwind_rva)..offset(unwind_rva) + 24].copy_from_slice(&[
        0x09, 0x19, 0x0a, 0x00, 0x19, 0xe4, 0x0b, 0x00, 0x19, 0x74, 0x0a, 0x00, 0x19, 0x64, 0x09,
        0x00, 0x19, 0x34, 0x08, 0x00, 0x19, 0x52, 0x15, 0xf0,
    ]);
    authenticate_amd64_sparse_entry(&image, entry).unwrap();

    image[offset(function_rva) + 6] = 9;
    assert!(authenticate_amd64_sparse_entry(&image, entry).is_err());
}

#[test]
fn standalone_i386_msvc_oep_rejects_noncanonical_or_weak_evidence() {
    let (image, pe, layout) = standalone_i386_fixture();
    let mut nonzero_jump = image.clone();
    write_rel32(
        &mut nonzero_jump,
        layout.entry + DIRECT_REL32_LEN as u32,
        0xe9,
        layout.entry + SEMANTIC_VENEER_LEN as u32 + 1,
    );
    assert!(discover_semantic_entry(&nonzero_jump, &pe).is_err());

    let mut wrong_cookie = image.clone();
    write_u32_at(&mut wrong_cookie, layout.cookie, 0);
    assert!(discover_semantic_entry(&wrong_cookie, &pe).is_err());

    let mut wrong_complement = image.clone();
    write_u32_at(&mut wrong_complement, layout.cookie_complement, 0);
    assert!(discover_semantic_entry(&wrong_complement, &pe).is_err());

    let mut weak_helper = image;
    weak_helper[offset(layout.seh_helper) + 6] = 0x90;
    assert!(discover_semantic_entry(&weak_helper, &pe).is_err());
}

#[test]
fn standalone_i386_msvc_oep_rejects_predecessor_and_duplicate_candidates() {
    let (image, pe, layout) = standalone_i386_fixture();
    let mut predecessor = image.clone();
    write_rel32(&mut predecessor, 0x1200, 0xe9, layout.entry);
    assert!(discover_semantic_entry(&predecessor, &pe).is_err());

    let mut duplicate = image;
    place_standalone_i386_entry(&mut duplicate, &pe, layout, 0x1900);
    let error = discover_semantic_entry(&duplicate, &pe)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("2 structurally valid semantic entries"),
        "{error}"
    );
}

#[test]
fn unchanged_native_profile_does_not_require_sparse_layout() {
    let (original, mut pe, layout) = standalone_i386_fixture();
    pe.sections[0].virtual_size -= 1;
    let mut mapped = original.clone();

    let profile = select_output_entry(&mut mapped, &pe).unwrap();

    assert_eq!(profile.entry.entry_rva(), layout.entry);
    assert_eq!(
        profile.code_transform,
        crate::report::CodeTransform::Unchanged
    );
    assert_eq!(
        profile.fingerprint(),
        crate::report::RecoveredProgram {
            code_transform: crate::report::CodeTransform::Unchanged,
            startup_kind: crate::report::StartupKind::I386MsvcStandalone,
            startup_rva: layout.entry,
            handoff_rva: None,
        }
    );
    assert_eq!(mapped, original);
}

#[test]
fn dll_and_managed_recovered_programs_have_no_code_transform() {
    let (mut native_image, mut native_pe, native_layout) = fixture(0);
    native_pe.coff_characteristics |= crate::pe::IMAGE_FILE_DLL;

    let native_profile = select_output_entry(&mut native_image, &native_pe).unwrap();

    assert_eq!(
        native_profile.code_transform,
        crate::report::CodeTransform::NotApplicable
    );
    assert_eq!(
        native_profile.fingerprint(),
        crate::report::RecoveredProgram {
            code_transform: crate::report::CodeTransform::NotApplicable,
            startup_kind: crate::report::StartupKind::NativeDllEntry,
            startup_rva: native_layout.entry,
            handoff_rva: None,
        }
    );

    let (mut managed_image, mut managed_pe, managed_layout) = fixture(0);
    managed_pe.coff_characteristics |= crate::pe::IMAGE_FILE_DLL;
    managed_pe.directories[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = DataDirectory {
        virtual_address: managed_layout.non_executable,
        size: 0x48,
    };
    let header_offset = usize::try_from(managed_layout.non_executable).unwrap();
    managed_image[header_offset..header_offset + 4].copy_from_slice(&0x48u32.to_le_bytes());

    let managed_profile = select_output_entry(&mut managed_image, &managed_pe).unwrap();

    assert_eq!(
        managed_profile.code_transform,
        crate::report::CodeTransform::NotApplicable
    );
    assert_eq!(
        managed_profile.fingerprint(),
        crate::report::RecoveredProgram {
            code_transform: crate::report::CodeTransform::NotApplicable,
            startup_kind: crate::report::StartupKind::ManagedDll,
            startup_rva: 0,
            handoff_rva: None,
        }
    );
}

#[test]
fn selects_i386_rol3_only_by_standalone_semantics() {
    let (original, pe, layout) = standalone_i386_fixture();
    let mut encoded = original.clone();
    decode_sparse_text_pages_in_place(&mut encoded, &pe, SparsePageKey::PageRvaRol(3)).unwrap();
    assert!(discover_semantic_entry(&encoded, &pe).is_err());

    let mut semantic_hits = Vec::new();
    for page_key in unique_sparse_page_keys(&pe).unwrap() {
        decode_sparse_text_pages_in_place(&mut encoded, &pe, page_key).unwrap();
        if let Ok(entry) = discover_semantic_entry(&encoded, &pe) {
            semantic_hits.push((page_key, entry.entry_rva));
        }
        decode_sparse_text_pages_in_place(&mut encoded, &pe, page_key).unwrap();
    }
    assert_eq!(
        semantic_hits,
        vec![(SparsePageKey::PageRvaRol(3), layout.entry)]
    );

    let profile = select_output_entry(&mut encoded, &pe).unwrap();

    assert_eq!(profile.entry.entry_rva(), layout.entry);
    assert_eq!(
        profile.code_transform,
        crate::report::CodeTransform::PageRvaRol { rotation: 3 }
    );
    assert_eq!(
        profile.fingerprint(),
        crate::report::RecoveredProgram {
            code_transform: crate::report::CodeTransform::PageRvaRol { rotation: 3 },
            startup_kind: crate::report::StartupKind::I386MsvcStandalone,
            startup_rva: layout.entry,
            handoff_rva: None,
        }
    );
    assert_eq!(encoded, original);
}

#[test]
fn recovered_program_preserves_semantic_evidence() {
    fn recovered_program(evidence: SemanticEvidence) -> crate::report::RecoveredProgram {
        SelectedOutputProfile {
            entry: OutputEntry::Native(SemanticEntry {
                entry_rva: 0x1000,
                predecessor_rva: Some(0x0ff0),
                veneer_call_target_rva: 0,
                veneer_helper_target_rva: 0,
                startup_rva: 0,
                crt_call_target_rva: 0,
                crt_helper_target_rva: 0,
                startup_data_rva: 0,
                startup_data_len: 0,
                evidence,
            }),
            code_transform: crate::report::CodeTransform::Unchanged,
        }
        .fingerprint()
    }

    let cases = [
        (
            SemanticEvidence::I386,
            crate::report::StartupKind::I386CrtHandoff,
        ),
        (
            SemanticEvidence::I386MsvcStandalone {
                cookie_rva: 0,
                cookie_complement_rva: 0,
            },
            crate::report::StartupKind::I386MsvcStandalone,
        ),
        (
            SemanticEvidence::Amd64 {
                iat_cell_rva: 0,
                runtime_function_rva: None,
            },
            crate::report::StartupKind::Amd64ImportHandoff,
        ),
        (
            SemanticEvidence::Amd64Msvc {
                entry_runtime_function_rva: 0,
                cookie_runtime_function_rva: 0,
                startup_runtime_function_rva: 0,
            },
            crate::report::StartupKind::Amd64MsvcUnwind,
        ),
    ];

    for (evidence, expected_startup_kind) in cases {
        let program = recovered_program(evidence);
        assert_eq!(program.startup_kind, expected_startup_kind);
        assert_eq!(program.startup_rva, 0x1000);
        assert_eq!(program.handoff_rva, Some(0x0ff0));
    }
}

#[test]
fn i386_sparse_profile_transform_is_involutive() {
    let (original, pe, _) = standalone_i386_fixture();
    let mut transformed = original.clone();
    decode_sparse_text_pages_in_place(&mut transformed, &pe, SparsePageKey::PageRvaRol(3)).unwrap();
    assert_ne!(transformed, original);
    decode_sparse_text_pages_in_place(&mut transformed, &pe, SparsePageKey::PageRvaRol(3)).unwrap();
    assert_eq!(transformed, original);
}
