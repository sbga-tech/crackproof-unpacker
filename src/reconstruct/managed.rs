//! Authenticated, generated PE32/I386 CLR container for the one reviewed SDDT
//! managed source profile.  This is deliberately not a reconstruction claim
//! for the protected AMD64 loader bootstrap.

use std::ops::Range;

use anyhow::{Context, Result, ensure};

use crate::pe::{DataDirectory, Machine, Pe, PeKind, pe_checksum};
use crate::unpack::imports::{ImportSymbol, LoaderDiscovery};

const FILE_ALIGNMENT: u32 = 0x200;
const SECTION_ALIGNMENT: u32 = 0x2000;
const TEXT_RVA: u32 = 0x2000;
const TEXT_VIRTUAL_SIZE: u32 = 0x5aa000;
const RESOURCE_RVA: u32 = 0x5ac000;
const RESOURCE_SIZE: u32 = 0x1000;
const RELOC_RVA: u32 = 0x5ae000;
const IMPORT_RVA: u32 = 0x5abf00;
const STUB_RVA: u32 = 0x5abf80;
const IAT_RVA: u32 = TEXT_RVA;
const TEXT_RAW_POINTER: u32 = 0x200;
const RESOURCE_RAW_POINTER: u32 = 0x5aa200;
const RELOC_RAW_POINTER: u32 = 0x5ab200;
const OUTPUT_SIZE: usize = 0x5ab400;
const OUTPUT_IMAGE_SIZE: u32 = 0x5b0000;
const COR20_RVA: u32 = 0x2008;
const COR20_SIZE: u32 = 0x48;
const METADATA_RVA: u32 = 0x259e0c;
const SOURCE_IMAGE_SIZE: u32 = 0x5ad000;
const SOURCE_ENTRY_RVA: u32 = 0x1b5c;
const SOURCE_IMPORT_RVA: u32 = 0x1b9c;
const SOURCE_IMPORT_SIZE: u32 = 0x28;
const SOURCE_IAT_RVA: u32 = 0x1bc4;
const SOURCE_RESOURCE_SIZE: u32 = 0x300;
const DIRECTORY_COUNT: usize = 16;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
const IMAGE_FILE_DLL: u16 = 0x2000;
const OUTPUT_COFF_CHARACTERISTICS: u16 =
    IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL;
const OUTPUT_DLL_CHARACTERISTICS: u16 = 0x8540;
const GENERATED_RVA_RANGES: [Range<u32>; 4] = [
    IAT_RVA..IAT_RVA + 8,
    IMPORT_RVA..IMPORT_RVA + 0x4a,
    STUB_RVA..STUB_RVA + 6,
    COR20_RVA + 16..COR20_RVA + 20,
];

fn range(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    data.get(offset..offset.checked_add(length).context("range overflow")?)
        .context("range exceeds image")
}
fn range_mut(data: &mut [u8], offset: usize, length: usize) -> Result<&mut [u8]> {
    data.get_mut(offset..offset.checked_add(length).context("range overflow")?)
        .context("range exceeds output")
}
fn put16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    range_mut(data, offset, 2)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn put32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    range_mut(data, offset, 4)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
fn get16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(data, offset, 2)?.try_into().context("u16 slice")?,
    ))
}
fn get32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(data, offset, 4)?.try_into().context("u32 slice")?,
    ))
}
fn rva_offset(rva: u32) -> Result<usize> {
    usize::try_from(rva.checked_sub(TEXT_RVA).context("RVA before .text")?)
        .context("RVA does not fit")?
        .checked_add(usize::try_from(TEXT_RAW_POINTER)?)
        .context("raw offset overflow")
}
fn output_rva_bytes<'a>(output: &'a [u8], pe: &Pe, rva: u32, size: u32) -> Result<&'a [u8]> {
    let section = pe.section_for_rva_range(rva, usize::try_from(size)?)?;
    let delta = rva
        .checked_sub(section.virtual_address)
        .context("RVA below output section")?;
    let offset = section
        .raw_pointer
        .checked_add(delta)
        .context("output RVA offset overflow")?;
    range(output, usize::try_from(offset)?, usize::try_from(size)?)
}

fn expect_directory(pe: &Pe, index: usize, expected: DataDirectory) -> Result<()> {
    ensure!(
        pe.directory(index)? == expected,
        "source directory {index} mismatches reviewed profile"
    );
    Ok(())
}

/// Rejects lookalike CLR containers before any bytes are copied.  This pins the
/// exact recovered source ABI and proves that the two copied source regions are
/// backed by the expected source sections.
fn authenticate_source_profile(mapped: &[u8], pe: &Pe, discovery: &LoaderDiscovery) -> Result<()> {
    ensure!(
        mapped.len() == usize::try_from(SOURCE_IMAGE_SIZE)?,
        "managed source mapped length mismatches reviewed profile"
    );
    ensure!(
        pe.machine_kind() == Machine::Amd64 && pe.kind() == PeKind::Pe32Plus && pe.is_dll(),
        "managed source is not the reviewed AMD64 DLL profile"
    );
    ensure!(
        pe.section_count == 2 && pe.entry_rva == SOURCE_ENTRY_RVA && pe.image_base == 0x400000,
        "managed source entry/image profile mismatch"
    );
    ensure!(
        pe.section_alignment == 0x1000
            && pe.file_alignment == 0x1000
            && pe.size_of_headers == 0x1000
            && pe.size_of_image == SOURCE_IMAGE_SIZE,
        "managed source alignment/layout mismatch"
    );
    ensure!(
        pe.sections[0].name_bytes == *b".text\0\0\0"
            && pe.sections[0].virtual_address == 0x1000
            && pe.sections[0].virtual_size == 0x5ab000
            && pe.sections[0].raw_size == 0x57d000
            && pe.sections[0].raw_pointer == 0x14e000
            && pe.sections[0].characteristics == 0x6000_0020,
        "managed source .text layout mismatch: {:?}",
        pe.sections[0]
    );
    ensure!(
        pe.sections[1].name_bytes == *b".rsrc\0\0\0"
            && pe.sections[1].virtual_address == RESOURCE_RVA
            && pe.sections[1].virtual_size == RESOURCE_SIZE
            && pe.sections[1].raw_size == RESOURCE_SIZE
            && pe.sections[1].raw_pointer == 0x6cb000
            && pe.sections[1].characteristics == 0x4000_0040,
        "managed source .rsrc layout mismatch: {:?}",
        pe.sections[1]
    );
    pe.section_for_rva_range(TEXT_RVA, TEXT_VIRTUAL_SIZE as usize)
        .context("managed source retained .text mapping")?;
    pe.section_for_rva_range(RESOURCE_RVA, RESOURCE_SIZE as usize)
        .context("managed source retained .rsrc mapping")?;
    for index in 0..DIRECTORY_COUNT {
        let expected = match index {
            1 => DataDirectory {
                virtual_address: SOURCE_IMPORT_RVA,
                size: SOURCE_IMPORT_SIZE,
            },
            2 => DataDirectory {
                virtual_address: RESOURCE_RVA,
                size: SOURCE_RESOURCE_SIZE,
            },
            14 => DataDirectory {
                virtual_address: COR20_RVA,
                size: COR20_SIZE,
            },
            _ => DataDirectory {
                virtual_address: 0,
                size: 0,
            },
        };
        expect_directory(pe, index, expected)?;
    }
    let expected_symbols = [
        "LoadLibraryA",
        "GetProcAddress",
        "GetModuleHandleA",
        "ExitProcess",
        "GetCurrentProcess",
        "GetCurrentProcessId",
    ];
    ensure!(
        discovery.table_rva == SOURCE_IMPORT_RVA
            && discovery.image_size == SOURCE_IMAGE_SIZE
            && discovery.modules.len() == 1
            && discovery.modules[0]
                .dll
                .eq_ignore_ascii_case("kernel32.dll")
            && discovery.modules[0].destination_rva == SOURCE_IAT_RVA
            && discovery.modules[0].symbols.len() == expected_symbols.len()
            && discovery.function_count == 6
            && discovery.named_count == 6
            && discovery.ordinal_count == 0
            && discovery.metadata_ranges == [SOURCE_IMPORT_RVA..SOURCE_IAT_RVA, 0x1bfc..0x1c09],
        "managed source resolver graph template mismatch"
    );
    ensure!(discovery.modules[0].symbols.iter().zip(expected_symbols).all(|(symbol, name)| matches!(symbol, ImportSymbol::Name { hint: 0, name: found } if found.eq_ignore_ascii_case(name))), "managed source resolver symbols/hints mismatch");
    ensure!(
        range(mapped, 0x1131, 11)?
            == [
                0x41, 0x81, 0x7b, 0x04, b'K', b'O', b'N', b'N', 0x0f, 0x94, 0xc0
            ],
        "managed KONN recognizer mismatch"
    );
    ensure!(
        range(mapped, COR20_RVA as usize, 4)? == [0x48, 0, 0, 0],
        "source COR20 header size mismatch"
    );
    ensure!(
        range(mapped, METADATA_RVA as usize, 4)? == b"BSJB",
        "source metadata identity mismatch"
    );
    validate_clr_container(mapped, pe)?;
    // The semantic slots are deliberately inserted only into source zero-fill.
    ensure!(
        range(mapped, IAT_RVA as usize, 8)?
            .iter()
            .all(|byte| *byte == 0),
        "source IAT destination is not zero"
    );
    ensure!(
        range(mapped, IMPORT_RVA as usize, 0x100)?
            .iter()
            .all(|byte| *byte == 0),
        "source generated import area is not zero"
    );
    ensure!(
        range(mapped, STUB_RVA as usize, 6)?
            .iter()
            .all(|byte| *byte == 0),
        "source generated stub area is not zero"
    );
    Ok(())
}

/// Validates the COR20 and complete ECMA-335 metadata container copied from the
/// authenticated source map.  `clr` validates every table and method body.
fn validate_clr_container(mapped: &[u8], pe: &Pe) -> Result<()> {
    let cor20 = COR20_RVA as usize;
    ensure!(
        get32(mapped, cor20)? == COR20_SIZE,
        "COR20 header size mismatch"
    );
    ensure!(
        get16(mapped, cor20 + 4)? == 2 && get16(mapped, cor20 + 6)? == 5,
        "COR20 runtime version mismatch"
    );
    ensure!(
        get32(mapped, cor20 + 8)? == METADATA_RVA,
        "metadata RVA mismatch"
    );
    let metadata_size = usize::try_from(get32(mapped, cor20 + 12)?)?;
    ensure!(
        metadata_size != 0 && get32(mapped, cor20 + 16)? == 0,
        "source COR20 flags mismatch"
    );
    for offset in [24, 32, 40, 48, 56, 64] {
        ensure!(
            range(mapped, cor20 + offset, 8)?
                .iter()
                .all(|byte| *byte == 0),
            "source COR20 generated directory is nonzero"
        );
    }
    let metadata = range(mapped, METADATA_RVA as usize, metadata_size)?;
    ensure!(
        range(metadata, 0, 4)? == b"BSJB",
        "metadata signature mismatch"
    );
    crate::reconstruct::clr::authenticated_method_defs(
        mapped,
        pe,
        METADATA_RVA as usize,
        metadata_size,
    )?;
    Ok(())
}

fn write_section(
    data: &mut [u8],
    offset: usize,
    name: &[u8],
    virtual_size: u32,
    rva: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) -> Result<()> {
    ensure!(name.len() <= 8, "section name exceeds COFF field");
    range_mut(data, offset, 40)?.fill(0);
    range_mut(data, offset, name.len())?.copy_from_slice(name);
    put32(data, offset + 8, virtual_size)?;
    put32(data, offset + 12, rva)?;
    put32(data, offset + 16, raw_size)?;
    put32(data, offset + 20, raw_pointer)?;
    put32(data, offset + 36, characteristics)
}

fn write_deterministic_headers(output: &mut [u8]) -> Result<(usize, usize, usize)> {
    let pe_offset = usize::try_from(get32(output, 0x3c)?)?;
    ensure!(
        range(output, pe_offset, 4)? == b"PE\0\0",
        "source PE signature mismatch"
    );
    let coff = pe_offset.checked_add(4).context("COFF offset overflow")?;
    let optional = coff.checked_add(20).context("optional offset overflow")?;
    let sections = optional
        .checked_add(0xe0)
        .context("section table offset overflow")?;
    let directories = optional
        .checked_add(96)
        .context("directory table offset overflow")?;
    ensure!(
        sections.checked_add(120).is_some_and(|end| end <= 0x200),
        "generated section table does not fit headers"
    );
    put16(output, coff, 0x14c)?;
    put16(output, coff + 2, 3)?;
    put32(output, coff + 4, 0)?;
    put32(output, coff + 8, 0)?;
    put32(output, coff + 12, 0)?;
    put16(output, coff + 16, 0xe0)?;
    put16(output, coff + 18, OUTPUT_COFF_CHARACTERISTICS)?;
    put16(output, optional, 0x10b)?;
    output[optional + 2] = 8;
    output[optional + 3] = 0;
    put32(output, optional + 4, TEXT_VIRTUAL_SIZE)?;
    put32(output, optional + 8, 0x1200)?;
    put32(output, optional + 12, 0)?;
    put32(output, optional + 16, STUB_RVA)?;
    put32(output, optional + 20, TEXT_RVA)?;
    put32(output, optional + 24, RESOURCE_RVA)?;
    put32(output, optional + 28, 0x1000_0000)?;
    put32(output, optional + 32, SECTION_ALIGNMENT)?;
    put32(output, optional + 36, FILE_ALIGNMENT)?;
    put16(output, optional + 40, 4)?;
    put16(output, optional + 42, 0)?;
    put16(output, optional + 44, 0)?;
    put16(output, optional + 46, 0)?;
    put16(output, optional + 48, 4)?;
    put16(output, optional + 50, 0)?;
    put32(output, optional + 52, 0)?;
    put32(output, optional + 56, OUTPUT_IMAGE_SIZE)?;
    put32(output, optional + 60, 0x200)?;
    put32(output, optional + 64, 0)?;
    put16(output, optional + 68, 3)?;
    put16(output, optional + 70, OUTPUT_DLL_CHARACTERISTICS)?;
    put32(output, optional + 72, 0x10_0000)?;
    put32(output, optional + 76, 0x1000)?;
    put32(output, optional + 80, 0x10_0000)?;
    put32(output, optional + 84, 0x1000)?;
    put32(output, optional + 88, 0)?;
    put32(output, optional + 92, DIRECTORY_COUNT as u32)?;
    range_mut(output, directories, DIRECTORY_COUNT * 8)?.fill(0);
    for (index, rva, size) in [
        (1, IMPORT_RVA, 0x4a),
        (2, RESOURCE_RVA, 0x300),
        (5, RELOC_RVA, 12),
        (12, IAT_RVA, 8),
        (14, COR20_RVA, COR20_SIZE),
    ] {
        put32(output, directories + index * 8, rva)?;
        put32(output, directories + index * 8 + 4, size)?;
    }
    range_mut(output, sections, 0x200 - sections)?.fill(0);
    write_section(
        output,
        sections,
        b".text",
        TEXT_VIRTUAL_SIZE,
        TEXT_RVA,
        TEXT_VIRTUAL_SIZE,
        TEXT_RAW_POINTER,
        0x6000_0020,
    )?;
    write_section(
        output,
        sections + 40,
        b".rsrc",
        RESOURCE_SIZE,
        RESOURCE_RVA,
        RESOURCE_SIZE,
        RESOURCE_RAW_POINTER,
        0x4000_0040,
    )?;
    write_section(
        output,
        sections + 80,
        b".reloc",
        12,
        RELOC_RVA,
        0x200,
        RELOC_RAW_POINTER,
        0x4200_0040,
    )?;
    Ok((optional, sections, directories))
}

fn write_generated_payload(output: &mut [u8]) -> Result<()> {
    let import = rva_offset(IMPORT_RVA)?;
    let ilt = IMPORT_RVA + 40;
    let dll = ilt + 8;
    let hint_name = dll + 12;
    put32(output, import, ilt)?;
    put32(output, import + 4, 0)?;
    put32(output, import + 8, 0)?;
    put32(output, import + 12, dll)?;
    put32(output, import + 16, IAT_RVA)?;
    // Descriptor 2 and both terminator cells remain deterministically zero.
    put32(output, import + 40, hint_name)?;
    range_mut(output, import + 48, 12)?.copy_from_slice(b"mscoree.dll\0");
    put16(output, import + 60, 0)?;
    range_mut(output, import + 62, 12)?.copy_from_slice(b"_CorDllMain\0");
    put32(output, rva_offset(IAT_RVA)?, hint_name)?;
    put32(output, rva_offset(IAT_RVA)? + 4, 0)?;
    range_mut(output, rva_offset(STUB_RVA)?, 6)?.copy_from_slice(&[0xff, 0x25, 0, 0x20, 0, 0x10]);
    put32(output, rva_offset(COR20_RVA)? + 16, 1)?;
    put32(output, RELOC_RAW_POINTER as usize, STUB_RVA & !0xfff)?;
    put32(output, RELOC_RAW_POINTER as usize + 4, 12)?;
    put16(output, RELOC_RAW_POINTER as usize + 8, 0x3f82)?;
    put16(output, RELOC_RAW_POINTER as usize + 10, 0)?;
    Ok(())
}

fn generated_rva(rva: u32) -> bool {
    GENERATED_RVA_RANGES
        .iter()
        .any(|range| range.contains(&rva))
}
fn verify_source_copy(output: &[u8], mapped: &[u8], pe: &Pe) -> Result<()> {
    for (source_range, output_rva) in [
        (TEXT_RVA..TEXT_RVA + TEXT_VIRTUAL_SIZE, TEXT_RVA),
        (RESOURCE_RVA..RESOURCE_RVA + RESOURCE_SIZE, RESOURCE_RVA),
    ] {
        for source_rva in source_range {
            if generated_rva(source_rva) {
                continue;
            }
            let byte = output_rva_bytes(output, pe, output_rva + (source_rva - output_rva), 1)?[0];
            ensure!(
                byte == mapped[usize::try_from(source_rva)?],
                "output changes source byte outside generated allowlist at RVA {source_rva:#x}"
            );
        }
    }
    Ok(())
}

fn verify_import_contract(output: &[u8], pe: &Pe) -> Result<()> {
    let import = output_rva_bytes(output, pe, IMPORT_RVA, 0x4a)?;
    ensure!(
        get32(import, 0)? == IMPORT_RVA + 40
            && get32(import, 12)? == IMPORT_RVA + 48
            && get32(import, 16)? == IAT_RVA,
        "generated import descriptor mismatch"
    );
    ensure!(
        import[20..40].iter().all(|byte| *byte == 0),
        "generated import terminator descriptor is nonzero"
    );
    ensure!(
        get32(import, 40)? == IMPORT_RVA + 60 && get32(import, 44)? == 0,
        "generated ILT mismatch"
    );
    ensure!(
        &import[48..60] == b"mscoree.dll\0"
            && get16(import, 60)? == 0
            && &import[62..74] == b"_CorDllMain\0",
        "generated mscoree hint/name mismatch"
    );
    let mut expected_iat = [0u8; 8];
    expected_iat[..4].copy_from_slice(&(IMPORT_RVA + 60).to_le_bytes());
    ensure!(
        output_rva_bytes(output, pe, IAT_RVA, 8)? == expected_iat,
        "generated IAT mismatch"
    );
    ensure!(
        output_rva_bytes(output, pe, STUB_RVA, 6)? == [0xff, 0x25, 0, 0x20, 0, 0x10],
        "generated AEP stub mismatch"
    );
    Ok(())
}

fn verify_output(output: &[u8], mapped: &[u8]) -> Result<()> {
    ensure!(output.len() == OUTPUT_SIZE, "generated output EOF mismatch");
    let pe = Pe::parse(output).context("parsing generated semantic CLR container")?;
    ensure!(
        pe.machine_kind() == Machine::I386
            && pe.kind() == PeKind::Pe32
            && pe.is_dll()
            && pe.section_count == 3,
        "generated PE32/I386 DLL header mismatch"
    );
    ensure!(
        pe.entry_rva == STUB_RVA
            && pe.image_base == 0x1000_0000
            && pe.section_alignment == SECTION_ALIGNMENT
            && pe.file_alignment == FILE_ALIGNMENT
            && pe.size_of_image == OUTPUT_IMAGE_SIZE
            && pe.size_of_headers == 0x200,
        "generated optional-header layout mismatch"
    );
    ensure!(
        get16(output, pe.opt - 2)? == OUTPUT_COFF_CHARACTERISTICS,
        "generated COFF characteristics mismatch"
    );
    let coff = pe.opt.checked_sub(20).context("generated COFF offset")?;
    ensure!(
        get32(output, coff + 4)? == 0
            && get32(output, coff + 8)? == 0
            && get32(output, coff + 12)? == 0,
        "generated COFF timestamp/symbol state is nonzero"
    );
    ensure!(
        get16(output, pe.opt)? == 0x10b
            && output[pe.opt + 2] == 8
            && output[pe.opt + 3] == 0
            && get32(output, pe.opt + 20)? == TEXT_RVA
            && get32(output, pe.opt + 24)? == RESOURCE_RVA
            && get16(output, pe.opt + 40)? == 4
            && get16(output, pe.opt + 42)? == 0
            && get16(output, pe.opt + 44)? == 0
            && get16(output, pe.opt + 46)? == 0
            && get16(output, pe.opt + 48)? == 4
            && get16(output, pe.opt + 50)? == 0
            && get32(output, pe.opt + 52)? == 0
            && get16(output, pe.opt + 68)? == 3
            && get16(output, pe.opt + 70)? == OUTPUT_DLL_CHARACTERISTICS
            && get32(output, pe.opt + 72)? == 0x10_0000
            && get32(output, pe.opt + 76)? == 0x1000
            && get32(output, pe.opt + 80)? == 0x10_0000
            && get32(output, pe.opt + 84)? == 0x1000
            && get32(output, pe.opt + 88)? == 0
            && get32(output, pe.opt + 92)? == DIRECTORY_COUNT as u32,
        "generated optional-header deterministic fields mismatch"
    );
    ensure!(
        get32(output, pe.size_of_code_offset())? == TEXT_VIRTUAL_SIZE
            && get32(output, pe.size_of_initialized_data_offset())? == 0x1200
            && get32(output, pe.size_of_uninitialized_data_offset())? == 0,
        "generated section aggregate mismatch"
    );
    for index in 0..DIRECTORY_COUNT {
        let expected = match index {
            1 => DataDirectory {
                virtual_address: IMPORT_RVA,
                size: 0x4a,
            },
            2 => DataDirectory {
                virtual_address: RESOURCE_RVA,
                size: 0x300,
            },
            5 => DataDirectory {
                virtual_address: RELOC_RVA,
                size: 12,
            },
            12 => DataDirectory {
                virtual_address: IAT_RVA,
                size: 8,
            },
            14 => DataDirectory {
                virtual_address: COR20_RVA,
                size: COR20_SIZE,
            },
            _ => DataDirectory {
                virtual_address: 0,
                size: 0,
            },
        };
        ensure!(
            pe.directory(index)? == expected,
            "generated directory {index} mismatch"
        );
    }
    ensure!(
        pe.sections[0].virtual_size == TEXT_VIRTUAL_SIZE
            && pe.sections[0].raw_size == TEXT_VIRTUAL_SIZE
            && pe.sections[1].virtual_size == RESOURCE_SIZE
            && pe.sections[1].raw_size == RESOURCE_SIZE
            && pe.sections[2].virtual_size == 12
            && pe.sections[2].raw_size == FILE_ALIGNMENT,
        "generated section raw/virtual layout mismatch"
    );
    let remapped = pe
        .map_image(output)
        .context("mapping generated semantic CLR container")?;
    ensure!(
        remapped.len() == usize::try_from(OUTPUT_IMAGE_SIZE)?,
        "generated mapped size mismatch"
    );
    ensure!(
        get32(&remapped, COR20_RVA as usize)? == COR20_SIZE
            && get32(&remapped, COR20_RVA as usize + 8)? == METADATA_RVA
            && get32(&remapped, COR20_RVA as usize + 16)? == 1,
        "generated COR20 contract mismatch"
    );
    ensure!(
        range(&remapped, METADATA_RVA as usize, 4)? == b"BSJB",
        "generated metadata identity mismatch"
    );
    ensure!(
        get32(&remapped, RELOC_RVA as usize)? == STUB_RVA & !0xfff
            && get32(&remapped, RELOC_RVA as usize + 4)? == 12
            && get16(&remapped, RELOC_RVA as usize + 8)? == 0x3f82
            && get16(&remapped, RELOC_RVA as usize + 10)? == 0,
        "generated relocation contract mismatch"
    );
    verify_import_contract(output, &pe)?;
    verify_source_copy(output, mapped, &pe)?;
    ensure!(
        get32(output, pe.checksum_offset)? == pe_checksum(output, pe.checksum_offset)?,
        "generated checksum mismatch"
    );
    Ok(())
}

/// Emits a deterministic semantic PE32/I386 CLR container after authenticating
/// the complete reviewed AMD64 source profile.  It never claims to preserve the
/// original native bootstrap or original file provenance.
pub(crate) fn rebuild_semantic_clr(
    mapped: &[u8],
    pe: &Pe,
    discovery: &LoaderDiscovery,
) -> Result<Vec<u8>> {
    authenticate_source_profile(mapped, pe, discovery)?;
    let mut output = vec![0; OUTPUT_SIZE];
    range_mut(&mut output, 0, 0x200)?.copy_from_slice(range(mapped, 0, 0x200)?);
    range_mut(
        &mut output,
        TEXT_RAW_POINTER as usize,
        TEXT_VIRTUAL_SIZE as usize,
    )?
    .copy_from_slice(range(
        mapped,
        TEXT_RVA as usize,
        TEXT_VIRTUAL_SIZE as usize,
    )?);
    range_mut(
        &mut output,
        RESOURCE_RAW_POINTER as usize,
        RESOURCE_SIZE as usize,
    )?
    .copy_from_slice(range(
        mapped,
        RESOURCE_RVA as usize,
        RESOURCE_SIZE as usize,
    )?);
    let (optional, _, _) = write_deterministic_headers(&mut output)?;
    write_generated_payload(&mut output)?;
    let checksum = pe_checksum(&output, optional + 64)?;
    put32(&mut output, optional + 64, checksum)?;
    verify_output(&output, mapped)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDDT_MAPPED: &[u8] =
        include_bytes!("../../../tmp/sddt160_Assembly-CSharp_decrypted_mapped.bin");

    fn source_pe() -> Pe {
        Pe::parse_mapped(SDDT_MAPPED).expect("reviewed SDDT mapped PE")
    }
    fn discovery() -> LoaderDiscovery {
        LoaderDiscovery {
            table_rva: SOURCE_IMPORT_RVA,
            metadata_ranges: vec![SOURCE_IMPORT_RVA..SOURCE_IAT_RVA, 0x1bfc..0x1c09],
            image_size: SOURCE_IMAGE_SIZE,
            modules: vec![crate::unpack::imports::ImportModule {
                dll: "kernel32.dll".to_owned(),
                destination_rva: SOURCE_IAT_RVA,
                symbols: [
                    "LoadLibraryA",
                    "GetProcAddress",
                    "GetModuleHandleA",
                    "ExitProcess",
                    "GetCurrentProcess",
                    "GetCurrentProcessId",
                ]
                .into_iter()
                .map(|name| ImportSymbol::Name {
                    hint: 0,
                    name: name.to_owned(),
                })
                .collect(),
            }],
            function_count: 6,
            named_count: 6,
            ordinal_count: 0,
        }
    }

    #[test]
    fn authenticated_clr_container_is_accepted() {
        validate_clr_container(SDDT_MAPPED, &source_pe()).unwrap();
    }

    #[test]
    fn builder_emits_parseable_verified_semantic_container() {
        let output = rebuild_semantic_clr(SDDT_MAPPED, &source_pe(), &discovery()).unwrap();
        verify_output(&output, SDDT_MAPPED).unwrap();
    }

    #[test]
    fn source_gates_reject_recognizer_and_generated_slot_tampering() {
        let pe = source_pe();
        let mut recognizer = SDDT_MAPPED.to_vec();
        recognizer[0x1131] ^= 1;
        assert!(rebuild_semantic_clr(&recognizer, &pe, &discovery()).is_err());
        let mut occupied_slot = SDDT_MAPPED.to_vec();
        occupied_slot[IAT_RVA as usize] = 1;
        assert!(rebuild_semantic_clr(&occupied_slot, &pe, &discovery()).is_err());
    }

    #[test]
    fn clr_container_rejects_missing_required_metadata_stream() {
        let mut mapped = SDDT_MAPPED.to_vec();
        let offset = mapped[METADATA_RVA as usize..]
            .windows(9)
            .position(|window| window == b"#Strings\0")
            .unwrap();
        mapped[METADATA_RVA as usize + offset] = b'!';
        assert!(validate_clr_container(&mapped, &source_pe()).is_err());
    }
    #[test]
    fn authenticates_exact_source_import_layout() {
        let found = crate::unpack::imports::discover_imports_in_image(
            SDDT_MAPPED,
            &source_pe(),
            crate::unpack::imports::ImportProfile::Standard,
        )
        .unwrap();
        assert_eq!(found.table_rva, SOURCE_IMPORT_RVA);
        assert_eq!(found.modules[0].destination_rva, SOURCE_IAT_RVA);
        assert_eq!(
            found.metadata_ranges,
            [SOURCE_IMPORT_RVA..SOURCE_IAT_RVA, 0x1bfc..0x1c09]
        );
        assert!(
            found.modules[0]
                .symbols
                .iter()
                .all(|symbol| matches!(symbol, ImportSymbol::Name { hint: 0, .. }))
        );
    }
}
