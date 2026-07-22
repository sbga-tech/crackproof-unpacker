use std::ops::Range;

use crate::pe::{DataDirectory, Machine, Pe, PointerWidth, Section};

use super::{
    DESCRIPTOR_SIZE, ImportModule, ImportSymbol, ordinal_flag, pointer_size_rva,
    sorted_merged_metadata_ranges,
};

pub(crate) const TABLE_SECTION_SIZE: u32 = 0x1000;
pub(crate) const IAT_SECTION_RVA: u32 = 0x5000;
pub(crate) const IAT_SECTION_SIZE: u32 = 0x1000;

#[derive(Clone)]
pub(crate) struct ModuleSpec {
    pub(crate) dll: &'static str,
    pub(crate) symbols: Vec<ImportSymbol>,
    pub(crate) destination_rva: u32,
}

pub(crate) struct RunFixture {
    pub(crate) table_rva: u32,
    pub(crate) expected_modules: Vec<ImportModule>,
    pub(crate) referenced_ranges: Vec<Range<u32>>,
    pub(crate) dll_rvas: Vec<u32>,
    pub(crate) source_rvas: Vec<u32>,
}

pub(crate) struct Fixture {
    pub(crate) mapped: Vec<u8>,
    pub(crate) pe: Pe,
    pub(crate) run: RunFixture,
}

pub(crate) fn put(mapped: &mut [u8], rva: u32, value: u32) {
    let offset = usize::try_from(rva).unwrap();
    mapped[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn put_pointer_cell(pe: &Pe, mapped: &mut [u8], rva: u32, value: u64) {
    pe.write_pointer(mapped, usize::try_from(rva).unwrap(), value)
        .unwrap();
}

pub(crate) fn encode_string(mapped: &mut [u8], rva: u32, key_rva: u32, plain: &str) {
    let mut key = key_rva as u8;
    let offset = usize::try_from(rva).unwrap();
    for (index, decoded) in plain.bytes().enumerate() {
        let adjusted = decoded.wrapping_add(key);
        mapped[offset + index] = adjusted.rotate_right(4);
        key = key.wrapping_add(0x43);
    }
    mapped[offset + plain.len()] = 0;
}

pub(crate) fn section(index: usize, virtual_address: u32, virtual_size: u32) -> Section {
    Section {
        index,
        header_offset: 0,
        name_bytes: [0; 8],
        virtual_size,
        virtual_address,
        raw_size: virtual_size,
        raw_pointer: 0,
        characteristics: 0,
    }
}

pub(crate) fn synthetic_pe(
    image_size: u32,
    sections: Vec<Section>,
    pointer_width: PointerWidth,
) -> Pe {
    Pe {
        opt: 0,
        machine: match pointer_width {
            PointerWidth::U32 => Machine::I386,
            PointerWidth::U64 => Machine::Amd64,
        },
        coff_characteristics: 0,
        section_count: sections.len(),
        entry_rva: sections[0].virtual_address,
        image_base: match pointer_width {
            PointerWidth::U32 => 0x0040_0000,
            PointerWidth::U64 => 0x0000_0001_4000_0000,
        },
        section_alignment: 0x1000,
        file_alignment: 0x200,
        size_of_image: image_size,
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
    }
}

pub(crate) fn write_run(
    pe: &Pe,
    mapped: &mut [u8],
    table_section_rva: u32,
    table_offset: u32,
    specs: &[ModuleSpec],
) -> RunFixture {
    let cell_size = pointer_size_rva(pe.pointer_width());
    let table_rva = table_section_rva + table_offset;
    let mut cursor =
        table_offset + (u32::try_from(specs.len()).unwrap() + 1) * DESCRIPTOR_SIZE as u32 + 0x20;
    let mut expected_modules = Vec::new();
    let table_end_rva =
        table_rva + (u32::try_from(specs.len()).unwrap() + 1) * DESCRIPTOR_SIZE as u32;
    let mut referenced_ranges: Vec<Range<u32>> = Vec::new();
    referenced_ranges.push(table_rva..table_end_rva);
    let mut dll_rvas = Vec::new();
    let mut source_rvas = Vec::new();

    for (index, spec) in specs.iter().enumerate() {
        cursor = (cursor + cell_size - 1) & !(cell_size - 1);
        let source_rva = table_section_rva + cursor;
        source_rvas.push(source_rva);
        cursor += (u32::try_from(spec.symbols.len()).unwrap() + 1) * cell_size;
        referenced_ranges.push(source_rva..table_section_rva + cursor);

        let dll_rva = table_section_rva + cursor;
        dll_rvas.push(dll_rva);
        encode_string(mapped, dll_rva, dll_rva, spec.dll);
        cursor += u32::try_from(spec.dll.len() + 1).unwrap();
        referenced_ranges.push(dll_rva..table_section_rva + cursor);

        for (symbol_index, symbol) in spec.symbols.iter().enumerate() {
            let value = match symbol {
                ImportSymbol::Ordinal(ordinal) => {
                    ordinal_flag(pe.pointer_width()) | u64::from(*ordinal)
                }
                ImportSymbol::Name { hint, name } => {
                    cursor = (cursor + 1) & !1;
                    let record_rva = table_section_rva + cursor;
                    let record_offset = usize::try_from(record_rva).unwrap();
                    mapped[record_offset..record_offset + 2].copy_from_slice(&hint.to_le_bytes());
                    encode_string(mapped, record_rva + 2, record_rva, name);
                    cursor += u32::try_from(name.len() + 3).unwrap();
                    referenced_ranges.push(record_rva..table_section_rva + cursor);
                    u64::from(record_rva)
                }
            };
            put_pointer_cell(
                pe,
                mapped,
                source_rva + u32::try_from(symbol_index).unwrap() * cell_size,
                value,
            );
        }
        put_pointer_cell(
            pe,
            mapped,
            source_rva + u32::try_from(spec.symbols.len()).unwrap() * cell_size,
            0,
        );
        let descriptor_rva = table_rva + u32::try_from(index).unwrap() * DESCRIPTOR_SIZE as u32;
        put(mapped, descriptor_rva, source_rva);
        put(mapped, descriptor_rva + 4, 0);
        put(mapped, descriptor_rva + 8, 0);
        put(mapped, descriptor_rva + 12, dll_rva);
        put(mapped, descriptor_rva + 16, spec.destination_rva);
        expected_modules.push(ImportModule {
            dll: spec.dll.to_owned(),
            destination_rva: spec.destination_rva,
            symbols: spec.symbols.clone(),
        });
    }
    let null_descriptor_rva =
        table_rva + u32::try_from(specs.len()).unwrap() * DESCRIPTOR_SIZE as u32;
    mapped[usize::try_from(null_descriptor_rva).unwrap()
        ..usize::try_from(null_descriptor_rva + DESCRIPTOR_SIZE as u32).unwrap()]
        .fill(0);
    RunFixture {
        table_rva,
        expected_modules,
        referenced_ranges,
        dll_rvas,
        source_rvas,
    }
}

pub(crate) fn fixture(table_section_rva: u32, table_offset: u32, specs: &[ModuleSpec]) -> Fixture {
    fixture_for_width(PointerWidth::U32, table_section_rva, table_offset, specs)
}

pub(crate) fn fixture_for_width(
    pointer_width: PointerWidth,
    table_section_rva: u32,
    table_offset: u32,
    specs: &[ModuleSpec],
) -> Fixture {
    fixture_with_table_section_size_for_width(
        pointer_width,
        table_section_rva,
        table_offset,
        TABLE_SECTION_SIZE,
        specs,
    )
}

pub(crate) fn fixture_with_table_section_size_for_width(
    pointer_width: PointerWidth,
    table_section_rva: u32,
    table_offset: u32,
    table_section_size: u32,
    specs: &[ModuleSpec],
) -> Fixture {
    let image_size = table_section_rva + table_section_size;
    let mut mapped = vec![0xa5; usize::try_from(image_size).unwrap()];
    let pe = synthetic_pe(
        image_size,
        vec![
            section(0, 0x1000, 0x1000),
            section(1, IAT_SECTION_RVA, IAT_SECTION_SIZE),
            section(2, table_section_rva, table_section_size),
        ],
        pointer_width,
    );
    // The IAT is structurally present but never inspected for resolution.
    mapped[usize::try_from(IAT_SECTION_RVA).unwrap()
        ..usize::try_from(IAT_SECTION_RVA + IAT_SECTION_SIZE).unwrap()]
        .fill(0);
    let run = write_run(&pe, &mut mapped, table_section_rva, table_offset, specs);
    Fixture { mapped, pe, run }
}

pub(crate) fn named(name: &str, hint: u16) -> ImportSymbol {
    ImportSymbol::Name {
        hint,
        name: name.to_owned(),
    }
}

pub(crate) fn merged_ranges(ranges: Vec<Range<u32>>) -> Vec<Range<u32>> {
    sorted_merged_metadata_ranges(ranges, u32::MAX).unwrap()
}

pub(crate) fn graph_specs() -> Vec<ModuleSpec> {
    vec![
        ModuleSpec {
            dll: "ZETA.Dll",
            symbols: vec![named("Create", 11), ImportSymbol::Ordinal(0x31)],
            destination_rva: IAT_SECTION_RVA + 0x100,
        },
        ModuleSpec {
            dll: "alpha.DLL",
            symbols: vec![named("Close", 5)],
            destination_rva: IAT_SECTION_RVA + 0x140,
        },
        ModuleSpec {
            dll: "gamma.dll",
            symbols: vec![named("Tick", 1)],
            destination_rva: IAT_SECTION_RVA + 0x180,
        },
    ]
}
