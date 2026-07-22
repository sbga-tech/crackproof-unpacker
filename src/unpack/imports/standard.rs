use anyhow::{Context, Result, ensure};

use crate::pe::Pe;

use super::{
    DESCRIPTOR_SIZE, DiscoveryBudget, ImportModule, ImportSymbol, LoaderDiscovery, MappedImage,
    checked_destination_bounds, named_thunk_rva, ordinal_flag, pointer_size_rva,
    record_metadata_range, sorted_merged_metadata_ranges, valid_module_name,
    validate_discovery_modules,
};

const IMPORT_DIRECTORY: usize = 1;
const MAX_STANDARD_DESCRIPTORS: usize = 4_096;
const MAX_STANDARD_THUNKS: usize = 1_000_000;
const MAX_STANDARD_STRING: usize = 4_096;

fn read_ascii(
    image: &MappedImage<'_>,
    rva: u32,
    budget: &mut DiscoveryBudget,
) -> Result<Option<(String, u32)>> {
    let mut end = rva;
    let mut bytes = Vec::new();
    while bytes.len() < MAX_STANDARD_STRING {
        budget.attempted_loader_string_byte()?;
        let Some(byte) = image.byte(end) else {
            return Ok(None);
        };
        end = match end.checked_add(1) {
            Some(value) => value,
            None => return Ok(None),
        };
        if byte == 0 {
            return Ok((!bytes.is_empty()
                && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)))
            .then(|| String::from_utf8(bytes).ok())
            .flatten()
            .map(|name| (name, end)));
        }
        bytes.push(byte);
    }
    Ok(None)
}

fn parse_thunks(
    image: &MappedImage<'_>,
    source_rva: u32,
    metadata_ranges: &mut Vec<std::ops::Range<u32>>,
    include_metadata: bool,
    budget: &mut DiscoveryBudget,
) -> Result<Option<Vec<ImportSymbol>>> {
    let width = pointer_size_rva(image.pointer_width);
    let mut rva = source_rva;
    let mut symbols = Vec::new();
    loop {
        if symbols.len() == MAX_STANDARD_THUNKS {
            return Ok(None);
        }
        let Some(value) = image.pointer(rva) else {
            return Ok(None);
        };
        rva = match rva.checked_add(width) {
            Some(value) => value,
            None => return Ok(None),
        };
        if value == 0 {
            if symbols.is_empty() {
                return Ok(None);
            }
            if include_metadata {
                record_metadata_range(metadata_ranges, source_rva, rva, budget)?;
            }
            return Ok(Some(symbols));
        }
        budget.parsed_function()?;
        let symbol = if value & ordinal_flag(image.pointer_width) != 0 {
            if value & !(ordinal_flag(image.pointer_width) | 0xffff) != 0 {
                return Ok(None);
            }
            ImportSymbol::Ordinal(value as u16)
        } else {
            let Some(name_rva) = named_thunk_rva(image.pointer_width, value) else {
                return Ok(None);
            };
            if !name_rva.is_multiple_of(2) {
                return Ok(None);
            }
            let Some(hint) = image.u16(name_rva) else {
                return Ok(None);
            };
            let Some((name, end)) = read_ascii(
                image,
                name_rva
                    .checked_add(2)
                    .context("standard import name RVA overflows")?,
                budget,
            )?
            else {
                return Ok(None);
            };
            if include_metadata {
                record_metadata_range(metadata_ranges, name_rva, end, budget)?;
            }
            ImportSymbol::Name { hint, name }
        };
        symbols.push(symbol);
    }
}

pub(super) fn discover_imports_in_image(mapped: &[u8], pe: &Pe) -> Result<LoaderDiscovery> {
    let directory = pe.directory(IMPORT_DIRECTORY)?;
    let range = directory
        .checked_rva_range()?
        .context("standard Import Directory is absent")?;
    ensure!(
        range.start.is_multiple_of(4) && range.end - range.start >= DESCRIPTOR_SIZE as u32,
        "standard Import Directory is malformed"
    );
    ensure!(
        (range.end - range.start) as usize / DESCRIPTOR_SIZE <= MAX_STANDARD_DESCRIPTORS,
        "standard Import Directory exceeds descriptor limit"
    );
    ensure!(
        mapped.len() == usize::try_from(pe.size_of_image)?,
        "standard import image length differs from PE"
    );
    let image = MappedImage {
        mapped,
        pe,
        pointer_width: pe.pointer_width(),
    };
    let mut modules = Vec::new();
    let mut metadata_ranges = Vec::new();
    let mut budget = DiscoveryBudget::default();
    let mut rva = range.start;
    loop {
        budget.parsed_descriptor()?;
        let descriptor = image
            .range(rva, DESCRIPTOR_SIZE)
            .context("standard import descriptor exceeds image")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            ensure!(
                !modules.is_empty(),
                "standard Import Directory has no descriptors"
            );
            record_metadata_range(
                &mut metadata_ranges,
                range.start,
                rva + DESCRIPTOR_SIZE as u32,
                &mut budget,
            )?;
            break;
        }
        let original_first_thunk =
            u32::from_le_bytes(descriptor[0..4].try_into().expect("descriptor field"));
        let name_rva = u32::from_le_bytes(descriptor[12..16].try_into().expect("descriptor field"));
        let first_thunk =
            u32::from_le_bytes(descriptor[16..20].try_into().expect("descriptor field"));
        ensure!(
            name_rva != 0 && first_thunk != 0,
            "standard import descriptor has null required fields"
        );
        let (dll, dll_end) = read_ascii(&image, name_rva, &mut budget)?
            .context("standard import DLL name is invalid")?;
        ensure!(
            valid_module_name(&dll),
            "standard import DLL name is invalid"
        );
        record_metadata_range(&mut metadata_ranges, name_rva, dll_end, &mut budget)?;
        let lookup = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        let symbols = parse_thunks(
            &image,
            lookup,
            &mut metadata_ranges,
            lookup != first_thunk,
            &mut budget,
        )?
        .context("standard import thunk array is invalid")?;
        let module = ImportModule {
            dll,
            destination_rva: first_thunk,
            symbols,
        };
        let (_, iat_end) =
            checked_destination_bounds(&module, pe.size_of_image, pe.pointer_width())?;
        ensure!(
            image.pointer(iat_end) == Some(0),
            "standard import IAT lacks a null terminator"
        );
        modules.push(module);
        rva = rva
            .checked_add(DESCRIPTOR_SIZE as u32)
            .context("standard import descriptor RVA overflows")?;
        ensure!(
            rva <= range.end,
            "standard Import Directory lacks a null descriptor"
        );
    }
    validate_discovery_modules(&modules, pe.size_of_image, pe.pointer_width())?;
    let function_count = modules.iter().map(|module| module.symbols.len()).sum();
    let named_count = modules
        .iter()
        .flat_map(|module| &module.symbols)
        .filter(|symbol| matches!(symbol, ImportSymbol::Name { .. }))
        .count();
    Ok(LoaderDiscovery {
        table_rva: range.start,
        metadata_ranges: sorted_merged_metadata_ranges(metadata_ranges, pe.size_of_image)?,
        image_size: pe.size_of_image,
        modules,
        function_count,
        named_count,
        ordinal_count: function_count - named_count,
    })
}
