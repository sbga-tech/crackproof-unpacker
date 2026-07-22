use std::ops::Range;

use anyhow::{Context, Result, ensure};

use crate::pe::Pe;

use super::{
    DESCRIPTOR_ALIGNMENT, DESCRIPTOR_SIZE, DecodedString, DiscoveryBudget, ImportModule,
    ImportSymbol, LoaderDiscovery, MAX_API_NAME_LEN, MAX_MODULE_NAME_LEN, MappedImage,
    ParsedThunks, checked_destination_bounds, ordinal_flag, pointer_size_rva, printable_ascii,
    record_metadata_range, sorted_merged_metadata_ranges, valid_module_name,
    validate_discovery_modules,
};

#[derive(Clone, Debug)]
struct Candidate {
    table_rva: u32,
    metadata_ranges: Vec<Range<u32>>,
    modules: Vec<ImportModule>,
}

fn decode_loader_string(
    image: &MappedImage<'_>,
    start_rva: u32,
    key_rva: u32,
    max_len: usize,
    budget: &mut DiscoveryBudget,
) -> Result<Option<DecodedString>> {
    let mut current_rva = start_rva;
    let mut key = key_rva as u8;
    let mut output = Vec::new();
    loop {
        let Some(encoded) = image.byte(current_rva) else {
            return Ok(None);
        };
        budget.attempted_loader_string_byte()?;
        let Some(next_rva) = current_rva.checked_add(1) else {
            return Ok(None);
        };
        current_rva = next_rva;
        if encoded == 0 {
            if output.is_empty() {
                return Ok(None);
            }
            let Some(record_delta) = current_rva.checked_sub(start_rva) else {
                return Ok(None);
            };
            let Ok(record_len) = usize::try_from(record_delta) else {
                return Ok(None);
            };
            // Validate the complete record after locating its terminator so a
            // string cannot cross into an adjacent section.
            if image.range(start_rva, record_len).is_none() {
                return Ok(None);
            }
            return Ok(String::from_utf8(output).ok().map(|value| DecodedString {
                value,
                end_rva: current_rva,
            }));
        }
        if output.len() == max_len {
            return Ok(None);
        }
        let mut decoded = encoded.rotate_left(4).wrapping_sub(key);
        if decoded == 0 {
            decoded = 0u8.wrapping_sub(key);
        }
        if !printable_ascii(decoded) {
            return Ok(None);
        }
        output.push(decoded);
        key = key.wrapping_add(0x43);
    }
}

fn parse_thunks(
    image: &MappedImage<'_>,
    source_rva: u32,
    budget: &mut DiscoveryBudget,
) -> Result<Option<ParsedThunks>> {
    let cell_size = pointer_size_rva(image.pointer_width);
    if !source_rva.is_multiple_of(cell_size) {
        return Ok(None);
    }
    let mut current_rva = source_rva;
    let mut symbols = Vec::new();
    let mut metadata_ranges = Vec::new();
    loop {
        let Some(value) = image.pointer(current_rva) else {
            return Ok(None);
        };
        let Some(next_rva) = current_rva.checked_add(cell_size) else {
            return Ok(None);
        };
        current_rva = next_rva;
        if value == 0 {
            if symbols.is_empty() {
                return Ok(None);
            }
            let Some(array_delta) = current_rva.checked_sub(source_rva) else {
                return Ok(None);
            };
            let Ok(array_len) = usize::try_from(array_delta) else {
                return Ok(None);
            };
            if image.range(source_rva, array_len).is_none() {
                return Ok(None);
            }
            record_metadata_range(&mut metadata_ranges, source_rva, current_rva, budget)?;
            return Ok(Some(ParsedThunks {
                symbols,
                metadata_ranges,
            }));
        }
        budget.parsed_function()?;
        let symbol = if value & ordinal_flag(image.pointer_width) != 0 {
            if value & !(ordinal_flag(image.pointer_width) | 0xffff) != 0 {
                return Ok(None);
            }
            ImportSymbol::Ordinal((value & 0xffff) as u16)
        } else {
            let Ok(value_rva) = u32::try_from(value) else {
                return Ok(None);
            };
            if !value_rva.is_multiple_of(2) {
                return Ok(None);
            }
            let Some(hint) = image.u16(value_rva) else {
                return Ok(None);
            };
            let Some(name_rva) = value_rva.checked_add(2) else {
                return Ok(None);
            };
            let Some(decoded) =
                decode_loader_string(image, name_rva, value_rva, MAX_API_NAME_LEN, budget)?
            else {
                return Ok(None);
            };
            let Some(record_delta) = decoded.end_rva.checked_sub(value_rva) else {
                return Ok(None);
            };
            let Ok(record_len) = usize::try_from(record_delta) else {
                return Ok(None);
            };
            if image.range(value_rva, record_len).is_none() {
                return Ok(None);
            }
            record_metadata_range(&mut metadata_ranges, value_rva, decoded.end_rva, budget)?;
            ImportSymbol::Name {
                hint,
                name: decoded.value,
            }
        };
        symbols.push(symbol);
    }
}

fn is_null_descriptor(image: &MappedImage<'_>, rva: u32) -> Option<bool> {
    Some(
        image
            .range(rva, DESCRIPTOR_SIZE)?
            .iter()
            .all(|byte| *byte == 0),
    )
}
fn parse_candidate(
    image: &MappedImage<'_>,
    table_rva: u32,
    budget: &mut DiscoveryBudget,
) -> Result<Option<Candidate>> {
    if !table_rva.is_multiple_of(DESCRIPTOR_ALIGNMENT) {
        return Ok(None);
    }
    let mut current_rva = table_rva;
    let mut metadata_ranges = Vec::new();
    let mut modules = Vec::new();
    loop {
        let Some(null_descriptor) = is_null_descriptor(image, current_rva) else {
            return Ok(None);
        };
        if null_descriptor {
            let Some(table_end_rva) = current_rva.checked_add(DESCRIPTOR_SIZE as u32) else {
                return Ok(None);
            };
            let Some(table_delta) = table_end_rva.checked_sub(table_rva) else {
                return Ok(None);
            };
            let Ok(table_len) = usize::try_from(table_delta) else {
                return Ok(None);
            };
            if modules.is_empty() || image.range(table_rva, table_len).is_none() {
                return Ok(None);
            }
            record_metadata_range(&mut metadata_ranges, table_rva, table_end_rva, budget)?;
            return Ok(Some(Candidate {
                table_rva,
                metadata_ranges: sorted_merged_metadata_ranges(
                    metadata_ranges,
                    image.pe.size_of_image,
                )?,
                modules,
            }));
        }

        let Some(source_rva) = image.u32(current_rva) else {
            return Ok(None);
        };
        let Some(timestamp_rva) = current_rva.checked_add(4) else {
            return Ok(None);
        };
        let Some(timestamp) = image.u32(timestamp_rva) else {
            return Ok(None);
        };
        let Some(forwarder_rva) = current_rva.checked_add(8) else {
            return Ok(None);
        };
        let Some(forwarder) = image.u32(forwarder_rva) else {
            return Ok(None);
        };
        let Some(name_field_rva) = current_rva.checked_add(12) else {
            return Ok(None);
        };
        let Some(name_rva) = image.u32(name_field_rva) else {
            return Ok(None);
        };
        let Some(destination_field_rva) = current_rva.checked_add(16) else {
            return Ok(None);
        };
        let Some(destination_rva) = image.u32(destination_field_rva) else {
            return Ok(None);
        };
        let Some(descriptor_end_rva) = current_rva.checked_add(DESCRIPTOR_SIZE as u32) else {
            return Ok(None);
        };
        if source_rva == 0
            || name_rva == 0
            || destination_rva == 0
            || timestamp != 0
            || forwarder != 0
        {
            return Ok(None);
        }
        budget.parsed_descriptor()?;

        let Some(decoded_dll) =
            decode_loader_string(image, name_rva, name_rva, MAX_MODULE_NAME_LEN, budget)?
        else {
            return Ok(None);
        };
        if !valid_module_name(&decoded_dll.value) {
            return Ok(None);
        }
        let Some(parsed_thunks) = parse_thunks(image, source_rva, budget)? else {
            return Ok(None);
        };
        let ParsedThunks {
            symbols,
            metadata_ranges: thunk_metadata_ranges,
        } = parsed_thunks;
        let module = ImportModule {
            dll: decoded_dll.value,
            destination_rva,
            symbols,
        };
        let Ok((destination_start_rva, destination_end_rva)) =
            checked_destination_bounds(&module, image.pe.size_of_image, image.pointer_width)
        else {
            return Ok(None);
        };
        let Some(terminated_end_rva) =
            destination_end_rva.checked_add(pointer_size_rva(image.pointer_width))
        else {
            return Ok(None);
        };
        let Some(destination_delta) = terminated_end_rva.checked_sub(destination_start_rva) else {
            return Ok(None);
        };
        let Ok(destination_len) = usize::try_from(destination_delta) else {
            return Ok(None);
        };
        if image
            .range(destination_start_rva, destination_len)
            .is_none()
        {
            return Ok(None);
        }

        record_metadata_range(&mut metadata_ranges, name_rva, decoded_dll.end_rva, budget)?;
        metadata_ranges.extend(thunk_metadata_ranges);
        modules.push(module);
        current_rva = descriptor_end_rva;
    }
}

fn candidate_is_suffix_of(candidate: &Candidate, winner: &Candidate) -> bool {
    let Some(suffix_start) = winner.modules.len().checked_sub(candidate.modules.len()) else {
        return false;
    };
    let Some(suffix_bytes) = u32::try_from(suffix_start)
        .ok()
        .and_then(|count| count.checked_mul(DESCRIPTOR_SIZE as u32))
    else {
        return false;
    };
    let Some(expected_start_rva) = winner.table_rva.checked_add(suffix_bytes) else {
        return false;
    };
    let Some(winner_descriptor_count) = winner.modules.len().checked_add(1) else {
        return false;
    };
    let Some(winner_table_bytes) = u32::try_from(winner_descriptor_count)
        .ok()
        .and_then(|count| count.checked_mul(DESCRIPTOR_SIZE as u32))
    else {
        return false;
    };
    let Some(winner_table_end_rva) = winner.table_rva.checked_add(winner_table_bytes) else {
        return false;
    };
    let Some(candidate_descriptor_count) = candidate.modules.len().checked_add(1) else {
        return false;
    };
    let Some(candidate_table_bytes) = u32::try_from(candidate_descriptor_count)
        .ok()
        .and_then(|count| count.checked_mul(DESCRIPTOR_SIZE as u32))
    else {
        return false;
    };
    candidate.table_rva == expected_start_rva
        && candidate.table_rva.checked_add(candidate_table_bytes) == Some(winner_table_end_rva)
        && candidate.modules == winner.modules[suffix_start..]
}

/// Discovers the custom loader's imports directly from the mapped PE image.
///
/// Descriptor starts are scanned at every 4-byte-aligned RVA in every mapped
/// section. A candidate is valid only when its full descriptor table, encoded
/// names, thunk arrays, hint/name records, and IAT ranges are structurally
/// valid in the image. There must be one globally longest candidate. Its
/// descriptor-row suffixes are expected scan results; every other valid graph,
/// including a shorter one, makes discovery ambiguous.
pub(super) fn discover_imports_in_image(mapped: &[u8], pe: &Pe) -> Result<LoaderDiscovery> {
    let image_size = usize::try_from(pe.size_of_image).context("SizeOfImage does not fit usize")?;
    ensure!(
        mapped.len() == image_size,
        "mapped image length {:#x} does not equal PE SizeOfImage {:#x}",
        mapped.len(),
        pe.size_of_image
    );
    ensure!(pe.size_of_image != 0, "PE image is empty");
    let image = MappedImage {
        mapped,
        pe,
        pointer_width: pe.pointer_width(),
    };
    let mut budget = DiscoveryBudget::default();
    let mut candidates = Vec::new();

    for section in &pe.sections {
        let section_range = section
            .virtual_range()
            .with_context(|| format!("reading virtual range for section {}", section.index))?;
        let section_end_rva = section_range.end.min(pe.size_of_image);
        let Some(first_rva) = section_range
            .start
            .checked_add(DESCRIPTOR_ALIGNMENT - 1)
            .map(|rva| rva & !(DESCRIPTOR_ALIGNMENT - 1))
        else {
            continue;
        };
        let Some(last_start_rva) = section_end_rva.checked_sub(DESCRIPTOR_SIZE as u32) else {
            continue;
        };
        if first_rva > last_start_rva {
            continue;
        }
        let mut table_rva = first_rva;
        loop {
            budget.scanned_descriptor_start()?;
            let Some(descriptor_start) = usize::try_from(table_rva).ok() else {
                break;
            };
            let Some(descriptor_end) = descriptor_start.checked_add(DESCRIPTOR_SIZE) else {
                break;
            };
            let Some(descriptor) = mapped.get(descriptor_start..descriptor_end) else {
                break;
            };
            if descriptor.iter().all(|byte| *byte == 0) {
                if table_rva == last_start_rva {
                    break;
                }
                let Some(next_rva) = table_rva.checked_add(DESCRIPTOR_ALIGNMENT) else {
                    break;
                };
                if next_rva > last_start_rva {
                    break;
                }
                table_rva = next_rva;
                continue;
            }
            if let Some(candidate) = parse_candidate(&image, table_rva, &mut budget)? {
                budget.valid_candidate()?;
                candidates.push(candidate);
            }
            if table_rva == last_start_rva {
                break;
            }
            let Some(next_rva) = table_rva.checked_add(DESCRIPTOR_ALIGNMENT) else {
                break;
            };
            if next_rva > last_start_rva {
                break;
            }
            table_rva = next_rva;
        }
    }

    let maximal_len = candidates
        .iter()
        .map(|candidate| candidate.modules.len())
        .max()
        .context("no valid encoded loader descriptor run found")?;
    let maximal_indexes = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| (candidate.modules.len() == maximal_len).then_some(index))
        .collect::<Vec<_>>();
    ensure!(
        maximal_indexes.len() == 1,
        "encoded loader descriptor discovery is ambiguous: {} maximal runs contain {maximal_len} modules",
        maximal_indexes.len()
    );
    let winner_index = maximal_indexes[0];
    let winner = &candidates[winner_index];
    ensure!(
        candidates
            .iter()
            .all(|candidate| candidate_is_suffix_of(candidate, winner)),
        "encoded loader descriptor discovery is ambiguous: a non-suffix valid graph was found"
    );
    let candidate = candidates.swap_remove(winner_index);
    validate_discovery_modules(&candidate.modules, pe.size_of_image, image.pointer_width)
        .context("validating selected loader descriptor run")?;
    let modules = candidate.modules;
    let function_count = modules.iter().map(|module| module.symbols.len()).sum();
    let named_count = modules
        .iter()
        .flat_map(|module| &module.symbols)
        .filter(|symbol| matches!(symbol, ImportSymbol::Name { .. }))
        .count();
    let ordinal_count = function_count - named_count;

    Ok(LoaderDiscovery {
        table_rva: candidate.table_rva,
        metadata_ranges: candidate.metadata_ranges,
        image_size: pe.size_of_image,
        modules,
        function_count,
        named_count,
        ordinal_count,
    })
}
