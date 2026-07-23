use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use anyhow::{Context, Result, ensure};

use crate::pe::{self, DataDirectory, Pe, PointerWidth, Section};
use crate::unpack::imports::{ImportSymbol, LoaderDiscovery};

use super::{
    BASE_RELOCATION_BLOCK_HEADER_SIZE, BASE_RELOCATION_DIRECTORY, EXCEPTION_DIRECTORY,
    EXPORT_DIRECTORY, IAT_DIRECTORY, IMAGE_IMPORT_DESCRIPTOR_SIZE, IMPORT_DIRECTORY, ScanBudget,
    canonical_import_graph, parse_export_candidate, parse_import_candidate,
    parse_relocation_candidate, resource_node, rva_slice, u32_at,
    validate_base_relocation_directory, validate_debug_directory, validate_exception_directory,
};

const DEBUG_DIRECTORY: usize = 6;
const RESOURCE_DIRECTORY: usize = 2;
const LOAD_CONFIG_DIRECTORY: usize = 10;
const IMAGE_DEBUG_DIRECTORY_SIZE: usize = 28;
const IMAGE_DEBUG_TYPE_POGO: u32 = 13;
const GCTL_SIGNATURE: &[u8; 4] = b"GCTL";
const MAX_GCTL_BYTES: usize = 1 << 20;
const MAX_GCTL_CONTRIBUTIONS: usize = 16_384;
const MAX_GCTL_NAME: usize = 128;
const NORMALIZED_FILE_ALIGNMENT: u32 = 0x200;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Contribution {
    name: String,
    range: Range<u32>,
}

#[derive(Clone, Debug)]
struct GctlLayout {
    contributions: Vec<Contribution>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum SectionKind {
    Text,
    Rdata,
    Data,
    Pdata,
    Gfids,
    CustomRdata,
    Resource,
}

#[derive(Debug)]
pub(super) struct PogoRecovery {
    pub(super) mapped: Vec<u8>,
    pub(super) pe: Pe,
    pub(super) directories: Vec<(usize, DataDirectory)>,
}

pub(super) fn recover(
    mapped: &[u8],
    pe: &Pe,
    discovery: &LoaderDiscovery,
    destination_ranges: &[Range<u32>],
) -> Result<Option<PogoRecovery>> {
    let Some(gctl) = parse_gctl(mapped, pe, destination_ranges)? else {
        return Ok(None);
    };
    let Some(grouped) = group_contributions(&gctl)? else {
        return Ok(None);
    };
    if !has_import_topology(&gctl) {
        return Ok(None);
    }
    let relocation = recover_relocations(mapped, pe, destination_ranges, &grouped)?;
    let Some(relocation) = relocation else {
        return Ok(None);
    };

    let mut recovered_pe = recovered_pe(pe, &grouped, relocation)?;
    let image_len = usize::try_from(recovered_pe.size_of_image)
        .context("POGO SizeOfImage does not fit usize")?;
    ensure!(
        image_len <= mapped.len(),
        "POGO SizeOfImage exceeds mapped image"
    );
    let mut recovered_mapped = mapped[..image_len].to_vec();

    let (imports, iat) = restore_imports(&mut recovered_mapped, &recovered_pe, discovery, &gctl)?;
    let export = unique_contribution(&gctl, ".edata").map(|value| value.range.clone());
    let resources = grouped.get(&SectionKind::Resource).cloned();
    let exception = grouped.get(&SectionKind::Pdata).cloned();
    let debug = pe
        .directories
        .get(DEBUG_DIRECTORY)
        .copied()
        .filter(|directory| !directory.is_empty())
        .context("POGO layout has no Debug Directory")?;
    let load_config = recover_load_config(&recovered_mapped, &recovered_pe, &gctl)?;

    let export_directory = export
        .map(|range| {
            let directory = DataDirectory {
                virtual_address: range.start,
                size: range.end - range.start,
            };
            let parsed = parse_export_candidate(&recovered_mapped, &recovered_pe, range.start)?
                .context("POGO .edata contribution is not a valid export graph")?;
            ensure!(
                parsed.size <= directory.size,
                "POGO export graph exceeds .edata contribution"
            );
            Ok(directory)
        })
        .transpose()?;
    let resource_directory = resources
        .map(|range| {
            let mut resource_nodes = 0usize;
            let resource_end = resource_node(
                &recovered_mapped,
                &recovered_pe,
                range.start,
                range.start,
                0,
                &mut resource_nodes,
            )?
            .context("POGO .rsrc contribution is not a valid resource graph")?;
            ensure!(
                resource_end <= range.end,
                "POGO resource graph exceeds .rsrc contributions"
            );
            Ok(DataDirectory {
                virtual_address: range.start,
                size: range.end - range.start,
            })
        })
        .transpose()?;
    let exception_directory = exception.map(|range| DataDirectory {
        virtual_address: range.start,
        size: range.end - range.start,
    });
    if let Some(exception) = exception_directory {
        validate_exception_directory(&recovered_mapped, &recovered_pe, exception)?;
    }
    validate_base_relocation_directory(&recovered_mapped, &recovered_pe, relocation)?;
    validate_debug_directory(&recovered_mapped, &recovered_pe, debug)?;

    let mut directories = vec![
        (IMPORT_DIRECTORY, imports),
        (BASE_RELOCATION_DIRECTORY, relocation),
        (DEBUG_DIRECTORY, debug),
        (IAT_DIRECTORY, iat),
    ];
    if let Some(directory) = export_directory {
        directories.push((EXPORT_DIRECTORY, directory));
    }
    if let Some(directory) = resource_directory {
        directories.push((RESOURCE_DIRECTORY, directory));
    }
    if let Some(directory) = exception_directory {
        directories.push((EXCEPTION_DIRECTORY, directory));
    }
    if let Some(load_config) = load_config {
        directories.push((LOAD_CONFIG_DIRECTORY, load_config));
    }
    directories.sort_by_key(|(index, _)| *index);
    for (index, directory) in &directories {
        let slot = recovered_pe
            .directories
            .get_mut(*index)
            .context("POGO directory index exceeds PE directory table")?;
        *slot = *directory;
    }
    for (index, directory) in recovered_pe.directories.iter_mut().enumerate() {
        if !directories.iter().any(|(retained, _)| *retained == index) {
            *directory = DataDirectory {
                virtual_address: 0,
                size: 0,
            };
        }
    }

    Ok(Some(PogoRecovery {
        mapped: recovered_mapped,
        pe: recovered_pe,
        directories,
    }))
}

fn parse_gctl(
    mapped: &[u8],
    pe: &Pe,
    destination_ranges: &[Range<u32>],
) -> Result<Option<GctlLayout>> {
    let Some(debug) = pe
        .directories
        .get(DEBUG_DIRECTORY)
        .copied()
        .filter(|directory| !directory.is_empty())
    else {
        return Ok(None);
    };
    validate_debug_directory(mapped, pe, debug)?;
    let debug_range = debug
        .checked_rva_range()?
        .context("Debug Directory is partial")?;
    ensure!(
        covered_by_destinations(destination_ranges, debug_range.clone()),
        "Debug Directory is not backed by authenticated A-record destinations"
    );
    ensure!(
        (debug.size as usize).is_multiple_of(IMAGE_DEBUG_DIRECTORY_SIZE),
        "Debug Directory size is not record-aligned"
    );

    let mut selected = None;
    for index in 0..usize::try_from(debug.size)? / IMAGE_DEBUG_DIRECTORY_SIZE {
        let record_rva = debug
            .virtual_address
            .checked_add(u32::try_from(index * IMAGE_DEBUG_DIRECTORY_SIZE)?)
            .context("Debug Directory record RVA overflows")?;
        let record = rva_slice(mapped, pe, record_rva, IMAGE_DEBUG_DIRECTORY_SIZE)
            .context("Debug Directory record exceeds mapped image")?;
        if u32::from_le_bytes(record[12..16].try_into().expect("four bytes"))
            != IMAGE_DEBUG_TYPE_POGO
        {
            continue;
        }
        let size = u32::from_le_bytes(record[16..20].try_into().expect("four bytes"));
        let rva = u32::from_le_bytes(record[20..24].try_into().expect("four bytes"));
        ensure!(size != 0 && rva != 0, "POGO debug payload range is partial");
        ensure!(
            usize::try_from(size)? <= MAX_GCTL_BYTES,
            "POGO debug payload exceeds the {MAX_GCTL_BYTES}-byte cap"
        );
        let range = rva..rva
            .checked_add(size)
            .context("POGO payload range overflows")?;
        ensure!(
            covered_by_destinations(destination_ranges, range.clone()),
            "POGO payload is not backed by authenticated A-record destinations"
        );
        let payload = rva_slice(mapped, pe, rva, usize::try_from(size)?)
            .context("POGO payload exceeds mapped image")?;
        if !payload.starts_with(GCTL_SIGNATURE) {
            continue;
        }
        ensure!(
            selected.is_none(),
            "multiple authenticated GCTL payloads found"
        );
        selected = Some(parse_gctl_payload(payload, pe)?);
    }
    Ok(selected)
}

fn parse_gctl_payload(payload: &[u8], pe: &Pe) -> Result<GctlLayout> {
    ensure!(
        payload.starts_with(GCTL_SIGNATURE),
        "GCTL signature is absent"
    );
    let mut offset = GCTL_SIGNATURE.len();
    let mut contributions = Vec::new();
    let mut previous_end = 0u32;
    while offset < payload.len() {
        ensure!(
            contributions.len() < MAX_GCTL_CONTRIBUTIONS,
            "GCTL contribution count exceeds {MAX_GCTL_CONTRIBUTIONS}"
        );
        let header = payload
            .get(offset..offset + 8)
            .context("GCTL contribution header is truncated")?;
        let rva = u32::from_le_bytes(header[..4].try_into().expect("four bytes"));
        let size = u32::from_le_bytes(header[4..].try_into().expect("four bytes"));
        ensure!(rva != 0 && size != 0, "GCTL contribution range is empty");
        let end = rva
            .checked_add(size)
            .context("GCTL contribution range overflows")?;
        ensure!(
            end <= pe.size_of_image,
            "GCTL contribution exceeds SizeOfImage"
        );
        ensure!(
            rva >= previous_end,
            "GCTL contributions are not RVA ordered"
        );
        offset += 8;

        let remaining = payload
            .get(offset..)
            .context("GCTL contribution name offset exceeds payload")?;
        let terminator = remaining
            .iter()
            .take(MAX_GCTL_NAME + 1)
            .position(|byte| *byte == 0)
            .context("GCTL contribution name is unterminated")?;
        ensure!(
            terminator != 0 && terminator <= MAX_GCTL_NAME,
            "GCTL contribution name length is invalid"
        );
        let name_bytes = &remaining[..terminator];
        ensure!(
            name_bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)),
            "GCTL contribution name is invalid"
        );
        let name = std::str::from_utf8(name_bytes)
            .context("GCTL contribution name is not UTF-8")?
            .to_owned();
        offset = offset
            .checked_add(terminator + 1)
            .context("GCTL contribution name end overflows")?;
        let aligned = pe::align_up(u32::try_from(offset)?, 4)? as usize;
        ensure!(
            aligned <= payload.len(),
            "GCTL contribution padding is truncated"
        );
        ensure!(
            payload[offset..aligned].iter().all(|byte| *byte == 0),
            "GCTL contribution padding is nonzero"
        );
        offset = aligned;
        contributions.push(Contribution {
            name,
            range: rva..end,
        });
        previous_end = end;
    }
    ensure!(!contributions.is_empty(), "GCTL contains no contributions");
    Ok(GctlLayout { contributions })
}

fn group_contributions(gctl: &GctlLayout) -> Result<Option<BTreeMap<SectionKind, Range<u32>>>> {
    let mut grouped: BTreeMap<SectionKind, Range<u32>> = BTreeMap::new();
    for contribution in &gctl.contributions {
        let Some(kind) = contribution_kind(&contribution.name) else {
            return Ok(None);
        };
        match grouped.get_mut(&kind) {
            None => {
                grouped.insert(kind, contribution.range.clone());
            }
            Some(range) => {
                ensure!(
                    range.end == contribution.range.start,
                    "GCTL contributions for {kind:?} are not contiguous"
                );
                range.end = contribution.range.end;
            }
        }
    }
    for required in [SectionKind::Text, SectionKind::Rdata, SectionKind::Data] {
        if !grouped.contains_key(&required) {
            return Ok(None);
        }
    }
    let mut ranges = grouped.values().cloned().collect::<Vec<_>>();
    ranges.sort_by_key(|range| range.start);
    for pair in ranges.windows(2) {
        ensure!(pair[0].end <= pair[1].start, "POGO section groups overlap");
    }
    Ok(Some(grouped))
}

fn contribution_kind(name: &str) -> Option<SectionKind> {
    if name.starts_with(".text") {
        Some(SectionKind::Text)
    } else if name == ".data" || name.starts_with(".data$") || name == ".bss" {
        Some(SectionKind::Data)
    } else if name.starts_with(".pdata") {
        Some(SectionKind::Pdata)
    } else if name.starts_with(".gfids") {
        Some(SectionKind::Gfids)
    } else if name.starts_with(".rsrc") {
        Some(SectionKind::Resource)
    } else if name == "_RDATA" {
        Some(SectionKind::CustomRdata)
    } else if name.starts_with(".idata")
        || name.starts_with(".rdata")
        || name.starts_with(".xdata")
        || name.starts_with(".edata")
        || name.starts_with(".CRT")
        || name.starts_with(".rtc")
        || name == ".00cfg"
    {
        Some(SectionKind::Rdata)
    } else {
        None
    }
}

fn recovered_pe(
    pe: &Pe,
    grouped: &BTreeMap<SectionKind, Range<u32>>,
    relocation: DataDirectory,
) -> Result<Pe> {
    let mut recovered = pe.clone();
    let first_header = pe
        .sections
        .first()
        .context("PE has no section header table")?
        .header_offset;
    let relocation_range = relocation
        .checked_rva_range()?
        .context("recovered relocation directory is partial")?;
    let mut definitions = vec![
        (SectionKind::Text, *b".text\0\0\0", 0x6000_0020),
        (SectionKind::Rdata, *b".rdata\0\0", 0x4000_0040),
        (SectionKind::Data, *b".data\0\0\0", 0xc000_0040),
    ];
    for definition in [
        (SectionKind::Pdata, *b".pdata\0\0", 0x4000_0040),
        (SectionKind::Gfids, *b".gfids\0\0", 0x4000_0040),
        (SectionKind::CustomRdata, *b"_RDATA\0\0", 0x4000_0040),
        (SectionKind::Resource, *b".rsrc\0\0\0", 0x4000_0040),
    ] {
        if grouped.contains_key(&definition.0) {
            definitions.push(definition);
        }
    }
    definitions.sort_by_key(|(kind, _, _)| grouped[kind].start);
    let mut sections = Vec::with_capacity(definitions.len() + 1);
    for (index, (kind, name, characteristics)) in definitions.into_iter().enumerate() {
        let range = grouped
            .get(&kind)
            .with_context(|| format!("POGO layout lacks {kind:?}"))?;
        ensure!(
            range.start.is_multiple_of(pe.section_alignment),
            "POGO {kind:?} section RVA is not section-aligned"
        );
        sections.push(Section {
            index,
            header_offset: first_header + index * 40,
            name_bytes: name,
            virtual_size: range.end - range.start,
            virtual_address: range.start,
            raw_size: 0,
            raw_pointer: 0,
            characteristics,
        });
    }
    let relocation_index = sections.len();
    ensure!(
        relocation_range.start.is_multiple_of(pe.section_alignment),
        "recovered relocation section RVA is not section-aligned"
    );
    sections.push(Section {
        index: relocation_index,
        header_offset: first_header + relocation_index * 40,
        name_bytes: *b".reloc\0\0",
        virtual_size: relocation.size,
        virtual_address: relocation.virtual_address,
        raw_size: 0,
        raw_pointer: 0,
        characteristics: 0x4200_0040,
    });
    for pair in sections.windows(2) {
        let end = pair[0]
            .virtual_address
            .checked_add(pair[0].virtual_size)
            .context("recovered POGO section range overflows")?;
        ensure!(
            end <= pair[1].virtual_address,
            "recovered POGO sections overlap"
        );
    }

    recovered.section_count = sections.len();
    recovered.sections = sections;
    recovered.file_alignment = NORMALIZED_FILE_ALIGNMENT;
    let section_table_end = first_header
        .checked_add(recovered.section_count * 40)
        .context("recovered section table end overflows")?;
    recovered.size_of_headers =
        pe::align_up(u32::try_from(section_table_end)?, recovered.file_alignment)?;
    recovered.size_of_image = pe::align_up(relocation_range.end, recovered.section_alignment)?;
    Ok(recovered)
}

fn recover_relocations(
    mapped: &[u8],
    pe: &Pe,
    destination_ranges: &[Range<u32>],
    grouped: &BTreeMap<SectionKind, Range<u32>>,
) -> Result<Option<DataDirectory>> {
    let minimum = grouped
        .values()
        .map(|range| range.end)
        .max()
        .context("POGO layout has no contribution ranges")?;
    let mut candidates = Vec::new();
    let mut budget = ScanBudget::default();
    for range in destination_ranges {
        let start = pe::align_up(range.start, 4)?;
        if start < minimum
            || start
                .checked_add(BASE_RELOCATION_BLOCK_HEADER_SIZE as u32)
                .is_none_or(|end| end > range.end)
        {
            continue;
        }
        let owner = pe
            .section_for_rva_range(start, BASE_RELOCATION_BLOCK_HEADER_SIZE)
            .context("locating provenance-backed relocation candidate owner")?;
        let owner_end = owner.virtual_range()?.end.min(pe.size_of_image);
        if let Some(candidate) =
            parse_relocation_candidate(mapped, pe, start, owner_end, &mut budget)?
        {
            let candidate_range = candidate
                .checked_rva_range()?
                .expect("relocation candidate is nonempty");
            if candidate.virtual_address == start
                && covered_by_destinations(destination_ranges, candidate_range)
            {
                candidates.push(candidate);
            }
        }
    }
    candidates.sort_by_key(|candidate| (candidate.virtual_address, candidate.size));
    candidates.dedup();
    ensure!(
        candidates.len() <= 1,
        "multiple provenance-backed relocation streams found"
    );
    Ok(candidates.pop())
}

fn restore_imports(
    mapped: &mut [u8],
    pe: &Pe,
    discovery: &LoaderDiscovery,
    gctl: &GctlLayout,
) -> Result<(DataDirectory, DataDirectory)> {
    let descriptors = contribution(gctl, ".idata$2")?.range.clone();
    let descriptor_tail = contribution(gctl, ".idata$3")?.range.clone();
    let lookup = contribution(gctl, ".idata$4")?.range.clone();
    let iat = contribution(gctl, ".idata$5")?.range.clone();
    let strings = contribution(gctl, ".idata$6")?.range.clone();
    ensure!(
        descriptors.end == descriptor_tail.start,
        "POGO import descriptor contributions are not contiguous"
    );

    let mut modules_by_iat = BTreeMap::new();
    for (index, module) in discovery.modules.iter().enumerate() {
        ensure!(
            modules_by_iat
                .insert(module.destination_rva, index)
                .is_none(),
            "loader graph has duplicate FirstThunk RVAs"
        );
    }
    let mut seen_modules = BTreeSet::new();
    let mut allocations: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let descriptor_limit = descriptor_tail.end;
    let mut descriptor_rva = descriptors.start;
    let import_end = loop {
        ensure!(
            descriptor_rva
                .checked_add(IMAGE_IMPORT_DESCRIPTOR_SIZE as u32)
                .is_some_and(|end| end <= descriptor_limit),
            "POGO import descriptor table lacks a null terminator"
        );
        let descriptor = rva_slice(mapped, pe, descriptor_rva, IMAGE_IMPORT_DESCRIPTOR_SIZE)
            .context("POGO import descriptor exceeds mapped image")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break descriptor_rva
                .checked_add(IMAGE_IMPORT_DESCRIPTOR_SIZE as u32)
                .context("POGO import directory end overflows")?;
        }
        let original_first_thunk =
            u32::from_le_bytes(descriptor[..4].try_into().expect("four bytes"));
        let name_rva = u32::from_le_bytes(descriptor[12..16].try_into().expect("four bytes"));
        let first_thunk = u32::from_le_bytes(descriptor[16..20].try_into().expect("four bytes"));
        ensure!(
            original_first_thunk != 0 && name_rva != 0 && first_thunk != 0,
            "POGO import descriptor is partial"
        );
        ensure!(
            lookup.contains(&original_first_thunk),
            "POGO OriginalFirstThunk is outside .idata$4"
        );
        ensure!(
            strings.contains(&name_rva),
            "POGO DLL name is outside .idata$6"
        );
        let module_index = *modules_by_iat
            .get(&first_thunk)
            .context("POGO FirstThunk has no loader-graph module")?;
        ensure!(
            seen_modules.insert(module_index),
            "POGO import descriptors repeat a loader-graph module"
        );
        let module = &discovery.modules[module_index];
        let thunk_bytes = u32::try_from(module.symbols.len())?
            .checked_add(1)
            .and_then(|count| count.checked_mul(u32::try_from(pe.pointer_width().bytes()).ok()?))
            .context("POGO thunk-array length overflows")?;
        ensure!(
            range_contains_span(&lookup, original_first_thunk, thunk_bytes),
            "POGO ILT array exceeds .idata$4"
        );
        ensure!(
            range_contains_span(&iat, first_thunk, thunk_bytes),
            "POGO IAT array exceeds .idata$5"
        );
        insert_allocation(
            &mut allocations,
            name_rva,
            [module.dll.as_bytes(), &[0]].concat(),
        )?;
        restore_thunks(
            mapped,
            pe,
            module,
            original_first_thunk,
            &lookup,
            &strings,
            &mut allocations,
        )?;
        descriptor_rva = descriptor_rva
            .checked_add(IMAGE_IMPORT_DESCRIPTOR_SIZE as u32)
            .context("POGO import descriptor RVA overflows")?;
    };
    ensure!(
        seen_modules.len() == discovery.modules.len(),
        "POGO import descriptors do not cover every loader-graph module"
    );

    let starts = allocations.keys().copied().collect::<Vec<_>>();
    for (index, start) in starts.iter().copied().enumerate() {
        let end = starts.get(index + 1).copied().unwrap_or(strings.end);
        ensure!(
            start >= strings.start && start < end && end <= strings.end,
            "POGO import string allocations overlap"
        );
        let value = allocations
            .get(&start)
            .expect("allocation start came from map");
        ensure!(
            value.len() <= usize::try_from(end - start)?,
            "loader string does not fit original .idata$6 allocation"
        );
        let slot = mapped
            .get_mut(usize::try_from(start)?..usize::try_from(end)?)
            .context("POGO import string allocation exceeds mapped image")?;
        slot.fill(0);
        slot[..value.len()].copy_from_slice(value);
    }

    let import_directory = DataDirectory {
        virtual_address: descriptors.start,
        size: import_end
            .checked_sub(descriptors.start)
            .context("POGO import directory underflows")?,
    };
    let iat_directory = DataDirectory {
        virtual_address: iat.start,
        size: iat.end - iat.start,
    };
    let mut budget = ScanBudget::default();
    let candidate = parse_import_candidate(mapped, pe, descriptors.start, &mut budget)?
        .context("restored POGO import topology is not a standard import graph")?;
    ensure!(
        candidate.graph == canonical_import_graph(discovery)?,
        "restored POGO import graph differs from loader graph"
    );
    ensure!(
        candidate.start == descriptors.start,
        "restored POGO import graph starts at an unexpected RVA"
    );
    Ok((import_directory, iat_directory))
}

fn restore_thunks(
    mapped: &mut [u8],
    pe: &Pe,
    module: &crate::unpack::imports::ImportModule,
    lookup_rva: u32,
    lookup_range: &Range<u32>,
    string_range: &Range<u32>,
    allocations: &mut BTreeMap<u32, Vec<u8>>,
) -> Result<()> {
    let width = pe.pointer_width().bytes();
    let width_rva = u32::try_from(width)?;
    let ordinal = match pe.pointer_width() {
        PointerWidth::U32 => 0x8000_0000,
        PointerWidth::U64 => 0x8000_0000_0000_0000,
    };
    for (index, symbol) in module.symbols.iter().enumerate() {
        let offset = u32::try_from(index)?
            .checked_mul(width_rva)
            .context("POGO thunk offset overflows")?;
        let source = lookup_rva
            .checked_add(offset)
            .context("POGO ILT RVA overflows")?;
        ensure!(
            range_contains_span(lookup_range, source, width_rva),
            "POGO ILT cell exceeds .idata$4"
        );
        let value = read_pointer(mapped, pe.pointer_width(), source)?;
        match symbol {
            ImportSymbol::Ordinal(expected) => {
                ensure!(
                    value == ordinal | u64::from(*expected),
                    "POGO ordinal thunk differs from loader graph"
                );
            }
            ImportSymbol::Name { hint, name } => {
                ensure!(
                    value & ordinal == 0,
                    "POGO named thunk carries ordinal flag"
                );
                let name_rva =
                    u32::try_from(value).context("POGO named thunk is not an untagged RVA")?;
                ensure!(
                    string_range.contains(&name_rva),
                    "POGO hint/name RVA is outside .idata$6"
                );
                let mut desired = Vec::with_capacity(2 + name.len() + 1);
                desired.extend_from_slice(&hint.to_le_bytes());
                desired.extend_from_slice(name.as_bytes());
                desired.push(0);
                insert_allocation(allocations, name_rva, desired)?;
            }
        }
        let destination = module
            .destination_rva
            .checked_add(offset)
            .context("POGO IAT RVA overflows")?;
        write_pointer(mapped, pe.pointer_width(), destination, value)?;
    }
    let terminator_offset = u32::try_from(module.symbols.len())?
        .checked_mul(width_rva)
        .context("POGO thunk terminator offset overflows")?;
    let source_terminator = lookup_rva
        .checked_add(terminator_offset)
        .context("POGO ILT terminator RVA overflows")?;
    ensure!(
        range_contains_span(lookup_range, source_terminator, width_rva),
        "POGO ILT terminator exceeds .idata$4"
    );
    ensure!(
        read_pointer(mapped, pe.pointer_width(), source_terminator)? == 0,
        "POGO ILT lacks a null terminator"
    );
    write_pointer(
        mapped,
        pe.pointer_width(),
        module
            .destination_rva
            .checked_add(terminator_offset)
            .context("POGO IAT terminator RVA overflows")?,
        0,
    )?;
    Ok(())
}

fn insert_allocation(
    allocations: &mut BTreeMap<u32, Vec<u8>>,
    rva: u32,
    value: Vec<u8>,
) -> Result<()> {
    if let Some(existing) = allocations.insert(rva, value.clone()) {
        ensure!(
            existing == value,
            "POGO import metadata allocation is aliased inconsistently"
        );
    }
    Ok(())
}

fn recover_load_config(mapped: &[u8], pe: &Pe, gctl: &GctlLayout) -> Result<Option<DataDirectory>> {
    let Some(contribution) = unique_contribution(gctl, ".rdata") else {
        return Ok(None);
    };
    let range = contribution.range.clone();
    let start = range.end.saturating_sub(0x400).max(range.start);
    let mut candidates = Vec::new();
    for rva in (pe::align_up(start, 8)?..range.end).step_by(8) {
        let Some(bytes) = rva_slice(mapped, pe, rva, 4) else {
            continue;
        };
        let size = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
        if !(0x70..=0x200).contains(&size) {
            continue;
        }
        let aligned_size = pe::align_up(size, 8)?;
        if rva.checked_add(aligned_size) != Some(range.end) {
            continue;
        }
        let directory = DataDirectory {
            virtual_address: rva,
            size,
        };
        if validate_load_config(mapped, pe, directory).is_ok() {
            candidates.push(directory);
        }
    }
    ensure!(
        candidates.len() <= 1,
        "multiple POGO Load Config candidates found"
    );
    Ok(candidates.pop())
}

fn validate_load_config(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    ensure!(
        pe.pointer_width() == PointerWidth::U64,
        "POGO Load Config recovery currently requires PE32+"
    );
    let bytes = rva_slice(
        mapped,
        pe,
        directory.virtual_address,
        usize::try_from(directory.size)?,
    )
    .context("POGO Load Config exceeds mapped image")?;
    ensure!(
        u32::from_le_bytes(bytes[..4].try_into().expect("four bytes")) == directory.size,
        "POGO Load Config Size field differs from directory size"
    );
    ensure!(
        directory.size >= 0x94,
        "POGO PE32+ Load Config is too short"
    );
    for offset in [40usize, 80, 88, 96, 112, 120, 128] {
        if offset + 8 > bytes.len() {
            continue;
        }
        let va = u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("eight bytes"));
        if va == 0 {
            continue;
        }
        let rva = pe
            .va_to_rva(va)
            .context("POGO Load Config pointer is outside image")?;
        pe.section_for_rva_range(rva, 1)
            .context("POGO Load Config pointer is not section-backed")?;
    }
    let guard_table = u64::from_le_bytes(bytes[128..136].try_into().expect("eight bytes"));
    let guard_count = u64::from_le_bytes(bytes[136..144].try_into().expect("eight bytes"));
    ensure!(
        (guard_table == 0) == (guard_count == 0),
        "POGO Load Config Guard CF table/count is partial"
    );
    if guard_count != 0 {
        let table_rva = pe.va_to_rva(guard_table)?;
        let count = usize::try_from(guard_count).context("Guard CF count does not fit usize")?;
        let length = count
            .checked_mul(4)
            .context("Guard CF table length overflows")?;
        pe.section_for_rva_range(table_rva, length)
            .context("Guard CF table is not section-backed")?;
        rva_slice(mapped, pe, table_rva, length).context("Guard CF table exceeds mapped image")?;
    }
    Ok(())
}

fn has_import_topology(gctl: &GctlLayout) -> bool {
    [".idata$2", ".idata$3", ".idata$4", ".idata$5", ".idata$6"]
        .into_iter()
        .all(|name| unique_contribution(gctl, name).is_some())
}

fn unique_contribution<'a>(gctl: &'a GctlLayout, name: &str) -> Option<&'a Contribution> {
    let mut matches = gctl
        .contributions
        .iter()
        .filter(|contribution| contribution.name == name);
    let selected = matches.next()?;
    matches.next().is_none().then_some(selected)
}

fn range_contains_span(range: &Range<u32>, start: u32, size: u32) -> bool {
    start >= range.start && start.checked_add(size).is_some_and(|end| end <= range.end)
}

fn contribution<'a>(gctl: &'a GctlLayout, name: &str) -> Result<&'a Contribution> {
    unique_contribution(gctl, name)
        .with_context(|| format!("GCTL lacks one unique required {name} contribution"))
}

fn covered_by_destinations(ranges: &[Range<u32>], target: Range<u32>) -> bool {
    if target.start >= target.end {
        return false;
    }
    let mut cursor = target.start;
    for range in ranges {
        if range.end <= cursor {
            continue;
        }
        if range.start > cursor {
            return false;
        }
        cursor = cursor.max(range.end);
        if cursor >= target.end {
            return true;
        }
    }
    false
}

fn read_pointer(mapped: &[u8], width: PointerWidth, rva: u32) -> Result<u64> {
    let start = usize::try_from(rva)?;
    match width {
        PointerWidth::U32 => Ok(u64::from(u32_at(mapped, start)?)),
        PointerWidth::U64 => {
            let bytes = mapped
                .get(start..start + 8)
                .context("POGO pointer cell exceeds mapped image")?;
            Ok(u64::from_le_bytes(bytes.try_into().expect("eight bytes")))
        }
    }
}

fn write_pointer(mapped: &mut [u8], width: PointerWidth, rva: u32, value: u64) -> Result<()> {
    let start = usize::try_from(rva)?;
    match width {
        PointerWidth::U32 => {
            let value = u32::try_from(value).context("POGO PE32 pointer exceeds u32")?;
            mapped
                .get_mut(start..start + 4)
                .context("POGO pointer cell exceeds mapped image")?
                .copy_from_slice(&value.to_le_bytes());
        }
        PointerWidth::U64 => mapped
            .get_mut(start..start + 8)
            .context("POGO pointer cell exceeds mapped image")?
            .copy_from_slice(&value.to_le_bytes()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::Machine;

    fn test_pe() -> Pe {
        Pe {
            opt: 0,
            machine: Machine::Amd64,
            coff_characteristics: 0x2022,
            section_count: 1,
            entry_rva: 0x1000,
            image_base: 0x0001_8000_0000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: 0x8000,
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
            sections: vec![Section {
                index: 0,
                header_offset: 0x200,
                name_bytes: *b".all\0\0\0\0",
                virtual_size: 0x7000,
                virtual_address: 0x1000,
                raw_size: 0,
                raw_pointer: 0,
                characteristics: 0x6000_0020,
            }],
            file_len: 0,
        }
    }

    fn append_contribution(payload: &mut Vec<u8>, rva: u32, size: u32, name: &str) {
        payload.extend_from_slice(&rva.to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        while !payload.len().is_multiple_of(4) {
            payload.push(0);
        }
    }

    #[test]
    fn parses_and_groups_msvc_gctl_contributions() {
        let pe = test_pe();
        let mut payload = GCTL_SIGNATURE.to_vec();
        append_contribution(&mut payload, 0x1000, 0x1000, ".text$mn");
        append_contribution(&mut payload, 0x2000, 0x100, ".idata$5");
        append_contribution(&mut payload, 0x2100, 0xf00, ".rdata");
        append_contribution(&mut payload, 0x3000, 0x800, ".data");
        append_contribution(&mut payload, 0x4000, 0x400, ".pdata");
        append_contribution(&mut payload, 0x5000, 0x100, "_RDATA");
        append_contribution(&mut payload, 0x6000, 0x200, ".rsrc$01");

        let gctl = parse_gctl_payload(&payload, &pe).unwrap();
        let grouped = group_contributions(&gctl).unwrap().unwrap();

        assert_eq!(grouped[&SectionKind::Text], 0x1000..0x2000);
        assert_eq!(grouped[&SectionKind::Rdata], 0x2000..0x3000);
        assert_eq!(grouped[&SectionKind::CustomRdata], 0x5000..0x5100);
        assert_eq!(grouped[&SectionKind::Resource], 0x6000..0x6200);
    }

    #[test]
    fn gctl_rejects_overlapping_ranges_and_nonzero_padding() {
        let pe = test_pe();
        let mut overlapping = GCTL_SIGNATURE.to_vec();
        append_contribution(&mut overlapping, 0x1000, 0x1000, ".text");
        append_contribution(&mut overlapping, 0x1800, 0x100, ".rdata");
        assert!(parse_gctl_payload(&overlapping, &pe).is_err());

        let mut padded = GCTL_SIGNATURE.to_vec();
        append_contribution(&mut padded, 0x1000, 0x1000, ".text");
        *padded.last_mut().unwrap() = 1;
        assert!(parse_gctl_payload(&padded, &pe).is_err());
    }

    #[test]
    fn groups_layout_without_optional_export_exception_or_resources() {
        let pe = test_pe();
        let mut payload = GCTL_SIGNATURE.to_vec();
        append_contribution(&mut payload, 0x1000, 0x1000, ".text");
        append_contribution(&mut payload, 0x2000, 0x1000, ".rdata");
        append_contribution(&mut payload, 0x3000, 0x800, ".data");

        let gctl = parse_gctl_payload(&payload, &pe).unwrap();
        let grouped = group_contributions(&gctl).unwrap().unwrap();

        assert!(!grouped.contains_key(&SectionKind::Pdata));
        assert!(!grouped.contains_key(&SectionKind::Resource));
    }

    #[test]
    fn import_profile_requires_unique_standard_contributions() {
        let mut contributions = Vec::new();
        for (index, name) in [".idata$2", ".idata$3", ".idata$4", ".idata$5", ".idata$6"]
            .into_iter()
            .enumerate()
        {
            let start = 0x2000 + u32::try_from(index).unwrap() * 0x100;
            contributions.push(Contribution {
                name: name.to_owned(),
                range: start..start + 0x100,
            });
        }
        let mut gctl = GctlLayout { contributions };
        assert!(has_import_topology(&gctl));

        gctl.contributions.push(Contribution {
            name: ".idata$6".to_owned(),
            range: 0x3000..0x3100,
        });
        assert!(!has_import_topology(&gctl));
    }

    #[test]
    fn range_span_check_rejects_partial_cells_and_overflow() {
        let range = 0x1000..0x1100;
        assert!(range_contains_span(&range, 0x1000, 0x100));
        assert!(!range_contains_span(&range, 0x10ff, 2));
        assert!(!range_contains_span(&range, u32::MAX, 2));
    }

    #[test]
    fn provenance_coverage_requires_a_gapless_union() {
        let ranges = [0x1000..0x1100, 0x1100..0x1200, 0x1300..0x1400];
        assert!(covered_by_destinations(&ranges, 0x1080..0x1180));
        assert!(!covered_by_destinations(&ranges, 0x1180..0x1380));
    }
}
