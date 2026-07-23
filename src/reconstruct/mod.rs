use std::collections::BTreeSet;
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pe::{self, DataDirectory, Pe, PointerWidth};
use crate::unpack::imports::{ImportModule, ImportSymbol, LoaderDiscovery, named_thunk_rva};
use crate::unpack::profile::OutputEntry;
pub(crate) mod managed;

const EXPORT_DIRECTORY: usize = 0;
const IMPORT_DIRECTORY: usize = 1;
const EXCEPTION_DIRECTORY: usize = 3;
const SECURITY_DIRECTORY: usize = 4;
const BASE_RELOCATION_DIRECTORY: usize = 5;
const IMAGE_IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMAGE_EXPORT_DIRECTORY_SIZE: usize = 40;
const IAT_DIRECTORY: usize = 12;
mod clr;
mod pogo;
const DELAY_IMPORT_DIRECTORY: usize = 13;
#[cfg(test)]
mod tests;
const MAX_IMPORT_MODULES: usize = 4_096;
const MAX_IMPORT_THUNKS: usize = 1_000_000;
const MAX_IMPORT_STRING: usize = 4_096;
const MAX_EXPORT_ENTRIES: usize = 1_000_000;
const MAX_EXPORT_STRING: usize = 4_096;
const IMPORT_SECTION_CHARACTERISTICS: u32 = 0x4000_0040;
const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const BASE_RELOCATION_BLOCK_HEADER_SIZE: usize = 8;
const DELAY_IMPORT_DESCRIPTOR_SIZE: usize = 32;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MAX_SCAN_STARTS: usize = 1 << 27;
const MAX_SCAN_CANDIDATES: usize = 4_096;
const MAX_SCAN_NESTED_WORK: usize = 16_000_000;

/// The immutable handoff from packer-specific recovery to PE serialization.
/// Authenticated A-record destinations and POGO contributions take precedence;
/// header values and structural scans are bounded fallback evidence.
pub(crate) struct ReconstructionInput {
    pub(crate) mapped: Vec<u8>,
    pub(crate) decrypted_pe: Pe,
    pub(crate) output_entry: OutputEntry,
    pub(crate) discovery: LoaderDiscovery,
    pub(crate) destination_ranges: Vec<Range<u32>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportGraph {
    modules: Vec<ImportModule>,
    functions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImportCandidate {
    start: u32,
    end: u32,
    graph: ImportGraph,
    metadata_ranges: Vec<Range<u32>>,
}

#[derive(Clone, Debug)]
struct RawSectionLayout {
    virtual_range: Range<u32>,
    raw_pointer: u32,
    raw_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportCandidate {
    rva: u32,
    size: u32,
    functions: u32,
    names: u32,
    dll: String,
}

#[derive(Clone, Debug)]
struct ImportEmission {
    bytes: Vec<u8>,
    directory_size: u32,
}

#[derive(Default)]
struct ScanBudget {
    nested_work: usize,
}
impl ScanBudget {
    fn consume(&mut self, work: usize) -> Result<()> {
        self.nested_work = self
            .nested_work
            .checked_add(work)
            .context("scan nested-work counter overflows")?;
        ensure!(
            self.nested_work <= MAX_SCAN_NESTED_WORK,
            "scan nested-work budget exceeded"
        );
        Ok(())
    }
}

/// Rebuilds a disk PE from the recovered mapped image.
///
/// Authenticated GCTL contributions recover original section and directory
/// placement first, including in-place standard imports. When that linker
/// metadata is absent or uses an unsupported contribution family, bounded
/// structural recovery emits the loader graph into a normalized import section.
pub(crate) fn rebuild(input: ReconstructionInput) -> Result<Vec<u8>> {
    let ReconstructionInput {
        mut mapped,
        decrypted_pe,
        output_entry,
        discovery,
        destination_ranges,
    } = input;
    ensure!(
        mapped.len() == usize::try_from(decrypted_pe.size_of_image)?,
        "mapped-image length differs from SizeOfImage"
    );
    ensure!(
        decrypted_pe.directories.len() > IAT_DIRECTORY,
        "PE has no IAT Directory slot for regenerated imports"
    );
    validate_entry_evidence(&mapped, &decrypted_pe, output_entry)?;
    validate_loader_graph(&decrypted_pe, &discovery)?;
    if let Some(recovery) = pogo::recover(&mapped, &decrypted_pe, &discovery, &destination_ranges)
        .context("recovering native layout from authenticated POGO metadata")?
    {
        return rebuild_pogo(recovery, output_entry, &discovery);
    }
    let iat_directory = iat_directory(&decrypted_pe, &discovery)?;

    // A standard bootstrap import table may be present in the provisional image.
    // Only a unique parser-proven winner is stale scaffolding. Competing graphs
    // fail closed in selection; descriptor suffixes coalesce to the winner.
    clear_selected_import_candidate(&mut mapped, &decrypted_pe)?;
    let retained_directories = recover_directories(&mapped, &decrypted_pe)?;

    let export = scan_export(&mapped, &decrypted_pe)?;
    let import_rva = pe::align_up(decrypted_pe.size_of_image, decrypted_pe.section_alignment)?;
    let emission = emit_imports(&decrypted_pe, &discovery, import_rva)?;
    let import_end = import_rva
        .checked_add(u32::try_from(emission.bytes.len())?)
        .context("import section RVA overflows")?;
    let import_virtual_size = pe::align_up(
        import_end
            .checked_sub(import_rva)
            .context("import section underflows")?,
        decrypted_pe.section_alignment,
    )?;
    let final_image_size = import_rva
        .checked_add(import_virtual_size)
        .context("final SizeOfImage overflows")?;

    initialize_iat_cells(
        &mut mapped,
        &decrypted_pe,
        &discovery,
        import_rva,
        &emission.bytes,
    )?;
    let mut output = serialize_sections(
        &mapped,
        &decrypted_pe,
        import_rva,
        import_virtual_size,
        &emission.bytes,
        output_entry.entry_rva(),
        export.as_ref(),
        emission.directory_size,
        final_image_size,
        &retained_directories,
        iat_directory,
    )?;

    let parsed = Pe::parse(&output).context("parsing reconstructed PE")?;
    pe::write_u32(&mut output, parsed.checksum_offset, 0)?;
    let checksum = pe::pe_checksum(&output, parsed.checksum_offset)?;
    pe::write_u32(&mut output, parsed.checksum_offset, checksum)?;

    let final_pe = Pe::parse(&output).context("reparsing checksummed PE")?;
    let final_mapped = final_pe
        .map_image(&output)
        .context("mapping reconstructed PE")?;
    verify_trimmed_section_mapping(&mapped, &final_mapped, &decrypted_pe, &retained_directories)?;
    ensure!(
        final_mapped.get(usize::try_from(output_entry.entry_rva())?)
            == mapped.get(usize::try_from(output_entry.entry_rva())?),
        "serialized entry byte differs from recovered mapped image"
    );
    let final_import = select_import_candidate(scan_import_candidates(&final_mapped, &final_pe)?)?
        .context("reconstructed image has no standard import graph")?;
    ensure!(
        final_import.graph == canonical_import_graph(&discovery)?,
        "reconstructed standard import graph differs from recovered loader graph"
    );
    ensure!(
        final_import.start == import_rva,
        "import scanner selected an unexpected graph"
    );
    ensure!(
        final_pe.directory(IAT_DIRECTORY)? == iat_directory,
        "serialized IAT directory differs from canonical envelope"
    );
    let aggregates = section_aggregate_sizes(final_pe.sections.iter().map(|section| {
        Ok((
            section.raw_size,
            section.virtual_size,
            section.characteristics,
        ))
    }))?;
    ensure!(
        u32_at(&output, final_pe.size_of_code_offset())? == aggregates.0,
        "serialized SizeOfCode differs from final section headers"
    );
    ensure!(
        u32_at(&output, final_pe.size_of_initialized_data_offset())? == aggregates.1,
        "serialized SizeOfInitializedData differs from final section headers"
    );
    ensure!(
        u32_at(&output, final_pe.size_of_uninitialized_data_offset())? == aggregates.2,
        "serialized SizeOfUninitializedData differs from final section headers"
    );
    for module in &discovery.modules {
        let span = iat_module_span(&final_pe, module)?;
        let envelope = iat_directory
            .checked_rva_range()?
            .expect("nonempty canonical IAT envelope");
        ensure!(
            span.start >= envelope.start && span.end <= envelope.end,
            "serialized IAT directory excludes a FirstThunk span"
        );
    }
    match (export, scan_export(&final_mapped, &final_pe)?) {
        (None, None) => {}
        (Some(expected), Some(actual)) => {
            ensure!(expected == actual, "export graph changed while serializing")
        }
        _ => bail!("export graph changed while serializing"),
    }
    for (index, directory) in &retained_directories {
        ensure!(
            final_pe.directory(*index)? == *directory,
            "retained directory header changed while serializing"
        );
        let start = usize::try_from(directory.virtual_address)?;
        let end = start
            .checked_add(usize::try_from(directory.size)?)
            .context("retained directory range overflows")?;
        if *index != 6 {
            ensure!(
                final_mapped.get(start..end) == mapped.get(start..end),
                "retained directory bytes changed while serializing"
            );
        }
    }
    Ok(output)
}

fn rebuild_pogo(
    recovery: pogo::PogoRecovery,
    output_entry: OutputEntry,
    discovery: &LoaderDiscovery,
) -> Result<Vec<u8>> {
    let pogo::PogoRecovery {
        mapped,
        pe,
        directories,
    } = recovery;
    validate_entry_evidence(&mapped, &pe, output_entry)?;
    let import_directory = directories
        .iter()
        .find(|(index, _)| *index == IMPORT_DIRECTORY)
        .map(|(_, directory)| *directory)
        .context("POGO recovery omitted Import Directory")?;
    let iat_directory = directories
        .iter()
        .find(|(index, _)| *index == IAT_DIRECTORY)
        .map(|(_, directory)| *directory)
        .context("POGO recovery omitted IAT Directory")?;

    let mut output =
        serialize_recovered_sections(&mapped, &pe, output_entry.entry_rva(), &directories)?;
    let parsed = Pe::parse(&output).context("parsing POGO-reconstructed PE")?;
    pe::write_u32(&mut output, parsed.checksum_offset, 0)?;
    let checksum = pe::pe_checksum(&output, parsed.checksum_offset)?;
    pe::write_u32(&mut output, parsed.checksum_offset, checksum)?;

    let final_pe = Pe::parse(&output).context("reparsing checksummed POGO PE")?;
    let final_mapped = final_pe
        .map_image(&output)
        .context("mapping POGO-reconstructed PE")?;
    verify_trimmed_section_mapping(&mapped, &final_mapped, &pe, &directories)?;
    ensure!(
        final_pe.section_count == pe.section_count
            && final_pe.file_alignment == pe.file_alignment
            && final_pe.size_of_image == pe.size_of_image,
        "serialized POGO geometry differs from authenticated layout"
    );
    ensure!(
        final_pe
            .sections
            .iter()
            .zip(&pe.sections)
            .all(
                |(actual, expected)| actual.name_bytes == expected.name_bytes
                    && actual.virtual_address == expected.virtual_address
                    && actual.virtual_size == expected.virtual_size
                    && actual.characteristics == expected.characteristics
            ),
        "serialized POGO section layout differs from authenticated contributions"
    );
    let final_import = select_import_candidate(scan_import_candidates(&final_mapped, &final_pe)?)?
        .context("POGO-reconstructed image has no standard import graph")?;
    ensure!(
        final_import.graph == canonical_import_graph(discovery)?,
        "POGO-reconstructed import graph differs from loader graph"
    );
    ensure!(
        final_import.start == import_directory.virtual_address,
        "POGO-reconstructed import graph starts at an unexpected RVA"
    );
    ensure!(
        final_pe.directory(IAT_DIRECTORY)? == iat_directory,
        "POGO-reconstructed IAT Directory differs from authenticated contribution"
    );
    for (index, directory) in &directories {
        ensure!(
            final_pe.directory(*index)? == *directory,
            "POGO-reconstructed directory {index} differs from authenticated metadata"
        );
    }
    let aggregates = pogo_section_aggregate_sizes(
        final_pe.sections.iter().map(|section| {
            Ok((
                section.raw_size,
                section.virtual_size,
                section.characteristics,
            ))
        }),
        final_pe.file_alignment,
    )?;
    ensure!(
        u32_at(&output, final_pe.size_of_code_offset())? == aggregates.0
            && u32_at(&output, final_pe.size_of_initialized_data_offset())? == aggregates.1
            && u32_at(&output, final_pe.size_of_uninitialized_data_offset())? == aggregates.2,
        "POGO-reconstructed aggregate section sizes are inconsistent"
    );
    Ok(output)
}

fn verify_trimmed_section_mapping(
    expected: &[u8],
    actual: &[u8],
    pe: &Pe,
    retained_directories: &[(usize, DataDirectory)],
) -> Result<()> {
    let debug_pointers = retained_directories
        .iter()
        .find(|(index, _)| *index == 6)
        .map(|(_, directory)| {
            (0..usize::try_from(directory.size / 28)?)
                .map(|index| {
                    let start = directory
                        .virtual_address
                        .checked_add(u32::try_from(
                            index
                                .checked_mul(28)
                                .context("debug pointer offset overflows")?,
                        )?)
                        .context("debug pointer RVA overflows")?
                        .checked_add(24)
                        .context("debug pointer RVA overflows")?;
                    Ok(start
                        ..start
                            .checked_add(4)
                            .context("debug pointer range overflows")?)
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    ensure!(
        expected.len() >= usize::try_from(pe.size_of_image)?
            && actual.len() >= usize::try_from(pe.size_of_image)?,
        "mapped image is shorter than SizeOfImage"
    );
    for rva in pe.size_of_headers..pe.size_of_image {
        if !debug_pointers.iter().any(|pointer| pointer.contains(&rva)) {
            ensure!(
                expected.get(usize::try_from(rva)?) == actual.get(usize::try_from(rva)?),
                "trimmed mapped image differs at RVA {rva:#x}"
            );
        }
    }
    Ok(())
}

fn validate_entry_evidence(mapped: &[u8], pe: &Pe, entry: OutputEntry) -> Result<()> {
    for range in entry.protected_ranges(pe)? {
        let start = usize::try_from(range.start)?;
        let end = usize::try_from(range.end)?;
        ensure!(
            mapped.get(start..end).is_some(),
            "semantic-entry provenance exceeds mapped image"
        );
    }
    if let Some(semantic) = entry.semantic() {
        for rva in semantic.executable_rvas() {
            let section = pe.section_for_rva_range(rva, 1)?;
            ensure!(
                section.characteristics & 0x2000_0000 != 0,
                "semantic executable evidence is not in an executable section"
            );
        }
    }
    Ok(())
}

fn validate_loader_graph(pe: &Pe, discovery: &LoaderDiscovery) -> Result<()> {
    ensure!(
        discovery.image_size == pe.size_of_image,
        "loader graph image size differs from mapped PE"
    );
    ensure!(!discovery.modules.is_empty(), "loader graph has no modules");
    ensure!(
        discovery.modules.len() <= MAX_IMPORT_MODULES,
        "loader graph has too many modules"
    );
    let graph = canonical_import_graph(discovery)?;
    ensure!(
        graph.functions == discovery.function_count,
        "loader graph function count is inconsistent"
    );
    let mut ranges = Vec::with_capacity(graph.modules.len());
    for module in &graph.modules {
        let span = iat_module_span(pe, module)?;
        let alignment = u32::try_from(pe.pointer_width().bytes())?;
        ensure!(
            module.destination_rva.is_multiple_of(alignment),
            "IAT is not pointer-width aligned"
        );
        ensure!(span.end <= pe.size_of_image, "IAT exceeds mapped image");
        pe.section_for_rva_range(span.start, usize::try_from(span.end - span.start)?)
            .context("IAT is not section-backed")?;
        ranges.push(span);
    }
    ranges.sort_by_key(|range| range.start);
    ensure!(
        ranges.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "loader IAT ranges overlap"
    );
    Ok(())
}

fn iat_module_span(pe: &Pe, module: &ImportModule) -> Result<Range<u32>> {
    let width = u32::try_from(pe.pointer_width().bytes())?;
    let cells = u32::try_from(module.symbols.len())?
        .checked_add(1)
        .context("IAT cell count overflows")?;
    let end = module
        .destination_rva
        .checked_add(
            cells
                .checked_mul(width)
                .context("IAT span size overflows")?,
        )
        .context("IAT span end overflows")?;
    Ok(module.destination_rva..end)
}

fn iat_directory(pe: &Pe, discovery: &LoaderDiscovery) -> Result<DataDirectory> {
    let mut spans = discovery
        .modules
        .iter()
        .map(|module| iat_module_span(pe, module))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        !spans.is_empty(),
        "cannot derive IAT directory from an empty loader graph"
    );
    spans.sort_by_key(|span| span.start);
    let start = spans.first().expect("nonempty spans").start;
    let end = spans.last().expect("nonempty spans").end;
    let owner = pe.section_for_rva_range(start, usize::try_from(end - start)?)?;
    for span in &spans {
        ensure!(
            pe.section_for_rva_range(span.start, usize::try_from(span.end - span.start)?)?
                .index
                == owner.index,
            "IAT envelope crosses owner sections"
        );
    }
    Ok(DataDirectory {
        virtual_address: start,
        size: end.checked_sub(start).context("IAT envelope underflows")?,
    })
}

fn canonical_import_graph(discovery: &LoaderDiscovery) -> Result<ImportGraph> {
    let mut functions = 0usize;
    for module in &discovery.modules {
        ensure!(
            !module.dll.is_empty()
                && module.dll.len() <= MAX_IMPORT_STRING
                && module.dll.bytes().all(printable),
            "invalid DLL name"
        );
        ensure!(
            !module.symbols.is_empty(),
            "module {} has no imports",
            module.dll
        );
        functions = functions
            .checked_add(module.symbols.len())
            .context("import function count overflows")?;
        ensure!(functions <= MAX_IMPORT_THUNKS, "too many imports");
        for symbol in &module.symbols {
            if let ImportSymbol::Name { name, .. } = symbol {
                ensure!(
                    !name.is_empty()
                        && name.len() <= MAX_IMPORT_STRING
                        && name.bytes().all(printable),
                    "invalid API name"
                );
            }
        }
    }
    Ok(ImportGraph {
        modules: discovery.modules.clone(),
        functions,
    })
}

fn initialize_iat_cells(
    mapped: &mut [u8],
    pe: &Pe,
    discovery: &LoaderDiscovery,
    import_rva: u32,
    imports: &[u8],
) -> Result<()> {
    let width = pe.pointer_width().bytes();
    for (index, module) in discovery.modules.iter().enumerate() {
        let descriptor = index
            .checked_mul(IMAGE_IMPORT_DESCRIPTOR_SIZE)
            .context("import descriptor offset overflows")?;
        let lookup_rva = u32_at(imports, descriptor)?;
        ensure!(
            u32_at(imports, descriptor + 16)? == module.destination_rva,
            "emitted import descriptor FirstThunk differs from loader graph"
        );
        let lookup_offset = lookup_rva
            .checked_sub(import_rva)
            .context("emitted import lookup table precedes import section")?;
        let bytes = (module.symbols.len() + 1)
            .checked_mul(width)
            .context("IAT initialization length overflows")?;
        let lookup = imports
            .get(usize::try_from(lookup_offset)?..)
            .and_then(|source| source.get(..bytes))
            .context("emitted import lookup table exceeds import section")?;
        ensure!(
            lookup[lookup.len() - width..].iter().all(|byte| *byte == 0),
            "emitted import lookup table lacks a null terminator"
        );
        let start = usize::try_from(module.destination_rva)?;
        let destination = mapped
            .get_mut(start..start.checked_add(bytes).context("IAT end overflows")?)
            .context("IAT initialization range exceeds mapped image")?;
        destination.copy_from_slice(lookup);
    }
    Ok(())
}
fn clear_candidate(mapped: &mut [u8], pe: &Pe, candidate: &ImportCandidate) -> Result<()> {
    let mut ranges = candidate.metadata_ranges.clone();
    let width = pe.pointer_width().bytes();
    for module in &candidate.graph.modules {
        let len = (module.symbols.len() + 1)
            .checked_mul(width)
            .context("stale IAT length overflows")?;
        let end = module
            .destination_rva
            .checked_add(u32::try_from(len)?)
            .context("stale IAT range overflows")?;
        ranges.push(module.destination_rva..end);
    }
    ranges.sort_by_key(|range| range.start);
    let mut merged: Vec<Range<u32>> = Vec::new();
    for range in ranges {
        ensure!(
            range.start < range.end,
            "parser supplied an empty import metadata range"
        );
        pe.section_for_rva_range(range.start, usize::try_from(range.end - range.start)?)
            .context("parser-proven import metadata is not section-backed")?;
        if let Some(last) = merged.last_mut().filter(|last| range.start <= last.end) {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    for range in merged {
        mapped
            .get_mut(usize::try_from(range.start)?..usize::try_from(range.end)?)
            .context("parser-proven import metadata exceeds mapped image")?
            .fill(0);
    }
    Ok(())
}

fn clear_selected_import_candidate(mapped: &mut [u8], pe: &Pe) -> Result<()> {
    if let Some(candidate) = select_import_candidate(scan_import_candidates(mapped, pe)?)? {
        clear_candidate(mapped, pe, &candidate)?;
    }
    Ok(())
}

fn emit_imports(pe: &Pe, discovery: &LoaderDiscovery, base_rva: u32) -> Result<ImportEmission> {
    let graph = canonical_import_graph(discovery)?;
    let width = pe.pointer_width().bytes();
    let descriptor_bytes = (graph.modules.len() + 1)
        .checked_mul(IMAGE_IMPORT_DESCRIPTOR_SIZE)
        .context("descriptor table size overflows")?;
    let mut cursor = descriptor_bytes;
    let mut ilt_offsets = Vec::with_capacity(graph.modules.len());
    for module in &graph.modules {
        cursor = align(cursor, width)?;
        ilt_offsets.push(cursor);
        cursor = cursor
            .checked_add((module.symbols.len() + 1) * width)
            .context("ILT layout overflows")?;
    }
    let mut dll_offsets = Vec::with_capacity(graph.modules.len());
    for module in &graph.modules {
        dll_offsets.push(cursor);
        cursor = cursor
            .checked_add(module.dll.len() + 1)
            .context("DLL layout overflows")?;
    }
    let mut name_offsets = Vec::new();
    for module in &graph.modules {
        for symbol in &module.symbols {
            if let ImportSymbol::Name { name, .. } = symbol {
                cursor = align(cursor, 2)?;
                name_offsets.push(cursor);
                cursor = cursor
                    .checked_add(2 + name.len() + 1)
                    .context("name layout overflows")?;
            }
        }
    }
    ensure!(
        cursor <= 16 * 1024 * 1024,
        "normalized imports exceed 16 MiB"
    );
    let mut bytes = vec![0; cursor];
    let mut next_name = 0;
    for (index, module) in graph.modules.iter().enumerate() {
        let descriptor = index * IMAGE_IMPORT_DESCRIPTOR_SIZE;
        put_u32(
            &mut bytes,
            descriptor,
            placed_rva(base_rva, ilt_offsets[index])?,
        )?;
        put_u32(
            &mut bytes,
            descriptor + 12,
            placed_rva(base_rva, dll_offsets[index])?,
        )?;
        put_u32(&mut bytes, descriptor + 16, module.destination_rva)?;
        bytes[dll_offsets[index]..dll_offsets[index] + module.dll.len()]
            .copy_from_slice(module.dll.as_bytes());
        for (symbol_index, symbol) in module.symbols.iter().enumerate() {
            let value = match symbol {
                ImportSymbol::Ordinal(ordinal) => {
                    ordinal_flag(pe.pointer_width()) | u64::from(*ordinal)
                }

                ImportSymbol::Name { hint, name } => {
                    let offset = name_offsets[next_name];
                    next_name += 1;
                    bytes[offset..offset + 2].copy_from_slice(&hint.to_le_bytes());
                    bytes[offset + 2..offset + 2 + name.len()].copy_from_slice(name.as_bytes());
                    placed_rva(base_rva, offset)? as u64
                }
            };
            put_pointer(
                pe,
                &mut bytes,
                ilt_offsets[index] + symbol_index * width,
                value,
            )?;
        }
    }
    Ok(ImportEmission {
        bytes,
        directory_size: u32::try_from(descriptor_bytes)?,
    })
}
fn compact_raw_layout(
    mapped: &[u8],
    pe: &Pe,
    retained_directories: &[(usize, DataDirectory)],
) -> Result<Vec<RawSectionLayout>> {
    let mut required = vec![0u32; pe.sections.len()];
    for &(index, directory) in retained_directories {
        let range = directory
            .checked_rva_range()?
            .expect("retained directory is nonempty");
        require_raw_rva_range(pe, &mut required, range)?;
        if index == 6 {
            for record_index in 0..usize::try_from(directory.size / 28)? {
                let record_rva = directory
                    .virtual_address
                    .checked_add(u32::try_from(
                        record_index
                            .checked_mul(28)
                            .context("debug record offset overflows")?,
                    )?)
                    .context("debug record RVA overflows")?;
                let record = rva_slice(mapped, pe, record_rva, 28)
                    .context("debug record exceeds mapped image")?;
                let size = u32::from_le_bytes(record[16..20].try_into().expect("four bytes"));
                let address = u32::from_le_bytes(record[20..24].try_into().expect("four bytes"));
                if size != 0 || address != 0 {
                    ensure!(
                        size != 0 && address != 0,
                        "debug record has partial payload range"
                    );
                    require_raw_rva_range(
                        pe,
                        &mut required,
                        address
                            ..address
                                .checked_add(size)
                                .context("debug payload range overflows")?,
                    )?;
                }
            }
        }
    }
    let mut raw_cursor = pe::align_up(pe.size_of_headers, pe.file_alignment)?;
    let mut layout = Vec::with_capacity(pe.sections.len());
    for section in &pe.sections {
        let range = section.virtual_range()?;
        let payload = mapped
            .get(usize::try_from(range.start)?..usize::try_from(range.end)?)
            .context("section range exceeds mapped image")?;
        let nonzero = payload
            .iter()
            .rposition(|byte| *byte != 0)
            .map(|index| u32::try_from(index + 1))
            .transpose()?;
        let required_prefix = required[section.index].max(nonzero.unwrap_or(0));
        ensure!(
            required_prefix <= u32::try_from(payload.len())?,
            "required raw extent exceeds section mapping"
        );
        let raw_size = if required_prefix == 0 {
            0
        } else {
            pe::align_up(required_prefix, pe.file_alignment)?
        };
        layout.push(RawSectionLayout {
            virtual_range: range,
            raw_pointer: raw_cursor,
            raw_size,
        });
        raw_cursor = raw_cursor
            .checked_add(raw_size)
            .context("raw section cursor overflows")?;
    }
    Ok(layout)
}

fn require_raw_rva_range(pe: &Pe, required: &mut [u32], range: Range<u32>) -> Result<()> {
    ensure!(range.start < range.end, "required raw range is empty");
    let section =
        pe.section_for_rva_range(range.start, usize::try_from(range.end - range.start)?)?;
    let end = range.end - section.virtual_address;
    let prefix = required
        .get_mut(section.index)
        .context("section index exceeds raw-layout state")?;
    *prefix = (*prefix).max(end);
    Ok(())
}

fn serialize_recovered_sections(
    mapped: &[u8],
    pe: &Pe,
    entry_rva: u32,
    directories: &[(usize, DataDirectory)],
) -> Result<Vec<u8>> {
    let section_table_end = pe
        .sections
        .last()
        .context("recovered PE has no sections")?
        .header_offset
        .checked_add(SECTION_HEADER_SIZE)
        .context("recovered section table end overflows")?;
    ensure!(
        section_table_end <= usize::try_from(pe.size_of_headers)?,
        "recovered section table exceeds SizeOfHeaders"
    );
    let mut output = vec![0; usize::try_from(pe.size_of_headers)?];
    let header_len = output.len();
    output.copy_from_slice(
        mapped
            .get(..header_len)
            .context("mapped image lacks recovered headers")?,
    );
    pe::write_u32(&mut output, pe.coff_symbol_table_offset(), 0)?;
    output
        .get_mut(0x28..0x3c)
        .context("DOS reserved fields exceed recovered headers")?
        .fill(0);
    pe::write_u32(&mut output, pe.coff_symbol_table_offset() + 4, 0)?;
    pe::write_u32(&mut output, pe.win32_version_value_offset(), 0)?;
    pe::write_u32(&mut output, pe.loader_flags_offset(), 0)?;
    output
        .get_mut(section_table_end..)
        .context("recovered section table exceeds header buffer")?
        .fill(0);
    output[pe.opt - 18..pe.opt - 16]
        .copy_from_slice(&u16::try_from(pe.section_count)?.to_le_bytes());
    pe::write_u32(&mut output, pe.entry_rva_offset(), entry_rva)?;
    pe::write_u32(&mut output, pe.opt + 32, pe.section_alignment)?;
    pe::write_u32(&mut output, pe.opt + 36, pe.file_alignment)?;
    pe::write_u32(&mut output, pe.size_of_image_offset(), pe.size_of_image)?;
    pe::write_u32(&mut output, pe.opt + 60, pe.size_of_headers)?;
    for index in 0..pe.directories.len() {
        write_directory(
            &mut output,
            pe,
            index,
            DataDirectory {
                virtual_address: 0,
                size: 0,
            },
        )?;
    }
    for &(index, directory) in directories {
        write_directory(&mut output, pe, index, directory)?;
    }

    let raw_layout = compact_raw_layout(mapped, pe, directories)?;
    for (section, layout) in pe.sections.iter().zip(&raw_layout) {
        let payload = mapped
            .get(
                usize::try_from(layout.virtual_range.start)?
                    ..usize::try_from(layout.virtual_range.end)?,
            )
            .context("recovered section range exceeds mapped image")?;
        write_section_header(
            &mut output,
            section.header_offset,
            &section.name_bytes,
            section.virtual_size,
            section.virtual_address,
            layout.raw_size,
            if layout.raw_size == 0 {
                0
            } else {
                layout.raw_pointer
            },
            section.characteristics,
        )?;
        append_payload(
            &mut output,
            layout.raw_pointer,
            layout.raw_size,
            &payload[..payload.len().min(usize::try_from(layout.raw_size)?)],
        )?;
    }
    let aggregates = pogo_section_aggregate_sizes(
        pe.sections
            .iter()
            .zip(&raw_layout)
            .map(|(section, layout)| {
                Ok((
                    layout.raw_size,
                    section.virtual_size,
                    section.characteristics,
                ))
            }),
        pe.file_alignment,
    )?;
    pe::write_u32(&mut output, pe.size_of_code_offset(), aggregates.0)?;
    pe::write_u32(
        &mut output,
        pe.size_of_initialized_data_offset(),
        aggregates.1,
    )?;
    pe::write_u32(
        &mut output,
        pe.size_of_uninitialized_data_offset(),
        aggregates.2,
    )?;
    if let Some((_, debug)) = directories.iter().find(|(index, _)| *index == 6) {
        rewrite_debug_raw_pointers(&mut output, &raw_layout, *debug)?;
    }
    Ok(output)
}

fn serialize_sections(
    mapped: &[u8],
    pe: &Pe,
    import_rva: u32,
    import_virtual_size: u32,
    import: &[u8],
    entry_rva: u32,
    export: Option<&ExportCandidate>,
    import_directory_size: u32,
    final_image_size: u32,
    retained_directories: &[(usize, DataDirectory)],
    iat_directory: DataDirectory,
) -> Result<Vec<u8>> {
    let section_table_end = pe
        .sections
        .last()
        .context("PE has no sections")?
        .header_offset
        + SECTION_HEADER_SIZE;
    ensure!(
        section_table_end + SECTION_HEADER_SIZE <= usize::try_from(pe.size_of_headers)?,
        "PE headers have no room for normalized import section"
    );
    let mut output = vec![0; usize::try_from(pe.size_of_headers)?];
    let header_bytes = mapped
        .get(..output.len())
        .context("mapped image lacks headers")?;
    output.copy_from_slice(header_bytes);
    pe::write_u32(&mut output, pe.coff_symbol_table_offset(), 0)?;
    pe::write_u32(&mut output, pe.coff_symbol_table_offset() + 4, 0)?;
    pe::write_u32(&mut output, pe.win32_version_value_offset(), 0)?;
    pe::write_u32(&mut output, pe.loader_flags_offset(), 0)?;
    let header_padding = section_table_end
        .checked_add(SECTION_HEADER_SIZE)
        .context("normalized section table end overflows")?;
    output
        .get_mut(header_padding..)
        .context("normalized section table exceeds SizeOfHeaders")?
        .fill(0);
    output[pe.opt - 18..pe.opt - 16]
        .copy_from_slice(&u16::try_from(pe.section_count + 1)?.to_le_bytes());
    pe::write_u32(&mut output, pe.entry_rva_offset(), entry_rva)?;
    pe::write_u32(&mut output, pe.size_of_image_offset(), final_image_size)?;
    for index in 0..pe.directories.len() {
        write_directory(
            &mut output,
            pe,
            index,
            DataDirectory {
                virtual_address: 0,
                size: 0,
            },
        )?;
    }
    for &(index, directory) in retained_directories {
        write_directory(&mut output, pe, index, directory)?;
    }
    if let Some(export) = export {
        write_directory(
            &mut output,
            pe,
            EXPORT_DIRECTORY,
            DataDirectory {
                virtual_address: export.rva,
                size: export.size,
            },
        )?;
    }
    write_directory(
        &mut output,
        pe,
        IMPORT_DIRECTORY,
        DataDirectory {
            virtual_address: import_rva,
            size: import_directory_size,
        },
    )?;
    write_directory(&mut output, pe, IAT_DIRECTORY, iat_directory)?;
    let raw_layout = compact_raw_layout(mapped, pe, retained_directories)?;
    for (section, layout) in pe.sections.iter().zip(&raw_layout) {
        let payload = mapped
            .get(
                usize::try_from(layout.virtual_range.start)?
                    ..usize::try_from(layout.virtual_range.end)?,
            )
            .context("section range exceeds mapped image")?;
        write_section_header(
            &mut output,
            section.header_offset,
            &section.name_bytes,
            section.virtual_size,
            section.virtual_address,
            layout.raw_size,
            if layout.raw_size == 0 {
                0
            } else {
                layout.raw_pointer
            },
            section.characteristics,
        )?;
        append_payload(
            &mut output,
            layout.raw_pointer,
            layout.raw_size,
            &payload[..payload.len().min(usize::try_from(layout.raw_size)?)],
        )?;
    }
    let raw_cursor = raw_layout
        .last()
        .context("PE has no sections")?
        .raw_pointer
        .checked_add(raw_layout.last().expect("nonempty raw layout").raw_size)
        .context("raw section cursor overflows")?;
    ensure!(
        u32::try_from(import.len())? <= import_virtual_size,
        "import payload exceeds virtual section"
    );
    let raw_size = if import.is_empty() {
        0
    } else {
        pe::align_up(u32::try_from(import.len())?, pe.file_alignment)?
    };
    let import_layout = RawSectionLayout {
        virtual_range: import_rva
            ..import_rva
                .checked_add(import_virtual_size)
                .context("import virtual range overflows")?,
        raw_pointer: raw_cursor,
        raw_size,
    };
    write_section_header(
        &mut output,
        section_table_end,
        b".cpimp\0\0",
        import_virtual_size,
        import_rva,
        import_layout.raw_size,
        if import_layout.raw_size == 0 {
            0
        } else {
            import_layout.raw_pointer
        },
        IMPORT_SECTION_CHARACTERISTICS,
    )?;
    append_payload(
        &mut output,
        import_layout.raw_pointer,
        import_layout.raw_size,
        import,
    )?;
    let aggregates =
        section_aggregate_sizes((0..usize::try_from(pe.section_count + 1)?).map(|index| {
            let offset = pe.sections[0].header_offset + index * SECTION_HEADER_SIZE;
            Ok((
                u32_at(&output, offset + 16)?,
                u32_at(&output, offset + 8)?,
                u32_at(&output, offset + 36)?,
            ))
        }))?;
    pe::write_u32(&mut output, pe.size_of_code_offset(), aggregates.0)?;
    pe::write_u32(
        &mut output,
        pe.size_of_initialized_data_offset(),
        aggregates.1,
    )?;
    pe::write_u32(
        &mut output,
        pe.size_of_uninitialized_data_offset(),
        aggregates.2,
    )?;
    if let Some((_, debug)) = retained_directories.iter().find(|(index, _)| *index == 6) {
        rewrite_debug_raw_pointers(&mut output, &raw_layout, *debug)?;
    }
    Ok(output)
}

fn section_aggregate_sizes<I>(sections: I) -> Result<(u32, u32, u32)>
where
    I: IntoIterator<Item = Result<(u32, u32, u32)>>,
{
    let mut code = 0u32;
    let mut initialized = 0u32;
    let mut uninitialized = 0u32;
    for section in sections {
        let (raw_size, virtual_size, characteristics) = section?;
        if characteristics & IMAGE_SCN_CNT_CODE != 0 {
            code = code.checked_add(raw_size).context("SizeOfCode overflows")?;
        }
        if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            initialized = initialized
                .checked_add(raw_size)
                .context("SizeOfInitializedData overflows")?;
        }
        if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            uninitialized = uninitialized
                .checked_add(virtual_size)
                .context("SizeOfUninitializedData overflows")?;
        }
    }
    Ok((code, initialized, uninitialized))
}

fn pogo_section_aggregate_sizes<I>(sections: I, file_alignment: u32) -> Result<(u32, u32, u32)>
where
    I: IntoIterator<Item = Result<(u32, u32, u32)>>,
{
    let mut code = 0u32;
    let mut initialized = 0u32;
    let mut uninitialized = 0u32;
    for section in sections {
        let (raw_size, virtual_size, characteristics) = section?;
        if characteristics & IMAGE_SCN_CNT_CODE != 0 {
            code = code.checked_add(raw_size).context("SizeOfCode overflows")?;
        }
        if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            initialized = initialized
                .checked_add(pe::align_up(virtual_size, file_alignment)?)
                .context("POGO SizeOfInitializedData overflows")?;
        }
        if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            uninitialized = uninitialized
                .checked_add(pe::align_up(virtual_size, file_alignment)?)
                .context("POGO SizeOfUninitializedData overflows")?;
        }
    }
    Ok((code, initialized, uninitialized))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("u32 field exceeds image")?
            .try_into()
            .expect("four-byte slice"),
    ))
}

fn append_payload(
    output: &mut Vec<u8>,
    raw_pointer: u32,
    raw_size: u32,
    payload: &[u8],
) -> Result<()> {
    ensure!(
        u32::try_from(payload.len())? <= raw_size,
        "payload exceeds raw section"
    );
    let start = usize::try_from(raw_pointer)?;
    let end = start + usize::try_from(raw_size)?;
    if output.len() < end {
        output.resize(end, 0);
    }
    output[start..start + payload.len()].copy_from_slice(payload);
    Ok(())
}
fn write_section_header(
    output: &mut [u8],
    offset: usize,
    name: &[u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_pointer: u32,
    characteristics: u32,
) -> Result<()> {
    let header = output
        .get_mut(offset..offset + SECTION_HEADER_SIZE)
        .context("section header exceeds output")?;
    header.fill(0);
    header[..8].copy_from_slice(name);
    header[8..12].copy_from_slice(&virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&virtual_address.to_le_bytes());
    header[16..20].copy_from_slice(&raw_size.to_le_bytes());
    header[20..24].copy_from_slice(&raw_pointer.to_le_bytes());
    header[36..40].copy_from_slice(&characteristics.to_le_bytes());
    Ok(())
}
fn write_directory(
    output: &mut [u8],
    pe: &Pe,
    index: usize,
    directory: DataDirectory,
) -> Result<()> {
    ensure!(
        index < pe.directories.len(),
        "PE has no data-directory slot {index}"
    );
    let offset = pe.data_directory_offset(index)?;
    pe::write_u32(output, offset, directory.virtual_address)?;
    pe::write_u32(output, offset + 4, directory.size)
}

fn disk_offset_for_rva(layout: &[RawSectionLayout], rva: u32) -> Result<u32> {
    let section = layout
        .iter()
        .find(|section| section.virtual_range.contains(&rva))
        .context("debug data RVA is not section-backed")?;
    let offset = rva - section.virtual_range.start;
    ensure!(
        offset < section.raw_size,
        "debug data RVA lies in trimmed raw tail"
    );
    section
        .raw_pointer
        .checked_add(offset)
        .context("debug raw pointer overflows")
}

fn rewrite_debug_raw_pointers(
    output: &mut [u8],
    layout: &[RawSectionLayout],
    directory: DataDirectory,
) -> Result<()> {
    for index in 0..usize::try_from(directory.size / 28)? {
        let record = directory
            .virtual_address
            .checked_add(u32::try_from(
                index
                    .checked_mul(28)
                    .context("debug record offset overflows")?,
            )?)
            .context("debug record RVA overflows")?;
        let record_offset = usize::try_from(disk_offset_for_rva(layout, record)?)?;
        let bytes = output
            .get(record_offset..record_offset + 28)
            .context("debug record exceeds output")?;
        let size = u32::from_le_bytes(bytes[16..20].try_into().expect("four bytes"));
        let address = u32::from_le_bytes(bytes[20..24].try_into().expect("four bytes"));
        let pointer = if address == 0 || size == 0 {
            0
        } else {
            disk_offset_for_rva(layout, address)?
        };
        output
            .get_mut(record_offset + 24..record_offset + 28)
            .context("debug raw pointer field exceeds output")?
            .copy_from_slice(&pointer.to_le_bytes());
    }
    Ok(())
}

fn recover_directories(mapped: &[u8], pe: &Pe) -> Result<Vec<(usize, DataDirectory)>> {
    let mut result = Vec::new();
    for (index, directory) in pe.directories.iter().copied().enumerate() {
        if matches!(
            index,
            EXPORT_DIRECTORY | IMPORT_DIRECTORY | SECURITY_DIRECTORY | 11 | IAT_DIRECTORY
        ) {
            continue;
        }
        if index == BASE_RELOCATION_DIRECTORY {
            if let Some(directory) = recover_base_relocation_directory(mapped, pe, directory)? {
                result.push((index, directory));
            }
            continue;
        }
        if directory.is_empty() {
            continue;
        }
        let directory = if index == 2 {
            scan_resource_root(mapped, pe)?
                .context("nonempty Resource Directory has no unique valid raw root")?
        } else {
            validate_retained_directory(mapped, pe, index, directory)?;
            directory
        };
        result.push((index, directory));
    }
    Ok(result)
}

fn validate_retained_directory(
    mapped: &[u8],
    pe: &Pe,
    index: usize,
    directory: DataDirectory,
) -> Result<()> {
    let range = directory
        .checked_rva_range()?
        .context("partial retained directory")?;
    rva_slice(
        mapped,
        pe,
        range.start,
        usize::try_from(range.end - range.start)?,
    )
    .context("retained directory is not section-backed")?;
    match index {
        EXCEPTION_DIRECTORY => validate_exception_directory(mapped, pe, directory),
        BASE_RELOCATION_DIRECTORY => {
            validate_base_relocation_directory(mapped, pe, directory).map(|_| ())
        }
        6 => validate_debug_directory(mapped, pe, directory),
        9 => validate_tls_directory(mapped, pe, directory),
        DELAY_IMPORT_DIRECTORY => validate_delay_import_directory(mapped, pe, directory),
        14 => validate_clr_directory(mapped, pe, directory),
        _ => bail!("nonempty unsupported data directory {index}"),
    }
}

const MAX_UNWIND_CHAIN_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnwindContract {
    frame_register: u8,
    frame_offset: u8,
    fixed_stack_allocation: u64,
}

fn nonvolatile_gpr(register: u8) -> bool {
    matches!(register, 3 | 5 | 6 | 7 | 12..=15)
}

fn saved_gpr(register: u8) -> bool {
    register != 4
}

fn valid_frame_gpr(register: u8) -> bool {
    nonvolatile_gpr(register) || matches!(register, 10 | 11)
}

fn validate_exception_directory(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    ensure!(
        pe.pointer_width() == PointerWidth::U64,
        "exception directory is only retained for PE32+"
    );
    ensure!(
        directory.virtual_address.is_multiple_of(4),
        "exception directory is not DWORD-aligned"
    );
    ensure!(
        directory.size.is_multiple_of(12),
        "exception directory has partial runtime-function entry"
    );
    let mut previous_begin = None;
    for offset in (0..directory.size).step_by(12) {
        let record = directory
            .virtual_address
            .checked_add(offset)
            .context("runtime-function RVA overflow")?;
        let (begin, _, _) = validate_runtime_function(mapped, pe, record, &mut BTreeSet::new(), 0)?;
        ensure!(
            previous_begin.is_none_or(|previous| begin > previous),
            "runtime-function entries are not strictly sorted"
        );
        previous_begin = Some(begin);
    }
    Ok(())
}

fn validate_runtime_function(
    mapped: &[u8],
    pe: &Pe,
    record_rva: u32,
    unwind_path: &mut BTreeSet<u32>,
    depth: usize,
) -> Result<(u32, u32, UnwindContract)> {
    ensure!(
        depth < MAX_UNWIND_CHAIN_DEPTH,
        "runtime-function chain exceeds {MAX_UNWIND_CHAIN_DEPTH} records"
    );
    ensure!(
        record_rva.is_multiple_of(4),
        "runtime-function record is not DWORD-aligned"
    );
    let bytes = rva_slice(mapped, pe, record_rva, 12)
        .context("runtime-function record is not section-backed")?;
    let begin = u32::from_le_bytes(bytes[0..4].try_into().expect("four bytes"));
    let end = u32::from_le_bytes(bytes[4..8].try_into().expect("four bytes"));
    let unwind = u32::from_le_bytes(bytes[8..12].try_into().expect("four bytes"));
    ensure!(
        begin < end && end <= pe.size_of_image,
        "runtime-function bounds are invalid"
    );
    let code = pe.section_for_rva_range(begin, usize::try_from(end - begin)?)?;
    ensure!(
        code.characteristics & 0x2000_0000 != 0,
        "runtime-function code range is not executable"
    );
    ensure!(
        unwind_path.insert(unwind),
        "runtime-function chain contains an UNWIND_INFO cycle"
    );
    let result = validate_unwind_info(mapped, pe, unwind, end - begin, unwind_path, depth);
    unwind_path.remove(&unwind);
    let contract = result?;
    Ok((begin, end, contract))
}

fn validate_v2_epilogue_codes(codes: &[u8], function_size: u32) -> Result<usize> {
    const UWOP_EPILOG: u8 = 6;
    if codes.is_empty() || codes[1] & 0x0f != UWOP_EPILOG {
        return Ok(0);
    }
    let epilogue_size = u32::from(codes[0]);
    let first_info = codes[1] >> 4;
    ensure!(
        epilogue_size != 0 && epilogue_size <= function_size,
        "UNWIND_INFO v2 has an invalid epilogue size"
    );
    ensure!(
        first_info <= 1,
        "UNWIND_INFO v2 first UWOP_EPILOG has reserved OpInfo bits"
    );
    let single_at_end = first_info == 1;
    let code_slots = codes.len() / 2;
    let mut slot = 1usize;
    while slot < code_slots {
        let code_offset = codes[slot * 2];
        let operation = codes[slot * 2 + 1] & 0x0f;
        let info = codes[slot * 2 + 1] >> 4;
        if operation != UWOP_EPILOG {
            break;
        }
        let end_offset = u32::from(code_offset) | (u32::from(info) << 8);
        slot += 1;
        if end_offset == 0 {
            break;
        }
        ensure!(
            !single_at_end,
            "UNWIND_INFO v2 single terminal epilogue has an additional descriptor"
        );
        ensure!(
            (epilogue_size..=function_size).contains(&end_offset),
            "UNWIND_INFO v2 epilogue offset is outside the runtime function"
        );
    }
    ensure!(
        slot.is_multiple_of(2),
        "UNWIND_INFO v2 epilogue descriptors lack an alignment record"
    );
    Ok(slot)
}

fn validate_unwind_info(
    mapped: &[u8],
    pe: &Pe,
    unwind_rva: u32,
    function_size: u32,
    unwind_path: &mut BTreeSet<u32>,
    depth: usize,
) -> Result<UnwindContract> {
    const UNW_FLAG_EHANDLER: u8 = 1;
    const UNW_FLAG_UHANDLER: u8 = 2;
    const UNW_FLAG_CHAININFO: u8 = 4;

    ensure!(
        unwind_rva.is_multiple_of(4),
        "UNWIND_INFO is not DWORD-aligned"
    );
    let header =
        rva_slice(mapped, pe, unwind_rva, 4).context("UNWIND_INFO header is not section-backed")?;
    let version = header[0] & 7;
    let flags = header[0] >> 3;
    let prolog_size = header[1];
    let code_slots = usize::from(header[2]);
    let frame_register = header[3] & 0x0f;
    let frame_offset = header[3] >> 4;
    ensure!(
        matches!(version, 1 | 2),
        "unsupported UNWIND_INFO version {version}"
    );
    ensure!(flags & !0x07 == 0, "reserved UNWIND_INFO flags are set");
    ensure!(
        flags & UNW_FLAG_CHAININFO == 0 || flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) == 0,
        "UNWIND_INFO CHAININFO conflicts with a handler"
    );
    ensure!(
        u32::from(prolog_size) <= function_size,
        "UNWIND_INFO prolog exceeds its runtime-function span"
    );
    ensure!(
        frame_register == 0 || valid_frame_gpr(frame_register),
        "UNWIND_INFO at {unwind_rva:#x} frame register {frame_register} is invalid"
    );
    ensure!(
        frame_register != 0 || frame_offset == 0,
        "UNWIND_INFO has a frame offset without a frame register"
    );

    let codes_rva = unwind_rva
        .checked_add(4)
        .context("UNWIND_INFO code RVA overflows")?;
    let codes_len = code_slots
        .checked_mul(2)
        .context("UNWIND_INFO code length overflows")?;
    let codes = if code_slots == 0 {
        &[]
    } else {
        rva_slice(mapped, pe, codes_rva, codes_len)
            .context("UNWIND_INFO code slots are not section-backed")?
    };
    let mut slot = if version == 2 {
        validate_v2_epilogue_codes(codes, function_size)?
    } else {
        0
    };
    let mut previous_offset = None;
    let mut fixed_stack_allocation = 0u64;
    while slot < code_slots {
        let code_offset = codes[slot * 2];
        let operation = codes[slot * 2 + 1] & 0x0f;
        let info = codes[slot * 2 + 1] >> 4;
        ensure!(
            code_offset <= prolog_size
                && previous_offset.is_none_or(|previous| code_offset <= previous),
            "UNWIND_INFO at {unwind_rva:#x} slot {slot} operation {operation} has code offset {code_offset} outside or out of order in prolog {prolog_size} after {previous_offset:?}"
        );
        previous_offset = Some(code_offset);
        let slots = match operation {
            0 => {
                ensure!(
                    saved_gpr(info),
                    "UNWIND_INFO at {unwind_rva:#x} slot {slot} UWOP_PUSH_NONVOL register {info} is invalid"
                );
                1
            }
            1 => match info {
                0 => {
                    ensure!(slot + 2 <= code_slots, "UWOP_ALLOC_LARGE is truncated");
                    let units = u16::from_le_bytes(
                        codes[slot * 2 + 2..slot * 2 + 4]
                            .try_into()
                            .expect("two bytes"),
                    );
                    ensure!(units != 0, "UWOP_ALLOC_LARGE has a zero allocation");
                    fixed_stack_allocation = fixed_stack_allocation
                        .checked_add(u64::from(units) * 8)
                        .context("UNWIND_INFO fixed-stack allocation overflows")?;
                    2
                }
                1 => {
                    ensure!(slot + 3 <= code_slots, "UWOP_ALLOC_LARGE is truncated");
                    let size = u32::from_le_bytes(
                        codes[slot * 2 + 2..slot * 2 + 6]
                            .try_into()
                            .expect("four bytes"),
                    );
                    ensure!(
                        size != 0 && size.is_multiple_of(8),
                        "UWOP_ALLOC_LARGE has an invalid allocation"
                    );
                    fixed_stack_allocation = fixed_stack_allocation
                        .checked_add(u64::from(size))
                        .context("UNWIND_INFO fixed-stack allocation overflows")?;
                    3
                }
                _ => bail!("UWOP_ALLOC_LARGE has a reserved OpInfo"),
            },
            2 => {
                fixed_stack_allocation = fixed_stack_allocation
                    .checked_add(u64::from(info) * 8 + 8)
                    .context("UNWIND_INFO fixed-stack allocation overflows")?;
                1
            }
            3 => {
                ensure!(frame_register != 0, "UWOP_SET_FPREG has no frame register");
                ensure!(
                    info == 0 || info == frame_register || info == frame_offset,
                    "UNWIND_INFO at {unwind_rva:#x} slot {slot} UWOP_SET_FPREG has invalid OpInfo {info}"
                );
                1
            }
            4 | 5 => {
                ensure!(saved_gpr(info), "UNWIND_INFO saved register is invalid");
                let slots = if operation == 4 { 2 } else { 3 };
                ensure!(
                    slot + slots <= code_slots,
                    "UNWIND_INFO nonvolatile save is truncated"
                );
                slots
            }
            6 => bail!("UWOP_EPILOG is not a leading UNWIND_INFO v2 descriptor"),
            7 => {
                ensure!(version == 2, "UWOP_SPARE is only valid in UNWIND_INFO v2");
                ensure!(slot + 3 <= code_slots, "UWOP_SPARE is truncated");
                3
            }
            8 | 9 => {
                ensure!(
                    (6..=15).contains(&info),
                    "UNWIND_INFO XMM register is not nonvolatile"
                );
                let slots = if operation == 8 { 2 } else { 3 };
                ensure!(
                    slot + slots <= code_slots,
                    "UNWIND_INFO XMM save is truncated"
                );
                slots
            }
            10 => {
                ensure!(info <= 1, "UWOP_PUSH_MACHFRAME has an invalid OpInfo");
                1
            }
            _ => bail!("reserved UNWIND_INFO operation {operation}"),
        };
        slot = slot
            .checked_add(slots)
            .context("UNWIND_INFO slot cursor overflows")?;
    }
    let contract = UnwindContract {
        frame_register,
        frame_offset,
        fixed_stack_allocation,
    };
    let trailer_offset = align(
        4usize
            .checked_add(codes_len)
            .context("UNWIND_INFO trailer offset overflows")?,
        4,
    )?;
    let trailer_rva = unwind_rva
        .checked_add(u32::try_from(trailer_offset)?)
        .context("UNWIND_INFO trailer RVA overflows")?;
    if flags & UNW_FLAG_CHAININFO != 0 {
        let (_, _, primary) =
            validate_runtime_function(mapped, pe, trailer_rva, unwind_path, depth + 1)?;
        ensure!(
            contract.frame_register == primary.frame_register
                && contract.frame_offset == primary.frame_offset,
            "UNWIND_INFO CHAININFO at {unwind_rva:#x} frame contract differs from primary {primary:?}"
        );
        ensure!(
            contract.fixed_stack_allocation == 0
                || contract.fixed_stack_allocation == primary.fixed_stack_allocation,
            "UNWIND_INFO CHAININFO at {unwind_rva:#x} fixed-stack allocation differs from primary {primary:?}"
        );
        Ok(primary)
    } else {
        if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            let handler = u32::from_le_bytes(
                rva_slice(mapped, pe, trailer_rva, 4)
                    .context("UNWIND_INFO handler RVA is not section-backed")?
                    .try_into()
                    .expect("four bytes"),
            );
            ensure!(handler != 0, "UNWIND_INFO handler RVA is null");
            let section = pe.section_for_rva_range(handler, 1)?;
            ensure!(
                section.characteristics & 0x2000_0000 != 0,
                "UNWIND_INFO handler is not executable"
            );
        }
        Ok(contract)
    }
}

fn recover_base_relocation_directory(
    mapped: &[u8],
    pe: &Pe,
    declared: DataDirectory,
) -> Result<Option<DataDirectory>> {
    if !declared.is_empty() {
        let relocations = validate_base_relocation_directory(mapped, pe, declared)?;
        if relocations != 0 {
            return Ok(Some(declared));
        }
    }

    let discovered = scan_base_relocation_directory(mapped, pe)?;
    Ok(discovered.or_else(|| (!declared.is_empty()).then_some(declared)))
}

fn scan_base_relocation_directory(mapped: &[u8], pe: &Pe) -> Result<Option<DataDirectory>> {
    let mut starts = 0usize;
    let mut candidates = Vec::new();
    let mut budget = ScanBudget::default();
    for section in &pe.sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            continue;
        }
        let range = section.virtual_range()?;
        let end = range.end.min(pe.size_of_image);
        let mut rva = pe::align_up(range.start, 4)?;
        while rva
            .checked_add(BASE_RELOCATION_BLOCK_HEADER_SIZE as u32)
            .is_some_and(|header_end| header_end <= end)
        {
            starts = starts
                .checked_add(1)
                .context("relocation scan start counter overflows")?;
            ensure!(
                starts <= MAX_SCAN_STARTS,
                "relocation scan start budget exceeded"
            );
            if let Some(candidate) = parse_relocation_candidate(mapped, pe, rva, end, &mut budget)?
            {
                ensure!(
                    candidates.len() < MAX_SCAN_CANDIDATES,
                    "relocation scan candidate budget exceeded"
                );
                candidates.push(candidate);
                rva = candidate
                    .virtual_address
                    .checked_add(candidate.size)
                    .context("relocation candidate end overflows")?;
            } else {
                rva = rva
                    .checked_add(4)
                    .context("relocation scan RVA overflows")?;
            }
        }
    }
    ensure!(
        candidates.len() <= 1,
        "multiple independent hidden relocation streams were found"
    );
    Ok(candidates.pop())
}

fn parse_relocation_candidate(
    mapped: &[u8],
    pe: &Pe,
    start: u32,
    owner_end: u32,
    budget: &mut ScanBudget,
) -> Result<Option<DataDirectory>> {
    let image_end = pe
        .image_base
        .checked_add(u64::from(pe.size_of_image))
        .context("preferred image range overflows")?;
    let mut cursor = start;
    let mut previous_page = None;
    let mut relocations = 0usize;
    while let Some(header_end) = cursor.checked_add(BASE_RELOCATION_BLOCK_HEADER_SIZE as u32) {
        if header_end > owner_end {
            break;
        }
        let Some(header) = rva_slice(mapped, pe, cursor, BASE_RELOCATION_BLOCK_HEADER_SIZE) else {
            break;
        };
        let page = u32::from_le_bytes(header[0..4].try_into().expect("four bytes"));
        let block_size = u32::from_le_bytes(header[4..8].try_into().expect("four bytes"));
        if page == 0
            || !page.is_multiple_of(0x1000)
            || page >= pe.size_of_image
            || pe.section_containing_rva(page).is_none()
            || previous_page.is_some_and(|previous| page <= previous)
            || block_size < BASE_RELOCATION_BLOCK_HEADER_SIZE as u32
            || !block_size.is_multiple_of(4)
        {
            break;
        }
        let Some(next) = cursor.checked_add(block_size) else {
            break;
        };
        if next > owner_end {
            break;
        }
        let entries = usize::try_from((block_size - BASE_RELOCATION_BLOCK_HEADER_SIZE as u32) / 2)?;
        let mut block_relocations = 0usize;
        let mut valid = true;
        for index in 0..entries {
            budget.consume(1)?;
            let entry_rva = header_end
                .checked_add(u32::try_from(
                    index.checked_mul(2).context("relocation index overflows")?,
                )?)
                .context("relocation entry RVA overflows")?;
            let Some(entry) = rva_slice(mapped, pe, entry_rva, 2) else {
                valid = false;
                break;
            };
            let word = u16::from_le_bytes(entry.try_into().expect("two bytes"));
            let kind = word >> 12;
            if kind == IMAGE_REL_BASED_ABSOLUTE {
                continue;
            }
            let width = match (pe.pointer_width(), kind) {
                (PointerWidth::U32, IMAGE_REL_BASED_HIGHLOW) => 4,
                (PointerWidth::U64, IMAGE_REL_BASED_DIR64) => 8,
                _ => {
                    valid = false;
                    break;
                }
            };
            let Some(target) = page.checked_add(u32::from(word & 0x0fff)) else {
                valid = false;
                break;
            };
            let Some(value) = rva_slice(mapped, pe, target, width) else {
                valid = false;
                break;
            };
            let value = match pe.pointer_width() {
                PointerWidth::U32 => {
                    u64::from(u32::from_le_bytes(value.try_into().expect("four bytes")))
                }
                PointerWidth::U64 => u64::from_le_bytes(value.try_into().expect("eight bytes")),
            };
            if value < pe.image_base || value >= image_end {
                valid = false;
                break;
            }
            block_relocations = block_relocations
                .checked_add(1)
                .context("relocation count overflows")?;
        }
        if !valid || block_relocations == 0 {
            break;
        }
        relocations = relocations
            .checked_add(block_relocations)
            .context("relocation count overflows")?;
        previous_page = Some(page);
        cursor = next;
    }
    if relocations == 0 {
        return Ok(None);
    }
    let directory = DataDirectory {
        virtual_address: start,
        size: cursor
            .checked_sub(start)
            .context("relocation candidate size underflows")?,
    };
    validate_base_relocation_directory(mapped, pe, directory)?;
    Ok(Some(directory))
}

fn validate_base_relocation_directory(
    mapped: &[u8],
    pe: &Pe,
    directory: DataDirectory,
) -> Result<usize> {
    let mut relocations = 0usize;
    ensure!(
        directory.virtual_address.is_multiple_of(4),
        "relocation directory is not DWORD-aligned"
    );
    let end = directory
        .virtual_address
        .checked_add(directory.size)
        .context("relocation directory overflow")?;
    let mut cursor = directory.virtual_address;
    while cursor < end {
        ensure!(
            cursor.is_multiple_of(4),
            "relocation block is not DWORD-aligned"
        );
        let header = rva_slice(mapped, pe, cursor, BASE_RELOCATION_BLOCK_HEADER_SIZE)
            .context("relocation header is not section-backed")?;
        let page = u32::from_le_bytes(header[0..4].try_into().expect("four bytes"));
        let block_size = u32::from_le_bytes(header[4..8].try_into().expect("four bytes"));
        ensure!(
            block_size >= BASE_RELOCATION_BLOCK_HEADER_SIZE as u32 && block_size.is_multiple_of(4),
            "relocation block size is invalid"
        );
        let next = cursor
            .checked_add(block_size)
            .context("relocation block overflow")?;
        ensure!(next <= end, "relocation block exceeds directory");
        // Linkers emit this eight-byte no-op block for an otherwise empty
        // relocation directory. It has no PageRVA or entries to retain.
        if page == 0 && block_size == BASE_RELOCATION_BLOCK_HEADER_SIZE as u32 {
            cursor = next;
            continue;
        }
        ensure!(
            page.is_multiple_of(0x1000),
            "relocation PageRVA is not page-aligned"
        );
        ensure!(page < pe.size_of_image, "relocation PageRVA exceeds image");
        pe.section_containing_rva(page)
            .with_context(|| format!("relocation PageRVA {page:#x} is not section-backed"))?;
        for entry_offset in (BASE_RELOCATION_BLOCK_HEADER_SIZE as u32..block_size).step_by(2) {
            let entry = rva_slice(
                mapped,
                pe,
                cursor
                    .checked_add(entry_offset)
                    .context("relocation entry overflow")?,
                2,
            )
            .context("relocation entry is not section-backed")?;
            let word = u16::from_le_bytes(entry.try_into().expect("two bytes"));
            let kind = word >> 12;
            let target = page
                .checked_add(u32::from(word & 0x0fff))
                .context("relocation target overflow")?;
            let width = match (pe.pointer_width(), kind) {
                (_, IMAGE_REL_BASED_ABSOLUTE) => continue,
                (PointerWidth::U32, IMAGE_REL_BASED_HIGHLOW) => 4,
                (PointerWidth::U64, IMAGE_REL_BASED_DIR64) => 8,
                _ => bail!("unsupported relocation kind {kind}"),
            };
            relocations = relocations
                .checked_add(1)
                .context("relocation count overflows")?;
            let target_end = target
                .checked_add(width)
                .context("relocation target end overflows")?;
            ensure!(
                target_end <= pe.size_of_image,
                "relocation target exceeds image"
            );
            rva_slice(mapped, pe, target, usize::try_from(width)?)
                .context("relocation target is not section-backed")?;
        }
        cursor = next;
    }
    ensure!(cursor == end, "relocation directory trailing bytes");
    Ok(relocations)
}

fn validate_delay_import_directory(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    ensure!(
        directory
            .size
            .is_multiple_of(DELAY_IMPORT_DESCRIPTOR_SIZE as u32),
        "delay-import directory is not descriptor aligned"
    );
    let end = directory
        .virtual_address
        .checked_add(directory.size)
        .context("delay-import directory overflow")?;
    let mut cursor = directory.virtual_address;
    while cursor < end {
        let descriptor = rva_slice(mapped, pe, cursor, DELAY_IMPORT_DESCRIPTOR_SIZE)
            .context("delay-import descriptor is not section-backed")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            ensure!(
                rva_slice(mapped, pe, cursor, usize::try_from(end - cursor)?)
                    .context("delay-import terminator is not section-backed")?
                    .iter()
                    .all(|byte| *byte == 0),
                "delay-import bytes follow the terminator"
            );
            return Ok(());
        }
        let attributes = u32::from_le_bytes(descriptor[0..4].try_into().expect("four bytes"));
        ensure!(
            attributes == 0 || attributes == 1,
            "delay-import attributes do not select exact RVA or VA semantics"
        );
        let rva_mode = attributes == 1;
        let field = |offset: usize| {
            u32::from_le_bytes(
                descriptor[offset..offset + 4]
                    .try_into()
                    .expect("four bytes"),
            )
        };
        let name = delay_descriptor_rva(pe, field(4), rva_mode, "DLL name")?
            .context("delay-import DLL name is null")?;
        let dll = read_ascii(mapped, pe, name, MAX_IMPORT_STRING)
            .context("delay-import DLL name is invalid or unterminated")?;
        ensure!(!dll.is_empty(), "delay-import DLL name is empty");

        let module_handle = delay_descriptor_rva(pe, field(8), rva_mode, "module handle")?
            .context("delay-import module handle is null")?;
        let iat = delay_descriptor_rva(pe, field(12), rva_mode, "IAT")?
            .context("delay-import IAT is null")?;
        let int = delay_descriptor_rva(pe, field(16), rva_mode, "INT")?
            .context("delay-import INT is null")?;
        let bound = delay_descriptor_rva(pe, field(20), rva_mode, "bound IAT")?;
        let unload = delay_descriptor_rva(pe, field(24), rva_mode, "unload IAT")?;
        let width = u32::try_from(pe.pointer_width().bytes())?;
        for (label, rva) in [("module handle", module_handle), ("IAT", iat)] {
            ensure!(
                rva.is_multiple_of(width),
                "delay-import {label} is not pointer aligned"
            );
            validate_delay_writable_cell(pe, rva, width, label)?;
        }
        for (label, rva) in [
            ("INT", Some(int)),
            ("bound IAT", bound),
            ("unload IAT", unload),
        ] {
            if let Some(rva) = rva {
                ensure!(
                    rva.is_multiple_of(width),
                    "delay-import {label} is not pointer aligned"
                );
                rva_slice(mapped, pe, rva, usize::try_from(width)?)
                    .with_context(|| format!("delay-import {label} is not section-backed"))?;
            }
        }
        validate_delay_import_tables(mapped, pe, int, iat, bound, unload, rva_mode)?;
        cursor = cursor
            .checked_add(DELAY_IMPORT_DESCRIPTOR_SIZE as u32)
            .context("delay-import descriptor overflow")?;
    }
    bail!("delay-import descriptor array has no terminator")
}

fn delay_descriptor_rva(pe: &Pe, value: u32, rva_mode: bool, label: &str) -> Result<Option<u32>> {
    if value == 0 {
        return Ok(None);
    }
    let rva = if rva_mode {
        value
    } else {
        va_to_rva(pe, u64::from(value))?
            .with_context(|| format!("delay-import {label} VA is null"))?
    };
    ensure!(rva < pe.size_of_image, "delay-import {label} exceeds image");
    Ok(Some(rva))
}

fn validate_delay_writable_cell(pe: &Pe, rva: u32, width: u32, label: &str) -> Result<()> {
    let section = pe
        .section_for_rva_range(rva, usize::try_from(width)?)
        .with_context(|| format!("delay-import {label} is not section-backed"))?;
    ensure!(
        section.characteristics & 0x8000_0000 != 0,
        "delay-import {label} is not writable"
    );
    Ok(())
}

fn delay_table_cell_rva(base: u32, index: usize, width: u32, label: &str) -> Result<u32> {
    base.checked_add(
        u32::try_from(index)?
            .checked_mul(width)
            .context("delay-import table offset overflows")?,
    )
    .with_context(|| format!("delay-import {label} cell RVA overflows"))
}

fn delay_table_value(mapped: &[u8], pe: &Pe, rva: u32, label: &str) -> Result<u64> {
    let bytes = rva_slice(mapped, pe, rva, pe.pointer_width().bytes())
        .with_context(|| format!("delay-import {label} cell is not section-backed"))?;
    Ok(match pe.pointer_width() {
        PointerWidth::U32 => u64::from(u32::from_le_bytes(bytes.try_into().expect("four bytes"))),
        PointerWidth::U64 => u64::from_le_bytes(bytes.try_into().expect("eight bytes")),
    })
}

fn validate_delay_thunk(
    mapped: &[u8],
    pe: &Pe,
    value: u64,
    rva_mode: bool,
    label: &str,
) -> Result<()> {
    let flag = ordinal_flag(pe.pointer_width());
    if value & flag != 0 {
        ensure!(
            value & !(flag | 0xffff) == 0 && value & 0xffff != 0,
            "delay-import {label} has an invalid ordinal thunk"
        );
        return Ok(());
    }
    let name_rva = if rva_mode {
        named_thunk_rva(pe.pointer_width(), value)
            .with_context(|| format!("delay-import {label} name RVA is invalid"))?
    } else {
        va_to_rva(pe, value)?.with_context(|| format!("delay-import {label} name VA is null"))?
    };
    ensure!(
        name_rva.is_multiple_of(2),
        "delay-import {label} hint/name is not aligned"
    );
    rva_slice(mapped, pe, name_rva, 2)
        .with_context(|| format!("delay-import {label} hint is not section-backed"))?;
    read_ascii(
        mapped,
        pe,
        name_rva
            .checked_add(2)
            .context("delay-import hint/name RVA overflows")?,
        MAX_IMPORT_STRING,
    )
    .with_context(|| format!("delay-import {label} name is invalid or unterminated"))?;
    Ok(())
}

fn validate_delay_import_tables(
    mapped: &[u8],
    pe: &Pe,
    int: u32,
    iat: u32,
    bound: Option<u32>,
    unload: Option<u32>,
    rva_mode: bool,
) -> Result<()> {
    let width = u32::try_from(pe.pointer_width().bytes())?;
    for index in 0..=MAX_IMPORT_THUNKS {
        let int_rva = delay_table_cell_rva(int, index, width, "INT")?;
        let iat_rva = delay_table_cell_rva(iat, index, width, "IAT")?;
        let int_value = delay_table_value(mapped, pe, int_rva, "INT")?;
        validate_delay_writable_cell(pe, iat_rva, width, "IAT")?;
        let iat_value = delay_table_value(mapped, pe, iat_rva, "IAT")?;
        let bound_value = bound
            .map(|base| {
                let rva = delay_table_cell_rva(base, index, width, "bound IAT")?;
                delay_table_value(mapped, pe, rva, "bound IAT")
            })
            .transpose()?;
        let unload_value = unload
            .map(|base| {
                let rva = delay_table_cell_rva(base, index, width, "unload IAT")?;
                delay_table_value(mapped, pe, rva, "unload IAT")
            })
            .transpose()?;
        if int_value == 0 {
            ensure!(
                iat_value == 0,
                "delay-import IAT and INT terminators differ"
            );
            ensure!(
                unload_value.is_none_or(|value| value == 0),
                "delay-import unload IAT terminator differs from INT"
            );
            ensure!(
                bound_value.is_none_or(|value| value == 0),
                "delay-import bound IAT terminator differs from INT"
            );
            return Ok(());
        }
        validate_delay_thunk(mapped, pe, int_value, rva_mode, "INT")?;
        // A bound IAT and a delay-loaded IAT may already hold resolved external
        // function VAs. Their format-defined invariant is the paired terminator,
        // not import-name encoding; reading each cell still bounds ownership.
        let _ = bound_value;
        if let Some(value) = unload_value {
            ensure!(value != 0, "delay-import unload IAT ends before INT");
            validate_delay_thunk(mapped, pe, value, rva_mode, "unload IAT")?;
        }
    }
    bail!("delay-import thunk array exceeds {MAX_IMPORT_THUNKS} entries")
}

fn scan_resource_root(mapped: &[u8], pe: &Pe) -> Result<Option<DataDirectory>> {
    let mut roots = Vec::new();
    let mut starts = 0usize;
    for section in &pe.sections {
        if !section.name_bytes.starts_with(b".rsrc") {
            continue;
        }
        let range = section.virtual_range()?;
        for rva in (range.start..range.end.saturating_sub(16)).step_by(4) {
            starts += 1;
            ensure!(
                starts <= MAX_SCAN_STARTS,
                "resource scan start budget exceeded"
            );
            let mut nodes = 0;
            if let Some(end) = resource_node(mapped, pe, rva, rva, 0, &mut nodes)? {
                roots.push(DataDirectory {
                    virtual_address: rva,
                    size: pe::align_up(end - rva, 4)?,
                });
                ensure!(
                    roots.len() <= MAX_SCAN_CANDIDATES,
                    "resource scan candidate budget exceeded"
                );
            }
        }
    }
    roots.sort_by_key(|root| (root.virtual_address, root.size));
    roots.dedup();
    ensure!(
        roots.len() <= 1,
        "multiple valid raw resource roots were found"
    );
    Ok(roots.pop())
}
fn resource_node(
    mapped: &[u8],
    pe: &Pe,
    root: u32,
    rva: u32,
    depth: usize,
    nodes: &mut usize,
) -> Result<Option<u32>> {
    if depth > 2 {
        return Ok(None);
    }
    let Some(header) = rva_slice(mapped, pe, rva, 16) else {
        return Ok(None);
    };
    let count = usize::from(u16::from_le_bytes(header[12..14].try_into().unwrap()))
        + usize::from(u16::from_le_bytes(header[14..16].try_into().unwrap()));
    if count == 0 || count > 4096 {
        return Ok(None);
    }
    *nodes = nodes
        .checked_add(count)
        .context("resource node budget overflows")?;
    if *nodes > 16384 {
        return Ok(None);
    }
    let len = count.checked_mul(8).context("resource entries overflow")?;
    let Some(entries) = rva_slice(
        mapped,
        pe,
        rva.checked_add(16)
            .context("resource entries RVA overflow")?,
        len,
    ) else {
        return Ok(None);
    };
    let mut end = rva
        .checked_add(16 + u32::try_from(len)?)
        .context("resource entry end overflows")?;
    for index in 0..count {
        let name = u32::from_le_bytes(entries[index * 8..index * 8 + 4].try_into().unwrap());
        if name & 0x8000_0000 != 0 {
            let at = root
                .checked_add(name & 0x7fff_ffff)
                .context("resource name overflow")?;
            let Some(length) = rva_slice(mapped, pe, at, 2)
                .map(|b| u16::from_le_bytes(b.try_into().unwrap()) as usize)
            else {
                return Ok(None);
            };
            let size = 2usize
                .checked_add(
                    length
                        .checked_mul(2)
                        .context("resource name length overflow")?,
                )
                .context("resource name size overflow")?;
            if rva_slice(mapped, pe, at, size).is_none() {
                return Ok(None);
            }
            end = end.max(at + u32::try_from(size)?);
        }
        let value = u32::from_le_bytes(entries[index * 8 + 4..index * 8 + 8].try_into().unwrap());
        let is_directory = value & 0x8000_0000 != 0;
        if (depth < 2) != is_directory {
            return Ok(None);
        }
        let child = root
            .checked_add(value & 0x7fff_ffff)
            .context("resource child overflow")?;
        if is_directory {
            let Some(child_end) = resource_node(mapped, pe, root, child, depth + 1, nodes)? else {
                return Ok(None);
            };
            end = end.max(child_end);
        } else {
            let Some(data) = rva_slice(mapped, pe, child, 16) else {
                return Ok(None);
            };
            let data_rva = u32::from_le_bytes(data[..4].try_into().unwrap());
            let size = u32::from_le_bytes(data[4..8].try_into().unwrap());
            if size == 0 || rva_slice(mapped, pe, data_rva, usize::try_from(size)?).is_none() {
                return Ok(None);
            }
            let root_section = pe
                .section_containing_rva(root)
                .context("resource root is not section-backed")?;
            let payload_section = pe
                .section_containing_rva(data_rva)
                .context("resource payload is not section-backed")?;
            if root_section.index != payload_section.index {
                return Ok(None);
            }
            end = end.max(child + 16).max(
                data_rva
                    .checked_add(size)
                    .context("resource data end overflows")?,
            );
        }
    }
    Ok(Some(end))
}

fn va_to_rva(pe: &Pe, va: u64) -> Result<Option<u32>> {
    if va == 0 {
        return Ok(None);
    }
    let rva = va
        .checked_sub(pe.image_base)
        .context("directory VA precedes image base")?;
    Ok(Some(
        u32::try_from(rva).context("directory VA exceeds 32-bit RVA")?,
    ))
}

fn validate_tls_directory(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    let width = pe.pointer_width().bytes();
    let size = if width == 4 { 24 } else { 40 };
    ensure!(directory.size >= size, "TLS Directory is truncated");
    let bytes = rva_slice(
        mapped,
        pe,
        directory.virtual_address,
        usize::try_from(size)?,
    )
    .context("TLS header is not section-backed")?;
    let read = |offset| {
        if width == 4 {
            u64::from(u32::from_le_bytes(
                bytes[offset..offset + 4].try_into().unwrap(),
            ))
        } else {
            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
        }
    };
    let start = va_to_rva(pe, read(0))?;
    let end = va_to_rva(pe, read(width))?;
    match (start, end) {
        (None, None) => {}
        (Some(start), Some(end)) => {
            ensure!(end >= start, "TLS raw-data range is inverted");
            rva_slice(mapped, pe, start, usize::try_from(end - start)?)
                .context("TLS raw-data range is invalid")?;
        }
        _ => bail!("TLS raw-data range has a partial null endpoint"),
    }
    if let Some(index) = va_to_rva(pe, read(width * 2))? {
        let section = pe.section_for_rva_range(index, 4)?;
        ensure!(
            section.characteristics & 0x8000_0000 != 0,
            "TLS AddressOfIndex is not writable"
        );
    }
    let characteristics_offset = width
        .checked_mul(4)
        .and_then(|offset| offset.checked_add(4))
        .context("TLS Characteristics offset overflows")?;
    let characteristics = u32::from_le_bytes(
        bytes[characteristics_offset..characteristics_offset + 4]
            .try_into()
            .expect("four bytes"),
    );
    ensure!(
        characteristics & !0x00f0_0000 == 0,
        "TLS Characteristics contains reserved bits"
    );
    if let Some(callbacks) = va_to_rva(pe, read(width * 3))? {
        for index in 0..4096usize {
            let cell = callbacks
                .checked_add(u32::try_from(index * width)?)
                .context("TLS callback RVA overflows")?;
            let bytes =
                rva_slice(mapped, pe, cell, width).context("TLS callback array is invalid")?;
            let value = if width == 4 {
                u64::from(u32::from_le_bytes(bytes.try_into().unwrap()))
            } else {
                u64::from_le_bytes(bytes.try_into().unwrap())
            };
            if value == 0 {
                return Ok(());
            }
            let target = va_to_rva(pe, value)?.context("TLS callback is unexpectedly null")?;
            let section = pe.section_for_rva_range(target, 1)?;
            ensure!(
                section.characteristics & 0x2000_0000 != 0,
                "TLS callback is not executable"
            );
        }
        bail!("TLS callback array has no terminator")
    }
    Ok(())
}

fn validate_debug_directory(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    ensure!(
        directory.size.is_multiple_of(28),
        "Debug Directory is not a sequence of IMAGE_DEBUG_DIRECTORY records"
    );
    for index in 0..usize::try_from(directory.size / 28)? {
        let record = directory.virtual_address + u32::try_from(index * 28)?;
        let bytes =
            rva_slice(mapped, pe, record, 28).context("Debug record is not section-backed")?;
        let size = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let address = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let pointer = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        if size == 0 {
            ensure!(
                address == 0 && pointer == 0,
                "empty Debug record has data pointers"
            );
        } else {
            ensure!(
                address != 0 && pointer != 0,
                "file-only or unmapped Debug data is unsupported"
            );
            rva_slice(mapped, pe, address, usize::try_from(size)?)
                .context("Debug payload is not section-backed")?;
        }
    }
    Ok(())
}

fn validate_clr_directory(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    ensure!(directory.size >= 72, "CLR Directory is truncated");
    let header = rva_slice(mapped, pe, directory.virtual_address, 72)
        .context("CLR header is not section-backed")?;
    let cb = u32::from_le_bytes(header[..4].try_into().unwrap());
    ensure!(
        cb >= 72 && cb <= directory.size,
        "CLR header size is invalid"
    );
    let metadata_rva = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let metadata_size = u32::from_le_bytes(header[12..16].try_into().unwrap());
    ensure!(metadata_size >= 16, "CLR metadata is truncated");
    let metadata = rva_slice(mapped, pe, metadata_rva, usize::try_from(metadata_size)?)
        .context("CLR metadata is not section-backed")?;
    ensure!(
        &metadata[..4] == b"BSJB",
        "CLR metadata signature is invalid"
    );
    let version_len = u32::from_le_bytes(metadata[12..16].try_into().unwrap()) as usize;
    ensure!(
        16usize
            .checked_add(version_len)
            .context("CLR version length overflows")?
            <= metadata.len(),
        "CLR metadata version is truncated"
    );
    Ok(())
}

fn scan_import_candidates(mapped: &[u8], pe: &Pe) -> Result<Vec<ImportCandidate>> {
    let mut candidates = Vec::new();
    let mut starts = 0usize;
    let mut budget = ScanBudget::default();
    for range in scan_ranges(pe)? {
        for rva in (range.start
            ..range
                .end
                .saturating_sub(IMAGE_IMPORT_DESCRIPTOR_SIZE as u32))
            .step_by(4)
        {
            starts += 1;
            ensure!(
                starts <= MAX_SCAN_STARTS,
                "import scan start budget exceeded"
            );
            if let Some(candidate) = parse_import_candidate(mapped, pe, rva, &mut budget)? {
                ensure!(
                    candidates.len() < MAX_SCAN_CANDIDATES,
                    "import scan candidate budget exceeded"
                );
                candidates.push(candidate);
            }
        }
    }
    Ok(candidates)
}

fn select_import_candidate(
    mut candidates: Vec<ImportCandidate>,
) -> Result<Option<ImportCandidate>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    candidates.sort_by(|left, right| {
        right
            .graph
            .modules
            .len()
            .cmp(&left.graph.modules.len())
            .then(left.start.cmp(&right.start))
    });
    let winner = candidates.remove(0);
    for candidate in candidates {
        let offset = winner
            .graph
            .modules
            .len()
            .checked_sub(candidate.graph.modules.len())
            .context("candidate has more descriptors than winner")?;
        let expected_start = winner
            .start
            .checked_add(u32::try_from(offset)? * IMAGE_IMPORT_DESCRIPTOR_SIZE as u32)
            .context("import suffix RVA overflows")?;
        ensure!(
            candidate.end == winner.end
                && candidate.start == expected_start
                && winner.graph.modules.ends_with(&candidate.graph.modules),
            "disjoint, cloned, or competing standard import graphs were found"
        );
    }
    Ok(Some(winner))
}

fn parse_import_candidate(
    mapped: &[u8],
    pe: &Pe,
    start: u32,
    budget: &mut ScanBudget,
) -> Result<Option<ImportCandidate>> {
    let mut modules = Vec::new();
    let mut metadata_ranges = Vec::new();
    let mut rva = start;
    let width = pe.pointer_width().bytes();
    loop {
        if modules.len() == MAX_IMPORT_MODULES {
            return Ok(None);
        }
        budget.consume(1)?;
        let Some(descriptor) = rva_slice(mapped, pe, rva, IMAGE_IMPORT_DESCRIPTOR_SIZE) else {
            return Ok(None);
        };
        if descriptor.iter().all(|byte| *byte == 0) {
            metadata_ranges.push(start..rva + IMAGE_IMPORT_DESCRIPTOR_SIZE as u32);
            return Ok((!modules.is_empty()).then(|| ImportCandidate {
                start,
                end: rva + IMAGE_IMPORT_DESCRIPTOR_SIZE as u32,
                metadata_ranges,
                graph: ImportGraph {
                    functions: modules
                        .iter()
                        .map(|module: &ImportModule| module.symbols.len())
                        .sum(),
                    modules,
                },
            }));
        }
        let original = u32::from_le_bytes(descriptor[..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(descriptor[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(descriptor[16..20].try_into().unwrap());
        if name_rva == 0 || first_thunk == 0 || !first_thunk.is_multiple_of(4) {
            return Ok(None);
        }
        let Some(dll) = read_ascii(mapped, pe, name_rva, MAX_IMPORT_STRING) else {
            return Ok(None);
        };
        let dll_end = name_rva
            .checked_add(u32::try_from(dll.len() + 1)?)
            .context("candidate DLL range overflows")?;
        let lookup = if original == 0 { first_thunk } else { original };
        let Some((symbols, mut thunk_metadata)) = parse_thunks(mapped, pe, lookup, budget)? else {
            return Ok(None);
        };
        metadata_ranges.push(name_rva..dll_end);
        metadata_ranges.append(&mut thunk_metadata);
        let length = (symbols.len() + 1)
            .checked_mul(width)
            .context("candidate IAT length overflows")?;
        if pe.section_for_rva_range(first_thunk, length).is_err() {
            return Ok(None);
        }
        modules.push(ImportModule {
            dll,
            destination_rva: first_thunk,
            symbols,
        });
        rva = match rva.checked_add(IMAGE_IMPORT_DESCRIPTOR_SIZE as u32) {
            Some(value) => value,
            None => return Ok(None),
        };
    }
}

fn parse_thunks(
    mapped: &[u8],
    pe: &Pe,
    mut rva: u32,
    budget: &mut ScanBudget,
) -> Result<Option<(Vec<ImportSymbol>, Vec<Range<u32>>)>> {
    let start = rva;
    let width = pe.pointer_width().bytes();
    let mut symbols = Vec::new();
    let mut metadata_ranges = Vec::new();
    loop {
        if symbols.len() == MAX_IMPORT_THUNKS {
            return Ok(None);
        }
        budget.consume(1)?;
        let Some(bytes) = rva_slice(mapped, pe, rva, width) else {
            return Ok(None);
        };
        let value = match pe.pointer_width() {
            PointerWidth::U32 => u64::from(u32::from_le_bytes(bytes.try_into().unwrap())),
            PointerWidth::U64 => u64::from_le_bytes(bytes.try_into().unwrap()),
        };
        rva = match rva.checked_add(u32::try_from(width)?) {
            Some(value) => value,
            None => return Ok(None),
        };
        if value == 0 {
            metadata_ranges.push(start..rva);
            return Ok((!symbols.is_empty()).then_some((symbols, metadata_ranges)));
        }
        let symbol = if value & ordinal_flag(pe.pointer_width()) != 0 {
            if value & !(ordinal_flag(pe.pointer_width()) | 0xffff) != 0 {
                return Ok(None);
            }
            ImportSymbol::Ordinal(value as u16)
        } else {
            let Some(name_rva) = named_thunk_rva(pe.pointer_width(), value) else {
                return Ok(None);
            };
            if !name_rva.is_multiple_of(2) {
                return Ok(None);
            }
            let Some(hint_bytes) = rva_slice(mapped, pe, name_rva, 2) else {
                return Ok(None);
            };
            let Some(name) = read_ascii(
                mapped,
                pe,
                name_rva
                    .checked_add(2)
                    .context("candidate name RVA overflow")?,
                MAX_IMPORT_STRING,
            ) else {
                return Ok(None);
            };
            let end = name_rva
                .checked_add(u32::try_from(2 + name.len() + 1)?)
                .context("candidate hint/name range overflows")?;
            metadata_ranges.push(name_rva..end);
            ImportSymbol::Name {
                hint: u16::from_le_bytes(hint_bytes.try_into().unwrap()),
                name,
            }
        };
        symbols.push(symbol);
    }
}

fn scan_export(mapped: &[u8], pe: &Pe) -> Result<Option<ExportCandidate>> {
    let mut candidates = Vec::new();
    let mut starts = 0usize;
    for range in scan_ranges(pe)? {
        for rva in
            (range.start..range.end.saturating_sub(IMAGE_EXPORT_DIRECTORY_SIZE as u32)).step_by(4)
        {
            starts = starts
                .checked_add(1)
                .context("export scan counter overflows")?;
            ensure!(
                starts <= MAX_SCAN_STARTS,
                "export scan start budget exceeded"
            );
            if let Some(candidate) = parse_export_candidate(mapped, pe, rva)? {
                ensure!(
                    candidates.len() < MAX_SCAN_CANDIDATES,
                    "export scan candidate budget exceeded"
                );
                candidates.push(candidate);
            }
        }
    }
    candidates.sort_by_key(|candidate| candidate.rva);
    candidates.dedup();
    ensure!(
        candidates.len() <= 1,
        "multiple independent export graphs were found"
    );
    Ok(candidates.pop())
}

fn parse_export_candidate(mapped: &[u8], pe: &Pe, rva: u32) -> Result<Option<ExportCandidate>> {
    let Some(header) = rva_slice(mapped, pe, rva, IMAGE_EXPORT_DIRECTORY_SIZE) else {
        return Ok(None);
    };
    let name_rva = u32::from_le_bytes(header[12..16].try_into().unwrap());
    let base = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let functions = u32::from_le_bytes(header[20..24].try_into().unwrap());
    let names = u32::from_le_bytes(header[24..28].try_into().unwrap());
    let eat = u32::from_le_bytes(header[28..32].try_into().unwrap());
    let npt = u32::from_le_bytes(header[32..36].try_into().unwrap());
    let ordinals = u32::from_le_bytes(header[36..40].try_into().unwrap());
    if base == 0
        || functions == 0
        || functions as usize > MAX_EXPORT_ENTRIES
        || names > functions
        || names as usize > MAX_EXPORT_ENTRIES
        || name_rva == 0
        || eat == 0
        || (names != 0 && (npt == 0 || ordinals == 0))
    {
        return Ok(None);
    }
    let Some(dll) = read_ascii(mapped, pe, name_rva, MAX_EXPORT_STRING) else {
        return Ok(None);
    };
    let Some(eat_bytes) = rva_slice(
        mapped,
        pe,
        eat,
        usize::try_from(functions.checked_mul(4).context("EAT size overflows")?)?,
    ) else {
        return Ok(None);
    };
    let Some(name_bytes) = rva_slice(
        mapped,
        pe,
        npt,
        usize::try_from(names.checked_mul(4).context("name table size overflows")?)?,
    ) else {
        return Ok(None);
    };
    let Some(ordinal_bytes) = rva_slice(
        mapped,
        pe,
        ordinals,
        usize::try_from(
            names
                .checked_mul(2)
                .context("ordinal table size overflows")?,
        )?,
    ) else {
        return Ok(None);
    };
    let mut closure_end = rva + IMAGE_EXPORT_DIRECTORY_SIZE as u32;
    for end in [
        string_end(mapped, pe, name_rva, MAX_EXPORT_STRING),
        eat.checked_add(functions * 4),
        npt.checked_add(names * 4),
        ordinals.checked_add(names * 2),
    ] {
        let Some(end) = end else {
            return Ok(None);
        };
        closure_end = closure_end.max(end);
    }
    let mut previous = None;
    let mut seen = BTreeSet::new();
    for index in 0..names as usize {
        let name = u32::from_le_bytes(name_bytes[index * 4..index * 4 + 4].try_into().unwrap());
        let ordinal =
            u16::from_le_bytes(ordinal_bytes[index * 2..index * 2 + 2].try_into().unwrap());
        if u32::from(ordinal) >= functions {
            return Ok(None);
        }
        let Some(text) = read_ascii(mapped, pe, name, MAX_EXPORT_STRING) else {
            return Ok(None);
        };
        if previous
            .as_ref()
            .is_some_and(|prior: &String| prior >= &text)
            || !seen.insert(text.clone())
        {
            return Ok(None);
        }
        previous = Some(text);
        let Some(end) = string_end(mapped, pe, name, MAX_EXPORT_STRING) else {
            return Ok(None);
        };
        closure_end = closure_end.max(end);
    }
    for index in 0..functions as usize {
        let target = u32::from_le_bytes(eat_bytes[index * 4..index * 4 + 4].try_into().unwrap());
        if target == 0 {
            continue;
        }
        if pe.section_containing_rva(target).is_none() {
            return Ok(None);
        }
        let forwarder =
            read_ascii(mapped, pe, target, MAX_EXPORT_STRING).filter(|text| valid_forwarder(text));
        if let Some(_) = forwarder {
            let Some(end) = string_end(mapped, pe, target, MAX_EXPORT_STRING) else {
                return Ok(None);
            };
            closure_end = closure_end.max(end);
        } else if target >= rva && target < closure_end {
            return Ok(None);
        }
    }
    let size = closure_end
        .checked_sub(rva)
        .context("export closure underflows")?;
    Ok(Some(ExportCandidate {
        rva,
        size,
        functions,
        names,
        dll,
    }))
}

fn scan_ranges(pe: &Pe) -> Result<Vec<Range<u32>>> {
    pe.sections
        .iter()
        .map(|section| section.virtual_range())
        .collect()
}

fn rva_slice<'a>(mapped: &'a [u8], pe: &Pe, rva: u32, len: usize) -> Option<&'a [u8]> {
    pe.section_for_rva_range(rva, len).ok()?;
    let start = usize::try_from(rva).ok()?;
    mapped.get(start..start.checked_add(len)?)
}

fn read_ascii(mapped: &[u8], pe: &Pe, rva: u32, limit: usize) -> Option<String> {
    let end = string_end(mapped, pe, rva, limit)?;
    let start = usize::try_from(rva).ok()?;
    let bytes = mapped.get(start..usize::try_from(end.checked_sub(1)?).ok()?)?;
    (!bytes.is_empty() && bytes.iter().all(|byte| printable(*byte)))
        .then(|| String::from_utf8(bytes.to_vec()).ok())
        .flatten()
}

fn valid_forwarder(value: &str) -> bool {
    let Some((module, symbol)) = value.rsplit_once('.') else {
        return false;
    };
    if module.is_empty() || !module.bytes().all(printable) || symbol.is_empty() {
        return false;
    }
    match symbol.strip_prefix('#') {
        Some(ordinal) => !ordinal.is_empty() && ordinal.bytes().all(|byte| byte.is_ascii_digit()),
        None => symbol.bytes().all(printable),
    }
}

fn string_end(mapped: &[u8], pe: &Pe, rva: u32, limit: usize) -> Option<u32> {
    let section = pe.section_containing_rva(rva)?;
    let end = section.virtual_range().ok()?.end;
    let bounded = end.min(rva.checked_add(u32::try_from(limit).ok()?)?);
    let start = usize::try_from(rva).ok()?;
    let finish = usize::try_from(bounded).ok()?;
    let bytes = mapped.get(start..finish)?;
    let index = bytes.iter().position(|byte| *byte == 0)?;
    (index != 0).then(|| rva + index as u32 + 1)
}

fn put_u32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    pe::write_u32(data, offset, value)
}
fn put_pointer(pe: &Pe, data: &mut [u8], offset: usize, value: u64) -> Result<()> {
    pe.write_pointer(data, offset, value)
}
fn ordinal_flag(width: PointerWidth) -> u64 {
    match width {
        PointerWidth::U32 => 0x8000_0000,
        PointerWidth::U64 => 0x8000_0000_0000_0000,
    }
}
fn placed_rva(base: u32, offset: usize) -> Result<u32> {
    base.checked_add(u32::try_from(offset)?)
        .context("metadata RVA overflows")
}
fn align(value: usize, alignment: usize) -> Result<usize> {
    value
        .checked_add(alignment - 1)
        .context("layout alignment overflows")
        .map(|value| value / alignment * alignment)
}
fn printable(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte)
}
