use std::collections::BTreeSet;
use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pe::{self, DataDirectory, Machine, Pe, PointerWidth};
use crate::unpack::imports::{ImportModule, ImportSymbol, LoaderDiscovery, named_thunk_rva};
use crate::unpack::profile::{OutputEntry, validate_amd64_exception_directory};

const EXPORT_DIRECTORY: usize = 0;
const IMPORT_DIRECTORY: usize = 1;
const EXCEPTION_DIRECTORY: usize = 3;
const SECURITY_DIRECTORY: usize = 4;
const BASE_RELOCATION_DIRECTORY: usize = 5;
const IMAGE_IMPORT_DESCRIPTOR_SIZE: usize = 20;
const IMAGE_EXPORT_DIRECTORY_SIZE: usize = 40;
const IAT_DIRECTORY: usize = 12;
const DELAY_IMPORT_DIRECTORY: usize = 13;
#[cfg(test)]
mod tests;
const MAX_IMPORT_MODULES: usize = 4_096;
const MAX_IMPORT_THUNKS: usize = 1_000_000;
const MAX_IMPORT_STRING: usize = 4_096;
const MAX_EXPORT_ENTRIES: usize = 1_000_000;
const MAX_EXPORT_STRING: usize = 4_096;
const IMPORT_SECTION_CHARACTERISTICS: u32 = 0xc030_0040;
const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const BASE_RELOCATION_BLOCK_HEADER_SIZE: usize = 8;
const DELAY_IMPORT_DESCRIPTOR_SIZE: usize = 32;
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const MAX_SCAN_STARTS: usize = 1 << 27;
const MAX_SCAN_CANDIDATES: usize = 4_096;
const MAX_SCAN_NESTED_WORK: usize = 16_000_000;

/// The immutable handoff from packer-specific recovery to PE serialization.
/// Import and export directory headers are never reconstruction authority;
/// other directory headers are retained only after dedicated validation.
pub(crate) struct ReconstructionInput {
    pub(crate) mapped: Vec<u8>,
    pub(crate) decrypted_pe: Pe,
    pub(crate) output_entry: OutputEntry,
    pub(crate) discovery: LoaderDiscovery,
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
/// Directory locations are recovered from section bytes, not inherited from
/// either the packed or provisional header. The canonical CrackProof loader
/// graph is normalized into a fresh standard import table in a new section.
pub(crate) fn rebuild(input: ReconstructionInput) -> Result<Vec<u8>> {
    let ReconstructionInput {
        mut mapped,
        decrypted_pe,
        output_entry,
        discovery,
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

    clear_iat_cells(&mut mapped, &decrypted_pe, &discovery)?;
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
        ensure!(
            module.destination_rva.is_multiple_of(4),
            "IAT is not DWORD aligned"
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

fn clear_iat_cells(mapped: &mut [u8], pe: &Pe, discovery: &LoaderDiscovery) -> Result<()> {
    let width = pe.pointer_width().bytes();
    for module in &discovery.modules {
        let bytes = (module.symbols.len() + 1)
            .checked_mul(width)
            .context("IAT clearing length overflows")?;
        let start = usize::try_from(module.destination_rva)?;
        let end = start
            .checked_add(bytes)
            .context("IAT clearing range overflows")?;
        mapped
            .get_mut(start..end)
            .context("IAT clearing range exceeds mapped image")?
            .fill(0);
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
            layout.raw_pointer,
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
        import_layout.raw_pointer,
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
        if directory.is_empty()
            || matches!(
                index,
                EXPORT_DIRECTORY | IMPORT_DIRECTORY | SECURITY_DIRECTORY | 11 | IAT_DIRECTORY
            )
        {
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
        EXCEPTION_DIRECTORY => {
            ensure!(
                pe.machine_kind() == Machine::Amd64,
                "nonempty Exception Directory is only supported for AMD64 images"
            );
            validate_amd64_exception_directory(mapped, pe)
        }
        BASE_RELOCATION_DIRECTORY => validate_base_relocation_directory(mapped, pe, directory),
        6 => validate_debug_directory(mapped, pe, directory),
        9 => validate_tls_directory(mapped, pe, directory),
        DELAY_IMPORT_DIRECTORY => validate_delay_import_directory(mapped, pe, directory),
        14 => validate_clr_directory(mapped, pe, directory),
        _ => bail!("nonempty unsupported data directory {index}"),
    }
}
fn validate_base_relocation_directory(
    mapped: &[u8],
    pe: &Pe,
    directory: DataDirectory,
) -> Result<()> {
    let bytes = rva_slice(
        mapped,
        pe,
        directory.virtual_address,
        usize::try_from(directory.size)?,
    )
    .context("Base Relocation Directory is not section-backed")?;
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let header_end = cursor
            .checked_add(BASE_RELOCATION_BLOCK_HEADER_SIZE)
            .context("base-relocation block header overflows")?;
        ensure!(
            header_end <= bytes.len(),
            "Base Relocation Directory has a truncated block header"
        );
        let page_rva = u32_at(bytes, cursor)?;
        let block_size = usize::try_from(u32_at(bytes, cursor + 4)?)?;
        ensure!(
            page_rva.is_multiple_of(0x1000),
            "base-relocation block at directory offset {cursor:#x} has unaligned page RVA {page_rva:#x}"
        );
        ensure!(
            block_size >= BASE_RELOCATION_BLOCK_HEADER_SIZE && block_size.is_multiple_of(2),
            "base-relocation block at directory offset {cursor:#x} has invalid size {block_size:#x}"
        );
        let block_end = cursor
            .checked_add(block_size)
            .context("base-relocation block range overflows")?;
        ensure!(
            block_end <= bytes.len(),
            "base-relocation block exceeds its directory"
        );
        for entry_offset in (header_end..block_end).step_by(2) {
            let entry = u16::from_le_bytes(
                bytes[entry_offset..entry_offset + 2]
                    .try_into()
                    .expect("bounded base-relocation entry"),
            );
            let kind = entry >> 12;
            if kind == IMAGE_REL_BASED_ABSOLUTE {
                continue;
            }
            let width = match (pe.machine_kind(), kind) {
                (Machine::I386, IMAGE_REL_BASED_HIGHLOW) => 4,
                (Machine::Amd64, IMAGE_REL_BASED_DIR64) => 8,
                (machine, kind) => {
                    bail!("unsupported base-relocation type {kind} for {machine:?}")
                }
            };
            let target_rva = page_rva
                .checked_add(u32::from(entry & 0x0fff))
                .context("base-relocation target RVA overflows")?;
            pe.section_for_rva_range(target_rva, width)
                .context("base-relocation target is not section-backed")?;
            let target = usize::try_from(target_rva)?;
            mapped
                .get(target..target + width)
                .context("base-relocation target exceeds mapped image")?;
        }
        cursor = block_end;
    }
    Ok(())
}
fn validate_delay_import_directory(mapped: &[u8], pe: &Pe, directory: DataDirectory) -> Result<()> {
    let size = usize::try_from(directory.size)?;
    ensure!(
        size.is_multiple_of(DELAY_IMPORT_DESCRIPTOR_SIZE),
        "Delay Import Directory is not a sequence of descriptors"
    );
    let count = size / DELAY_IMPORT_DESCRIPTOR_SIZE;
    ensure!(
        count <= MAX_IMPORT_MODULES,
        "Delay Import Directory exceeds the module cap"
    );
    let descriptors = rva_slice(mapped, pe, directory.virtual_address, size)
        .context("Delay Import Directory is not section-backed")?;
    let mut budget = ScanBudget::default();
    let mut terminated = false;
    for index in 0..count {
        let offset = index * DELAY_IMPORT_DESCRIPTOR_SIZE;
        let descriptor = &descriptors[offset..offset + DELAY_IMPORT_DESCRIPTOR_SIZE];
        if descriptor.iter().all(|byte| *byte == 0) {
            ensure!(
                descriptors[offset..].iter().all(|byte| *byte == 0),
                "Delay Import Directory has data after its terminator"
            );
            terminated = true;
            break;
        }
        let attributes = u32_at(descriptor, 0)?;
        ensure!(
            attributes == 1,
            "delay-import descriptor {index} does not use RVA-based fields"
        );
        let name_rva = u32_at(descriptor, 4)?;
        let module_handle_rva = u32_at(descriptor, 8)?;
        let iat_rva = u32_at(descriptor, 12)?;
        let int_rva = u32_at(descriptor, 16)?;
        ensure!(
            name_rva != 0 && module_handle_rva != 0 && iat_rva != 0 && int_rva != 0,
            "delay-import descriptor {index} has a null required RVA"
        );
        read_ascii(mapped, pe, name_rva, MAX_IMPORT_STRING)
            .with_context(|| format!("delay-import descriptor {index} has an invalid DLL name"))?;
        let (symbols, _) = parse_thunks(mapped, pe, int_rva, &mut budget)?.with_context(|| {
            format!("delay-import descriptor {index} has an invalid name table")
        })?;
        let width = pe.pointer_width().bytes();
        let thunk_bytes = symbols
            .len()
            .checked_add(1)
            .and_then(|count| count.checked_mul(width))
            .context("delay-import thunk span overflows")?;
        let validate_span = |rva: u32, len: usize, field: &str| -> Result<()> {
            ensure!(
                rva.is_multiple_of(u32::try_from(width)?),
                "delay-import descriptor {index} has an unaligned {field}"
            );
            pe.section_for_rva_range(rva, len).with_context(|| {
                format!("delay-import descriptor {index} has an invalid {field}")
            })?;
            let start = usize::try_from(rva)?;
            mapped.get(start..start + len).with_context(|| {
                format!("delay-import descriptor {index} {field} exceeds the mapped image")
            })?;
            Ok(())
        };
        validate_span(module_handle_rva, width, "module handle cell")?;
        validate_span(iat_rva, thunk_bytes, "IAT")?;
        for (field_offset, field_name) in [(20, "bound IAT"), (24, "unload IAT")] {
            let rva = u32_at(descriptor, field_offset)?;
            if rva != 0 {
                validate_span(rva, thunk_bytes, field_name)?;
            }
        }
    }
    ensure!(terminated, "Delay Import Directory has no null terminator");
    Ok(())
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
    if let (Some(start), Some(end)) = (start, end) {
        ensure!(end >= start, "TLS raw-data range is inverted");
        rva_slice(mapped, pe, start, usize::try_from(end - start)?)
            .context("TLS raw-data range is invalid")?;
    }
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
            pe.section_for_rva_range(target, 1)?;
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
