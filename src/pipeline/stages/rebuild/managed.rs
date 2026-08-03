//! Generic semantic reconstruction for CrackProof-managed DLL payloads.
//!
//! CrackProof leaves an AMD64 or I386 native loader prefix in front of a valid
//! CLR payload. Reconstruction discards only that authenticated prefix, keeps
//! every CLR-owned mapped section at its original RVA, and appends fresh PE32
//! `_CorDllMain` import, bootstrap, and relocation sections.

use std::ops::Range;

use anyhow::{Context, Result, bail, ensure};

use crate::pe::{self, DataDirectory, Machine, Pe, pe_checksum};
use crate::pipeline::outcome::{GeneratedSemanticClrContainer, ManagedSemanticClrSource};
use crate::pipeline::stages::imports::LoaderDiscovery;

const FILE_ALIGNMENT: u32 = 0x200;
const DIRECTORY_COUNT: usize = 16;
const COR20_DIRECTORY: usize = 14;
const RESOURCE_DIRECTORY: usize = 2;
const DEBUG_DIRECTORY: usize = 6;
const IMPORT_DIRECTORY: usize = 1;
const BASE_RELOCATION_DIRECTORY: usize = 5;
const IAT_DIRECTORY: usize = 12;
const COR20_MIN_SIZE: u32 = 72;
const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x0000_0010;
const KNOWN_COR20_FLAGS: u32 = 0x0003_001f;
const OUTPUT_IMAGE_BASE: u32 = 0x1000_0000;
const PE_OFFSET: usize = 0x80;
const OPTIONAL_OFFSET: usize = PE_OFFSET + 4 + 20;
const SECTION_TABLE_OFFSET: usize = OPTIONAL_OFFSET + 0xe0;
const SECTION_HEADER_SIZE: usize = 40;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMPORT_CHARACTERISTICS: u32 = 0xc000_0040;
const STUB_CHARACTERISTICS: u32 = 0x6000_0020;
const RELOC_CHARACTERISTICS: u32 = 0x4200_0040;

#[derive(Clone, Copy, Debug)]
struct ClrLayout {
    cor20: DataDirectory,
    metadata: DataDirectory,
    source_flags: u32,
}

#[derive(Clone, Copy, Debug)]
struct SourceProfile {
    payload_start: u32,
    clr: ClrLayout,
    resource: Option<DataDirectory>,
    debug: Option<DataDirectory>,
}

#[derive(Debug)]
enum SectionPayload {
    Source(Range<u32>),
    Generated(Vec<u8>),
}

#[derive(Debug)]
struct OutputSection {
    name: [u8; 8],
    virtual_address: u32,
    virtual_size: u32,
    raw_pointer: u32,
    raw_size: u32,
    characteristics: u32,
    payload: SectionPayload,
}

pub(crate) struct ManagedRebuild {
    pub(crate) output: Vec<u8>,
    pub(crate) generated: GeneratedSemanticClrContainer,
    pub(crate) source: ManagedSemanticClrSource,
}

fn range(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    data.get(offset..offset.checked_add(length).context("range overflow")?)
        .context("range exceeds image")
}

fn range_mut(data: &mut [u8], offset: usize, length: usize) -> Result<&mut [u8]> {
    data.get_mut(offset..offset.checked_add(length).context("range overflow")?)
        .context("range exceeds output")
}

fn get16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        range(data, offset, 2)?.try_into().expect("two bytes"),
    ))
}

fn get32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        range(data, offset, 4)?.try_into().expect("four bytes"),
    ))
}

fn put16(data: &mut [u8], offset: usize, value: u16) -> Result<()> {
    range_mut(data, offset, 2)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    range_mut(data, offset, 4)?.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn directory_at(image: &[u8], offset: usize) -> Result<DataDirectory> {
    Ok(DataDirectory {
        virtual_address: get32(image, offset)?,
        size: get32(image, offset + 4)?,
    })
}

fn validate_subdirectory(
    mapped: &[u8],
    pe: &Pe,
    directory: DataDirectory,
    label: &str,
) -> Result<()> {
    let Some(span) = directory.checked_rva_range()? else {
        return Ok(());
    };
    pe.section_for_rva_range(span.start, usize::try_from(span.end - span.start)?)
        .with_context(|| format!("CLR {label} directory is not section-backed"))?;
    range(
        mapped,
        usize::try_from(span.start)?,
        usize::try_from(span.end - span.start)?,
    )
    .with_context(|| format!("CLR {label} directory exceeds mapped image"))?;
    Ok(())
}

/// Validates the dynamic COR20/metadata contract without pinning any sample
/// address, section count, runtime version, or optional managed resource.
fn validate_clr_container(mapped: &[u8], pe: &Pe) -> Result<ClrLayout> {
    ensure!(pe.is_dll(), "semantic CLR reconstruction requires a DLL");
    let cor20 = pe
        .directory(COR20_DIRECTORY)
        .context("reading COM Descriptor")?;
    let cor20_span = cor20
        .checked_rva_range()?
        .context("COM Descriptor is empty")?;
    ensure!(cor20.size >= COR20_MIN_SIZE, "COR20 header is truncated");
    pe.section_for_rva_range(
        cor20_span.start,
        usize::try_from(cor20_span.end - cor20_span.start)?,
    )
    .context("COR20 header is not section-backed")?;
    let cor20_offset = usize::try_from(cor20.virtual_address)?;
    let header = range(mapped, cor20_offset, usize::try_from(cor20.size)?)?;
    let header_size = get32(header, 0)?;
    ensure!(
        (COR20_MIN_SIZE..=cor20.size).contains(&header_size),
        "COR20 cb is invalid"
    );
    ensure!(
        get16(header, 4)? != 0,
        "COR20 runtime major version is zero"
    );

    let metadata = directory_at(header, 8)?;
    let metadata_span = metadata
        .checked_rva_range()?
        .context("CLR metadata directory is empty")?;
    ensure!(metadata.size >= 16, "CLR metadata is truncated");
    validate_subdirectory(mapped, pe, metadata, "metadata")?;
    ensure!(
        range(mapped, usize::try_from(metadata_span.start)?, 4)? == b"BSJB",
        "CLR metadata signature is invalid"
    );

    let source_flags = get32(header, 16)?;
    ensure!(
        source_flags & !KNOWN_COR20_FLAGS == 0,
        "COR20 header contains unknown flags {source_flags:#x}"
    );
    ensure!(
        source_flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT == 0 && get32(header, 20)? == 0,
        "managed DLL has a native or managed entry point"
    );

    let resources = directory_at(header, 24)?;
    let strong_name = directory_at(header, 32)?;
    validate_subdirectory(mapped, pe, resources, "resources")?;
    validate_subdirectory(mapped, pe, strong_name, "strong-name signature")?;
    for (offset, label) in [
        (40, "code-manager table"),
        (48, "VTableFixups"),
        (56, "export-address jumps"),
        (64, "managed-native header"),
    ] {
        ensure!(
            directory_at(header, offset)?.is_empty(),
            "CLR {label} is unsupported by an architecture-neutral semantic rebuild"
        );
    }

    crate::pipeline::stages::rebuild::clr::authenticated_method_defs(
        mapped,
        pe,
        usize::try_from(metadata.virtual_address)?,
        usize::try_from(metadata.size)?,
    )?;
    Ok(ClrLayout {
        cor20,
        metadata,
        source_flags,
    })
}

fn directory_entirely_before(directory: DataDirectory, boundary: u32) -> Result<bool> {
    Ok(directory
        .checked_rva_range()?
        .is_some_and(|span| span.end <= boundary))
}

/// Proves the CrackProof-native prefix boundary while allowing arbitrary CLR
/// sizes, section layouts, loader symbols, resources, and metadata addresses.
fn authenticate_source(
    mapped: &[u8],
    pe: &Pe,
    discovery: &LoaderDiscovery,
) -> Result<SourceProfile> {
    ensure!(
        mapped.len() == usize::try_from(pe.size_of_image)?,
        "managed mapped length differs from SizeOfImage"
    );
    ensure!(pe.is_dll(), "managed source is not a DLL");
    ensure!(
        discovery.image_size == pe.size_of_image,
        "managed loader graph image size mismatch"
    );
    ensure!(
        pe.directories.len() >= DIRECTORY_COUNT,
        "managed source has fewer than 16 data-directory slots"
    );
    let clr = validate_clr_container(mapped, pe)?;
    let first = pe
        .sections
        .first()
        .context("managed source has no sections")?;
    let cor20_section = pe
        .section_for_rva_range(clr.cor20.virtual_address, usize::try_from(clr.cor20.size)?)
        .context("locating COR20 source section")?;
    ensure!(
        cor20_section.index == first.index,
        "COR20 header is not in the first mapped section"
    );
    let payload_start = clr.cor20.virtual_address & !(pe.section_alignment - 1);
    let first_span = first.virtual_range()?;
    ensure!(
        first_span.contains(&payload_start),
        "CLR payload boundary is outside the first section"
    );
    ensure!(
        pe.entry_rva < payload_start,
        "native source entry is not confined to the CrackProof prefix"
    );
    ensure!(
        discovery.table_rva < payload_start,
        "native source import table is not confined to the CrackProof prefix"
    );
    for metadata in &discovery.metadata_ranges {
        ensure!(
            metadata.end <= payload_start,
            "native loader metadata crosses the CLR payload boundary"
        );
    }
    let pointer_width = u32::try_from(pe.pointer_width().bytes())?;
    for module in &discovery.modules {
        let cells = u32::try_from(module.symbols.len())?
            .checked_add(1)
            .context("native source IAT cell count overflows")?;
        let iat_end = module
            .destination_rva
            .checked_add(
                cells
                    .checked_mul(pointer_width)
                    .context("native source IAT size overflows")?,
            )
            .context("native source IAT end overflows")?;
        ensure!(
            iat_end <= payload_start,
            "native source IAT crosses the CLR payload boundary"
        );
    }

    let mut resource = None;
    let mut debug = None;
    for (index, directory) in pe.directories.iter().copied().enumerate() {
        if directory.is_empty() {
            continue;
        }
        match index {
            IMPORT_DIRECTORY | IAT_DIRECTORY => ensure!(
                directory_entirely_before(directory, payload_start)?,
                "native source import directory crosses the CLR payload boundary"
            ),
            RESOURCE_DIRECTORY => {
                let recovered = super::scan_resource_root(mapped, pe)?
                    .context("nonempty managed Resource Directory has no unique valid root")?;
                ensure!(
                    !directory_entirely_before(recovered, payload_start)?,
                    "managed Resource Directory lies in the discarded native prefix"
                );
                resource = Some(recovered);
            }
            DEBUG_DIRECTORY => {
                super::validate_debug_directory(mapped, pe, directory)?;
                ensure!(
                    !directory_entirely_before(directory, payload_start)?,
                    "managed Debug Directory lies in the discarded native prefix"
                );
                debug = Some(directory);
            }
            COR20_DIRECTORY => {}
            4 => bail!("managed source has a nonempty Security Directory in mapped state"),
            _ => ensure!(
                directory_entirely_before(directory, payload_start)?,
                "managed payload contains unsupported native data directory {index}"
            ),
        }
    }
    Ok(SourceProfile {
        payload_start,
        clr,
        resource,
        debug,
    })
}

fn import_payload(import_rva: u32, iat_rva: u32) -> Result<Vec<u8>> {
    const DESCRIPTOR_BYTES: usize = 40;
    const ILT_OFFSET: u32 = 40;
    const IAT_OFFSET: u32 = 48;
    const DLL_OFFSET: u32 = 56;
    const NAME_OFFSET: u32 = 68;
    let mut payload = vec![0; 82];
    put32(&mut payload, 0, import_rva + ILT_OFFSET)?;
    put32(&mut payload, 12, import_rva + DLL_OFFSET)?;
    put32(&mut payload, 16, iat_rva)?;
    put32(
        &mut payload,
        usize::try_from(ILT_OFFSET)?,
        import_rva + NAME_OFFSET,
    )?;
    put32(
        &mut payload,
        usize::try_from(IAT_OFFSET)?,
        import_rva + NAME_OFFSET,
    )?;
    range_mut(&mut payload, usize::try_from(DLL_OFFSET)?, 12)?.copy_from_slice(b"mscoree.dll\0");
    put16(&mut payload, usize::try_from(NAME_OFFSET)?, 0)?;
    range_mut(&mut payload, usize::try_from(NAME_OFFSET + 2)?, 12)?
        .copy_from_slice(b"_CorDllMain\0");
    ensure!(
        payload[20..DESCRIPTOR_BYTES].iter().all(|byte| *byte == 0),
        "generated import terminator is nonzero"
    );
    Ok(payload)
}

fn stub_payload(iat_rva: u32) -> Result<Vec<u8>> {
    let iat_va = OUTPUT_IMAGE_BASE
        .checked_add(iat_rva)
        .context("generated IAT VA overflows PE32")?;
    let mut stub = vec![0xff, 0x25, 0, 0, 0, 0];
    stub[2..6].copy_from_slice(&iat_va.to_le_bytes());
    Ok(stub)
}

fn relocation_payload(stub_rva: u32) -> Result<Vec<u8>> {
    let relocated_rva = stub_rva
        .checked_add(2)
        .context("generated stub relocation RVA overflows")?;
    let page = relocated_rva & !0xfff;
    let offset = u16::try_from(relocated_rva - page)?;
    let mut reloc = vec![0; 12];
    put32(&mut reloc, 0, page)?;
    put32(&mut reloc, 4, 12)?;
    put16(&mut reloc, 8, 0x3000 | offset)?;
    Ok(reloc)
}

fn source_sections(mapped: &[u8], pe: &Pe, payload_start: u32) -> Result<Vec<OutputSection>> {
    let mut sections = Vec::with_capacity(pe.sections.len());
    for (position, source) in pe.sections.iter().enumerate() {
        let source_span = source.virtual_range()?;
        let start = if position == 0 {
            payload_start
        } else {
            source_span.start
        };
        ensure!(start < source_span.end, "retained managed section is empty");
        let span = start..source_span.end;
        range(
            mapped,
            usize::try_from(span.start)?,
            usize::try_from(span.end - span.start)?,
        )?;
        sections.push(OutputSection {
            name: source.name_bytes,
            virtual_address: span.start,
            virtual_size: span.end - span.start,
            raw_pointer: 0,
            raw_size: 0,
            characteristics: source.characteristics,
            payload: SectionPayload::Source(span),
        });
    }
    Ok(sections)
}

fn push_generated_section(
    sections: &mut Vec<OutputSection>,
    name: [u8; 8],
    rva: u32,
    characteristics: u32,
    payload: Vec<u8>,
) -> Result<()> {
    sections.push(OutputSection {
        name,
        virtual_address: rva,
        virtual_size: u32::try_from(payload.len())?,
        raw_pointer: 0,
        raw_size: 0,
        characteristics,
        payload: SectionPayload::Generated(payload),
    });
    Ok(())
}

fn payload_len(section: &OutputSection) -> Result<u32> {
    match &section.payload {
        SectionPayload::Source(span) => Ok(span.end - span.start),
        SectionPayload::Generated(bytes) => {
            u32::try_from(bytes.len()).context("section payload exceeds u32")
        }
    }
}

fn layout_raw_sections(sections: &mut [OutputSection], header_size: u32) -> Result<u32> {
    let mut cursor = header_size;
    for section in sections {
        section.raw_pointer = cursor;
        section.raw_size = pe::align_up(payload_len(section)?, FILE_ALIGNMENT)?;
        cursor = cursor
            .checked_add(section.raw_size)
            .context("managed output raw layout overflows")?;
    }
    Ok(cursor)
}

fn write_section_header(output: &mut [u8], offset: usize, section: &OutputSection) -> Result<()> {
    let header = range_mut(output, offset, SECTION_HEADER_SIZE)?;
    header.fill(0);
    header[..8].copy_from_slice(&section.name);
    header[8..12].copy_from_slice(&section.virtual_size.to_le_bytes());
    header[12..16].copy_from_slice(&section.virtual_address.to_le_bytes());
    header[16..20].copy_from_slice(&section.raw_size.to_le_bytes());
    header[20..24].copy_from_slice(&section.raw_pointer.to_le_bytes());
    header[36..40].copy_from_slice(&section.characteristics.to_le_bytes());
    Ok(())
}

fn write_directory(output: &mut [u8], index: usize, directory: DataDirectory) -> Result<()> {
    let offset = OPTIONAL_OFFSET
        .checked_add(96)
        .and_then(|table| table.checked_add(index.checked_mul(8)?))
        .context("generated data-directory offset overflows")?;
    put32(output, offset, directory.virtual_address)?;
    put32(output, offset + 4, directory.size)
}

fn output_header_size(section_count: usize) -> Result<u32> {
    let section_table_end = SECTION_TABLE_OFFSET
        .checked_add(
            section_count
                .checked_mul(SECTION_HEADER_SIZE)
                .context("section table size overflows")?,
        )
        .context("section table end overflows")?;
    pe::align_up(u32::try_from(section_table_end)?, FILE_ALIGNMENT)
}

fn write_headers(
    output: &mut [u8],
    source: &[u8],
    pe: &Pe,
    sections: &[OutputSection],
    image_size: u32,
    entry_rva: u32,
    directories: &[(usize, DataDirectory)],
) -> Result<()> {
    let header_size = output_header_size(sections.len())?;
    range_mut(output, 0, usize::try_from(header_size)?)?.fill(0);
    output[..2].copy_from_slice(b"MZ");
    put32(output, 0x3c, u32::try_from(PE_OFFSET)?)?;
    range_mut(output, PE_OFFSET, 4)?.copy_from_slice(b"PE\0\0");
    let coff = PE_OFFSET + 4;
    put16(output, coff, 0x14c)?;
    put16(output, coff + 2, u16::try_from(sections.len())?)?;
    put16(output, coff + 16, 0xe0)?;
    put16(output, coff + 18, 0x2102)?;

    put16(output, OPTIONAL_OFFSET, 0x10b)?;
    let mut code_size = 0u32;
    let mut initialized_size = 0u32;
    let mut uninitialized_size = 0u32;
    for section in sections {
        if section.characteristics & IMAGE_SCN_CNT_CODE != 0 {
            code_size = code_size
                .checked_add(section.raw_size)
                .context("SizeOfCode overflows")?;
        }
        if section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            initialized_size = initialized_size
                .checked_add(section.raw_size)
                .context("SizeOfInitializedData overflows")?;
        }
        if section.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            uninitialized_size = uninitialized_size
                .checked_add(section.virtual_size)
                .context("SizeOfUninitializedData overflows")?;
        }
    }
    put32(output, OPTIONAL_OFFSET + 4, code_size)?;
    put32(output, OPTIONAL_OFFSET + 8, initialized_size)?;
    put32(output, OPTIONAL_OFFSET + 12, uninitialized_size)?;
    put32(output, OPTIONAL_OFFSET + 16, entry_rva)?;
    let base_of_code = sections
        .iter()
        .find(|section| section.characteristics & IMAGE_SCN_CNT_CODE != 0)
        .map(|section| section.virtual_address)
        .context("generated managed output has no code section")?;
    let base_of_data = sections
        .iter()
        .find(|section| {
            section.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
                && section.characteristics & IMAGE_SCN_CNT_CODE == 0
        })
        .map(|section| section.virtual_address)
        .unwrap_or(base_of_code);
    put32(output, OPTIONAL_OFFSET + 20, base_of_code)?;
    put32(output, OPTIONAL_OFFSET + 24, base_of_data)?;
    put32(output, OPTIONAL_OFFSET + 28, OUTPUT_IMAGE_BASE)?;
    put32(output, OPTIONAL_OFFSET + 32, pe.section_alignment)?;
    put32(output, OPTIONAL_OFFSET + 36, FILE_ALIGNMENT)?;
    put16(output, OPTIONAL_OFFSET + 40, 4)?;
    put16(output, OPTIONAL_OFFSET + 48, 4)?;
    put32(output, OPTIONAL_OFFSET + 56, image_size)?;
    put32(output, OPTIONAL_OFFSET + 60, header_size)?;
    put16(output, OPTIONAL_OFFSET + 68, get16(source, pe.opt + 68)?)?;
    put16(output, OPTIONAL_OFFSET + 70, get16(source, pe.opt + 70)?)?;
    put32(output, OPTIONAL_OFFSET + 72, 0x10_0000)?;
    put32(output, OPTIONAL_OFFSET + 76, 0x1000)?;
    put32(output, OPTIONAL_OFFSET + 80, 0x10_0000)?;
    put32(output, OPTIONAL_OFFSET + 84, 0x1000)?;
    put32(output, OPTIONAL_OFFSET + 92, DIRECTORY_COUNT as u32)?;
    for &(index, directory) in directories {
        write_directory(output, index, directory)?;
    }
    for (index, section) in sections.iter().enumerate() {
        write_section_header(
            output,
            SECTION_TABLE_OFFSET + index * SECTION_HEADER_SIZE,
            section,
        )?;
    }
    Ok(())
}

fn copy_sections(output: &mut [u8], mapped: &[u8], sections: &[OutputSection]) -> Result<()> {
    for section in sections {
        let payload = match &section.payload {
            SectionPayload::Source(span) => range(
                mapped,
                usize::try_from(span.start)?,
                usize::try_from(span.end - span.start)?,
            )?,
            SectionPayload::Generated(bytes) => bytes,
        };
        range_mut(output, usize::try_from(section.raw_pointer)?, payload.len())?
            .copy_from_slice(payload);
    }
    Ok(())
}

fn file_offset_for_rva(sections: &[OutputSection], rva: u32) -> Result<u32> {
    let section = sections
        .iter()
        .find(|section| {
            rva >= section.virtual_address
                && rva < section.virtual_address.saturating_add(section.virtual_size)
        })
        .context("RVA is not backed by an output section")?;
    section
        .raw_pointer
        .checked_add(rva - section.virtual_address)
        .context("output file offset overflows")
}

fn rewrite_debug_pointers(
    output: &mut [u8],
    sections: &[OutputSection],
    directory: DataDirectory,
) -> Result<Vec<Range<u32>>> {
    ensure!(
        directory.size.is_multiple_of(28),
        "Debug Directory has a partial record"
    );
    let mut changed = Vec::new();
    for index in 0..directory.size / 28 {
        let record_rva = directory
            .virtual_address
            .checked_add(
                index
                    .checked_mul(28)
                    .context("debug record RVA overflows")?,
            )
            .context("debug record RVA overflows")?;
        let record_offset = usize::try_from(file_offset_for_rva(sections, record_rva)?)?;
        let size = get32(output, record_offset + 16)?;
        let address = get32(output, record_offset + 20)?;
        let pointer = if size == 0 && address == 0 {
            0
        } else {
            ensure!(
                size != 0 && address != 0,
                "debug record has a partial payload range"
            );
            file_offset_for_rva(sections, address)?
        };
        put32(output, record_offset + 24, pointer)?;
        changed.push(record_rva + 24..record_rva + 28);
    }
    Ok(changed)
}

fn changed_rva(rva: u32, changes: &[Range<u32>]) -> bool {
    changes.iter().any(|change| change.contains(&rva))
}

fn verify_output(
    output: &[u8],
    mapped: &[u8],
    source_pe: &Pe,
    source_profile: SourceProfile,
    source_sections: &[Range<u32>],
    generated: &GeneratedSemanticClrContainer,
    changes: &[Range<u32>],
) -> Result<()> {
    let pe = Pe::parse(output).context("parsing generated semantic CLR container")?;
    ensure!(
        pe.machine_kind() == Machine::I386 && pe.is_dll(),
        "generated semantic CLR container is not a PE32/I386 DLL"
    );
    ensure!(
        pe.entry_rva == generated.entry_rva,
        "generated CLR entry RVA mismatch"
    );
    ensure!(
        pe.directory(IMPORT_DIRECTORY)?
            == DataDirectory {
                virtual_address: generated.import_rva,
                size: 40,
            },
        "generated CLR import directory mismatch"
    );
    ensure!(
        pe.directory(IAT_DIRECTORY)?
            == DataDirectory {
                virtual_address: generated.iat_rva,
                size: 8,
            },
        "generated CLR IAT directory mismatch"
    );
    ensure!(
        pe.directory(BASE_RELOCATION_DIRECTORY)?
            == DataDirectory {
                virtual_address: generated.reloc_rva,
                size: 12,
            },
        "generated CLR relocation directory mismatch"
    );
    ensure!(
        pe.directory(COR20_DIRECTORY)? == source_profile.clr.cor20,
        "generated COR20 directory differs from source"
    );
    let remapped = pe
        .map_image(output)
        .context("mapping generated semantic CLR container")?;
    let mut permitted_changes = changes.to_vec();
    permitted_changes.push(
        source_profile.clr.cor20.virtual_address + 16
            ..source_profile.clr.cor20.virtual_address + 20,
    );
    for span in source_sections {
        for rva in span.clone() {
            if changed_rva(rva, &permitted_changes) {
                continue;
            }
            ensure!(
                remapped[usize::try_from(rva)?] == mapped[usize::try_from(rva)?],
                "generated output changes retained source byte at RVA {rva:#x}"
            );
        }
    }
    let rebuilt_clr = validate_clr_container(&remapped, &pe)?;
    ensure!(
        rebuilt_clr.metadata == source_profile.clr.metadata
            && rebuilt_clr.source_flags
                == (source_profile.clr.source_flags | COMIMAGE_FLAGS_ILONLY),
        "generated CLR metadata/flags contract mismatch"
    );
    ensure!(
        get32(output, pe.checksum_offset)? == pe_checksum(output, pe.checksum_offset)?,
        "generated CLR checksum mismatch"
    );
    ensure!(
        source_pe.section_alignment == pe.section_alignment,
        "generated CLR section alignment changed"
    );
    Ok(())
}

fn source_architecture(machine: Machine) -> &'static str {
    match machine {
        Machine::I386 => "PE32/I386",
        Machine::Amd64 => "PE32+/AMD64",
    }
}

/// Emits a deterministic PE32 CLR DLL after authenticating only structural
/// CrackProof-prefix and ECMA-335 invariants. No sample RVA, section size,
/// import symbol, resource shape, or metadata address is assumed.
pub(crate) fn rebuild_semantic_clr(
    mapped: &[u8],
    pe: &Pe,
    discovery: &LoaderDiscovery,
) -> Result<ManagedRebuild> {
    let source_profile = authenticate_source(mapped, pe, discovery)?;
    let mut sections = source_sections(mapped, pe, source_profile.payload_start)?;
    let source_ranges = sections
        .iter()
        .map(|section| match &section.payload {
            SectionPayload::Source(span) => span.clone(),
            SectionPayload::Generated(_) => unreachable!(),
        })
        .collect::<Vec<_>>();

    ensure!(
        sections
            .len()
            .checked_add(3)
            .is_some_and(|count| count <= 96),
        "managed output section count exceeds the PE limit"
    );
    let import_rva = pe::align_up(pe.size_of_image, pe.section_alignment)?;
    let iat_rva = import_rva + 48;
    let stub_rva = import_rva
        .checked_add(pe.section_alignment)
        .context("generated CLR stub RVA overflows")?;
    let reloc_rva = stub_rva
        .checked_add(pe.section_alignment)
        .context("generated CLR relocation RVA overflows")?;
    let image_size = reloc_rva
        .checked_add(pe.section_alignment)
        .context("generated CLR SizeOfImage overflows")?;
    push_generated_section(
        &mut sections,
        *b".clrimp\0",
        import_rva,
        IMPORT_CHARACTERISTICS,
        import_payload(import_rva, iat_rva)?,
    )?;
    push_generated_section(
        &mut sections,
        *b".clrstb\0",
        stub_rva,
        STUB_CHARACTERISTICS,
        stub_payload(iat_rva)?,
    )?;
    push_generated_section(
        &mut sections,
        *b".reloc\0\0",
        reloc_rva,
        RELOC_CHARACTERISTICS,
        relocation_payload(stub_rva)?,
    )?;

    let header_size = output_header_size(sections.len())?;
    ensure!(
        header_size <= source_profile.payload_start,
        "generated headers overlap the retained CLR payload"
    );
    let output_size = layout_raw_sections(&mut sections, header_size)?;
    let mut output = vec![0; usize::try_from(output_size)?];
    let mut directories = vec![
        (
            IMPORT_DIRECTORY,
            DataDirectory {
                virtual_address: import_rva,
                size: 40,
            },
        ),
        (
            BASE_RELOCATION_DIRECTORY,
            DataDirectory {
                virtual_address: reloc_rva,
                size: 12,
            },
        ),
        (
            IAT_DIRECTORY,
            DataDirectory {
                virtual_address: iat_rva,
                size: 8,
            },
        ),
        (COR20_DIRECTORY, source_profile.clr.cor20),
    ];
    if let Some(resource) = source_profile.resource {
        directories.push((RESOURCE_DIRECTORY, resource));
    }
    if let Some(debug) = source_profile.debug {
        directories.push((DEBUG_DIRECTORY, debug));
    }
    write_headers(
        &mut output,
        mapped,
        pe,
        &sections,
        image_size,
        stub_rva,
        &directories,
    )?;
    copy_sections(&mut output, mapped, &sections)?;
    let cor20_flags_offset = usize::try_from(file_offset_for_rva(
        &sections,
        source_profile.clr.cor20.virtual_address + 16,
    )?)?;
    put32(
        &mut output,
        cor20_flags_offset,
        source_profile.clr.source_flags | COMIMAGE_FLAGS_ILONLY,
    )?;
    let changed = source_profile
        .debug
        .map(|debug| rewrite_debug_pointers(&mut output, &sections, debug))
        .transpose()?
        .unwrap_or_default();
    put32(&mut output, OPTIONAL_OFFSET + 64, 0)?;
    let checksum = pe_checksum(&output, OPTIONAL_OFFSET + 64)?;
    put32(&mut output, OPTIONAL_OFFSET + 64, checksum)?;

    let generated = GeneratedSemanticClrContainer {
        generated_architecture: "PE32/I386",
        entry_rva: stub_rva,
        import_rva,
        iat_rva,
        reloc_rva,
        cor20_rva: source_profile.clr.cor20.virtual_address,
        cor20_size: source_profile.clr.cor20.size,
        metadata_rva: source_profile.clr.metadata.virtual_address,
    };
    verify_output(
        &output,
        mapped,
        pe,
        source_profile,
        &source_ranges,
        &generated,
        &changed,
    )?;
    let source_iat_rva = discovery
        .modules
        .first()
        .context("managed source loader graph has no modules")?
        .destination_rva;
    Ok(ManagedRebuild {
        output,
        generated,
        source: ManagedSemanticClrSource {
            source_architecture: source_architecture(pe.machine_kind()),
            source_pe_entry_rva: pe.entry_rva,
            source_import_rva: discovery.table_rva,
            source_iat_rva,
            source_cor20_rva: source_profile.clr.cor20.virtual_address,
            source_metadata_rva: source_profile.clr.metadata.virtual_address,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SDDT_MAPPED: &[u8] =
        include_bytes!("../../../../../tmp/sddt160_Assembly-CSharp_decrypted_mapped.bin");

    fn source_pe() -> Pe {
        Pe::parse_mapped(SDDT_MAPPED).expect("reviewed SDDT mapped PE")
    }

    fn discovery() -> LoaderDiscovery {
        crate::pipeline::stages::imports::discover_imports_in_image(
            SDDT_MAPPED,
            &source_pe(),
            crate::pipeline::stages::imports::ImportProfile::Standard,
        )
        .expect("source standard import graph")
    }

    #[test]
    fn builder_emits_structural_semantic_container() {
        let rebuilt = rebuild_semantic_clr(SDDT_MAPPED, &source_pe(), &discovery()).unwrap();
        let output_pe = Pe::parse(&rebuilt.output).unwrap();
        assert_eq!(output_pe.machine_kind(), Machine::I386);
        assert_eq!(output_pe.sections.len(), source_pe().sections.len() + 3);
        assert_eq!(
            output_pe.directory(COR20_DIRECTORY).unwrap(),
            source_pe().directory(COR20_DIRECTORY).unwrap()
        );
    }

    #[test]
    fn source_authentication_is_not_tied_to_konn_bytes_or_generated_zero_fill() {
        let pe = source_pe();
        let profile = authenticate_source(SDDT_MAPPED, &pe, &discovery()).unwrap();
        let mut changed = SDDT_MAPPED.to_vec();
        changed[0x1131] ^= 1;
        changed[usize::try_from(profile.payload_start).unwrap()] = 0x5a;
        let changed_pe = Pe::parse_mapped(&changed).unwrap();
        let rebuilt = rebuild_semantic_clr(&changed, &changed_pe, &discovery()).unwrap();
        let output_pe = Pe::parse(&rebuilt.output).unwrap();
        let remapped = output_pe.map_image(&rebuilt.output).unwrap();
        assert_eq!(
            remapped[usize::try_from(profile.payload_start).unwrap()],
            0x5a
        );
    }

    #[test]
    fn rejects_native_loader_state_crossing_into_clr_payload() {
        let mut discovery = discovery();
        let profile = authenticate_source(SDDT_MAPPED, &source_pe(), &discovery).unwrap();
        discovery.modules[0].destination_rva = profile.payload_start;
        assert!(rebuild_semantic_clr(SDDT_MAPPED, &source_pe(), &discovery).is_err());
    }

    #[test]
    fn rejects_corrupt_metadata_signature() {
        let pe = source_pe();
        let metadata = pe.directory(COR20_DIRECTORY).unwrap().virtual_address;
        let metadata_rva = get32(SDDT_MAPPED, usize::try_from(metadata).unwrap() + 8).unwrap();
        let mut mapped = SDDT_MAPPED.to_vec();
        mapped[usize::try_from(metadata_rva).unwrap()] ^= 1;
        assert!(rebuild_semantic_clr(&mapped, &pe, &discovery()).is_err());
    }
}
