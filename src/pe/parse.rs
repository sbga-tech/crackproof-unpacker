use std::ops::Range;

use anyhow::{Context, Result, ensure};

use super::model::{
    COFF_HEADER_SIZE, DOS_HEADER_SIZE, DataDirectory, IMAGE_BASE_ALIGNMENT, MAX_FILE_ALIGNMENT,
    MAX_MAPPABLE_IMAGE_SIZE, MAX_PE_SECTIONS, MIN_STANDARD_FILE_ALIGNMENT, Machine, PE_PAGE_SIZE,
    PE_SIGNATURE_SIZE, PE32_OPTIONAL_HEADER_MAGIC, PE32_PLUS_OPTIONAL_HEADER_MAGIC, Pe,
    PeInputLayout, PeKind, SECTION_HEADER_SIZE, Section,
};
use crate::util::bytes::{read_bytes, read_u16, read_u32, read_u64};

impl Pe {
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_with_layout(data, PeInputLayout::Disk)
    }

    pub(crate) fn parse_mapped(data: &[u8]) -> Result<Self> {
        Self::parse_with_layout(data, PeInputLayout::Mapped)
    }

    fn parse_with_layout(data: &[u8], layout: PeInputLayout) -> Result<Self> {
        ensure!(
            data.len() >= DOS_HEADER_SIZE,
            "input is too short for a DOS header"
        );
        ensure!(&data[..2] == b"MZ", "missing DOS signature");

        let nt = usize::try_from(read_u32(data, 0x3c)?)
            .context("PE header offset does not fit usize")?;
        let signature_end = nt
            .checked_add(PE_SIGNATURE_SIZE)
            .context("PE signature offset overflow")?;
        ensure!(
            read_bytes(data, nt, PE_SIGNATURE_SIZE)? == b"PE\0\0",
            "missing PE signature at {nt:#x}"
        );

        let coff = signature_end;
        read_bytes(data, coff, COFF_HEADER_SIZE).context("reading COFF header")?;
        let raw_machine = read_u16(data, coff)?;
        let section_count = usize::from(read_u16(data, coff + 2)?);
        let coff_characteristics = read_u16(data, coff + 18)?;
        ensure!(section_count != 0, "PE contains no sections");
        ensure!(
            section_count <= MAX_PE_SECTIONS,
            "PE section count {section_count} exceeds the Windows image limit {MAX_PE_SECTIONS}"
        );
        let optional_header_size = usize::from(read_u16(data, coff + 16)?);
        let opt = coff
            .checked_add(COFF_HEADER_SIZE)
            .context("optional-header offset overflow")?;
        read_bytes(data, opt, optional_header_size).context("reading optional header")?;
        let magic = read_u16(data, opt)?;
        let kind = match magic {
            PE32_OPTIONAL_HEADER_MAGIC => PeKind::Pe32,
            PE32_PLUS_OPTIONAL_HEADER_MAGIC => PeKind::Pe32Plus,
            _ => anyhow::bail!("unsupported optional-header magic {magic:#06x}"),
        };
        let machine = Machine::from_raw(raw_machine)?;
        ensure!(
            machine.kind() == kind,
            "PE machine {raw_machine:#06x} does not match {kind:?} optional-header magic {magic:#06x}; it requires {:#06x}",
            machine.kind().magic()
        );
        let profile = kind.profile();
        ensure!(
            optional_header_size >= profile.fixed_size,
            "{kind:?} optional header is only {optional_header_size:#x} bytes"
        );

        let entry_rva = read_u32(data, opt + 16)?;
        let image_base = match kind {
            PeKind::Pe32 => u64::from(read_u32(data, opt + profile.image_base)?),
            PeKind::Pe32Plus => read_u64(data, opt + profile.image_base)?,
        };
        let section_alignment = read_u32(data, opt + profile.section_alignment)?;
        let file_alignment = read_u32(data, opt + profile.file_alignment)?;
        ensure!(
            image_base.is_multiple_of(IMAGE_BASE_ALIGNMENT),
            "ImageBase {image_base:#x} is not {IMAGE_BASE_ALIGNMENT:#x}-aligned"
        );
        ensure!(
            section_alignment.is_power_of_two(),
            "SectionAlignment {section_alignment:#x} is not a power of two"
        );
        ensure!(
            file_alignment.is_power_of_two(),
            "FileAlignment {file_alignment:#x} is not a power of two"
        );
        ensure!(
            section_alignment >= PE_PAGE_SIZE,
            "low-alignment PE images are unsupported because reconstruction requires page-aligned virtual sections"
        );
        ensure!(
            (MIN_STANDARD_FILE_ALIGNMENT..=MAX_FILE_ALIGNMENT).contains(&file_alignment),
            "FileAlignment {file_alignment:#x} is outside the PE32 range {MIN_STANDARD_FILE_ALIGNMENT:#x}..={MAX_FILE_ALIGNMENT:#x}"
        );
        ensure!(
            section_alignment >= file_alignment,
            "SectionAlignment {section_alignment:#x} is smaller than FileAlignment {file_alignment:#x}"
        );

        let size_of_image = read_u32(data, opt + profile.size_of_image)?;
        let size_of_headers = read_u32(data, opt + profile.size_of_headers)?;
        ensure!(size_of_image != 0, "SizeOfImage is zero");
        ensure!(size_of_headers != 0, "SizeOfHeaders is zero");
        ensure!(
            size_of_image % section_alignment == 0,
            "SizeOfImage {size_of_image:#x} is not SectionAlignment-aligned"
        );
        ensure!(
            size_of_headers % file_alignment == 0,
            "SizeOfHeaders {size_of_headers:#x} is not FileAlignment-aligned"
        );
        let header_len =
            usize::try_from(size_of_headers).context("SizeOfHeaders does not fit usize")?;
        ensure!(
            header_len <= data.len(),
            "SizeOfHeaders {size_of_headers:#x} exceeds file length {:#x}",
            data.len()
        );
        ensure!(
            size_of_headers <= size_of_image,
            "SizeOfHeaders {size_of_headers:#x} exceeds SizeOfImage {size_of_image:#x}"
        );
        checked_mappable_image_len(size_of_image)?;

        let checksum_offset = opt
            .checked_add(profile.checksum)
            .context("checksum offset overflow")?;
        read_bytes(data, checksum_offset, 4).context("reading PE checksum")?;
        let number_of_rva_and_sizes_offset = opt
            .checked_add(profile.number_of_rva_and_sizes)
            .context("directory-count offset overflow")?;
        let directory_count = usize::try_from(read_u32(data, number_of_rva_and_sizes_offset)?)
            .context("data-directory count does not fit usize")?;
        let directory_bytes = directory_count
            .checked_mul(8)
            .context("data-directory table size overflow")?;
        let data_directory_table_offset = opt
            .checked_add(profile.data_directory_table)
            .context("data-directory table offset overflow")?;
        let optional_header_end = opt
            .checked_add(optional_header_size)
            .context("optional-header end overflow")?;
        let directory_table_end = data_directory_table_offset
            .checked_add(directory_bytes)
            .context("data-directory table end overflow")?;
        ensure!(
            directory_table_end <= optional_header_end,
            "{directory_count} data directories do not fit the optional header"
        );
        let mut directories = Vec::with_capacity(directory_count);
        for index in 0..directory_count {
            let offset = data_directory_table_offset + index * 8;
            directories.push(DataDirectory {
                virtual_address: read_u32(data, offset)?,
                size: read_u32(data, offset + 4)?,
            });
        }

        let section_table_offset = optional_header_end;
        let section_table_bytes = section_count
            .checked_mul(SECTION_HEADER_SIZE)
            .context("section table size overflow")?;
        let section_table_end = section_table_offset
            .checked_add(section_table_bytes)
            .context("section table end overflow")?;
        read_bytes(data, section_table_offset, section_table_bytes)
            .context("reading section table")?;
        ensure!(
            section_table_end <= header_len,
            "section table ends at {section_table_end:#x}, beyond SizeOfHeaders {size_of_headers:#x}"
        );

        let mut sections = Vec::with_capacity(section_count);
        for index in 0..section_count {
            let header_offset = section_table_offset + index * SECTION_HEADER_SIZE;
            sections.push(Section {
                index,
                header_offset,
                name_bytes: read_bytes(data, header_offset, 8)?
                    .try_into()
                    .expect("bounded eight-byte section name"),
                virtual_size: read_u32(data, header_offset + 8)?,
                virtual_address: read_u32(data, header_offset + 12)?,
                raw_size: read_u32(data, header_offset + 16)?,
                raw_pointer: read_u32(data, header_offset + 20)?,
                characteristics: read_u32(data, header_offset + 36)?,
            });
        }

        let pe = Self {
            opt,
            machine,
            coff_characteristics,
            section_count,
            entry_rva,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            checksum_offset,
            data_directory_table_offset,
            directories,
            sections,
            #[cfg(test)]
            file_len: data.len(),
        };
        pe.validate_layout_for(data.len(), layout)?;
        Ok(pe)
    }

    pub fn validate_layout(&self, data_len: usize) -> Result<()> {
        self.validate_layout_for(data_len, PeInputLayout::Disk)
    }

    fn validate_layout_for(&self, data_len: usize, layout: PeInputLayout) -> Result<()> {
        let header_len =
            usize::try_from(self.size_of_headers).context("SizeOfHeaders does not fit usize")?;
        ensure!(header_len <= data_len, "PE headers exceed input length");
        let image_len = checked_mappable_image_len(self.size_of_image)?;
        if layout == PeInputLayout::Mapped {
            ensure!(
                data_len >= image_len,
                "mapped image length {data_len:#x} is smaller than SizeOfImage {:#x}",
                self.size_of_image
            );
        }
        for pair in self.sections.windows(2) {
            let left = &pair[0];
            let right = &pair[1];
            ensure!(
                left.virtual_address < right.virtual_address,
                "section RVAs are not strictly increasing: section {} at {:#x}, section {} at {:#x}",
                left.index,
                left.virtual_address,
                right.index,
                right.virtual_address
            );
            let left_end = left
                .virtual_range()
                .with_context(|| format!("reading section {} virtual range", left.index))?
                .end;
            ensure!(
                left_end <= right.virtual_address,
                "section {} mapped range ending at {left_end:#x} shadows section {} at {:#x}",
                left.index,
                right.index,
                right.virtual_address
            );
        }

        let mut raw_ranges =
            (layout == PeInputLayout::Disk).then(|| Vec::with_capacity(self.sections.len()));
        let mut virtual_ranges = Vec::with_capacity(self.sections.len());
        for section in &self.sections {
            ensure!(
                section.virtual_address % self.section_alignment == 0,
                "section {} RVA {:#x} is not SectionAlignment-aligned",
                section.index,
                section.virtual_address
            );
            if section.raw_size != 0 {
                ensure!(
                    section.raw_pointer % self.file_alignment == 0,
                    "section {} raw pointer {:#x} is not FileAlignment-aligned",
                    section.index,
                    section.raw_pointer
                );
                ensure!(
                    section.raw_size % self.file_alignment == 0,
                    "section {} raw size {:#x} is not FileAlignment-aligned",
                    section.index,
                    section.raw_size
                );
                if let Some(raw_ranges) = &mut raw_ranges {
                    let raw = section.raw_range()?;
                    ensure!(
                        raw.start >= header_len,
                        "section {} raw data overlaps the PE headers",
                        section.index
                    );
                    ensure!(
                        raw.end <= data_len,
                        "section {} raw range {:#x}..{:#x} exceeds input length {data_len:#x}",
                        section.index,
                        raw.start,
                        raw.end
                    );
                    raw_ranges.push((raw, section.index));
                }
            }

            if section.mapped_size() != 0 {
                let virtual_range = section.virtual_range()?;
                ensure!(
                    virtual_range.start >= self.size_of_headers,
                    "section {} virtual range overlaps the PE headers",
                    section.index
                );
                ensure!(
                    virtual_range.end <= self.size_of_image,
                    "section {} virtual range ends at {:#x}, beyond SizeOfImage {:#x}",
                    section.index,
                    virtual_range.end,
                    self.size_of_image
                );
                if layout == PeInputLayout::Mapped {
                    let mapped_end = usize::try_from(virtual_range.end)
                        .context("section virtual range end does not fit usize")?;
                    ensure!(
                        mapped_end <= data_len,
                        "section {} virtual range {:#x}..{:#x} exceeds mapped input length {data_len:#x}",
                        section.index,
                        virtual_range.start,
                        virtual_range.end
                    );
                }
                virtual_ranges.push((virtual_range, section.index));
            }
        }
        if let Some(raw_ranges) = &mut raw_ranges {
            ensure_disjoint(raw_ranges, "raw")?;
        }
        ensure_disjoint(&mut virtual_ranges, "virtual")?;
        Ok(())
    }
}

fn ensure_disjoint<T>(ranges: &mut [(Range<T>, usize)], kind: &str) -> Result<()>
where
    T: Copy + Ord + std::fmt::LowerHex,
{
    ranges.sort_unstable_by_key(|(range, _)| range.start);
    for pair in ranges.windows(2) {
        let (left, left_index) = &pair[0];
        let (right, right_index) = &pair[1];
        ensure!(
            left.end <= right.start,
            "section {left_index} {kind} range {:#x}..{:#x} overlaps section {right_index} at {:#x}",
            left.start,
            left.end,
            right.start
        );
    }
    Ok(())
}

pub(super) fn checked_mappable_image_len(size_of_image: u32) -> Result<usize> {
    ensure!(
        size_of_image <= MAX_MAPPABLE_IMAGE_SIZE,
        "SizeOfImage {size_of_image:#x} exceeds the maximum mappable image size {MAX_MAPPABLE_IMAGE_SIZE:#x}"
    );
    usize::try_from(size_of_image).context("SizeOfImage does not fit usize")
}
