use std::ops::Range;

use anyhow::{Context, Result, ensure};

use crate::util::bytes::{checked_range, read_bytes, read_u32, read_u64, write_u32, write_u64};

use super::model::{DataDirectory, IMAGE_DIRECTORY_ENTRY_SECURITY, Pe, PointerWidth, Section};
use super::parse::checked_mappable_image_len;

impl DataDirectory {
    /// Interprets the directory's first field as a file offset.
    pub fn checked_file_range(self, data_len: usize) -> Result<Option<Range<usize>>> {
        if self.is_empty() {
            return Ok(None);
        }
        ensure!(
            self.virtual_address != 0 && self.size != 0,
            "data directory has a partial null file range"
        );
        let offset = usize::try_from(self.virtual_address)
            .context("directory file offset does not fit usize")?;
        let size = usize::try_from(self.size).context("directory file size does not fit usize")?;
        Ok(Some(checked_range(data_len, offset, size)?))
    }
}

impl Pe {
    /// Reads an architecture-sized pointer cell without architecture probing.
    pub(crate) fn read_pointer(&self, data: &[u8], offset: usize) -> Result<u64> {
        match self.pointer_width() {
            PointerWidth::U32 => Ok(u64::from(read_u32(data, offset)?)),
            PointerWidth::U64 => read_u64(data, offset),
        }
    }

    /// Writes an architecture-sized pointer cell without architecture probing.
    pub(crate) fn write_pointer(&self, data: &mut [u8], offset: usize, value: u64) -> Result<()> {
        match self.pointer_width() {
            PointerWidth::U32 => write_u32(
                data,
                offset,
                u32::try_from(value).context("32-bit pointer value does not fit")?,
            ),
            PointerWidth::U64 => write_u64(data, offset, value),
        }
    }

    /// Converts an image-relative virtual address to an RVA.
    pub(crate) fn va_to_rva(&self, va: u64) -> Result<u32> {
        let rva = va
            .checked_sub(self.image_base)
            .context("VA is below ImageBase")?;
        u32::try_from(rva).context("VA-to-RVA exceeds u32")
    }

    /// Converts an RVA to an image-relative virtual address.
    pub(crate) fn rva_to_va(&self, rva: u32) -> Result<u64> {
        self.image_base
            .checked_add(u64::from(rva))
            .context("RVA-to-VA overflow")
    }

    pub fn directory(&self, index: usize) -> Result<DataDirectory> {
        self.directories.get(index).copied().with_context(|| {
            format!(
                "data-directory index {index} exceeds declared count {}",
                self.directories.len()
            )
        })
    }

    pub fn data_directory_offset(&self, index: usize) -> Result<usize> {
        ensure!(
            index < self.directories.len(),
            "data-directory index {index} exceeds declared count {}",
            self.directories.len()
        );
        self.data_directory_table_offset
            .checked_add(
                index
                    .checked_mul(8)
                    .context("data-directory index overflow")?,
            )
            .context("data-directory offset overflow")
    }

    pub fn security_directory_file_range(&self, data_len: usize) -> Result<Option<Range<usize>>> {
        self.directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
            .context("reading Security Directory")?
            .checked_file_range(data_len)
            .context("validating Security Directory file range")
    }

    pub fn section_containing_rva(&self, rva: u32) -> Option<&Section> {
        let insertion = self
            .sections
            .partition_point(|section| section.virtual_address <= rva);
        let candidate = self.sections.get(insertion.checked_sub(1)?)?;
        candidate.contains_rva(rva).then_some(candidate)
    }

    pub fn section_for_rva_range(&self, rva: u32, len: usize) -> Result<&Section> {
        ensure!(len != 0, "RVA range length is zero");
        let len_u32 = u32::try_from(len).context("RVA range length exceeds u32")?;
        let end = rva.checked_add(len_u32).context("RVA range overflow")?;
        let section = self
            .section_containing_rva(rva)
            .with_context(|| format!("RVA {rva:#x} is not contained in a section"))?;
        let section_end = section.virtual_range()?.end;
        ensure!(
            end <= section_end,
            "RVA range {rva:#x}..{end:#x} crosses section {}",
            section.index
        );
        Ok(section)
    }

    #[cfg(test)]
    pub fn rva_to_file_offset(&self, rva: u32) -> Result<usize> {
        Ok(self.rva_range_to_file_offset(rva, 1)?.start)
    }

    #[cfg(test)]
    pub fn rva_range_to_file_offset(&self, rva: u32, len: usize) -> Result<Range<usize>> {
        ensure!(len != 0, "RVA range length is zero");
        let len_u32 = u32::try_from(len).context("RVA range length exceeds u32")?;
        let rva_end = rva.checked_add(len_u32).context("RVA range overflow")?;
        if rva < self.size_of_headers {
            ensure!(
                rva_end <= self.size_of_headers,
                "RVA range {rva:#x}..{rva_end:#x} crosses the end of the PE headers"
            );
            let start = usize::try_from(rva).context("header RVA does not fit usize")?;
            return checked_range(self.file_len, start, len).context("header RVA exceeds file");
        }

        let section = self.section_for_rva_range(rva, len)?;
        let delta = rva - section.virtual_address;
        ensure!(
            delta < section.raw_size && len_u32 <= section.raw_size - delta,
            "RVA range {rva:#x}..{rva_end:#x} lies in section {} virtual zero-fill",
            section.index
        );
        let file_offset = section
            .raw_pointer
            .checked_add(delta)
            .context("RVA-to-file offset overflow")?;
        let start = usize::try_from(file_offset).context("file offset does not fit usize")?;
        checked_range(self.file_len, start, len).context("mapped RVA range exceeds file")
    }

    /// Maps a disk-layout PE into a zero-initialized in-memory image.
    pub fn map_image(&self, data: &[u8]) -> Result<Vec<u8>> {
        let image_len = checked_mappable_image_len(self.size_of_image)?;
        self.validate_layout(data.len())
            .context("validating disk image before mapping")?;
        let header_len =
            usize::try_from(self.size_of_headers).context("SizeOfHeaders does not fit usize")?;
        let mut image = Vec::new();
        image
            .try_reserve_exact(image_len)
            .with_context(|| format!("allocating {image_len:#x}-byte PE image"))?;
        image.resize(image_len, 0);
        image[..header_len].copy_from_slice(read_bytes(data, 0, header_len)?);

        for section in &self.sections {
            if section.raw_size == 0 {
                continue;
            }
            let source = section.raw_range()?;
            let destination_start = usize::try_from(section.virtual_address)
                .context("section RVA does not fit usize")?;
            let destination = checked_range(image.len(), destination_start, source.len())
                .with_context(|| format!("mapping section {} into image", section.index))?;
            image[destination].copy_from_slice(
                data.get(source.clone())
                    .with_context(|| format!("reading section {} raw data", section.index))?,
            );
        }
        Ok(image)
    }
}
