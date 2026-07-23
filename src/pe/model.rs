use std::ops::Range;

use anyhow::{Context, Result, ensure};

pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub(crate) const IMAGE_FILE_DLL: u16 = 0x2000;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

pub(super) const DOS_HEADER_SIZE: usize = 0x40;
pub(super) const PE_SIGNATURE_SIZE: usize = 4;
pub(super) const COFF_HEADER_SIZE: usize = 20;
pub(super) const PE32_OPTIONAL_HEADER_MAGIC: u16 = 0x010b;
pub(super) const PE32_PLUS_OPTIONAL_HEADER_MAGIC: u16 = 0x020b;
pub(super) const PE32_FIXED_OPTIONAL_HEADER_SIZE: usize = 96;
pub(super) const PE32_PLUS_FIXED_OPTIONAL_HEADER_SIZE: usize = 112;
pub(super) const SECTION_HEADER_SIZE: usize = 40;
pub(super) const MAX_PE_SECTIONS: usize = 96;
// Mapping untrusted SizeOfImage values must not request an unbounded heap allocation.
pub(super) const MAX_MAPPABLE_IMAGE_SIZE: u32 = 512 * 1024 * 1024;
pub(super) const PE_PAGE_SIZE: u32 = 0x1000;
pub(super) const MIN_STANDARD_FILE_ALIGNMENT: u32 = 0x200;
pub(super) const MAX_FILE_ALIGNMENT: u32 = 0x1_0000;
pub(super) const IMAGE_BASE_ALIGNMENT: u64 = 0x1_0000;

/// The only executable optional-header forms accepted by the unpacker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeKind {
    Pe32,
    Pe32Plus,
}

impl PeKind {
    pub(super) const fn profile(self) -> OptionalHeaderProfile {
        match self {
            Self::Pe32 => OptionalHeaderProfile {
                fixed_size: PE32_FIXED_OPTIONAL_HEADER_SIZE,
                image_base: 28,
                section_alignment: 32,
                file_alignment: 36,
                size_of_image: 56,
                size_of_headers: 60,
                checksum: 64,
                number_of_rva_and_sizes: 92,
                data_directory_table: 96,
            },
            Self::Pe32Plus => OptionalHeaderProfile {
                fixed_size: PE32_PLUS_FIXED_OPTIONAL_HEADER_SIZE,
                image_base: 24,
                section_alignment: 32,
                file_alignment: 36,
                size_of_image: 56,
                size_of_headers: 60,
                checksum: 64,
                number_of_rva_and_sizes: 108,
                data_directory_table: 112,
            },
        }
    }

    pub(crate) const fn pointer_width(self) -> PointerWidth {
        match self {
            Self::Pe32 => PointerWidth::U32,
            Self::Pe32Plus => PointerWidth::U64,
        }
    }

    pub(super) const fn magic(self) -> u16 {
        match self {
            Self::Pe32 => PE32_OPTIONAL_HEADER_MAGIC,
            Self::Pe32Plus => PE32_PLUS_OPTIONAL_HEADER_MAGIC,
        }
    }
}

/// The only COFF machines accepted by the unpacker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Machine {
    I386,
    Amd64,
}

impl Machine {
    #[cfg(test)]
    pub(crate) const fn raw(self) -> u16 {
        match self {
            Self::I386 => IMAGE_FILE_MACHINE_I386,
            Self::Amd64 => IMAGE_FILE_MACHINE_AMD64,
        }
    }

    pub(crate) const fn kind(self) -> PeKind {
        match self {
            Self::I386 => PeKind::Pe32,
            Self::Amd64 => PeKind::Pe32Plus,
        }
    }

    pub(super) fn from_raw(value: u16) -> Result<Self> {
        match value {
            IMAGE_FILE_MACHINE_I386 => Ok(Self::I386),
            IMAGE_FILE_MACHINE_AMD64 => Ok(Self::Amd64),
            _ => anyhow::bail!("unsupported PE machine {value:#06x}; expected I386 or AMD64"),
        }
    }
}

/// Width of architecture-sized addresses and pointer cells in the image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PointerWidth {
    U32,
    U64,
}

impl PointerWidth {
    pub(crate) const fn bytes(self) -> usize {
        match self {
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OptionalHeaderProfile {
    pub(super) fixed_size: usize,
    pub(super) image_base: usize,
    pub(super) section_alignment: usize,
    pub(super) file_alignment: usize,
    pub(super) size_of_image: usize,
    pub(super) size_of_headers: usize,
    pub(super) checksum: usize,
    pub(super) number_of_rva_and_sizes: usize,
    pub(super) data_directory_table: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Section {
    pub index: usize,
    pub header_offset: usize,
    pub name_bytes: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug)]
pub struct Pe {
    pub opt: usize,
    pub machine: Machine,
    pub(crate) coff_characteristics: u16,
    pub section_count: usize,
    pub entry_rva: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum_offset: usize,
    pub data_directory_table_offset: usize,
    pub directories: Vec<DataDirectory>,
    pub sections: Vec<Section>,
    #[cfg(test)]
    pub file_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PeInputLayout {
    Disk,
    Mapped,
}

impl Pe {
    /// Returns the validated optional-header form for this image.
    pub(crate) const fn kind(&self) -> PeKind {
        self.machine.kind()
    }

    /// Returns the validated COFF machine for this image.
    pub(crate) const fn machine_kind(&self) -> Machine {
        self.machine
    }

    /// Whether the COFF header identifies this image as a DLL.
    pub(crate) const fn is_dll(&self) -> bool {
        self.coff_characteristics & IMAGE_FILE_DLL != 0
    }

    /// Returns the single pointer-cell width selected from the validated PE kind.
    pub(crate) const fn pointer_width(&self) -> PointerWidth {
        self.kind().pointer_width()
    }

    fn profile(&self) -> OptionalHeaderProfile {
        self.kind().profile()
    }

    /// Minimum encoded optional-header span for this PE kind, before directories.
    #[cfg(test)]
    pub(crate) fn fixed_optional_header_size(&self) -> usize {
        self.profile().fixed_size
    }

    fn optional_header_offset(&self, relative_offset: usize) -> usize {
        self.opt
            .checked_add(relative_offset)
            .expect("PE optional-header offset was validated during parsing")
    }

    /// Absolute offset of COFF PointerToSymbolTable; NumberOfSymbols follows it.
    pub(crate) fn coff_symbol_table_offset(&self) -> usize {
        self.opt
            .checked_sub(12)
            .expect("PE COFF header was validated during parsing")
    }

    /// Absolute offset of reserved IMAGE_OPTIONAL_HEADER.Win32VersionValue.
    pub(crate) fn win32_version_value_offset(&self) -> usize {
        self.optional_header_offset(52)
    }

    /// Absolute offset of reserved IMAGE_OPTIONAL_HEADER.LoaderFlags.
    pub(crate) fn loader_flags_offset(&self) -> usize {
        self.number_of_rva_and_sizes_offset()
            .checked_sub(4)
            .expect("PE optional header was validated during parsing")
    }

    /// Absolute offset of IMAGE_OPTIONAL_HEADER.AddressOfEntryPoint.
    pub(crate) fn entry_rva_offset(&self) -> usize {
        self.optional_header_offset(16)
    }

    /// Absolute offsets of optional-header section-size aggregates.
    pub(crate) fn size_of_code_offset(&self) -> usize {
        self.optional_header_offset(4)
    }

    pub(crate) fn size_of_initialized_data_offset(&self) -> usize {
        self.optional_header_offset(8)
    }

    pub(crate) fn size_of_uninitialized_data_offset(&self) -> usize {
        self.optional_header_offset(12)
    }

    /// Absolute offset of ImageBase, whose encoded width follows `pointer_width`.
    #[cfg(test)]
    pub(crate) fn image_base_offset(&self) -> usize {
        self.optional_header_offset(self.profile().image_base)
    }

    /// Absolute offset of IMAGE_OPTIONAL_HEADER.SizeOfImage.
    pub(crate) fn size_of_image_offset(&self) -> usize {
        self.optional_header_offset(self.profile().size_of_image)
    }

    #[cfg(test)]
    pub(crate) fn dll_characteristics_offset(&self) -> usize {
        self.optional_header_offset(70)
    }

    /// Absolute offset of IMAGE_OPTIONAL_HEADER.NumberOfRvaAndSizes.
    pub(crate) fn number_of_rva_and_sizes_offset(&self) -> usize {
        self.optional_header_offset(self.profile().number_of_rva_and_sizes)
    }
}

impl DataDirectory {
    pub fn is_empty(self) -> bool {
        self.virtual_address == 0 && self.size == 0
    }

    /// Returns the nonempty RVA span described by this directory.
    ///
    /// This must not be used for the Security Directory, whose first field is
    /// a file offset rather than an RVA.
    pub fn checked_rva_range(self) -> Result<Option<Range<u32>>> {
        if self.is_empty() {
            return Ok(None);
        }
        ensure!(
            self.virtual_address != 0 && self.size != 0,
            "data directory has a partial null RVA range"
        );
        let end = self
            .virtual_address
            .checked_add(self.size)
            .context("data-directory RVA range overflow")?;
        Ok(Some(self.virtual_address..end))
    }
}

impl Section {
    /// The in-memory span used when deciding which section owns an RVA.
    /// PE loaders account for both VirtualSize and SizeOfRawData.
    pub fn mapped_size(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }

    pub fn raw_range(&self) -> Result<Range<usize>> {
        let start =
            usize::try_from(self.raw_pointer).context("section raw pointer does not fit usize")?;
        let len = usize::try_from(self.raw_size).context("section raw size does not fit usize")?;
        let end = start
            .checked_add(len)
            .context("section raw range overflow")?;
        Ok(start..end)
    }

    pub fn virtual_range(&self) -> Result<Range<u32>> {
        let end = self
            .virtual_address
            .checked_add(self.mapped_size())
            .context("section virtual range overflow")?;
        Ok(self.virtual_address..end)
    }

    pub fn contains_rva(&self, rva: u32) -> bool {
        self.virtual_range()
            .is_ok_and(|range| range.start <= rva && rva < range.end)
    }
}
