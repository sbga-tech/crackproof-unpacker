use std::ops::Range;

use anyhow::{Context, Result, ensure};

use crate::pe::{Pe, PointerWidth};

const DESCRIPTOR_SIZE: usize = 20;
const DESCRIPTOR_ALIGNMENT: u32 = 4;
pub(crate) const MAX_MODULE_NAME_LEN: usize = 511;
pub(crate) const MAX_API_NAME_LEN: usize = 4095;
const MAX_SCANNED_DESCRIPTOR_STARTS: usize = 1 << 25;
pub(crate) const MAX_PARSED_DESCRIPTORS: usize = 1_000_000;
pub(crate) const MAX_PARSED_FUNCTIONS: usize = 1_000_000;
const MAX_VALID_CANDIDATES: usize = 4096;
const MAX_REFERENCED_METADATA_BYTES: usize = 16 * 1024 * 1024;
const MAX_ATTEMPTED_LOADER_STRING_BYTES: usize = 16 * 1024 * 1024;

/// Selects the validated import representation retained by the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ImportProfile {
    EncodedLoader,
    Standard,
}

/// One decoded import target in the immutable loader graph.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ImportSymbol {
    Name { hint: u16, name: String },
    Ordinal(u16),
}

/// A descriptor and its authoritative source thunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ImportModule {
    pub(crate) dll: String,
    pub(crate) destination_rva: u32,
    pub(crate) symbols: Vec<ImportSymbol>,
}

/// The complete static import graph discovered in a decrypted image.
///
/// `metadata_ranges` are sorted, merged, half-open RVA ranges. They contain
/// exactly the descriptor table (including its null descriptor), source thunk
/// arrays (including their nulls), DLL strings, and hint/name records
/// referenced while decoding the selected descriptor run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LoaderDiscovery {
    pub(crate) table_rva: u32,
    pub(crate) metadata_ranges: Vec<Range<u32>>,
    pub(crate) image_size: u32,
    pub(crate) modules: Vec<ImportModule>,
    pub(crate) function_count: usize,
    pub(crate) named_count: usize,
    pub(crate) ordinal_count: usize,
}

pub(crate) fn pointer_size(width: PointerWidth) -> usize {
    width.bytes()
}

pub(crate) fn pointer_size_rva(width: PointerWidth) -> u32 {
    u32::try_from(pointer_size(width)).expect("PE pointer widths fit in an RVA")
}

pub(crate) fn ordinal_flag(width: PointerWidth) -> u64 {
    match width {
        PointerWidth::U32 => 0x8000_0000,
        PointerWidth::U64 => 0x8000_0000_0000_0000,
    }
}

/// Decodes the only accepted non-ordinal named-import thunk encodings.
/// PE32 uses a plain RVA; PE32+ additionally accepts the established bit-32 tag.
pub(crate) fn named_thunk_rva(width: PointerWidth, value: u64) -> Option<u32> {
    match width {
        PointerWidth::U32 => u32::try_from(value).ok(),
        PointerWidth::U64 if value <= u64::from(u32::MAX) => Some(value as u32),
        PointerWidth::U64 if value >> 32 == 1 => Some(value as u32),
        PointerWidth::U64 => None,
    }
}

pub(crate) fn printable_ascii(value: u8) -> bool {
    (0x21..=0x7e).contains(&value)
}

pub(crate) fn valid_module_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_MODULE_NAME_LEN && name.bytes().all(printable_ascii)
}

/// Validates one writable IAT span without comparing it with other modules.
/// Range-overlap policy belongs to the reconstruction layer.
pub(crate) fn checked_destination_bounds(
    module: &ImportModule,
    image_size: u32,
    pointer_width: PointerWidth,
) -> Result<(u32, u32)> {
    let cell_size = pointer_size_rva(pointer_width);
    ensure!(
        !module.symbols.is_empty(),
        "module {} has no imports",
        module.dll
    );
    ensure!(
        module.destination_rva.is_multiple_of(DESCRIPTOR_ALIGNMENT),
        "module {} IAT RVA is not {DESCRIPTOR_ALIGNMENT}-byte aligned",
        module.dll
    );
    let byte_len = u32::try_from(module.symbols.len())
        .context("module import count exceeds PE limits")?
        .checked_mul(cell_size)
        .context("module IAT length overflow")?;
    let end_rva = module
        .destination_rva
        .checked_add(byte_len)
        .context("module IAT range overflow")?;
    let terminated_end_rva = end_rva
        .checked_add(cell_size)
        .context("module IAT terminator range overflow")?;
    ensure!(
        terminated_end_rva <= image_size,
        "module {} terminated IAT {:#x}..{terminated_end_rva:#x} exceeds image size {image_size:#x}",
        module.dll,
        module.destination_rva
    );
    Ok((module.destination_rva, end_rva))
}

pub(super) fn validate_discovery_modules(
    modules: &[ImportModule],
    image_size: u32,
    pointer_width: PointerWidth,
) -> Result<()> {
    ensure!(
        modules.len() <= MAX_PARSED_DESCRIPTORS,
        "loader descriptor count exceeds {MAX_PARSED_DESCRIPTORS}-descriptor budget"
    );
    let mut function_count = 0usize;
    for module in modules {
        ensure!(
            valid_module_name(&module.dll),
            "invalid module name {:?}",
            module.dll
        );
        for symbol in &module.symbols {
            function_count = function_count
                .checked_add(1)
                .context("loader function count overflow")?;
            ensure!(
                function_count <= MAX_PARSED_FUNCTIONS,
                "loader function count exceeds {MAX_PARSED_FUNCTIONS}-function budget"
            );
            if let ImportSymbol::Name { name, .. } = symbol {
                ensure!(
                    name.len() <= MAX_API_NAME_LEN,
                    "module {} API name exceeds {MAX_API_NAME_LEN}-byte verifier limit",
                    module.dll
                );
                ensure!(
                    !name.is_empty() && name.bytes().all(printable_ascii),
                    "module {} has an invalid import name",
                    module.dll
                );
            }
        }
        checked_destination_bounds(module, image_size, pointer_width)?;
    }
    Ok(())
}

#[derive(Default)]
pub(super) struct DiscoveryBudget {
    pub(super) scanned_descriptor_starts: usize,
    pub(super) parsed_descriptors: usize,
    pub(super) parsed_functions: usize,
    pub(super) valid_candidates: usize,
    pub(super) referenced_metadata_bytes: usize,
    pub(super) attempted_loader_string_bytes: usize,
}

impl DiscoveryBudget {
    fn consume(counter: &mut usize, maximum: usize, kind: &str) -> Result<()> {
        *counter = counter
            .checked_add(1)
            .with_context(|| format!("encoded loader import {kind} budget counter overflow"))?;
        ensure!(
            *counter <= maximum,
            "encoded loader import {kind} budget of {maximum} exceeded"
        );
        Ok(())
    }

    pub(super) fn scanned_descriptor_start(&mut self) -> Result<()> {
        Self::consume(
            &mut self.scanned_descriptor_starts,
            MAX_SCANNED_DESCRIPTOR_STARTS,
            "scan",
        )
    }

    pub(super) fn parsed_descriptor(&mut self) -> Result<()> {
        Self::consume(
            &mut self.parsed_descriptors,
            MAX_PARSED_DESCRIPTORS,
            "descriptor",
        )
    }

    pub(super) fn parsed_function(&mut self) -> Result<()> {
        Self::consume(&mut self.parsed_functions, MAX_PARSED_FUNCTIONS, "function")
    }

    pub(super) fn valid_candidate(&mut self) -> Result<()> {
        Self::consume(
            &mut self.valid_candidates,
            MAX_VALID_CANDIDATES,
            "candidate",
        )
    }

    /// Charges every encoded loader-string byte inspected during discovery,
    /// whether its enclosing string eventually validates or is rejected.
    pub(super) fn attempted_loader_string_byte(&mut self) -> Result<()> {
        Self::consume(
            &mut self.attempted_loader_string_bytes,
            MAX_ATTEMPTED_LOADER_STRING_BYTES,
            "loader string byte",
        )
    }

    pub(super) fn referenced_metadata(&mut self, length: usize) -> Result<()> {
        self.referenced_metadata_bytes = self
            .referenced_metadata_bytes
            .checked_add(length)
            .context("encoded loader import metadata budget counter overflow")?;
        ensure!(
            self.referenced_metadata_bytes <= MAX_REFERENCED_METADATA_BYTES,
            "encoded loader import metadata budget of {MAX_REFERENCED_METADATA_BYTES} bytes exceeded"
        );
        Ok(())
    }
}

pub(super) struct MappedImage<'a> {
    pub(super) mapped: &'a [u8],
    pub(super) pe: &'a Pe,
    pub(super) pointer_width: PointerWidth,
}

#[derive(Debug)]
pub(super) struct DecodedString {
    pub(super) value: String,
    pub(super) end_rva: u32,
}

#[derive(Debug)]
pub(super) struct ParsedThunks {
    pub(super) symbols: Vec<ImportSymbol>,
    pub(super) metadata_ranges: Vec<Range<u32>>,
}

pub(super) fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

impl<'a> MappedImage<'a> {
    /// Returns a range only when it is fully backed by the mapped image and by
    /// one PE section. Loader metadata records never legitimately straddle a
    /// section boundary.
    pub(super) fn range(&self, rva: u32, len: usize) -> Option<&'a [u8]> {
        if len == 0 {
            return Some(&[]);
        }
        let len_u32 = u32::try_from(len).ok()?;
        let end_rva = rva.checked_add(len_u32)?;
        if end_rva > self.pe.size_of_image {
            return None;
        }
        self.pe.section_for_rva_range(rva, len).ok()?;
        let start = usize::try_from(rva).ok()?;
        let end = start.checked_add(len)?;
        self.mapped.get(start..end)
    }

    pub(super) fn byte(&self, rva: u32) -> Option<u8> {
        self.range(rva, 1).map(|bytes| bytes[0])
    }

    pub(super) fn u16(&self, rva: u32) -> Option<u16> {
        let bytes = self.range(rva, 2)?;
        read_u16(bytes, 0)
    }

    pub(super) fn u32(&self, rva: u32) -> Option<u32> {
        let bytes = self.range(rva, 4)?;
        read_u32(bytes, 0)
    }

    pub(super) fn pointer(&self, rva: u32) -> Option<u64> {
        let len = pointer_size(self.pointer_width);
        self.range(rva, len)?;
        let offset = usize::try_from(rva).ok()?;
        self.pe.read_pointer(self.mapped, offset).ok()
    }
}

pub(super) fn record_metadata_range(
    ranges: &mut Vec<Range<u32>>,
    start_rva: u32,
    end_rva: u32,
    budget: &mut DiscoveryBudget,
) -> Result<()> {
    ensure!(
        start_rva < end_rva,
        "encoded loader metadata range is empty or reversed"
    );
    let length = usize::try_from(end_rva - start_rva)
        .context("encoded loader metadata range length does not fit usize")?;
    budget.referenced_metadata(length)?;
    ranges.push(start_rva..end_rva);
    Ok(())
}

pub(super) fn sorted_merged_metadata_ranges(
    mut ranges: Vec<Range<u32>>,
    image_size: u32,
) -> Result<Vec<Range<u32>>> {
    for range in &ranges {
        ensure!(
            range.start < range.end && range.end <= image_size,
            "encoded loader metadata range is invalid"
        );
    }
    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged = Vec::<Range<u32>>::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && range.start <= previous.end
        {
            previous.end = previous.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    Ok(merged)
}

mod loader;
mod standard;

/// Discovers imports using the profile selected by the unpack pipeline.
pub(crate) fn discover_imports_in_image(
    mapped: &[u8],
    pe: &Pe,
    profile: ImportProfile,
) -> Result<LoaderDiscovery> {
    match profile {
        ImportProfile::EncodedLoader => loader::discover_imports_in_image(mapped, pe),
        ImportProfile::Standard => standard::discover_imports_in_image(mapped, pe),
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
