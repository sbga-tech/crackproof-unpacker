use anyhow::{Context, Result, bail, ensure};
use std::ops::Range;

use crate::pe::{Machine, Pe, PeKind, PointerWidth};

pub(crate) const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub(crate) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub(crate) const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
pub(crate) const DIRECT_REL32_LEN: usize = 5;
pub(crate) const SEMANTIC_VENEER_LEN: usize = DIRECT_REL32_LEN * 2;
pub(crate) const CRT_STARTUP_PROLOGUE_LEN: usize = 12;
pub(crate) const I386_COOKIE_EVIDENCE_LEN: usize = 0xa0;
pub(crate) const I386_SEH_HELPER_EVIDENCE_LEN: usize = 0x50;
pub(crate) const I386_COOKIE_CELL_LEN: usize = 4;
pub(crate) const AMD64_IMPORT_THUNK_LEN: usize = 6;
pub(crate) const AMD64_POINTER_CELL_LEN: usize = 8;
pub(crate) const AMD64_RUNTIME_FUNCTION_LEN: usize = 12;
pub(crate) const AMD64_STARTUP_LEN: usize = 13;
pub(crate) const AMD64_HELPER_TARGET_LEN: usize = 5;
pub(crate) const AMD64_MSVC_ENTRY_LEN: usize = 18;
pub(crate) const AMD64_COOKIE_EVIDENCE_LEN: usize = 0x2c;
pub(crate) const AMD64_CRT_EVIDENCE_LEN: usize = 0x60;
pub(crate) const SEMANTIC_PROTECTED_RANGE_COUNT: usize = 8;
pub(crate) const MAX_SEMANTIC_EXECUTABLE_SCAN_BYTES: usize = 512 << 20;

mod native;
mod sparse;
mod stage;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use sparse::SparsePageKey;
pub(crate) use sparse::{decode_sparse_text_pages_in_place, unique_sparse_page_keys};
#[cfg(test)]
pub(crate) use stage::SelectedOutputProfile;
pub(crate) use stage::select_output_entry;

const SPARSE_PAGE_SIZE: usize = 0x1000;
const SPARSE_BLOCK_SIZE: usize = 0x10;

/// The retained handoff veneer that transfers control to the original CRT
/// startup path, together with the control-flow targets that prove that
/// handoff's semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SemanticEntry {
    pub(crate) entry_rva: u32,
    /// An inbound executable edge only exists for profiles that prove one.
    /// Standalone MSVC OEPs deliberately have no synthetic predecessor.
    pub(crate) predecessor_rva: Option<u32>,
    pub(crate) veneer_call_target_rva: u32,
    pub(crate) veneer_helper_target_rva: u32,
    pub(crate) startup_rva: u32,
    pub(crate) crt_call_target_rva: u32,
    pub(crate) crt_helper_target_rva: u32,
    pub(crate) startup_data_rva: u32,
    pub(crate) startup_data_len: u32,
    pub(crate) evidence: SemanticEvidence,
}

/// Architecture-specific proof material that cannot be represented by the
/// historical I386 handoff fields alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SemanticEvidence {
    I386,
    I386MsvcStandalone {
        cookie_rva: u32,
        cookie_complement_rva: u32,
    },
    Amd64 {
        iat_cell_rva: u32,
        runtime_function_rva: Option<u32>,
    },
    Amd64Msvc {
        entry_runtime_function_rva: u32,
        cookie_runtime_function_rva: u32,
        startup_runtime_function_rva: u32,
    },
}

impl SemanticEntry {
    pub(crate) fn veneer_range(self) -> Result<Range<u32>> {
        rva_range(self.entry_rva, SEMANTIC_VENEER_LEN, "semantic veneer range")
    }

    /// The executable proof locations whose owner sections must remain
    /// immutable. A predecessor is present only when that evidence profile
    /// establishes an actual inbound executable edge.
    pub(crate) fn executable_rvas(self) -> Vec<u32> {
        let mut rvas = self.predecessor_rva.into_iter().collect::<Vec<_>>();
        match self.evidence {
            SemanticEvidence::I386 => rvas.extend([
                self.entry_rva,
                self.veneer_call_target_rva,
                self.crt_call_target_rva,
                self.veneer_helper_target_rva,
                self.crt_helper_target_rva,
                self.startup_rva,
            ]),
            SemanticEvidence::I386MsvcStandalone { .. } => rvas.extend([
                self.entry_rva,
                self.veneer_call_target_rva,
                self.startup_rva,
                self.crt_call_target_rva,
                self.crt_helper_target_rva,
            ]),
            SemanticEvidence::Amd64 { .. } => rvas.extend([
                self.entry_rva,
                self.veneer_call_target_rva,
                self.crt_call_target_rva,
                self.crt_helper_target_rva,
                self.startup_rva,
            ]),
            SemanticEvidence::Amd64Msvc { .. } => rvas.extend([
                self.entry_rva,
                self.veneer_call_target_rva,
                self.startup_rva,
            ]),
        }
        rvas
    }

    /// Every exact instruction and data span whose provenance establishes the
    /// retained semantic handoff.
    ///
    /// The AMD64 profile adds the entire six-byte RIP-relative import thunk,
    /// its eight-byte target cell, and the exact twelve-byte runtime-function
    /// record when the Exception Directory supplied that independent proof.
    pub(crate) fn protected_ranges(self) -> Result<Vec<Range<u32>>> {
        let mut ranges = Vec::new();
        match self.evidence {
            SemanticEvidence::I386 => {
                let predecessor_rva = self
                    .predecessor_rva
                    .context("legacy I386 semantic entry has no predecessor evidence")?;
                ranges
                    .try_reserve_exact(SEMANTIC_PROTECTED_RANGE_COUNT)
                    .context("reserving I386 semantic provenance ranges")?;
                ranges.push(rva_range(
                    predecessor_rva,
                    DIRECT_REL32_LEN,
                    "semantic predecessor range",
                )?);
                ranges.push(self.veneer_range()?);
                ranges.push(rva_range(
                    self.startup_rva,
                    CRT_STARTUP_PROLOGUE_LEN,
                    "semantic startup prologue range",
                )?);
                ranges.push(rva_range(
                    self.veneer_call_target_rva,
                    DIRECT_REL32_LEN,
                    "semantic veneer helper thunk range",
                )?);
                ranges.push(rva_range(
                    self.crt_call_target_rva,
                    DIRECT_REL32_LEN,
                    "semantic startup helper thunk range",
                )?);
                ranges.push(rva_range(
                    self.veneer_helper_target_rva,
                    DIRECT_REL32_LEN,
                    "semantic veneer helper target range",
                )?);
                ranges.push(rva_range(
                    self.crt_helper_target_rva,
                    DIRECT_REL32_LEN,
                    "semantic startup helper target range",
                )?);
                ranges.push(rva_range(
                    self.startup_data_rva,
                    usize::try_from(self.startup_data_len)
                        .context("semantic startup data length does not fit usize")?,
                    "semantic startup data range",
                )?);
            }
            SemanticEvidence::I386MsvcStandalone {
                cookie_rva,
                cookie_complement_rva,
            } => {
                ranges
                    .try_reserve_exact(7)
                    .context("reserving standalone I386 MSVC OEP provenance ranges")?;
                ranges.push(self.veneer_range()?);
                ranges.push(rva_range(
                    self.startup_rva,
                    CRT_STARTUP_PROLOGUE_LEN,
                    "standalone I386 MSVC startup range",
                )?);
                ranges.push(rva_range(
                    self.veneer_call_target_rva,
                    I386_COOKIE_EVIDENCE_LEN,
                    "standalone I386 security-cookie initializer range",
                )?);
                ranges.push(rva_range(
                    self.crt_call_target_rva,
                    DIRECT_REL32_LEN,
                    "standalone I386 SEH helper thunk range",
                )?);
                ranges.push(rva_range(
                    self.crt_helper_target_rva,
                    I386_SEH_HELPER_EVIDENCE_LEN,
                    "standalone I386 SEH helper evidence range",
                )?);
                ranges.push(rva_range(
                    cookie_rva,
                    I386_COOKIE_CELL_LEN,
                    "standalone I386 security-cookie cell range",
                )?);
                ranges.push(rva_range(
                    cookie_complement_rva,
                    I386_COOKIE_CELL_LEN,
                    "standalone I386 security-cookie complement range",
                )?);
                ranges.push(rva_range(
                    self.startup_data_rva,
                    usize::try_from(self.startup_data_len)
                        .context("standalone I386 startup data length does not fit usize")?,
                    "standalone I386 startup data range",
                )?);
            }
            SemanticEvidence::Amd64 {
                iat_cell_rva,
                runtime_function_rva,
            } => {
                let predecessor_rva = self
                    .predecessor_rva
                    .context("AMD64 semantic entry has no predecessor evidence")?;
                ranges
                    .try_reserve_exact(9)
                    .context("reserving AMD64 semantic provenance ranges")?;
                ranges.push(rva_range(
                    predecessor_rva,
                    DIRECT_REL32_LEN,
                    "AMD64 semantic predecessor range",
                )?);
                ranges.push(self.veneer_range()?);
                ranges.push(rva_range(
                    self.startup_rva,
                    AMD64_STARTUP_LEN,
                    "AMD64 startup range",
                )?);
                ranges.push(rva_range(
                    self.veneer_call_target_rva,
                    AMD64_IMPORT_THUNK_LEN,
                    "AMD64 import thunk range",
                )?);
                ranges.push(rva_range(
                    self.crt_call_target_rva,
                    DIRECT_REL32_LEN,
                    "AMD64 startup helper thunk range",
                )?);
                ranges.push(rva_range(
                    self.crt_helper_target_rva,
                    AMD64_HELPER_TARGET_LEN,
                    "AMD64 startup helper target range",
                )?);
                ranges.push(rva_range(
                    self.startup_data_rva,
                    usize::try_from(self.startup_data_len)
                        .context("AMD64 startup state length does not fit usize")?,
                    "AMD64 RIP-relative startup-state range",
                )?);
                if iat_cell_rva != self.startup_data_rva {
                    ranges.push(rva_range(
                        iat_cell_rva,
                        AMD64_POINTER_CELL_LEN,
                        "AMD64 import target-cell range",
                    )?);
                }
                if let Some(runtime_function_rva) = runtime_function_rva {
                    ranges.push(rva_range(
                        runtime_function_rva,
                        AMD64_RUNTIME_FUNCTION_LEN,
                        "AMD64 runtime-function range",
                    )?);
                }
            }
            SemanticEvidence::Amd64Msvc {
                entry_runtime_function_rva,
                cookie_runtime_function_rva,
                startup_runtime_function_rva,
            } => {
                ranges
                    .try_reserve_exact(7)
                    .context("reserving AMD64 MSVC semantic provenance ranges")?;
                ranges.push(rva_range(
                    self.entry_rva,
                    AMD64_MSVC_ENTRY_LEN,
                    "AMD64 MSVC entry range",
                )?);
                ranges.push(rva_range(
                    self.veneer_call_target_rva,
                    AMD64_COOKIE_EVIDENCE_LEN,
                    "AMD64 security-cookie initializer range",
                )?);
                ranges.push(rva_range(
                    self.startup_rva,
                    AMD64_CRT_EVIDENCE_LEN,
                    "AMD64 CRT startup evidence range",
                )?);
                ranges.push(rva_range(
                    self.startup_data_rva,
                    usize::try_from(self.startup_data_len)
                        .context("AMD64 security-cookie length does not fit usize")?,
                    "AMD64 security-cookie data range",
                )?);
                for (rva, description) in [
                    (
                        entry_runtime_function_rva,
                        "AMD64 MSVC entry runtime-function range",
                    ),
                    (
                        cookie_runtime_function_rva,
                        "AMD64 security-cookie runtime-function range",
                    ),
                    (
                        startup_runtime_function_rva,
                        "AMD64 CRT startup runtime-function range",
                    ),
                ] {
                    ranges.push(rva_range(rva, AMD64_RUNTIME_FUNCTION_LEN, description)?);
                }
            }
        }
        Ok(ranges)
    }

    /// Compatibility construction for fixtures outside this module.  Production
    /// entries are exclusively created by `discover_semantic_entry`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn i386_for_test(
        entry_rva: u32,
        predecessor_rva: u32,
        veneer_call_target_rva: u32,
        veneer_helper_target_rva: u32,
        startup_rva: u32,
        crt_call_target_rva: u32,
        crt_helper_target_rva: u32,
        startup_data_rva: u32,
        startup_data_len: u32,
    ) -> Self {
        Self {
            entry_rva,
            predecessor_rva: Some(predecessor_rva),
            veneer_call_target_rva,
            veneer_helper_target_rva,
            startup_rva,
            crt_call_target_rva,
            crt_helper_target_rva,
            startup_data_rva,
            startup_data_len,
            evidence: SemanticEvidence::I386,
        }
    }
}

/// The entry contract selected from decrypted PE semantics.
///
/// Native executables must expose the unique CrackProof-to-CRT handoff proved
/// by [`SemanticEntry`]. Native DLLs must expose an authenticated architecture-
/// specific entry wrapper. CLR images instead derive their managed entry
/// contract from the COM Descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedKind {
    Dll,
    Exe,
}

impl ManagedKind {
    pub(crate) const fn is_dll(self) -> bool {
        matches!(self, Self::Dll)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OutputEntry {
    Native(SemanticEntry),
    NativeDll { entry_rva: u32 },
    Managed { entry_rva: u32, kind: ManagedKind },
}

impl OutputEntry {
    pub(crate) const fn entry_rva(self) -> u32 {
        match self {
            Self::Native(entry) => entry.entry_rva,
            Self::NativeDll { entry_rva } | Self::Managed { entry_rva, .. } => entry_rva,
        }
    }

    pub(crate) const fn semantic(self) -> Option<SemanticEntry> {
        match self {
            Self::Native(entry) => Some(entry),
            Self::NativeDll { .. } | Self::Managed { .. } => None,
        }
    }

    /// Returns every immutable range that establishes this entry contract.
    ///
    /// A managed image has no retained native entry range; its authoritative
    /// contract is the independently retained COM Descriptor and metadata.
    /// An authenticated native DLL startup protects its executable owner
    /// section.
    pub(crate) fn protected_ranges(self, pe: &Pe) -> Result<Vec<Range<u32>>> {
        match self {
            Self::Native(entry) => entry.protected_ranges(),
            Self::Managed { .. } | Self::NativeDll { entry_rva: 0 } => Ok(Vec::new()),
            Self::NativeDll { entry_rva } => {
                let section = pe
                    .section_for_rva_range(entry_rva, 1)
                    .context("locating authenticated DLL entry section")?;
                ensure!(
                    section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                    "authenticated DLL entry RVA {entry_rva:#x} belongs to non-executable section {}",
                    section.index
                );
                Ok(vec![section.virtual_range().with_context(|| {
                    format!(
                        "reading authenticated DLL entry section {} range",
                        section.index
                    )
                })?])
            }
        }
    }
}

/// Selects the decrypted-image entry profile without trusting the packed
/// AddressOfEntryPoint. A nonempty COM Descriptor selects a managed DLL or EXE
/// profile; native DLLs and executables must independently authenticate their
/// respective entry contracts.
pub(crate) fn discover_output_entry(mapped: &[u8], pe: &Pe) -> Result<OutputEntry> {
    let com_descriptor = pe
        .directories
        .get(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
        .copied()
        .unwrap_or(crate::pe::DataDirectory {
            virtual_address: 0,
            size: 0,
        });
    ensure!(
        (com_descriptor.virtual_address == 0) == (com_descriptor.size == 0),
        "COM Descriptor is partially null"
    );
    if com_descriptor.is_empty() {
        if pe.is_dll() {
            return match pe.machine_kind() {
                Machine::Amd64 => {
                    ensure!(
                        pe.kind() == PeKind::Pe32Plus && pe.pointer_width() == PointerWidth::U64,
                        "AMD64 DLL discovery requires a PE32+ image with 64-bit pointers"
                    );
                    native::amd64::discover_amd64_dll_entry(mapped, pe)
                        .map(|entry_rva| OutputEntry::NativeDll { entry_rva })
                }
                Machine::I386 => bail!(
                    "I386 native DLL entry discovery is unsupported; refusing to preserve a packed bootstrap"
                ),
            };
        }
        return discover_semantic_entry(mapped, pe).map(OutputEntry::Native);
    }

    const COR20_REQUIRED_FIELDS: u32 = 24;
    const COMIMAGE_FLAGS_NATIVE_ENTRYPOINT: u32 = 0x10;
    ensure!(
        com_descriptor.size >= COR20_REQUIRED_FIELDS,
        "managed COM Descriptor is too short for entry semantics"
    );
    let header_size = read_u32_rva(mapped, com_descriptor.virtual_address)
        .context("reading managed COM Descriptor size")?;
    ensure!(
        (COR20_REQUIRED_FIELDS..=com_descriptor.size).contains(&header_size),
        "managed COM Descriptor header size is invalid"
    );
    let flags_rva = com_descriptor
        .virtual_address
        .checked_add(16)
        .context("managed COM Descriptor flags RVA overflow")?;
    let entry_rva = flags_rva
        .checked_add(4)
        .context("managed COM Descriptor entry RVA overflow")?;
    let flags = read_u32_rva(mapped, flags_rva).context("reading managed COM Descriptor flags")?;
    let managed_entry =
        read_u32_rva(mapped, entry_rva).context("reading managed COM Descriptor entry")?;
    ensure!(
        flags & COMIMAGE_FLAGS_NATIVE_ENTRYPOINT == 0,
        "managed images with a native entry point are unsupported"
    );
    let kind = if pe.is_dll() {
        ensure!(managed_entry == 0, "managed DLL has a nonzero entry token");
        ManagedKind::Dll
    } else {
        ensure!(
            managed_entry & 0xff00_0000 == 0x0600_0000 && managed_entry & 0x00ff_ffff != 0,
            "managed EXE entry is not a nonzero MethodDef token"
        );
        ManagedKind::Exe
    };
    Ok(OutputEntry::Managed { entry_rva: 0, kind })
}

/// Locates the unique CrackProof handoff from protected code into the original
/// MSVC startup sequence.
///
/// A candidate is an executable `CALL rel32; JMP rel32` veneer whose CALL
/// target is executable and whose JMP target starts the observed CRT startup
/// prologue.  A candidate is meaningful only when exactly one executable
/// `JMP rel32` reaches the veneer itself.  Unreferenced veneer-shaped byte
/// sequences are deliberately ignored; every remaining ambiguity is rejected.
pub(crate) fn discover_semantic_entry(mapped: &[u8], pe: &Pe) -> Result<SemanticEntry> {
    match pe.machine_kind() {
        Machine::I386 => {
            ensure!(
                pe.kind() == PeKind::Pe32 && pe.pointer_width() == PointerWidth::U32,
                "I386 semantic discovery requires a PE32 image with 32-bit pointers"
            );
            native::i386::discover_i386_semantic_entry(mapped, pe)
        }
        Machine::Amd64 => {
            ensure!(
                pe.kind() == PeKind::Pe32Plus && pe.pointer_width() == PointerWidth::U64,
                "AMD64 semantic discovery requires a PE32+ image with 64-bit pointers"
            );
            native::amd64::discover_amd64_semantic_entry(mapped, pe)
        }
    }
}

pub(crate) fn authenticate_sparse_output_entry(
    mapped: &[u8],
    pe: &Pe,
    entry: OutputEntry,
) -> Result<()> {
    let OutputEntry::Native(entry) = entry else {
        bail!("sparse executable-page profile produced a non-native output entry");
    };
    match pe.machine_kind() {
        Machine::I386 => native::i386::authenticate_i386_sparse_entry(mapped, pe, entry),
        Machine::Amd64 => native::amd64::authenticate_amd64_sparse_entry(mapped, entry),
    }
}

pub(crate) fn read_u32_rva(mapped: &[u8], rva: u32) -> Result<u32> {
    Ok(u32::from_le_bytes(
        mapped_bytes(mapped, rva, 4)?
            .try_into()
            .expect("a bounded u32 cell has exactly four bytes"),
    ))
}

pub(crate) fn executable_section_ranges(mapped: &[u8], pe: &Pe) -> Result<Vec<Range<u32>>> {
    let mut ranges = Vec::new();

    for section in &pe.sections {
        if section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
            continue;
        }

        let range = section
            .virtual_range()
            .with_context(|| format!("reading executable section {} RVA range", section.index))?;
        let mapped_end = usize::try_from(range.end)
            .context("executable section RVA end does not fit the host address space")?;
        if mapped_end > mapped.len() {
            bail!(
                "executable section {} RVA range {:#x}..{:#x} exceeds mapped image length {:#x}",
                section.index,
                range.start,
                range.end,
                mapped.len()
            );
        }
        ranges.push(range);
    }

    ranges.sort_unstable_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<u32>> = Vec::with_capacity(ranges.len());
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
pub(crate) fn ensure_executable_scan_bound(executable_ranges: &[Range<u32>]) -> Result<()> {
    let mut total = 0usize;
    for range in executable_ranges {
        let length = usize::try_from(range.end - range.start)
            .context("executable scan range length does not fit usize")?;
        total = total
            .checked_add(length)
            .context("executable scan byte count overflows")?;
        ensure!(
            total <= MAX_SEMANTIC_EXECUTABLE_SCAN_BYTES,
            "semantic entry scan exceeds its {MAX_SEMANTIC_EXECUTABLE_SCAN_BYTES}-byte executable work cap"
        );
    }
    Ok(())
}

pub(crate) fn is_mapped_readable_non_executable_range(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    rva: u32,
    len: u32,
) -> Result<bool> {
    let len_usize = usize::try_from(len).context("startup data length does not fit usize")?;
    if mapped_bytes(mapped, rva, len_usize).is_err() {
        return Ok(false);
    }
    let end = rva
        .checked_add(len)
        .context("startup data RVA range overflows")?;
    if rva < pe.size_of_headers {
        return Ok(false);
    }
    let Ok(section) = pe.section_for_rva_range(rva, len_usize) else {
        return Ok(false);
    };
    Ok(section.characteristics & IMAGE_SCN_MEM_READ != 0
        && section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0
        && !executable_ranges
            .iter()
            .any(|range| range.start < end && rva < range.end))
}

pub(crate) fn direct_rel32_target(mapped: &[u8], rva: u32, opcode: u8) -> Result<Option<u32>> {
    let bytes = mapped_bytes(mapped, rva, DIRECT_REL32_LEN)?;
    if bytes[0] != opcode {
        return Ok(None);
    }

    let displacement =
        i64::from(i32::from_le_bytes(bytes[1..].try_into().expect(
            "a bounded direct rel32 instruction has exactly four displacement bytes",
        )));
    let next_rva = i64::from(rva)
        .checked_add(i64::try_from(DIRECT_REL32_LEN).expect("direct rel32 length fits i64"))
        .context("direct rel32 next-RVA arithmetic overflow")?;
    let target = next_rva
        .checked_add(displacement)
        .context("direct rel32 target arithmetic overflow")?;

    Ok(u32::try_from(target).ok())
}

pub(crate) fn is_executable_range(
    executable_ranges: &[Range<u32>],
    rva: u32,
    len: usize,
) -> Result<bool> {
    let len = u32::try_from(len).context("executable range length exceeds u32")?;
    let end = rva
        .checked_add(len)
        .context("executable range end overflow")?;
    Ok(executable_ranges
        .iter()
        .any(|range| range.start <= rva && end <= range.end))
}

fn rva_range(rva: u32, len: usize, description: &str) -> Result<Range<u32>> {
    let len = u32::try_from(len).with_context(|| format!("{description} length exceeds u32"))?;
    let end = rva
        .checked_add(len)
        .with_context(|| format!("{description} end overflows"))?;
    Ok(rva..end)
}

pub(crate) fn mapped_bytes(mapped: &[u8], rva: u32, len: usize) -> Result<&[u8]> {
    let start = usize::try_from(rva).context("mapped RVA does not fit the host address space")?;
    let end = start
        .checked_add(len)
        .context("mapped byte range end overflow")?;
    mapped
        .get(start..end)
        .with_context(|| format!("mapped RVA range {rva:#x}..{end:#x} exceeds image"))
}
