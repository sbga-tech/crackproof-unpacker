use crate::pe::Pe;
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::ops::Range;

use super::super::*;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const AMD64_DEFAULT_SECURITY_COOKIE: u64 = 0x0000_2b99_2ddf_a232;
const MAX_SEMANTIC_VENEERS: usize = 4_096;
const MAX_EXECUTABLE_JUMPS: usize = 1 << 20;
const MAX_RUNTIME_FUNCTIONS: usize = 1 << 20;
const AMD64_DLL_STARTUP_LEN: usize = 0x3d;
const AMD64_DLL_STARTUP_PREFIX: [u8; 28] = [
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10, 0x57, 0x48, 0x83, 0xec, 0x20, 0x49,
    0x8b, 0xf8, 0x8b, 0xda, 0x48, 0x8b, 0xf1, 0x83, 0xfa, 0x01, 0x75, 0x05,
];
const AMD64_DLL_STARTUP_SUFFIX: [u8; 23] = [
    0x4c, 0x8b, 0xc7, 0x8b, 0xd3, 0x48, 0x8b, 0xce, 0x48, 0x8b, 0x5c, 0x24, 0x30, 0x48, 0x8b, 0x74,
    0x24, 0x38, 0x48, 0x83, 0xc4, 0x20, 0x5f,
];

#[derive(Clone, Copy, Debug)]
struct JumpPredecessors {
    count: usize,
    source_rva: u32,
}

#[derive(Clone, Copy, Debug)]
struct Amd64VeneerEvidence {
    entry_rva: u32,
    veneer_call_target_rva: u32,
    startup_rva: u32,
    crt_call_target_rva: u32,
    crt_helper_target_rva: u32,
    startup_data_rva: u32,
    iat_cell_rva: u32,
    runtime_function_rva: Option<u32>,
}

#[derive(Clone, Copy, Debug)]
struct Amd64StartupEvidence {
    crt_call_target_rva: u32,
    crt_helper_target_rva: u32,
    startup_data_rva: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Amd64Instruction {
    CallRel32 { target_rva: u32 },
    JumpRel32 { target_rva: u32 },
    IndirectJumpRip { cell_rva: u32 },
    LeaRip { target_rva: u32 },
    Nop,
    Return,
}

#[derive(Clone, Copy, Debug)]
struct Amd64UnwindOperation {
    code_offset: usize,
    opcode: u8,
    info: u8,
    stack_size: Option<usize>,
    save_offset: Option<usize>,
}
#[derive(Clone, Copy, Debug)]
struct Amd64RuntimeFunction {
    record_rva: u32,
    begin_rva: u32,
    end_rva: u32,
}

#[derive(Debug)]
struct Amd64RuntimeFunctionIndex {
    records: Vec<Amd64RuntimeFunction>,
}

impl Amd64RuntimeFunctionIndex {
    fn parse(mapped: &[u8], pe: &Pe, executable_ranges: &[Range<u32>]) -> Result<Option<Self>> {
        let Some(directory) = pe.directories.get(IMAGE_DIRECTORY_ENTRY_EXCEPTION).copied() else {
            return Ok(None);
        };
        let Some(range) = directory
            .checked_rva_range()
            .context("validating AMD64 Exception Directory")?
        else {
            return Ok(None);
        };
        let size = usize::try_from(directory.size)
            .context("AMD64 Exception Directory size does not fit usize")?;
        ensure!(
            size.is_multiple_of(AMD64_RUNTIME_FUNCTION_LEN),
            "AMD64 Exception Directory size {size:#x} is not a multiple of {AMD64_RUNTIME_FUNCTION_LEN}"
        );
        let count = size / AMD64_RUNTIME_FUNCTION_LEN;
        ensure!(
            count <= MAX_RUNTIME_FUNCTIONS,
            "AMD64 Exception Directory has {count} runtime functions, exceeding the {MAX_RUNTIME_FUNCTIONS} record cap"
        );
        let directory_section = pe
            .section_for_rva_range(range.start, size)
            .context("locating AMD64 Exception Directory owner")?;
        ensure!(
            directory_section.characteristics & IMAGE_SCN_MEM_READ != 0
                && directory_section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0,
            "AMD64 Exception Directory belongs to section {} without readable non-executable ownership",
            directory_section.index
        );
        mapped_bytes(mapped, range.start, size)
            .context("reading AMD64 Exception Directory from mapped image")?;

        let mut records = Vec::<Amd64RuntimeFunction>::new();
        records
            .try_reserve_exact(count)
            .context("reserving AMD64 runtime-function index")?;
        for index in 0..count {
            let record_rva = range
                .start
                .checked_add(
                    u32::try_from(
                        index
                            .checked_mul(AMD64_RUNTIME_FUNCTION_LEN)
                            .context("AMD64 runtime-function record offset overflows")?,
                    )
                    .context("AMD64 runtime-function record offset exceeds u32")?,
                )
                .context("AMD64 runtime-function record RVA overflows")?;
            let begin_rva = read_u32_rva(mapped, record_rva)?;
            let end_rva = read_u32_rva(
                mapped,
                record_rva
                    .checked_add(4)
                    .context("AMD64 runtime-function EndAddress RVA overflows")?,
            )?;
            let unwind_rva = read_u32_rva(
                mapped,
                record_rva
                    .checked_add(8)
                    .context("AMD64 runtime-function UnwindInfo RVA overflows")?,
            )?;
            ensure!(
                begin_rva < end_rva,
                "AMD64 runtime function at {record_rva:#x} has invalid {begin_rva:#x}..{end_rva:#x} code bounds"
            );
            if let Some(previous) = records.last() {
                ensure!(
                    previous.end_rva <= begin_rva,
                    "AMD64 runtime functions at {:#x} and {record_rva:#x} overlap or are out of order",
                    previous.record_rva
                );
            }
            let function_len = usize::try_from(end_rva - begin_rva)
                .context("AMD64 runtime-function length does not fit usize")?;
            ensure!(
                is_executable_range(executable_ranges, begin_rva, function_len)?,
                "AMD64 runtime function at {record_rva:#x} does not own executable code bounds {begin_rva:#x}..{end_rva:#x}"
            );
            ensure!(
                unwind_rva != 0,
                "AMD64 runtime function at {record_rva:#x} has a null UnwindInfoAddress"
            );
            let unwind_section = pe.section_for_rva_range(unwind_rva, 4).with_context(|| {
                format!(
                    "locating AMD64 unwind info at {unwind_rva:#x} for runtime function {record_rva:#x}"
                )
            })?;
            ensure!(
                unwind_section.characteristics & IMAGE_SCN_MEM_READ != 0
                    && unwind_section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0,
                "AMD64 unwind info at {unwind_rva:#x} belongs to section {} without readable non-executable ownership",
                unwind_section.index
            );
            mapped_bytes(mapped, unwind_rva, 4).with_context(|| {
                format!(
                    "reading AMD64 unwind info at {unwind_rva:#x} for runtime function {record_rva:#x}"
                )
            })?;
            records.push(Amd64RuntimeFunction {
                record_rva,
                begin_rva,
                end_rva,
            });
        }
        Ok(Some(Self { records }))
    }

    fn record_containing(
        &self,
        function_rva: u32,
        evidence_len: usize,
    ) -> Result<Option<Amd64RuntimeFunction>> {
        let function_end = function_rva
            .checked_add(
                u32::try_from(evidence_len)
                    .context("AMD64 function evidence length exceeds u32")?,
            )
            .context("AMD64 function evidence range overflows")?;
        let insertion = self
            .records
            .partition_point(|record| record.begin_rva <= function_rva);
        let Some(record) = insertion
            .checked_sub(1)
            .and_then(|index| self.records.get(index))
            .copied()
        else {
            return Ok(None);
        };
        Ok((function_end <= record.end_rva).then_some(record))
    }
}

pub(crate) fn discover_amd64_semantic_entry(mapped: &[u8], pe: &Pe) -> Result<SemanticEntry> {
    if let Some(entry) = discover_amd64_msvc_semantic_entry(mapped, pe)? {
        return Ok(entry);
    }

    let executable_ranges = executable_section_ranges(mapped, pe)?;
    ensure_executable_scan_bound(&executable_ranges)?;
    let veneer_starts = amd64_veneer_starts(mapped, &executable_ranges)?;
    let jumps = amd64_executable_jumps(mapped, &executable_ranges, &veneer_starts)?;

    let mut entries = Vec::new();
    let mut incomplete_candidate = None;
    for entry_rva in veneer_starts {
        let Some(predecessors) = jumps.get(&entry_rva) else {
            continue;
        };
        if predecessors.count != 1 {
            continue;
        }

        let Some(veneer) = amd64_veneer_evidence(mapped, pe, &executable_ranges, entry_rva)? else {
            incomplete_candidate.get_or_insert((predecessors.source_rva, entry_rva));
            continue;
        };

        entries
            .try_reserve(1)
            .context("reserving AMD64 semantic entry candidates")?;
        entries.push(SemanticEntry {
            entry_rva: veneer.entry_rva,
            predecessor_rva: Some(predecessors.source_rva),
            veneer_call_target_rva: veneer.veneer_call_target_rva,
            veneer_helper_target_rva: veneer.crt_helper_target_rva,
            startup_rva: veneer.startup_rva,
            crt_call_target_rva: veneer.crt_call_target_rva,
            crt_helper_target_rva: veneer.crt_helper_target_rva,
            startup_data_rva: veneer.startup_data_rva,
            startup_data_len: AMD64_POINTER_CELL_LEN as u32,
            evidence: SemanticEvidence::Amd64 {
                iat_cell_rva: veneer.iat_cell_rva,
                runtime_function_rva: veneer.runtime_function_rva,
            },
        });
    }

    match entries.as_slice() {
        [] => {
            if let Some((predecessor_rva, entry_rva)) = incomplete_candidate {
                bail!(
                    "AMD64 predecessor at {predecessor_rva:#x} reaches a veneer candidate at {entry_rva:#x} with incomplete or unknown instruction evidence"
                );
            }
            bail!("found no structurally valid AMD64 semantic entry")
        }
        [entry] => Ok(*entry),
        _ => bail!(
            "found {} structurally valid AMD64 semantic entries",
            entries.len()
        ),
    }
}

pub(crate) fn discover_amd64_msvc_semantic_entry(
    mapped: &[u8],
    pe: &Pe,
) -> Result<Option<SemanticEntry>> {
    let executable_ranges = executable_section_ranges(mapped, pe)?;
    ensure_executable_scan_bound(&executable_ranges)?;
    let Some(runtime_functions) = Amd64RuntimeFunctionIndex::parse(mapped, pe, &executable_ranges)?
    else {
        return Ok(None);
    };
    let entries = amd64_msvc_semantic_entries(mapped, pe, &executable_ranges, &runtime_functions)?;
    match entries.as_slice() {
        [] => Ok(None),
        [entry] => Ok(Some(*entry)),
        _ => bail!(
            "found {} structurally valid AMD64 MSVC semantic entries",
            entries.len()
        ),
    }
}

/// Authenticates CrackProof's header-selected AMD64 DLL dispatch family.
///
/// The decrypted header AEP is accepted only when it is a `CALL dispatcher;
/// RET` thunk followed by selectors 0, 1, and 2 that call the same dispatcher.
/// The dispatcher must preserve every non-RAX general register around a
/// callsite resolver and tail-transfer only a nonzero resolved target. This is
/// deliberately rooted at the recovered header AEP; it never scans for a bare
/// thunk or trusts the packed header value without its complete closure.
fn discover_amd64_header_dispatch_dll_entry(mapped: &[u8], pe: &Pe) -> Result<Option<u32>> {
    const ENTRY_FAMILY_LEN: usize = 30;
    const DISPATCHER_PREFIX: [u8; 30] = [
        0x58, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
        0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0xc8,
    ];
    const DISPATCHER_SUFFIX: [u8; 34] = [
        0x48, 0x83, 0xc4, 0x28, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41,
        0x5a, 0x41, 0x59, 0x41, 0x58, 0x5f, 0x5e, 0x5d, 0x5b, 0x5a, 0x59, 0x48, 0x85, 0xc0, 0x74,
        0x02, 0x50, 0xc3, 0xc3,
    ];
    const DISPATCHER_LEN: usize = DISPATCHER_PREFIX.len() + 5 + DISPATCHER_SUFFIX.len();

    let entry_rva = pe.entry_rva;
    if entry_rva == 0 {
        return Ok(None);
    }
    let executable_ranges = executable_section_ranges(mapped, pe)?;
    if !is_executable_range(&executable_ranges, entry_rva, ENTRY_FAMILY_LEN)? {
        return Ok(None);
    }
    let entry = mapped_bytes(mapped, entry_rva, 6)?;
    if entry[0] != 0xe8 || entry[5] != 0xc3 {
        return Ok(None);
    }
    let Some(dispatcher_rva) = direct_rel32_target(mapped, entry_rva, 0xe8)? else {
        return Ok(None);
    };

    for selector in 0..3u32 {
        let selector_rva = entry_rva
            .checked_add(6 + selector * 8)
            .context("AMD64 DLL selector RVA overflows")?;
        let bytes = mapped_bytes(mapped, selector_rva, 8)?;
        if bytes[0] != 0x6a
            || bytes[1] != u8::try_from(selector).expect("selector fits u8")
            || bytes[2] != 0xe8
            || bytes[7] != 0xc3
            || direct_rel32_target(mapped, selector_rva + 2, 0xe8)? != Some(dispatcher_rva)
        {
            return Ok(None);
        }
    }

    if !is_executable_range(&executable_ranges, dispatcher_rva, DISPATCHER_LEN)? {
        return Ok(None);
    }
    let dispatcher = mapped_bytes(mapped, dispatcher_rva, DISPATCHER_LEN)?;
    if dispatcher[..DISPATCHER_PREFIX.len()] != DISPATCHER_PREFIX
        || dispatcher[DISPATCHER_PREFIX.len()] != 0xe8
        || dispatcher[DISPATCHER_PREFIX.len() + 5..] != DISPATCHER_SUFFIX
    {
        return Ok(None);
    }
    let resolver_call_rva = dispatcher_rva
        .checked_add(u32::try_from(DISPATCHER_PREFIX.len()).expect("prefix length fits u32"))
        .context("AMD64 DLL resolver CALL RVA overflows")?;
    let Some(resolver_rva) = direct_rel32_target(mapped, resolver_call_rva, 0xe8)? else {
        return Ok(None);
    };
    if resolver_rva == entry_rva
        || resolver_rva == dispatcher_rva
        || !is_executable_range(&executable_ranges, resolver_rva, 1)?
    {
        return Ok(None);
    }
    Ok(Some(entry_rva))
}

/// Locates the canonical MSVC AMD64 DLL entry wrapper that initializes the
/// security cookie before transferring to the CRT DllMain dispatcher.
/// CrackProof's packed header entry is not payload provenance and must not be
/// retained in a standalone DLL.
pub(crate) fn discover_amd64_dll_entry(mapped: &[u8], pe: &Pe) -> Result<u32> {
    let executable_ranges = executable_section_ranges(mapped, pe)?;
    ensure_executable_scan_bound(&executable_ranges)?;
    let mut entries = Vec::new();

    for range in &executable_ranges {
        let Some(last_rva) = range.end.checked_sub(AMD64_DLL_STARTUP_LEN as u32) else {
            continue;
        };
        for entry_rva in range.start..=last_rva {
            let bytes = mapped_bytes(mapped, entry_rva, AMD64_DLL_STARTUP_LEN)?;
            if bytes[..AMD64_DLL_STARTUP_PREFIX.len()] != AMD64_DLL_STARTUP_PREFIX
                || bytes[28] != 0xe8
                || bytes[33..56] != AMD64_DLL_STARTUP_SUFFIX
                || bytes[56] != 0xe9
            {
                continue;
            }

            let Some(cookie_initializer_rva) = direct_rel32_target(
                mapped,
                entry_rva
                    .checked_add(28)
                    .context("AMD64 DLL cookie CALL RVA overflows")?,
                0xe8,
            )?
            else {
                continue;
            };
            let Some(crt_dispatcher_rva) = direct_rel32_target(
                mapped,
                entry_rva
                    .checked_add(56)
                    .context("AMD64 DLL CRT JMP RVA overflows")?,
                0xe9,
            )?
            else {
                continue;
            };
            if !is_executable_range(
                &executable_ranges,
                cookie_initializer_rva,
                AMD64_COOKIE_EVIDENCE_LEN,
            )? || !is_executable_range(
                &executable_ranges,
                crt_dispatcher_rva,
                AMD64_STARTUP_LEN,
            )? {
                continue;
            }
            if amd64_security_cookie_evidence(
                mapped,
                pe,
                &executable_ranges,
                cookie_initializer_rva,
            )?
            .is_none()
            {
                continue;
            }

            let Some(entry_runtime_function_rva) =
                amd64_runtime_function_evidence(mapped, pe, &executable_ranges, entry_rva)?
            else {
                continue;
            };
            let Some(cookie_runtime_function_rva) = amd64_runtime_function_evidence(
                mapped,
                pe,
                &executable_ranges,
                cookie_initializer_rva,
            )?
            else {
                continue;
            };
            let Some(dispatcher_runtime_function_rva) = amd64_runtime_function_evidence(
                mapped,
                pe,
                &executable_ranges,
                crt_dispatcher_rva,
            )?
            else {
                continue;
            };
            if read_u32_rva(mapped, entry_runtime_function_rva)? != entry_rva
                || read_u32_rva(mapped, cookie_runtime_function_rva)? != cookie_initializer_rva
                || read_u32_rva(mapped, dispatcher_runtime_function_rva)? != crt_dispatcher_rva
            {
                continue;
            }

            ensure!(
                entries.len() < MAX_SEMANTIC_VENEERS,
                "AMD64 DLL entry candidate budget of {MAX_SEMANTIC_VENEERS} exceeded"
            );
            entries
                .try_reserve(1)
                .context("reserving AMD64 DLL entry candidate")?;
            entries.push(entry_rva);
        }
    }

    match entries.as_slice() {
        [] => discover_amd64_header_dispatch_dll_entry(mapped, pe)?.map_or_else(
            || bail!("found no structurally valid AMD64 MSVC DLL entry or authenticated header dispatch entry"),

            Ok,
        ),
        [entry_rva] => Ok(*entry_rva),
        _ => bail!(
            "found {} structurally valid AMD64 MSVC DLL entries",
            entries.len()
        ),
    }
}

fn amd64_msvc_semantic_entries(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    runtime_functions: &Amd64RuntimeFunctionIndex,
) -> Result<Vec<SemanticEntry>> {
    let mut entries = Vec::new();
    for function in &runtime_functions.records {
        let entry_rva = function.begin_rva;
        let Some(entry_end) = entry_rva.checked_add(AMD64_MSVC_ENTRY_LEN as u32) else {
            continue;
        };
        if entry_end > function.end_rva {
            continue;
        }
        let bytes = mapped_bytes(mapped, entry_rva, AMD64_MSVC_ENTRY_LEN)?;
        if bytes[..4] != [0x48, 0x83, 0xec, 0x28]
            || bytes[4] != 0xe8
            || bytes[9..13] != [0x48, 0x83, 0xc4, 0x28]
            || bytes[13] != 0xe9
        {
            continue;
        }
        let Some(cookie_initializer_rva) = direct_rel32_target(
            mapped,
            entry_rva
                .checked_add(4)
                .context("AMD64 MSVC cookie CALL RVA overflows")?,
            0xe8,
        )?
        else {
            continue;
        };
        let Some(startup_rva) = direct_rel32_target(
            mapped,
            entry_rva
                .checked_add(13)
                .context("AMD64 MSVC startup JMP RVA overflows")?,
            0xe9,
        )?
        else {
            continue;
        };
        if !is_executable_range(
            executable_ranges,
            cookie_initializer_rva,
            AMD64_COOKIE_EVIDENCE_LEN,
        )? || !is_executable_range(executable_ranges, startup_rva, AMD64_CRT_EVIDENCE_LEN)?
        {
            continue;
        }
        let Some(cookie_rva) =
            amd64_security_cookie_evidence(mapped, pe, executable_ranges, cookie_initializer_rva)?
        else {
            continue;
        };
        if !amd64_crt_startup_evidence(mapped, executable_ranges, startup_rva)? {
            continue;
        }
        let Some(cookie_runtime_function) =
            runtime_functions.record_containing(cookie_initializer_rva, AMD64_STARTUP_LEN)?
        else {
            continue;
        };
        let Some(startup_runtime_function) =
            runtime_functions.record_containing(startup_rva, AMD64_STARTUP_LEN)?
        else {
            continue;
        };

        ensure!(
            entries.len() < MAX_SEMANTIC_VENEERS,
            "AMD64 MSVC entry candidate budget of {MAX_SEMANTIC_VENEERS} exceeded"
        );
        entries
            .try_reserve(1)
            .context("reserving AMD64 MSVC semantic entry candidate")?;
        entries.push(SemanticEntry {
            entry_rva,
            predecessor_rva: None,
            veneer_call_target_rva: cookie_initializer_rva,
            veneer_helper_target_rva: cookie_initializer_rva,
            startup_rva,
            crt_call_target_rva: startup_rva,
            crt_helper_target_rva: startup_rva,
            startup_data_rva: cookie_rva,
            startup_data_len: AMD64_POINTER_CELL_LEN as u32,
            evidence: SemanticEvidence::Amd64Msvc {
                entry_runtime_function_rva: function.record_rva,
                cookie_runtime_function_rva: cookie_runtime_function.record_rva,
                startup_runtime_function_rva: startup_runtime_function.record_rva,
            },
        });
    }
    Ok(entries)
}

/// Authenticates sparse-profile hits against the unwind program for each
/// MSVC startup function.  The entry pattern alone can survive a wrong sparse
/// transform; unwind codes independently describe the exact stack prologue.
pub(crate) fn authenticate_amd64_sparse_entry(mapped: &[u8], entry: SemanticEntry) -> Result<()> {
    let functions = match entry.evidence {
        SemanticEvidence::Amd64Msvc {
            entry_runtime_function_rva,
            cookie_runtime_function_rva,
            startup_runtime_function_rva,
        } => vec![
            (entry.entry_rva, entry_runtime_function_rva),
            (entry.veneer_call_target_rva, cookie_runtime_function_rva),
            (entry.startup_rva, startup_runtime_function_rva),
        ],
        SemanticEvidence::Amd64 {
            runtime_function_rva: Some(runtime_function_rva),
            ..
        } => vec![(entry.startup_rva, runtime_function_rva)],
        SemanticEvidence::Amd64 {
            runtime_function_rva: None,
            ..
        }
        | SemanticEvidence::I386
        | SemanticEvidence::I386MsvcStandalone { .. } => return Ok(()),
    };

    for (function_rva, runtime_function_rva) in functions {
        ensure!(
            amd64_unwind_prologue_evidence(mapped, function_rva, runtime_function_rva)?,
            "AMD64 sparse candidate does not match unwind prologue at {function_rva:#x}"
        );
    }
    Ok(())
}

fn parse_amd64_unwind_operations(
    mapped: &[u8],
    unwind_rva: u32,
) -> Result<(usize, Vec<Amd64UnwindOperation>)> {
    let header = mapped_bytes(mapped, unwind_rva, 4)?;
    ensure!(
        header[0] & 7 == 1,
        "AMD64 unwind info has unsupported version"
    );
    let prologue_len = usize::from(header[1]);
    let code_count = usize::from(header[2]);
    let code_rva = unwind_rva
        .checked_add(4)
        .context("AMD64 unwind-code RVA overflows")?;
    let codes = mapped_bytes(
        mapped,
        code_rva,
        code_count
            .checked_mul(2)
            .context("AMD64 unwind-code length overflows")?,
    )?;
    let mut operations = Vec::new();
    operations
        .try_reserve(code_count)
        .context("reserving AMD64 unwind operations")?;
    let mut index = 0usize;
    while index < code_count {
        let code_offset = usize::from(codes[index * 2]);
        let opcode = codes[index * 2 + 1] & 0x0f;
        let info = codes[index * 2 + 1] >> 4;
        let mut consumed = 1usize;
        let mut stack_size = None;
        let mut save_offset = None;
        match opcode {
            0 => stack_size = Some(8),
            1 => match info {
                0 => {
                    ensure!(index + 1 < code_count, "truncated UWOP_ALLOC_LARGE");
                    stack_size = Some(
                        usize::from(u16::from_le_bytes([
                            codes[(index + 1) * 2],
                            codes[(index + 1) * 2 + 1],
                        ]))
                        .checked_mul(8)
                        .context("UWOP_ALLOC_LARGE size overflows")?,
                    );
                    consumed = 2;
                }
                1 => {
                    ensure!(index + 2 < code_count, "truncated far UWOP_ALLOC_LARGE");
                    stack_size = Some(
                        usize::try_from(u32::from_le_bytes([
                            codes[(index + 1) * 2],
                            codes[(index + 1) * 2 + 1],
                            codes[(index + 2) * 2],
                            codes[(index + 2) * 2 + 1],
                        ]))
                        .context("far UWOP_ALLOC_LARGE size does not fit usize")?,
                    );
                    consumed = 3;
                }
                _ => bail!("UWOP_ALLOC_LARGE has invalid operation info {info}"),
            },
            2 => stack_size = Some(usize::from(info) * 8 + 8),
            4 | 8 => {
                ensure!(
                    index + 1 < code_count,
                    "truncated AMD64 unwind save operation"
                );
                let scale = if opcode == 4 { 8 } else { 16 };
                save_offset = Some(
                    usize::from(u16::from_le_bytes([
                        codes[(index + 1) * 2],
                        codes[(index + 1) * 2 + 1],
                    ]))
                    .checked_mul(scale)
                    .context("AMD64 unwind save offset overflows")?,
                );
                consumed = 2;
            }
            5 | 9 => {
                ensure!(
                    index + 2 < code_count,
                    "truncated far AMD64 unwind save operation"
                );
                save_offset = Some(
                    usize::try_from(u32::from_le_bytes([
                        codes[(index + 1) * 2],
                        codes[(index + 1) * 2 + 1],
                        codes[(index + 2) * 2],
                        codes[(index + 2) * 2 + 1],
                    ]))
                    .context("far AMD64 unwind save offset does not fit usize")?,
                );
                consumed = 3;
            }
            10 => stack_size = Some(40 + usize::from(info != 0) * 8),
            _ => {}
        }
        ensure!(
            code_offset <= prologue_len,
            "AMD64 unwind operation lies beyond its prologue"
        );
        operations.push(Amd64UnwindOperation {
            code_offset,
            opcode,
            info,
            stack_size,
            save_offset,
        });
        index = index
            .checked_add(consumed)
            .context("AMD64 unwind-code index overflows")?;
    }
    Ok((prologue_len, operations))
}

fn amd64_unwind_prologue_evidence(
    mapped: &[u8],
    function_rva: u32,
    runtime_function_rva: u32,
) -> Result<bool> {
    let begin_rva = read_u32_rva(mapped, runtime_function_rva)?;
    let end_rva = read_u32_rva(
        mapped,
        runtime_function_rva
            .checked_add(4)
            .context("AMD64 runtime-function end RVA overflows")?,
    )?;
    let unwind_rva = read_u32_rva(
        mapped,
        runtime_function_rva
            .checked_add(8)
            .context("AMD64 runtime-function unwind RVA overflows")?,
    )?;
    if begin_rva != function_rva || begin_rva >= end_rva || unwind_rva == 0 {
        return Ok(false);
    }
    let (prologue_len, operations) = parse_amd64_unwind_operations(mapped, unwind_rva)?;
    if prologue_len > usize::try_from(end_rva - begin_rva).context("AMD64 function length")? {
        return Ok(false);
    }
    let prologue = mapped_bytes(mapped, function_rva, prologue_len)?;
    for operation in &operations {
        let valid = match operation.opcode {
            0 => amd64_push_matches(prologue, operation.code_offset, operation.info),
            1 | 2 => operation.stack_size.is_some_and(|size| {
                amd64_stack_allocation_matches(prologue, operation.code_offset, size)
            }),
            4 | 5 => operation.save_offset.is_some_and(|save_offset| {
                amd64_nonvolatile_save_matches(prologue, operation.info, save_offset, &operations)
            }),
            _ => true,
        };
        if !valid {
            return Ok(false);
        }
    }
    Ok(true)
}

fn amd64_push_matches(prologue: &[u8], end: usize, register: u8) -> bool {
    if register < 8 {
        end >= 1 && prologue.get(end - 1) == Some(&(0x50 + register))
    } else {
        end >= 2 && prologue.get(end - 2..end) == Some(&[0x41, 0x50 + (register - 8)][..])
    }
}

fn amd64_stack_allocation_matches(prologue: &[u8], end: usize, size: usize) -> bool {
    let short = (size <= i8::MAX as usize)
        .then_some(size)
        .is_some_and(|size| {
            end >= 4 && prologue.get(end - 4..end) == Some(&[0x48, 0x83, 0xec, size as u8][..])
        });
    short
        || u32::try_from(size).ok().is_some_and(|size| {
            end >= 7
                && prologue.get(end - 7..end - 4) == Some(&[0x48, 0x81, 0xec][..])
                && prologue.get(end - 4..end) == Some(&size.to_le_bytes()[..])
        })
}

fn amd64_nonvolatile_save_matches(
    prologue: &[u8],
    register: u8,
    save_offset: usize,
    operations: &[Amd64UnwindOperation],
) -> bool {
    let rax_is_entry_rsp = prologue.starts_with(&[0x48, 0x8b, 0xc4]);
    for start in 0..prologue.len() {
        let Some(&rex) = prologue.get(start) else {
            continue;
        };
        if rex & 0xf8 != 0x48 || rex & 3 != 0 || prologue.get(start + 1) != Some(&0x89) {
            continue;
        }
        let Some(&modrm) = prologue.get(start + 2) else {
            continue;
        };
        let mode = modrm >> 6;
        let encoded_register = ((modrm >> 3) & 7) | ((rex & 4) << 1);
        if encoded_register != register {
            continue;
        }
        let base = modrm & 7;
        let displacement_start = match base {
            4 if prologue.get(start + 3) == Some(&0x24) => start + 4,
            0 if rax_is_entry_rsp => start + 3,
            _ => continue,
        };
        let (instruction_end, displacement) = match mode {
            1 => {
                let Some(&value) = prologue.get(displacement_start) else {
                    continue;
                };
                let value = isize::from(i8::from_ne_bytes([value]));
                let Ok(value) = usize::try_from(value) else {
                    continue;
                };
                (displacement_start + 1, value)
            }
            2 => {
                let Some(bytes) = prologue.get(displacement_start..displacement_start + 4) else {
                    continue;
                };
                let value = i32::from_le_bytes(bytes.try_into().expect("four-byte displacement"));
                let Ok(value) = usize::try_from(value) else {
                    continue;
                };
                (displacement_start + 4, value)
            }
            _ => continue,
        };
        let Some(final_offset) = operations
            .iter()
            .filter(|operation| operation.code_offset > instruction_end)
            .filter_map(|operation| operation.stack_size)
            .try_fold(displacement, usize::checked_add)
        else {
            continue;
        };
        if final_offset == save_offset {
            return true;
        }
    }
    false
}

fn amd64_security_cookie_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    initializer_rva: u32,
) -> Result<Option<u32>> {
    let bytes = mapped_bytes(mapped, initializer_rva, AMD64_COOKIE_EVIDENCE_LEN)?;
    if !bytes
        .windows(AMD64_POINTER_CELL_LEN)
        .any(|window| window == AMD64_DEFAULT_SECURITY_COOKIE.to_le_bytes())
    {
        return Ok(None);
    }

    let mut cookie_rva = None;
    for offset in 0..=bytes.len().saturating_sub(7) {
        if bytes[offset] != 0x48 || bytes[offset + 1] != 0x8b || bytes[offset + 2] & 0xc7 != 0x05 {
            continue;
        }
        let instruction_rva = initializer_rva
            .checked_add(
                u32::try_from(offset).context("AMD64 cookie instruction offset exceeds u32")?,
            )
            .context("AMD64 cookie instruction RVA overflows")?;
        let Some(candidate_rva) = rip_relative_target(mapped, instruction_rva, 7, 3)? else {
            continue;
        };
        if !is_mapped_readable_non_executable_range(
            mapped,
            pe,
            executable_ranges,
            candidate_rva,
            AMD64_POINTER_CELL_LEN as u32,
        )? || read_u64_rva(mapped, candidate_rva)? != AMD64_DEFAULT_SECURITY_COOKIE
        {
            continue;
        }
        if let Some(existing) = cookie_rva {
            ensure!(
                existing == candidate_rva,
                "AMD64 security-cookie initializer references multiple default-cookie cells"
            );
        } else {
            cookie_rva = Some(candidate_rva);
        }
    }
    Ok(cookie_rva)
}

pub(crate) fn amd64_crt_startup_evidence(
    mapped: &[u8],
    executable_ranges: &[Range<u32>],
    startup_rva: u32,
) -> Result<bool> {
    let bytes = mapped_bytes(mapped, startup_rva, AMD64_CRT_EVIDENCE_LEN)?;
    if amd64_modern_crt_markers(bytes) || amd64_legacy_crt_markers(bytes) {
        return Ok(true);
    }

    for (offset, instruction) in bytes.windows(DIRECT_REL32_LEN).enumerate() {
        if instruction[0] != 0xe8 {
            continue;
        }
        let call_rva = startup_rva
            .checked_add(u32::try_from(offset).context("AMD64 CRT CALL offset exceeds u32")?)
            .context("AMD64 CRT CALL RVA overflows")?;
        let Some(helper_rva) = direct_rel32_target(mapped, call_rva, 0xe8)? else {
            continue;
        };
        if !is_executable_range(executable_ranges, helper_rva, AMD64_CRT_EVIDENCE_LEN)? {
            continue;
        }
        let helper = mapped_bytes(mapped, helper_rva, AMD64_CRT_EVIDENCE_LEN)?;
        if amd64_modern_crt_markers(helper) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn amd64_modern_crt_markers(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|window| window == [0x65, 0x48, 0x8b])
        && bytes
            .windows(4)
            .any(|window| window == [0xf0, 0x48, 0x0f, 0xb1])
}

fn amd64_legacy_crt_markers(bytes: &[u8]) -> bool {
    bytes
        .windows(4)
        .any(|window| window == [0x4d, 0x5a, 0x00, 0x00])
        && bytes
            .windows(4)
            .any(|window| window == [0x50, 0x45, 0x00, 0x00])
        && bytes
            .windows(4)
            .any(|window| window == [0x0b, 0x02, 0x00, 0x00])
}

fn amd64_veneer_starts(mapped: &[u8], executable_ranges: &[Range<u32>]) -> Result<Vec<u32>> {
    let mut starts = Vec::new();
    for range in executable_ranges {
        let length = usize::try_from(range.end - range.start)
            .context("AMD64 executable range length does not fit usize")?;
        let bytes = mapped_bytes(mapped, range.start, length)?;
        for (offset, window) in bytes.windows(SEMANTIC_VENEER_LEN).enumerate() {
            if window[0] != 0xe8 || window[DIRECT_REL32_LEN] != 0xe9 {
                continue;
            }
            let entry_rva = range
                .start
                .checked_add(u32::try_from(offset).context("AMD64 veneer offset exceeds u32")?)
                .context("AMD64 veneer RVA overflows")?;
            let Ok(Some(Amd64Instruction::CallRel32 { .. })) =
                decode_amd64_instruction(mapped, entry_rva)
            else {
                continue;
            };
            let jump_rva = entry_rva
                .checked_add(DIRECT_REL32_LEN as u32)
                .context("AMD64 semantic veneer JMP RVA overflow")?;
            let Ok(Some(Amd64Instruction::JumpRel32 { .. })) =
                decode_amd64_instruction(mapped, jump_rva)
            else {
                continue;
            };

            ensure!(
                starts.len() < MAX_SEMANTIC_VENEERS,
                "AMD64 semantic veneer candidate budget of {MAX_SEMANTIC_VENEERS} exceeded"
            );
            starts
                .try_reserve(1)
                .context("reserving AMD64 semantic veneer start")?;
            starts.push(entry_rva);
        }
    }
    Ok(starts)
}

fn amd64_executable_jumps(
    mapped: &[u8],
    executable_ranges: &[Range<u32>],
    veneer_starts: &[u32],
) -> Result<BTreeMap<u32, JumpPredecessors>> {
    let mut jumps = BTreeMap::new();
    for &entry_rva in veneer_starts {
        jumps.insert(
            entry_rva,
            JumpPredecessors {
                count: 0,
                source_rva: 0,
            },
        );
    }

    let mut jump_count = 0usize;
    for range in executable_ranges {
        let length = usize::try_from(range.end - range.start)
            .context("AMD64 executable range length does not fit usize")?;
        let bytes = mapped_bytes(mapped, range.start, length)?;
        for (offset, window) in bytes.windows(DIRECT_REL32_LEN).enumerate() {
            if window[0] != 0xe9 {
                continue;
            }
            let rva = range
                .start
                .checked_add(
                    u32::try_from(offset).context("AMD64 executable jump offset exceeds u32")?,
                )
                .context("AMD64 executable jump RVA overflows")?;
            let Ok(Some(Amd64Instruction::JumpRel32 { target_rva })) =
                decode_amd64_instruction(mapped, rva)
            else {
                continue;
            };
            let Some(predecessors) = jumps.get_mut(&target_rva) else {
                continue;
            };
            jump_count = jump_count
                .checked_add(1)
                .context("matched AMD64 executable E9 rel32 predecessor count overflow")?;
            ensure!(
                jump_count <= MAX_EXECUTABLE_JUMPS,
                "matched AMD64 executable E9 rel32 predecessor budget of {MAX_EXECUTABLE_JUMPS} exceeded"
            );
            predecessors.count = predecessors
                .count
                .checked_add(1)
                .context("AMD64 semantic predecessor count overflow")?;
            predecessors.source_rva = rva;
        }
    }
    Ok(jumps)
}

fn amd64_veneer_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    entry_rva: u32,
) -> Result<Option<Amd64VeneerEvidence>> {
    if !is_executable_range(executable_ranges, entry_rva, SEMANTIC_VENEER_LEN)? {
        return Ok(None);
    }
    let Some(Amd64Instruction::CallRel32 {
        target_rva: veneer_call_target_rva,
    }) = decode_amd64_instruction(mapped, entry_rva)?
    else {
        return Ok(None);
    };
    let jump_rva = entry_rva
        .checked_add(DIRECT_REL32_LEN as u32)
        .context("AMD64 semantic veneer JMP RVA overflow")?;
    let Some(Amd64Instruction::JumpRel32 {
        target_rva: startup_rva,
    }) = decode_amd64_instruction(mapped, jump_rva)?
    else {
        return Ok(None);
    };

    if !is_executable_range(
        executable_ranges,
        veneer_call_target_rva,
        AMD64_IMPORT_THUNK_LEN,
    )? {
        return Ok(None);
    }
    let Some(Amd64Instruction::IndirectJumpRip {
        cell_rva: iat_cell_rva,
    }) = decode_amd64_instruction(mapped, veneer_call_target_rva)?
    else {
        return Ok(None);
    };
    if !is_mapped_readable_non_executable_range(
        mapped,
        pe,
        executable_ranges,
        iat_cell_rva,
        AMD64_POINTER_CELL_LEN as u32,
    )? {
        return Ok(None);
    }
    let _import_target_va = read_u64_rva(mapped, iat_cell_rva)
        .context("reading AMD64 FF25 eight-byte import target cell")?;

    let Some(startup) = amd64_startup_evidence(mapped, pe, executable_ranges, startup_rva)? else {
        return Ok(None);
    };
    let runtime_function_rva =
        amd64_runtime_function_evidence(mapped, pe, executable_ranges, startup_rva)?;

    Ok(Some(Amd64VeneerEvidence {
        entry_rva,
        veneer_call_target_rva,
        startup_rva,
        crt_call_target_rva: startup.crt_call_target_rva,
        crt_helper_target_rva: startup.crt_helper_target_rva,
        startup_data_rva: startup.startup_data_rva,
        iat_cell_rva,
        runtime_function_rva,
    }))
}

fn amd64_startup_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    rva: u32,
) -> Result<Option<Amd64StartupEvidence>> {
    if !is_executable_range(executable_ranges, rva, AMD64_STARTUP_LEN)? {
        return Ok(None);
    }
    let Some(Amd64Instruction::LeaRip {
        target_rva: startup_data_rva,
    }) = decode_amd64_instruction(mapped, rva)?
    else {
        return Ok(None);
    };
    if !is_mapped_readable_non_executable_range(
        mapped,
        pe,
        executable_ranges,
        startup_data_rva,
        AMD64_POINTER_CELL_LEN as u32,
    )? {
        return Ok(None);
    }
    let _startup_state = read_u64_rva(mapped, startup_data_rva)
        .context("reading AMD64 RIP-relative startup state")?;

    let call_rva = rva
        .checked_add(7)
        .context("AMD64 startup CALL RVA overflow")?;
    let Some(Amd64Instruction::CallRel32 {
        target_rva: crt_call_target_rva,
    }) = decode_amd64_instruction(mapped, call_rva)?
    else {
        return Ok(None);
    };
    let return_rva = call_rva
        .checked_add(DIRECT_REL32_LEN as u32)
        .context("AMD64 startup return RVA overflow")?;
    if decode_amd64_instruction(mapped, return_rva)? != Some(Amd64Instruction::Return) {
        return Ok(None);
    }
    let Some(crt_helper_target_rva) =
        amd64_helper_thunk_target(mapped, executable_ranges, crt_call_target_rva)?
    else {
        return Ok(None);
    };

    Ok(Some(Amd64StartupEvidence {
        crt_call_target_rva,
        crt_helper_target_rva,
        startup_data_rva,
    }))
}

fn amd64_helper_thunk_target(
    mapped: &[u8],
    executable_ranges: &[Range<u32>],
    thunk_rva: u32,
) -> Result<Option<u32>> {
    if !is_executable_range(executable_ranges, thunk_rva, DIRECT_REL32_LEN)? {
        return Ok(None);
    }
    let Some(Amd64Instruction::JumpRel32 { target_rva }) =
        decode_amd64_instruction(mapped, thunk_rva)?
    else {
        return Ok(None);
    };
    if !is_executable_range(executable_ranges, target_rva, AMD64_HELPER_TARGET_LEN)? {
        return Ok(None);
    }
    for offset in 0..AMD64_HELPER_TARGET_LEN - 1 {
        let rva = target_rva
            .checked_add(u32::try_from(offset).expect("AMD64 helper offset fits u32"))
            .context("AMD64 helper NOP RVA overflow")?;
        if decode_amd64_instruction(mapped, rva)? != Some(Amd64Instruction::Nop) {
            return Ok(None);
        }
    }
    let return_rva = target_rva
        .checked_add((AMD64_HELPER_TARGET_LEN - 1) as u32)
        .context("AMD64 helper return RVA overflow")?;
    if decode_amd64_instruction(mapped, return_rva)? != Some(Amd64Instruction::Return) {
        return Ok(None);
    }
    Ok(Some(target_rva))
}

fn amd64_runtime_function_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    startup_rva: u32,
) -> Result<Option<u32>> {
    validate_amd64_exception_directory_with_ranges(mapped, pe, executable_ranges, Some(startup_rva))
}

fn validate_amd64_exception_directory_with_ranges(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    startup_rva: Option<u32>,
) -> Result<Option<u32>> {
    let Some(runtime_functions) = Amd64RuntimeFunctionIndex::parse(mapped, pe, executable_ranges)?
    else {
        return Ok(None);
    };
    let Some(startup_rva) = startup_rva else {
        return Ok(None);
    };
    runtime_functions
        .record_containing(startup_rva, AMD64_STARTUP_LEN)?
        .map(|record| record.record_rva)
        .map(Some)
        .ok_or_else(|| {
            anyhow::anyhow!("AMD64 startup at {startup_rva:#x} has no owning runtime function")
        })
}

fn decode_amd64_instruction(mapped: &[u8], rva: u32) -> Result<Option<Amd64Instruction>> {
    let opcode = mapped_bytes(mapped, rva, 1)?[0];
    match opcode {
        0xe8 => direct_rel32_target(mapped, rva, 0xe8)
            .map(|target| target.map(|target_rva| Amd64Instruction::CallRel32 { target_rva })),
        0xe9 => direct_rel32_target(mapped, rva, 0xe9)
            .map(|target| target.map(|target_rva| Amd64Instruction::JumpRel32 { target_rva })),
        0xff => {
            let bytes = mapped_bytes(mapped, rva, AMD64_IMPORT_THUNK_LEN)?;
            if bytes[1] != 0x25 {
                return Ok(None);
            }
            rip_relative_target(mapped, rva, AMD64_IMPORT_THUNK_LEN, 2)
                .map(|target| target.map(|cell_rva| Amd64Instruction::IndirectJumpRip { cell_rva }))
        }
        0x48 => {
            let bytes = mapped_bytes(mapped, rva, 7)?;
            if bytes[1] != 0x8d || bytes[2] != 0x0d {
                return Ok(None);
            }
            rip_relative_target(mapped, rva, 7, 3)
                .map(|target| target.map(|target_rva| Amd64Instruction::LeaRip { target_rva }))
        }
        0x90 => Ok(Some(Amd64Instruction::Nop)),
        0xc3 => Ok(Some(Amd64Instruction::Return)),
        _ => Ok(None),
    }
}

fn rip_relative_target(
    mapped: &[u8],
    rva: u32,
    instruction_len: usize,
    displacement_offset: usize,
) -> Result<Option<u32>> {
    let bytes = mapped_bytes(mapped, rva, instruction_len)?;
    let displacement_end = displacement_offset
        .checked_add(4)
        .context("AMD64 RIP-relative displacement end overflows")?;
    let displacement = i64::from(i32::from_le_bytes(
        bytes
            .get(displacement_offset..displacement_end)
            .context("AMD64 RIP-relative instruction has no rel32 displacement")?
            .try_into()
            .expect("a bounded AMD64 RIP-relative displacement has exactly four bytes"),
    ));
    let next_rva = i64::from(rva)
        .checked_add(i64::try_from(instruction_len).expect("AMD64 instruction length fits i64"))
        .context("AMD64 RIP-relative next-RVA arithmetic overflow")?;
    let target = next_rva
        .checked_add(displacement)
        .context("AMD64 RIP-relative target arithmetic overflow")?;
    Ok(u32::try_from(target).ok())
}

fn read_u64_rva(mapped: &[u8], rva: u32) -> Result<u64> {
    Ok(u64::from_le_bytes(
        mapped_bytes(mapped, rva, AMD64_POINTER_CELL_LEN)?
            .try_into()
            .expect("a bounded u64 cell has exactly eight bytes"),
    ))
}
