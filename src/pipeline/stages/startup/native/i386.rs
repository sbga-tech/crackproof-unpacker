use crate::pe::Pe;
use anyhow::{Context, Result, bail, ensure};
use std::collections::BTreeMap;
use std::ops::Range;

use super::super::*;
const MAX_SEMANTIC_VENEERS: usize = 4_096;
const MAX_EXECUTABLE_JUMPS: usize = 65_536;
const MAX_STARTUP_DATA_LEN: u32 = 0x7f;

#[derive(Clone, Copy, Debug)]
pub(crate) struct SemanticVeneer {
    pub(crate) entry_rva: u32,
    pub(crate) veneer_call_target_rva: u32,
    pub(crate) veneer_helper_target_rva: u32,
    pub(crate) startup_rva: u32,
    pub(crate) crt_call_target_rva: u32,
    pub(crate) crt_helper_target_rva: u32,
    pub(crate) startup_data_rva: u32,
    pub(crate) startup_data_len: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct JumpPredecessors {
    count: usize,
    source_rva: u32,
}

#[derive(Clone, Copy, Debug)]
struct StartupEvidence {
    crt_call_target_rva: u32,
    crt_helper_target_rva: u32,
    startup_data_rva: u32,
    startup_data_len: u32,
    direct_callee: bool,
}

pub(crate) fn discover_i386_semantic_entry(mapped: &[u8], pe: &Pe) -> Result<SemanticEntry> {
    let executable_ranges = executable_section_ranges(mapped, pe)?;
    ensure_executable_scan_bound(&executable_ranges)?;
    let legacy_veneers = semantic_veneers(mapped, pe, &executable_ranges)?;
    let standalone_veneers = standalone_msvc_veneers(mapped, pe, &executable_ranges)?;
    let mut predecessor_targets = legacy_veneers.clone();
    predecessor_targets.extend(standalone_veneers.iter().map(|candidate| candidate.veneer));
    let jumps = executable_jumps(mapped, &executable_ranges, &predecessor_targets)?;

    let mut entries = Vec::new();
    for veneer in legacy_veneers {
        if standalone_veneers
            .iter()
            .any(|candidate| candidate.veneer.entry_rva == veneer.entry_rva)
        {
            continue;
        }

        let Some(predecessors) = jumps.get(&veneer.entry_rva) else {
            continue;
        };

        match predecessors.count {
            0 if veneer.entry_rva == pe.entry_rva => {
                let Some((cookie_rva, cookie_complement_rva)) = i386_security_cookie_evidence(
                    mapped,
                    pe,
                    &executable_ranges,
                    veneer.veneer_helper_target_rva,
                    false,
                )?
                else {
                    continue;
                };
                if !i386_seh_startup_helper_evidence(
                    mapped,
                    pe,
                    &executable_ranges,
                    veneer.crt_helper_target_rva,
                    cookie_rva,
                )? {
                    continue;
                }
                entries
                    .try_reserve(1)
                    .context("reserving header-selected I386 semantic entry")?;
                entries.push(SemanticEntry {
                    entry_rva: veneer.entry_rva,
                    predecessor_rva: None,
                    veneer_call_target_rva: veneer.veneer_call_target_rva,
                    veneer_helper_target_rva: veneer.veneer_helper_target_rva,
                    startup_rva: veneer.startup_rva,
                    crt_call_target_rva: veneer.crt_call_target_rva,
                    crt_helper_target_rva: veneer.crt_helper_target_rva,
                    startup_data_rva: veneer.startup_data_rva,
                    startup_data_len: veneer.startup_data_len,
                    evidence: SemanticEvidence::I386MsvcStandalone {
                        cookie_rva,
                        cookie_complement_rva,
                    },
                });
            }
            0 => {}
            1 => {
                entries
                    .try_reserve(1)
                    .context("reserving legacy I386 semantic entry candidate")?;
                entries.push(SemanticEntry {
                    entry_rva: veneer.entry_rva,
                    predecessor_rva: Some(predecessors.source_rva),
                    veneer_call_target_rva: veneer.veneer_call_target_rva,
                    veneer_helper_target_rva: veneer.veneer_helper_target_rva,
                    startup_rva: veneer.startup_rva,
                    crt_call_target_rva: veneer.crt_call_target_rva,
                    crt_helper_target_rva: veneer.crt_helper_target_rva,
                    startup_data_rva: veneer.startup_data_rva,
                    startup_data_len: veneer.startup_data_len,
                    evidence: SemanticEvidence::I386,
                });
            }
            predecessor_count => {
                bail!(
                    "semantic veneer at {:#x} has {predecessor_count} executable E9 rel32 predecessors",
                    veneer.entry_rva
                );
            }
        }
    }

    for candidate in standalone_veneers {
        let Some(predecessors) = jumps.get(&candidate.veneer.entry_rva) else {
            continue;
        };
        if predecessors.count != 0 {
            continue;
        }
        let veneer = candidate.veneer;
        entries
            .try_reserve(1)
            .context("reserving standalone I386 MSVC OEP candidate")?;
        entries.push(SemanticEntry {
            entry_rva: veneer.entry_rva,
            predecessor_rva: None,
            veneer_call_target_rva: veneer.veneer_call_target_rva,
            veneer_helper_target_rva: veneer.veneer_helper_target_rva,
            startup_rva: veneer.startup_rva,
            crt_call_target_rva: veneer.crt_call_target_rva,
            crt_helper_target_rva: veneer.crt_helper_target_rva,
            startup_data_rva: veneer.startup_data_rva,
            startup_data_len: veneer.startup_data_len,
            evidence: SemanticEvidence::I386MsvcStandalone {
                cookie_rva: candidate.cookie_rva,
                cookie_complement_rva: candidate.cookie_complement_rva,
            },
        });
    }

    match entries.as_slice() {
        [] => bail!("found no structurally valid semantic entry"),
        [entry] => Ok(*entry),
        _ => bail!(
            "found {} structurally valid semantic entries",
            entries.len()
        ),
    }
}

/// Strengthens the legacy veneer proof when it is used to choose between
/// distinct sparse-page transforms.  The historical profile alone only proves
/// control-flow shape; the selected transform must also recover the matching
/// MSVC cookie initializer and SEH helper bodies.
pub(crate) fn authenticate_i386_sparse_entry(
    mapped: &[u8],
    pe: &Pe,
    entry: SemanticEntry,
) -> Result<()> {
    if !matches!(entry.evidence, SemanticEvidence::I386) {
        return Ok(());
    }
    let executable_ranges = executable_section_ranges(mapped, pe)?;
    let Some((cookie_rva, _cookie_complement_rva)) = i386_security_cookie_evidence(
        mapped,
        pe,
        &executable_ranges,
        entry.veneer_helper_target_rva,
        false,
    )?
    else {
        bail!(
            "legacy I386 sparse candidate does not recover the MSVC security-cookie initializer at {:#x}",
            entry.veneer_helper_target_rva
        );
    };
    ensure!(
        i386_seh_startup_helper_evidence(
            mapped,
            pe,
            &executable_ranges,
            entry.crt_helper_target_rva,
            cookie_rva,
        )?,
        "legacy I386 sparse candidate does not recover the matching SEH helper at {:#x}",
        entry.crt_helper_target_rva
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct StandaloneMsvcVeneer {
    veneer: SemanticVeneer,
    cookie_rva: u32,
    cookie_complement_rva: u32,
}

fn standalone_msvc_veneers(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
) -> Result<Vec<StandaloneMsvcVeneer>> {
    let mut veneers = Vec::new();
    for range in executable_ranges {
        let Some(last_rva) = range.end.checked_sub(SEMANTIC_VENEER_LEN as u32) else {
            continue;
        };
        if last_rva < range.start {
            continue;
        }

        for entry_rva in range.start..=last_rva {
            let Some(cookie_initializer_rva) = direct_rel32_target(mapped, entry_rva, 0xe8)? else {
                continue;
            };
            let jump_rva = entry_rva
                .checked_add(DIRECT_REL32_LEN as u32)
                .context("standalone I386 MSVC OEP JMP RVA overflow")?;
            let Some(startup_rva) = direct_rel32_target(mapped, jump_rva, 0xe9)? else {
                continue;
            };
            let expected_startup_rva = jump_rva
                .checked_add(DIRECT_REL32_LEN as u32)
                .context("standalone I386 MSVC OEP startup RVA overflow")?;
            if startup_rva != expected_startup_rva {
                continue;
            }
            if !is_executable_range(
                executable_ranges,
                cookie_initializer_rva,
                I386_COOKIE_EVIDENCE_LEN,
            )? {
                continue;
            }
            let Some((cookie_rva, cookie_complement_rva)) = i386_security_cookie_evidence(
                mapped,
                pe,
                executable_ranges,
                cookie_initializer_rva,
                true,
            )?
            else {
                continue;
            };
            let Some(startup) = crt_startup_evidence(mapped, pe, executable_ranges, startup_rva)?
            else {
                continue;
            };
            if !i386_seh_startup_helper_evidence(
                mapped,
                pe,
                executable_ranges,
                startup.crt_helper_target_rva,
                cookie_rva,
            )? {
                continue;
            }

            ensure!(
                veneers.len() < MAX_SEMANTIC_VENEERS,
                "standalone I386 MSVC OEP candidate budget of {MAX_SEMANTIC_VENEERS} exceeded"
            );
            veneers
                .try_reserve(1)
                .context("reserving standalone I386 MSVC OEP candidate")?;
            veneers.push(StandaloneMsvcVeneer {
                veneer: SemanticVeneer {
                    entry_rva,
                    veneer_call_target_rva: cookie_initializer_rva,
                    veneer_helper_target_rva: cookie_initializer_rva,
                    startup_rva,
                    crt_call_target_rva: startup.crt_call_target_rva,
                    crt_helper_target_rva: startup.crt_helper_target_rva,
                    startup_data_rva: startup.startup_data_rva,
                    startup_data_len: startup.startup_data_len,
                },
                cookie_rva,
                cookie_complement_rva,
            });
        }
    }
    Ok(veneers)
}

fn has_absolute_register_store(bytes: &[u8], address: u32) -> bool {
    let address = address.to_le_bytes();
    bytes
        .windows(6)
        .any(|window| window[0] == 0x89 && window[1] & 0xc7 == 0x05 && window[2..] == address)
        || bytes
            .windows(5)
            .any(|window| window[0] == 0xa3 && window[1..] == address)
}

fn has_not_then_absolute_store(bytes: &[u8], address: u32) -> bool {
    let address = address.to_le_bytes();
    bytes.windows(8).any(|window| {
        let register = window[1].wrapping_sub(0xd0);
        window[0] == 0xf7
            && register < 8
            && window[2] == 0x89
            && window[3] == 0x05 | (register << 3)
            && window[4..] == address
    }) || bytes
        .windows(7)
        .any(|window| window[..3] == [0xf7, 0xd0, 0xa3] && window[3..] == address)
}

fn i386_security_cookie_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    initializer_rva: u32,
    require_cookie_store: bool,
) -> Result<Option<(u32, u32)>> {
    const DEFAULT_COOKIE: u32 = 0xbb40_e64e;
    const DEFAULT_COOKIE_HIGH_WORD_GUARD: u32 = 0xffff_0000;

    let bytes = mapped_bytes(mapped, initializer_rva, I386_COOKIE_EVIDENCE_LEN)?;
    let standard_prologue = bytes[..5] == [0x55, 0x8b, 0xec, 0x83, 0xec];
    let hotpatch_prologue = bytes[..7] == [0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xec];
    if (!standard_prologue && !hotpatch_prologue)
        || !bytes.windows(5).any(|window| {
            (0xb8..=0xbf).contains(&window[0]) && window[1..] == DEFAULT_COOKIE.to_le_bytes()
        })
        || !bytes.windows(5).any(|window| {
            (0xb8..=0xbf).contains(&window[0])
                && window[1..] == DEFAULT_COOKIE_HIGH_WORD_GUARD.to_le_bytes()
        })
    {
        return Ok(None);
    }

    for window in bytes.windows(5) {
        if window[0] != 0xa1 {
            continue;
        }
        let cookie_va = u32::from_le_bytes(
            window[1..]
                .try_into()
                .expect("bounded I386 cookie load has an absolute address"),
        );
        let Ok(cookie_rva) = pe.va_to_rva(u64::from(cookie_va)) else {
            continue;
        };
        if !is_mapped_readable_non_executable_range(
            mapped,
            pe,
            executable_ranges,
            cookie_rva,
            I386_COOKIE_CELL_LEN as u32,
        )? || read_u32_rva(mapped, cookie_rva)? != DEFAULT_COOKIE
        {
            continue;
        }

        if require_cookie_store && !has_absolute_register_store(bytes, cookie_va) {
            continue;
        }
        for complement_window in bytes.windows(7) {
            if complement_window[..3] != [0xf7, 0xd0, 0xa3] {
                continue;
            }
            let complement_va = u32::from_le_bytes(
                complement_window[3..]
                    .try_into()
                    .expect("bounded I386 cookie complement store has an absolute address"),
            );
            let Ok(complement_rva) = pe.va_to_rva(u64::from(complement_va)) else {
                continue;
            };
            if !is_mapped_readable_non_executable_range(
                mapped,
                pe,
                executable_ranges,
                complement_rva,
                I386_COOKIE_CELL_LEN as u32,
            )? || read_u32_rva(mapped, complement_rva)? != !DEFAULT_COOKIE
            {
                continue;
            }
            if has_not_then_absolute_store(bytes, complement_va) {
                return Ok(Some((cookie_rva, complement_rva)));
            }
        }
    }
    Ok(None)
}

fn i386_seh_startup_helper_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    helper_rva: u32,
    cookie_rva: u32,
) -> Result<bool> {
    if !is_executable_range(executable_ranges, helper_rva, I386_SEH_HELPER_EVIDENCE_LEN)? {
        return Ok(false);
    }
    let bytes = mapped_bytes(mapped, helper_rva, I386_SEH_HELPER_EVIDENCE_LEN)?;
    if bytes[0] != 0x68 || bytes[5..12] != [0x64, 0xff, 0x35, 0, 0, 0, 0] {
        return Ok(false);
    }
    let cookie_va = pe
        .rva_to_va(cookie_rva)
        .context("converting standalone I386 security-cookie RVA to VA")?;
    let cookie_va = u32::try_from(cookie_va)
        .context("standalone I386 security-cookie VA does not fit u32")?
        .to_le_bytes();
    let cookie_load = [
        0xa1,
        cookie_va[0],
        cookie_va[1],
        cookie_va[2],
        cookie_va[3],
        0x31,
        0x45,
        0xfc,
        0x33,
        0xc5,
    ];
    Ok(bytes
        .windows(cookie_load.len())
        .any(|window| window == cookie_load))
}

fn semantic_veneers(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
) -> Result<Vec<SemanticVeneer>> {
    let mut veneers = Vec::new();

    for range in executable_ranges {
        let Some(last_rva) = range.end.checked_sub(SEMANTIC_VENEER_LEN as u32) else {
            continue;
        };
        if last_rva < range.start {
            continue;
        }

        for entry_rva in range.start..=last_rva {
            if mapped_bytes(mapped, entry_rva, 1)?[0] != 0xe8 {
                continue;
            }

            let Some(veneer_call_target_rva) = direct_rel32_target(mapped, entry_rva, 0xe8)? else {
                continue;
            };
            let Some((veneer_helper_target_rva, veneer_direct_callee)) =
                helper_target(mapped, executable_ranges, veneer_call_target_rva)?
            else {
                continue;
            };

            let jump_rva = entry_rva
                .checked_add(DIRECT_REL32_LEN as u32)
                .context("semantic veneer JMP RVA overflow")?;
            let Some(startup_rva) = direct_rel32_target(mapped, jump_rva, 0xe9)? else {
                continue;
            };
            let Some(startup) = crt_startup_evidence(mapped, pe, executable_ranges, startup_rva)?
            else {
                continue;
            };
            if veneer_direct_callee != startup.direct_callee {
                continue;
            }

            ensure!(
                veneers.len() < MAX_SEMANTIC_VENEERS,
                "semantic veneer candidate budget of {MAX_SEMANTIC_VENEERS} exceeded"
            );
            veneers
                .try_reserve(1)
                .context("reserving semantic veneer candidate")?;
            veneers.push(SemanticVeneer {
                entry_rva,
                veneer_call_target_rva,
                veneer_helper_target_rva,
                startup_rva,
                crt_call_target_rva: startup.crt_call_target_rva,
                crt_helper_target_rva: startup.crt_helper_target_rva,
                startup_data_rva: startup.startup_data_rva,
                startup_data_len: startup.startup_data_len,
            });
        }
    }

    Ok(veneers)
}

pub(crate) fn executable_jumps(
    mapped: &[u8],
    executable_ranges: &[Range<u32>],
    veneers: &[SemanticVeneer],
) -> Result<BTreeMap<u32, JumpPredecessors>> {
    let mut jumps = BTreeMap::new();
    for veneer in veneers {
        jumps.insert(
            veneer.entry_rva,
            JumpPredecessors {
                count: 0,
                source_rva: 0,
            },
        );
    }
    let mut jump_count = 0usize;

    for range in executable_ranges {
        let Some(last_rva) = range.end.checked_sub(DIRECT_REL32_LEN as u32) else {
            continue;
        };
        if last_rva < range.start {
            continue;
        }

        for rva in range.start..=last_rva {
            if mapped_bytes(mapped, rva, 1)?[0] != 0xe9 {
                continue;
            }
            let Some(target) = direct_rel32_target(mapped, rva, 0xe9)? else {
                continue;
            };
            let Some(predecessors) = jumps.get_mut(&target) else {
                continue;
            };
            jump_count = jump_count
                .checked_add(1)
                .context("matched executable E9 rel32 predecessor count overflow")?;
            ensure!(
                jump_count <= MAX_EXECUTABLE_JUMPS,
                "matched executable E9 rel32 predecessor budget of {MAX_EXECUTABLE_JUMPS} exceeded"
            );
            predecessors.count = predecessors
                .count
                .checked_add(1)
                .context("semantic predecessor count overflow")?;
            predecessors.source_rva = rva;
        }
    }

    Ok(jumps)
}

fn crt_startup_evidence(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    rva: u32,
) -> Result<Option<StartupEvidence>> {
    if !is_executable_range(executable_ranges, rva, CRT_STARTUP_PROLOGUE_LEN)? {
        return Ok(None);
    }

    let bytes = mapped_bytes(mapped, rva, CRT_STARTUP_PROLOGUE_LEN)?;
    if bytes[0] != 0x6a || bytes[2] != 0x68 || bytes[7] != 0xe8 {
        return Ok(None);
    }
    let signed_data_len = i32::from(i8::from_ne_bytes([bytes[1]]));
    if signed_data_len <= 0 || signed_data_len > MAX_STARTUP_DATA_LEN as i32 {
        return Ok(None);
    }
    let startup_data_len =
        u32::try_from(signed_data_len).expect("positive i8 startup data length fits u32");
    let immediate = u32::from_le_bytes(
        bytes[3..7]
            .try_into()
            .expect("a bounded startup immediate has exactly four bytes"),
    );
    let Some(startup_data_rva) =
        startup_data_rva(mapped, pe, executable_ranges, immediate, startup_data_len)?
    else {
        return Ok(None);
    };

    let call_rva = rva
        .checked_add(7)
        .context("CRT startup CALL RVA overflow")?;
    let Some(crt_call_target_rva) = direct_rel32_target(mapped, call_rva, 0xe8)? else {
        return Ok(None);
    };
    let Some((crt_helper_target_rva, direct_callee)) =
        helper_target(mapped, executable_ranges, crt_call_target_rva)?
    else {
        return Ok(None);
    };
    Ok(Some(StartupEvidence {
        crt_call_target_rva,
        crt_helper_target_rva,
        startup_data_rva,
        startup_data_len,
        direct_callee,
    }))
}

fn helper_target(
    mapped: &[u8],
    executable_ranges: &[Range<u32>],
    call_target_rva: u32,
) -> Result<Option<(u32, bool)>> {
    if !is_executable_range(executable_ranges, call_target_rva, DIRECT_REL32_LEN)? {
        return Ok(None);
    }
    if mapped_bytes(mapped, call_target_rva, 1)?[0] != 0xe9 {
        return Ok(Some((call_target_rva, true)));
    }
    let Some(target_rva) = direct_rel32_target(mapped, call_target_rva, 0xe9)? else {
        return Ok(None);
    };
    Ok(
        is_executable_range(executable_ranges, target_rva, DIRECT_REL32_LEN)?
            .then_some((target_rva, false)),
    )
}

fn startup_data_rva(
    mapped: &[u8],
    pe: &Pe,
    executable_ranges: &[Range<u32>],
    immediate: u32,
    len: u32,
) -> Result<Option<u32>> {
    let Ok(rva) = pe.va_to_rva(u64::from(immediate)) else {
        return Ok(None);
    };
    Ok(
        is_mapped_readable_non_executable_range(mapped, pe, executable_ranges, rva, len)?
            .then_some(rva),
    )
}

fn is_mapped_readable_non_executable_range(
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
