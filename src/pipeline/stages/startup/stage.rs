use anyhow::{Context, Result, bail};
use tracing::{debug, info};

use crate::{
    pe::{Machine, Pe},
    pipeline::outcome::{CodeTransform, RecoveredProgram, StartupKind},
};

use super::{
    OutputEntry, SemanticEvidence, authenticate_sparse_output_entry,
    decode_sparse_text_pages_in_place, discover_output_entry,
    native::amd64::discover_amd64_msvc_semantic_entry, sparse::SparsePageKey,
    unique_sparse_page_keys,
};

fn corroborate_sparse<T: Copy>(
    mapped: &mut [u8],
    pe: &Pe,
    candidates: &mut Vec<(Option<SparsePageKey>, T)>,
    corroborates: impl Fn(&[u8], T) -> bool,
) -> Result<()> {
    let mut supported = None;
    for &(key, entry) in candidates.iter() {
        if let Some(key) = key {
            decode_sparse_text_pages_in_place(mapped, pe, key)?;
        }
        let matches = corroborates(mapped, entry);
        if let Some(key) = key {
            decode_sparse_text_pages_in_place(mapped, pe, key)?;
        }
        if matches {
            if supported.is_some() {
                return Ok(());
            }
            supported = Some((key, entry));
        }
    }
    if let Some(candidate) = supported {
        candidates.clear();
        candidates.push(candidate);
    }
    Ok(())
}

/// The recovered program selected from semantic entry evidence.
///
/// `code_transform` records whether executable code was used unchanged or restored through an
/// authenticated sparse-page transform. DLL and managed profiles have no code
/// transform selection, so they use [`CodeTransform::NotApplicable`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SelectedOutputProfile {
    pub(crate) entry: OutputEntry,
    pub(crate) code_transform: CodeTransform,
}

impl SelectedOutputProfile {
    /// Converts the selected entry and its architecture-specific evidence into
    /// the report's stable recovered-program summary.
    pub(crate) const fn fingerprint(self) -> RecoveredProgram {
        match self.entry {
            OutputEntry::Native(entry) => RecoveredProgram {
                code_transform: self.code_transform,
                startup_kind: match entry.evidence {
                    SemanticEvidence::I386 => StartupKind::I386CrtHandoff,
                    SemanticEvidence::I386MsvcStandalone { .. } => StartupKind::I386MsvcStandalone,
                    SemanticEvidence::Amd64 { .. } => StartupKind::Amd64ImportHandoff,
                    SemanticEvidence::Amd64Msvc { .. } => StartupKind::Amd64MsvcUnwind,
                },
                startup_rva: entry.entry_rva,
                handoff_rva: entry.predecessor_rva,
            },
            OutputEntry::NativeDll { entry_rva } => RecoveredProgram {
                code_transform: self.code_transform,
                startup_kind: StartupKind::NativeDllEntry,
                startup_rva: entry_rva,
                handoff_rva: None,
            },
            OutputEntry::Managed { entry_rva, kind } => RecoveredProgram {
                code_transform: self.code_transform,
                startup_kind: match kind {
                    super::ManagedKind::Dll => StartupKind::ManagedDll,
                    super::ManagedKind::Exe => StartupKind::ManagedExe,
                },
                startup_rva: entry_rva,
                handoff_rva: None,
            },
        }
    }
}

fn native_entry(mapped: &[u8], pe: &Pe) -> Result<OutputEntry> {
    if pe.machine_kind() == Machine::Amd64
        && let Some(entry) = discover_amd64_msvc_semantic_entry(mapped, pe)?
    {
        return Ok(OutputEntry::Native(entry));
    }
    discover_output_entry(mapped, pe)
}

fn authenticated_entry(mapped: &[u8], pe: &Pe) -> Result<OutputEntry> {
    let entry = native_entry(mapped, pe)?;
    authenticate_sparse_output_entry(mapped, pe, entry)?;
    Ok(entry)
}

pub(crate) fn select_output_entry(mapped: &mut [u8], pe: &Pe) -> Result<SelectedOutputProfile> {
    if pe.is_dll() || has_nonempty_com_descriptor(pe) {
        let raw = discover_output_entry(mapped, pe);
        return raw
            .map(|entry| {
                info!(
                    entry_rva = entry.entry_rva(),
                    "selected DLL or managed startup entry"
                );
                SelectedOutputProfile {
                    entry,
                    code_transform: CodeTransform::NotApplicable,
                }
            })
            .context("selecting DLL or managed output entry profile");
    }
    let evidence = super::sparse::page_evidence(mapped, pe)?;
    let mut successes = Vec::new();
    let mut failures = Vec::new();
    let page_keys = match evidence {
        super::sparse::PageEvidence::Unique(key) => {
            decode_sparse_text_pages_in_place(mapped, pe, key)?;
            let entry = authenticated_entry(mapped, pe)?;
            info!(
                ?key,
                entry_rva = entry.entry_rva(),
                "selected sparse text profile from page encoding and startup evidence"
            );
            return Ok(SelectedOutputProfile {
                entry,
                code_transform: sparse_code_transform(key),
            });
        }
        super::sparse::PageEvidence::Partial(keys) => {
            if let Ok(raw) = authenticated_entry(mapped, pe) {
                successes.push((None, raw));
            }
            keys
        }
        super::sparse::PageEvidence::None => {
            match native_entry(mapped, pe) {
                Ok(entry) => {
                    return Ok(SelectedOutputProfile {
                        entry,
                        code_transform: CodeTransform::Unchanged,
                    });
                }
                Err(error) => failures.push(format!("raw: {error:#}")),
            }
            unique_sparse_page_keys(pe)?
        }
    };
    for page_key in page_keys {
        debug!(page_key = ?page_key, "testing sparse executable-page startup profile");
        decode_sparse_text_pages_in_place(mapped, pe, page_key)
            .with_context(|| format!("decoding sparse executable pages with {page_key:?}"))?;
        let result = authenticated_entry(mapped, pe);
        decode_sparse_text_pages_in_place(mapped, pe, page_key).with_context(|| {
            format!("restoring sparse executable pages after testing {page_key:?}")
        })?;

        match result {
            Ok(entry) => {
                debug!(page_key = ?page_key, entry_rva = entry.entry_rva(), "sparse startup profile authenticated");
                successes.push((Some(page_key), entry));
            }
            Err(error) => {
                debug!(page_key = ?page_key, reason = %format!("{error:#}"), "sparse startup profile rejected");
                failures.push(format!("{page_key:?}: {error:#}"));
            }
        }
    }

    if successes.len() > 1
        && successes.iter().all(|(_, entry)| {
            matches!(
                entry.semantic().map(|e| e.evidence),
                Some(SemanticEvidence::Amd64Msvc { .. })
            )
        })
    {
        let sites = super::native::amd64::unwind_push_sites(mapped, pe)?;
        corroborate_sparse(mapped, pe, &mut successes, |bytes, _| {
            super::native::amd64::matches_unwind_pushes(bytes, &sites)
        })?;
    }
    if successes.len() > 1
        && pe.machine_kind() == Machine::I386
        && successes.iter().all(|(_, entry)| {
            matches!(
                entry.semantic().map(|e| e.evidence),
                Some(SemanticEvidence::I386MsvcStandalone { .. })
            )
        })
        && let Some(slot) = super::native::i386::cookie_time_import(mapped, pe)?
    {
        corroborate_sparse(mapped, pe, &mut successes, |bytes, entry| {
            let init = entry
                .semantic()
                .expect("standalone I386 entry")
                .veneer_call_target_rva;
            super::native::i386::cookie_calls_time_import(bytes, init, slot)
        })?;
    }

    let [(page_key, entry)] = successes.as_slice() else {
        if successes.is_empty() {
            bail!(
                "no native output profile produced a semantic entry: {}",
                failures.join("; ")
            );
        }
        let profiles = successes
            .iter()
            .map(|(key, entry)| format!("{key:?} -> {:#x}", entry.entry_rva()))
            .collect::<Vec<_>>();
        bail!(
            "multiple sparse executable-page profiles produce semantic entries: {}",
            profiles.join("; ")
        );
    };

    let page_key = page_key.context("sparse page evidence has no authenticated decoded startup")?;
    decode_sparse_text_pages_in_place(mapped, pe, page_key).with_context(|| {
        format!("applying selected sparse executable-page profile {page_key:?}")
    })?;
    info!(
        page_key = ?page_key,
        entry_rva = entry.entry_rva(),
        "selected unique sparse startup profile"
    );
    Ok(SelectedOutputProfile {
        entry: *entry,
        code_transform: sparse_code_transform(page_key),
    })
}

const fn sparse_code_transform(page_key: SparsePageKey) -> CodeTransform {
    match page_key {
        SparsePageKey::PageIndex => CodeTransform::PageIndex,
        SparsePageKey::PageRvaOrTextSizeMask => CodeTransform::PageRvaOrTextSizeMask,
        SparsePageKey::PageRvaRol(rotation) => CodeTransform::PageRvaRol { rotation },
    }
}

fn has_nonempty_com_descriptor(pe: &Pe) -> bool {
    pe.directories
        .get(14)
        .is_some_and(|directory| !directory.is_empty())
}
