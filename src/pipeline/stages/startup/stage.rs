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

fn select_amd64_msvc_profile(mapped: &mut [u8], pe: &Pe) -> Result<Option<SelectedOutputProfile>> {
    if let Some(entry) = discover_amd64_msvc_semantic_entry(mapped, pe)? {
        info!(
            entry_rva = entry.entry_rva,
            "selected unchanged AMD64 MSVC startup entry"
        );
        return Ok(Some(SelectedOutputProfile {
            entry: OutputEntry::Native(entry),
            code_transform: CodeTransform::Unchanged,
        }));
    }

    let page_keys = unique_sparse_page_keys(pe)
        .context("enumerating sparse executable-page profiles for AMD64 MSVC startup")?;
    let mut successes = Vec::new();
    for page_key in page_keys {
        decode_sparse_text_pages_in_place(mapped, pe, page_key)
            .with_context(|| format!("decoding sparse executable pages with {page_key:?}"))?;
        let result = discover_amd64_msvc_semantic_entry(mapped, pe).and_then(|entry| {
            let Some(entry) = entry else {
                return Ok(None);
            };
            authenticate_sparse_output_entry(mapped, pe, OutputEntry::Native(entry))
                .context("authenticating sparse AMD64 MSVC entry")?;
            Ok(Some(entry))
        });
        decode_sparse_text_pages_in_place(mapped, pe, page_key).with_context(|| {
            format!("restoring sparse executable pages after testing {page_key:?}")
        })?;

        match result {
            Ok(Some(entry)) => {
                debug!(
                    ?page_key,
                    entry_rva = entry.entry_rva,
                    "sparse AMD64 MSVC startup profile authenticated"
                );
                successes.push((page_key, entry));
            }
            Ok(None) => {}
            Err(error) => debug!(
                ?page_key,
                reason = %format!("{error:#}"),
                "sparse AMD64 MSVC startup profile rejected"
            ),
        }
    }

    let [(page_key, entry)] = successes.as_slice() else {
        if successes.is_empty() {
            return Ok(None);
        }
        let profiles = successes
            .iter()
            .map(|(key, entry)| format!("{key:?} -> {:#x}", entry.entry_rva))
            .collect::<Vec<_>>();
        bail!(
            "multiple sparse executable-page profiles produce AMD64 MSVC entries: {}",
            profiles.join("; ")
        );
    };

    decode_sparse_text_pages_in_place(mapped, pe, *page_key).with_context(|| {
        format!("applying selected sparse executable-page profile {page_key:?}")
    })?;
    info!(
        ?page_key,
        entry_rva = entry.entry_rva,
        "selected unique sparse AMD64 MSVC startup profile"
    );
    Ok(Some(SelectedOutputProfile {
        entry: OutputEntry::Native(*entry),
        code_transform: sparse_code_transform(*page_key),
    }))
}

/// Selects the native output profile. A semantic entry in the decrypted
/// image is authoritative; reversible sparse-page transforms are tested only
/// as a fail-closed fallback. The selected fallback remains applied for the
/// remainder of reconstruction.
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
    if pe.machine_kind() == Machine::Amd64
        && let Some(profile) = select_amd64_msvc_profile(mapped, pe)?
    {
        return Ok(profile);
    }

    let raw = discover_output_entry(mapped, pe);

    let raw_error = match raw {
        Ok(entry) => {
            info!(
                entry_rva = entry.entry_rva(),
                "selected unchanged native startup entry"
            );
            return Ok(SelectedOutputProfile {
                entry,
                code_transform: CodeTransform::Unchanged,
            });
        }
        Err(error) => {
            debug!(reason = %format!("{error:#}"), "raw native startup profile rejected");
            error
        }
    };
    let mut successes = Vec::new();
    let mut failures = vec![format!("raw: {raw_error:#}")];

    let page_keys = unique_sparse_page_keys(pe)
        .context("enumerating sparse executable-page profiles for native application")?;
    for page_key in page_keys {
        debug!(page_key = ?page_key, "testing sparse executable-page startup profile");
        decode_sparse_text_pages_in_place(mapped, pe, page_key)
            .with_context(|| format!("decoding sparse executable pages with {page_key:?}"))?;
        let result = discover_output_entry(mapped, pe).and_then(|entry| {
            debug!(
                page_key = ?page_key,
                ?entry,
                "diagnostic sparse semantic candidate"
            );
            authenticate_sparse_output_entry(mapped, pe, entry)
                .context("authenticating sparse semantic entry")?;
            Ok(entry)
        });
        decode_sparse_text_pages_in_place(mapped, pe, page_key).with_context(|| {
            format!("restoring sparse executable pages after testing {page_key:?}")
        })?;

        match result {
            Ok(entry) => {
                debug!(page_key = ?page_key, entry_rva = entry.entry_rva(), "sparse startup profile authenticated");
                successes.push((page_key, entry));
            }
            Err(error) => {
                debug!(page_key = ?page_key, reason = %format!("{error:#}"), "sparse startup profile rejected");
                failures.push(format!("{page_key:?}: {error:#}"));
            }
        }
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

    decode_sparse_text_pages_in_place(mapped, pe, *page_key).with_context(|| {
        format!("applying selected sparse executable-page profile {page_key:?}")
    })?;
    info!(
        page_key = ?page_key,
        entry_rva = entry.entry_rva(),
        "selected unique sparse startup profile"
    );
    Ok(SelectedOutputProfile {
        entry: *entry,
        code_transform: sparse_code_transform(*page_key),
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
