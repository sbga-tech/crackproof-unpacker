//! Static replays of producer-rooted CrackProof payload controllers.
//!
//! Family names encode only the distinguishing producer/terminal graph action.

mod codec_control_metadata;
mod codec_control_payload;
mod codec_operation_dispatch;
mod codec_relocation;
mod image_base_metadata_binding;
mod payload_checksum_manifest;
mod shared;
mod shell_directory_manifest;
mod state_asset_selection;
mod terminal_profile_dispatch;

use anyhow::{Error, Result, ensure};

use crate::pe::{Machine, Pe};
use crate::pipeline::cancellation::{CancellationToken, Cancelled};
use crate::pipeline::outcome::ControllerKind;

use super::DecryptedImage;
use super::records::PayloadBlockTable;
use super::replay::{AuthenticatedPayloadPlan, PayloadPlanCandidate};
use super::source::BoundPayloadSource;

pub(super) enum ControllerProbe {
    ShellDirectoryManifest(shell_directory_manifest::Probe),
    CodecRelocation(codec_relocation::Probe),
    CodecControlPayload(codec_control_payload::Probe),
    CodecOperationDispatch(codec_operation_dispatch::Probe),
    StateAssetSelection(state_asset_selection::Probe),
    ImageBaseMetadataBinding(image_base_metadata_binding::Probe),
    CodecControlMetadata(codec_control_metadata::Probe),
    PayloadChecksumManifest(payload_checksum_manifest::Probe),
    TerminalProfileDispatch(terminal_profile_dispatch::Probe),
}

pub(super) enum ControllerProbeOutcome {
    NotApplicable,
    Applicable(ControllerProbe),
    Cancelled(Error),
    Rejected(Error),
}
/// A single source-derived controller plan awaiting full-table authentication.
pub(super) struct ControllerProposal {
    pub(super) base_image: Vec<u8>,
    pub(super) block_table: PayloadBlockTable,
    pub(super) candidate: PayloadPlanCandidate,
    pub(super) finalizer: ControllerFinalizer,
}

pub(super) enum ControllerFinalizer {
    ShellDirectoryManifest(shell_directory_manifest::Finalizer),
    CodecRelocation(codec_relocation::Finalizer),
    CodecControlPayload(codec_control_payload::Finalizer),
    CodecOperationDispatch(codec_operation_dispatch::Finalizer),
    StateAssetSelection(state_asset_selection::Finalizer),
    ImageBaseMetadataBinding(image_base_metadata_binding::Finalizer),
    CodecControlMetadata(codec_control_metadata::Finalizer),
    PayloadChecksumManifest(payload_checksum_manifest::Finalizer),
    TerminalProfileDispatch(terminal_profile_dispatch::Finalizer),
}

/// Post-authentication reconstruction behavior, independent of family identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FinalizerProfile {
    AuthenticatedImage,
    ManagedHeaderOrPristineOuter,
    MappedHeaderRestore,
    Pe32HeaderAndTlsRestore,
    TerminalProfileSelected,
}

impl ControllerFinalizer {
    const fn profile(&self) -> FinalizerProfile {
        match self {
            Self::ShellDirectoryManifest(_) => FinalizerProfile::Pe32HeaderAndTlsRestore,
            Self::CodecRelocation(_) => FinalizerProfile::ManagedHeaderOrPristineOuter,
            Self::StateAssetSelection(_) => FinalizerProfile::MappedHeaderRestore,
            Self::TerminalProfileDispatch(_) => FinalizerProfile::TerminalProfileSelected,
            Self::CodecControlPayload(_)
            | Self::CodecOperationDispatch(_)
            | Self::ImageBaseMetadataBinding(_)
            | Self::CodecControlMetadata(_)
            | Self::PayloadChecksumManifest(_) => FinalizerProfile::AuthenticatedImage,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackedImageRole {
    Any,
    Executable,
    Dll,
}

/// Corpus-proven packed-container routing bounds, independent of family identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PackedContainerApplicability {
    machine: Machine,
    image_role: PackedImageRole,
}

impl PackedContainerApplicability {
    const I386_ANY_IMAGE: Self = Self {
        machine: Machine::I386,
        image_role: PackedImageRole::Any,
    };
    const AMD64_EXECUTABLE: Self = Self {
        machine: Machine::Amd64,
        image_role: PackedImageRole::Executable,
    };
    const AMD64_DLL: Self = Self {
        machine: Machine::Amd64,
        image_role: PackedImageRole::Dll,
    };

    fn accepts(self, pe: &Pe) -> bool {
        self.accepts_container(pe.machine_kind(), pe.is_dll())
    }

    fn accepts_container(self, machine: Machine, is_dll: bool) -> bool {
        self.machine == machine
            && match self.image_role {
                PackedImageRole::Any => true,
                PackedImageRole::Executable => !is_dll,
                PackedImageRole::Dll => is_dll,
            }
    }
}

/// One action-only family plus its independently variable routing and finalization contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ControllerRegistration {
    pub(super) kind: ControllerKind,
    pub(super) applicability: PackedContainerApplicability,
    pub(super) finalizer_profile: FinalizerProfile,
}

/// Fixed controller registry in deterministic routing order.
pub(super) const REGISTRY: [ControllerRegistration; 9] = [
    ControllerRegistration {
        kind: ControllerKind::ShellDirectoryManifest,
        applicability: PackedContainerApplicability::I386_ANY_IMAGE,
        finalizer_profile: FinalizerProfile::Pe32HeaderAndTlsRestore,
    },
    ControllerRegistration {
        kind: ControllerKind::CodecRelocation,
        applicability: PackedContainerApplicability::AMD64_DLL,
        finalizer_profile: FinalizerProfile::ManagedHeaderOrPristineOuter,
    },
    ControllerRegistration {
        kind: ControllerKind::CodecControlPayload,
        applicability: PackedContainerApplicability::AMD64_EXECUTABLE,
        finalizer_profile: FinalizerProfile::AuthenticatedImage,
    },
    ControllerRegistration {
        kind: ControllerKind::StateAssetSelection,
        applicability: PackedContainerApplicability::AMD64_DLL,
        finalizer_profile: FinalizerProfile::MappedHeaderRestore,
    },
    ControllerRegistration {
        kind: ControllerKind::CodecOperationDispatch,
        applicability: PackedContainerApplicability::I386_ANY_IMAGE,
        finalizer_profile: FinalizerProfile::AuthenticatedImage,
    },
    ControllerRegistration {
        kind: ControllerKind::ImageBaseMetadataBinding,
        applicability: PackedContainerApplicability::AMD64_EXECUTABLE,
        finalizer_profile: FinalizerProfile::AuthenticatedImage,
    },
    ControllerRegistration {
        kind: ControllerKind::CodecControlMetadata,
        applicability: PackedContainerApplicability::AMD64_DLL,
        finalizer_profile: FinalizerProfile::AuthenticatedImage,
    },
    ControllerRegistration {
        kind: ControllerKind::PayloadChecksumManifest,
        applicability: PackedContainerApplicability::AMD64_EXECUTABLE,
        finalizer_profile: FinalizerProfile::AuthenticatedImage,
    },
    ControllerRegistration {
        kind: ControllerKind::TerminalProfileDispatch,
        applicability: PackedContainerApplicability::AMD64_EXECUTABLE,
        finalizer_profile: FinalizerProfile::TerminalProfileSelected,
    },
];

pub(super) fn probe(
    registration: ControllerRegistration,
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> ControllerProbeOutcome {
    let kind = registration.kind;
    if let Some(cancellation) = cancellation
        && let Err(error) = cancellation.checkpoint()
    {
        return ControllerProbeOutcome::Cancelled(error);
    }

    if !registration.applicability.accepts(source.pe) {
        return ControllerProbeOutcome::NotApplicable;
    }

    let result = match kind {
        ControllerKind::ShellDirectoryManifest => {
            shell_directory_manifest::probe(source, cancellation)
                .map(|probe| probe.map(ControllerProbe::ShellDirectoryManifest))
        }
        ControllerKind::CodecRelocation => codec_relocation::probe(source, cancellation)
            .map(|probe| probe.map(ControllerProbe::CodecRelocation)),
        ControllerKind::CodecControlPayload => codec_control_payload::probe(source, cancellation)
            .map(|probe| probe.map(ControllerProbe::CodecControlPayload)),
        ControllerKind::StateAssetSelection => state_asset_selection::probe(source, cancellation)
            .map(|probe| probe.map(ControllerProbe::StateAssetSelection)),
        ControllerKind::CodecOperationDispatch => {
            codec_operation_dispatch::probe(source, cancellation)
                .map(|probe| probe.map(ControllerProbe::CodecOperationDispatch))
        }
        ControllerKind::ImageBaseMetadataBinding => {
            image_base_metadata_binding::probe(source, cancellation)
                .map(|probe| probe.map(ControllerProbe::ImageBaseMetadataBinding))
        }
        ControllerKind::CodecControlMetadata => codec_control_metadata::probe(source, cancellation)
            .map(|probe| probe.map(ControllerProbe::CodecControlMetadata)),
        ControllerKind::PayloadChecksumManifest => {
            payload_checksum_manifest::probe(source, cancellation)
                .map(|probe| probe.map(ControllerProbe::PayloadChecksumManifest))
        }
        ControllerKind::TerminalProfileDispatch => {
            terminal_profile_dispatch::probe(source, cancellation)
                .map(|probe| probe.map(ControllerProbe::TerminalProfileDispatch))
        }
    };

    if let Some(cancellation) = cancellation
        && let Err(error) = cancellation.checkpoint()
    {
        return ControllerProbeOutcome::Cancelled(error);
    }

    match result {
        Ok(Some(probe)) => ControllerProbeOutcome::Applicable(probe),
        Ok(None) => ControllerProbeOutcome::NotApplicable,
        Err(error) if error.downcast_ref::<Cancelled>().is_some() => {
            ControllerProbeOutcome::Cancelled(error)
        }
        Err(error) => ControllerProbeOutcome::Rejected(error),
    }
}
pub(super) fn recover(
    source: &BoundPayloadSource<'_>,
    probe: ControllerProbe,
    cancellation: Option<&CancellationToken>,
) -> Result<ControllerProposal> {
    match probe {
        ControllerProbe::ShellDirectoryManifest(probe) => {
            shell_directory_manifest::recover(source, probe, cancellation)
        }
        ControllerProbe::CodecRelocation(probe) => {
            codec_relocation::recover(source, probe, cancellation)
        }
        ControllerProbe::CodecControlPayload(probe) => {
            let proposal = codec_control_payload::recover(source, probe, cancellation)?;
            Ok(ControllerProposal {
                base_image: proposal.base_image,
                block_table: proposal.block_table,
                candidate: proposal.candidate,
                finalizer: ControllerFinalizer::CodecControlPayload(proposal.finalizer),
            })
        }
        ControllerProbe::StateAssetSelection(probe) => {
            let proposal = state_asset_selection::recover(source, probe, cancellation)?;
            Ok(ControllerProposal {
                base_image: proposal.base_image,
                block_table: proposal.block_table,
                candidate: proposal.candidate,
                finalizer: ControllerFinalizer::StateAssetSelection(proposal.finalizer),
            })
        }
        ControllerProbe::CodecOperationDispatch(probe) => {
            let proposal = codec_operation_dispatch::recover(source, probe, cancellation)?;
            Ok(ControllerProposal {
                base_image: proposal.base_image,
                block_table: proposal.block_table,
                candidate: proposal.candidate,
                finalizer: ControllerFinalizer::CodecOperationDispatch(proposal.finalizer),
            })
        }
        ControllerProbe::ImageBaseMetadataBinding(probe) => {
            let proposal = image_base_metadata_binding::recover(source, probe, cancellation)?;
            Ok(ControllerProposal {
                base_image: proposal.base_image,
                block_table: proposal.block_table,
                candidate: proposal.candidate,
                finalizer: ControllerFinalizer::ImageBaseMetadataBinding(proposal.finalizer),
            })
        }
        ControllerProbe::CodecControlMetadata(probe) => {
            codec_control_metadata::recover(source, probe, cancellation)
        }
        ControllerProbe::PayloadChecksumManifest(probe) => {
            let proposal = payload_checksum_manifest::recover(source, probe, cancellation)?;
            Ok(ControllerProposal {
                base_image: proposal.base_image,
                block_table: proposal.block_table,
                candidate: proposal.candidate,
                finalizer: ControllerFinalizer::PayloadChecksumManifest(proposal.finalizer),
            })
        }
        ControllerProbe::TerminalProfileDispatch(probe) => {
            let proposal = terminal_profile_dispatch::recover(source, probe, cancellation)?;
            Ok(ControllerProposal {
                base_image: proposal.base_image,
                block_table: proposal.block_table,
                candidate: proposal.candidate,
                finalizer: ControllerFinalizer::TerminalProfileDispatch(proposal.finalizer),
            })
        }
    }
}

pub(super) fn finalize(
    profile: FinalizerProfile,
    source: &BoundPayloadSource<'_>,
    block_table: PayloadBlockTable,
    finalizer: ControllerFinalizer,
    authenticated: AuthenticatedPayloadPlan,
) -> Result<DecryptedImage> {
    let recovered_profile = finalizer.profile();
    ensure!(
        recovered_profile == profile,
        "recovered controller finalizer profile {recovered_profile:?} does not match registered profile {profile:?}"
    );
    match finalizer {
        ControllerFinalizer::ShellDirectoryManifest(finalizer) => {
            shell_directory_manifest::finalize(source, block_table, finalizer, authenticated)
        }
        ControllerFinalizer::CodecRelocation(finalizer) => {
            codec_relocation::finalize(source, block_table, finalizer, authenticated)
        }
        ControllerFinalizer::CodecControlPayload(finalizer) => {
            let _ = block_table;
            codec_control_payload::finalize(source, finalizer, authenticated)
        }
        ControllerFinalizer::StateAssetSelection(finalizer) => {
            finalizer.finalize(source, block_table, authenticated)
        }
        ControllerFinalizer::CodecOperationDispatch(finalizer) => {
            codec_operation_dispatch::finalize(source, block_table, finalizer, authenticated)
        }
        ControllerFinalizer::ImageBaseMetadataBinding(finalizer) => {
            image_base_metadata_binding::finalize(source, block_table, finalizer, authenticated)
        }
        ControllerFinalizer::CodecControlMetadata(finalizer) => {
            codec_control_metadata::finalize(source, block_table, finalizer, authenticated)
        }
        ControllerFinalizer::PayloadChecksumManifest(finalizer) => {
            payload_checksum_manifest::finalize(block_table, finalizer, authenticated)
        }
        ControllerFinalizer::TerminalProfileDispatch(finalizer) => {
            terminal_profile_dispatch::finalize(source, block_table, finalizer, authenticated)
        }
    }
}

pub(super) fn shell_directory_manifest_proposal(
    base_image: Vec<u8>,
    block_table: PayloadBlockTable,
    candidate: PayloadPlanCandidate,
    finalizer: shell_directory_manifest::Finalizer,
) -> ControllerProposal {
    ControllerProposal {
        base_image,
        block_table,
        candidate,
        finalizer: ControllerFinalizer::ShellDirectoryManifest(finalizer),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_keeps_packed_container_applicability_separate_from_family_identity() {
        let applicability = |kind| {
            REGISTRY
                .iter()
                .find(|registration| registration.kind == kind)
                .expect("controller must have one registration")
                .applicability
        };

        for kind in [
            ControllerKind::ShellDirectoryManifest,
            ControllerKind::CodecOperationDispatch,
        ] {
            let applicability = applicability(kind);
            assert!(applicability.accepts_container(Machine::I386, false));
            assert!(applicability.accepts_container(Machine::I386, true));
            assert!(!applicability.accepts_container(Machine::Amd64, false));
        }

        for kind in [
            ControllerKind::CodecRelocation,
            ControllerKind::CodecControlMetadata,
            ControllerKind::StateAssetSelection,
        ] {
            let applicability = applicability(kind);
            assert!(applicability.accepts_container(Machine::Amd64, true));
            assert!(!applicability.accepts_container(Machine::Amd64, false));
            assert!(!applicability.accepts_container(Machine::I386, true));
        }

        for kind in [
            ControllerKind::CodecControlPayload,
            ControllerKind::ImageBaseMetadataBinding,
            ControllerKind::PayloadChecksumManifest,
            ControllerKind::TerminalProfileDispatch,
        ] {
            let applicability = applicability(kind);
            assert!(applicability.accepts_container(Machine::Amd64, false));
            assert!(!applicability.accepts_container(Machine::Amd64, true));
            assert!(!applicability.accepts_container(Machine::I386, false));
        }
    }

    #[test]
    fn registry_keeps_finalizer_profiles_separate_from_family_identity() {
        assert_eq!(
            REGISTRY.map(|registration| (registration.kind, registration.finalizer_profile)),
            [
                (
                    ControllerKind::ShellDirectoryManifest,
                    FinalizerProfile::Pe32HeaderAndTlsRestore,
                ),
                (
                    ControllerKind::CodecRelocation,
                    FinalizerProfile::ManagedHeaderOrPristineOuter,
                ),
                (
                    ControllerKind::CodecControlPayload,
                    FinalizerProfile::AuthenticatedImage,
                ),
                (
                    ControllerKind::StateAssetSelection,
                    FinalizerProfile::MappedHeaderRestore,
                ),
                (
                    ControllerKind::CodecOperationDispatch,
                    FinalizerProfile::AuthenticatedImage,
                ),
                (
                    ControllerKind::ImageBaseMetadataBinding,
                    FinalizerProfile::AuthenticatedImage,
                ),
                (
                    ControllerKind::CodecControlMetadata,
                    FinalizerProfile::AuthenticatedImage,
                ),
                (
                    ControllerKind::PayloadChecksumManifest,
                    FinalizerProfile::AuthenticatedImage,
                ),
                (
                    ControllerKind::TerminalProfileDispatch,
                    FinalizerProfile::TerminalProfileSelected,
                ),
            ]
        );
    }
}
