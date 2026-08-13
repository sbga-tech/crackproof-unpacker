#![forbid(unsafe_code)]

mod pe;
mod util;
pub use pe::{FileOffset, FileRange, Rva, RvaRange};
pub mod pipeline;

pub use pipeline::Pipeline;
pub use pipeline::cancellation::CancellationToken;
pub use pipeline::failure::{FailureReason, PipelineFailure, RunFailure};
pub use pipeline::observer::{NoopObserver, Observer, StateEvent};
pub use pipeline::outcome::{
    ArtifactSummary, ByteTransform, CodeTransform, ControllerKind, DecryptionDetails,
    GeneratedSemanticClrContainer, ImportSource, ImportSummary, ManagedSemanticClrSource,
    OutputArtifactSummary, PayloadPlanProvenance, PayloadProviderAttempt,
    PayloadProviderAttemptOutcome, PeSummary, PipelineOutput, ProtectorInfo, RecoveredProgram,
    RootedNativeControllerGraphNode, RootedNativeControllerNodeKind,
    RootedNativeControllerTerminalProfile, RunSummary, SelectedAesContext,
    SelectedCodecControlPayloadController, SelectedCodecRelocationController, SelectedController,
    SelectedDecoder, SelectedDecryptionChain, SelectedRootedNativeController,
    SelectedShellDirectoryManifestController, StartupKind,
};
pub use pipeline::progress::ProgressUnit;
pub use pipeline::request::PipelineRequest;
pub use pipeline::stage::{Operation, Stage};
