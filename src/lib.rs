#![forbid(unsafe_code)]

mod pe;
pub use pe::{FileOffset, FileRange, Rva, RvaRange};
pub mod pipeline;

pub use pipeline::Pipeline;
pub use pipeline::cancellation::CancellationToken;
pub use pipeline::failure::{FailureReason, PipelineFailure, RunFailure};
pub use pipeline::observer::{NoopObserver, Observer, StateEvent};
pub use pipeline::outcome::{
    ArtifactSummary, ByteTransform, CodeTransform, DecryptionDetails,
    GeneratedSemanticClrContainer, ImportSource, ImportSummary, ManagedSemanticClrSource,
    OutputArtifactSummary, PayloadGrammar, PeSummary, PipelineOutput, ProtectorInfo,
    RecoveredProgram, RunSummary, SelectedAesContext, SelectedDecoder, SelectedDecryptionChain,
    SelectedStagedTable, StartupKind,
};
pub use pipeline::progress::ProgressUnit;
pub use pipeline::request::PipelineRequest;
pub use pipeline::stage::{Operation, Stage};
