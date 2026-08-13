use std::time::Duration;

use serde::Serialize;

use super::stage::Stage;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtectorInfo {
    pub format: &'static str,
    pub descriptor_file_offset: usize,
    pub key: u32,
    pub packed_entry_rva: u32,
    pub destination_rva: u32,
    pub source_offset: u32,
    pub length: u32,
    pub source_rva: u32,
    pub destination_section_index: usize,
}

/// Provenance of the provider that authenticated the payload materialization plan.
///
/// Structural resemblance may prioritize a provider, but this value is reported
/// only after the provider's complete payload block table authenticates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadPlanProvenance {
    EvidenceSearch,
    Controller,
}

/// Exact native controller graph followed by a controller provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControllerKind {
    ShellDirectoryManifest,
    CodecRelocation,
    CodecControlPayload,
    CodecOperationDispatch,
    ImageBaseMetadataBinding,
    CodecControlMetadata,
    PayloadChecksumManifest,
    TerminalProfileDispatch,
    StateAssetSelection,
}

/// Result of one provider considered by deterministic payload routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadProviderAttemptOutcome {
    NotApplicable,
    Rejected,
    Authenticated,
    Ambiguous,
    Fatal,
}

/// Provider phase that produced an attempt outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadProviderStage {
    Probe,
    Recovery,
    Authentication,
    Finalization,
    EvidenceSearch,
}

/// Stable machine-readable classification for a failed provider attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadProviderAttemptCode {
    StructuralMismatch,
    NoAuthenticatedPlan,
    AmbiguousPlans,
    InternalFailure,
    EvidenceSearchRejected,
}
/// Bounded routing evidence for one controller or evidence-search attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PayloadProviderAttempt {
    pub provenance: PayloadPlanProvenance,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<ControllerKind>,
    pub outcome: PayloadProviderAttemptOutcome,
    pub stage: PayloadProviderStage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<PayloadProviderAttemptCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteTransform {
    Identity,
    FixedF8,
    ByteMap,
}
/// Descriptor-authenticated origin of the packed payload block stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedPayloadStream {
    pub locator_file_offset: usize,
    pub base_file_offset: usize,
    pub gap_after_outer_source: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedAesContext {
    pub file_offset: usize,
    pub seed: u8,
    pub raw_key_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedDecoder {
    pub source_file_offset: usize,
    pub phase: u8,
    pub table_nodes: usize,
}

/// Evidence-search coordinates for the uniquely replayed generic decryption
/// chain. Exact controller providers retain their rooted mapped-image RVAs in
/// [`SelectedController`] instead of fabricating packed-file offsets or seeds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedDecryptionChain {
    pub aes: SelectedAesContext,
    pub decoder: SelectedDecoder,
    pub byte_transform: ByteTransform,
    pub byte_map: Vec<u8>,
}
/// Provenance for the shell-directory/payload-manifest controller graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedShellDirectoryManifestController {
    pub shell_table_rva: u32,
    pub byte_map_layer_rva: u32,
    pub payload_manifest_rva: u32,
    pub manifest_config_rva: u32,
    pub file_checksum_list_rva: u32,
    pub compressed_info_list_rva: u32,
    pub zero_list_rva: u32,
    pub file_decoder_rva: u32,
    pub layer_decoder_rva: u32,
    pub file_aes_context_rva: u32,
    pub layer_aes_context_rva: u32,
    pub file_raw_key_hex: String,
    pub layer_raw_key_hex: String,
    /// Mapped-image RVA of the selected LFSR-encrypted AL program in the byte-map layer.
    pub custom_program_rva: u32,
    pub custom_program_length: usize,
    pub custom_byte_map: Vec<u8>,
    /// Mapped-image RVA of the selected LFSR-encrypted AL program in the payload manifest.
    pub file_program_rva: u32,
    pub file_program_length: usize,
    pub file_byte_map: Vec<u8>,
}

/// Provenance for the codec-relocation controller graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedCodecRelocationController {
    pub anchor_rva: u32,
    pub primary_rva: u32,
    pub codec_rva: u32,
    pub map_layer_rva: u32,
    pub final_controller_rva: u32,
    pub payload_list_rva: u32,
    pub file_decoder_rva: u32,
    pub layer_decoder_rva: u32,
    pub file_aes_context_rva: u32,
    pub layer_aes_context_rva: u32,
    pub file_raw_key_hex: String,
    pub layer_raw_key_hex: String,
    /// Mapped-image RVA of the controller's layer AL program.
    pub layer_program_rva: u32,
    pub layer_program_length: usize,
    pub layer_byte_map: Vec<u8>,
    /// Mapped-image RVA of the controller's file AL program.
    pub file_program_rva: u32,
    pub file_program_length: usize,
    pub file_byte_map: Vec<u8>,
    pub metadata_record_count: usize,
    pub zero_record_count: usize,
}

/// Provenance for the codec-control/payload controller graph.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedCodecControlPayloadController {
    pub root_rva: u32,
    pub primary_descriptor_rva: u32,
    pub stage2_descriptor_rva: u32,
    pub codec_table_rva: u32,
    pub payload_list_rva: u32,
    pub file_decoder_rva: u32,
    pub layer_decoder_rva: u32,
    pub file_aes_context_rva: u32,
    pub layer_aes_context_rva: u32,
    pub file_raw_key_hex: String,
    pub layer_raw_key_hex: String,
    /// Mapped-image RVA of the controller's layer AL program.
    pub layer_program_rva: u32,
    pub layer_program_length: usize,
    pub layer_byte_map: Vec<u8>,
    /// Mapped-image RVA of the controller's file AL program.
    pub file_program_rva: u32,
    pub file_program_length: usize,
    pub file_byte_map: Vec<u8>,
}
/// Typed node in an authenticated rooted-native controller graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootedNativeControllerNodeKind {
    Anchor,
    ShellTable,
    ControlDescriptor,
    Control,
    CodecDescriptor,
    Codec,
    CodecOperationTable,
    PrimaryDescriptor,
    Stage1,
    Stage2Descriptor,
    Stage2,
    Stage3Descriptor,
    Stage3,
    Stage3bDescriptor,
    Stage3b,
    Stage4Descriptor,
    MapLayer,
    Stage5Descriptor,
    Terminal,
    TerminalDescriptor,
    MappedStageDescriptor,
    FifthStageDescriptor,
    SeventhStageDescriptor,
    EighthStageDescriptor,
    EighthStage,
}

/// One named RVA in an authenticated rooted-native controller graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RootedNativeControllerGraphNode {
    pub kind: RootedNativeControllerNodeKind,
    pub rva: u32,
}

/// Terminal layout selected by a rooted-native controller when it has one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootedNativeControllerTerminalProfile {
    DirectPayloadList,
    NestedFinalDescriptor,
}

/// Provenance retained after a rooted-native controller authenticates its payload plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SelectedRootedNativeController {
    pub root_rva: u32,
    pub graph_nodes: Vec<RootedNativeControllerGraphNode>,
    pub payload_list_rva: u32,
    pub file_decoder_rva: u32,
    pub layer_decoder_rva: Option<u32>,
    pub file_aes_context_rva: u32,
    pub layer_aes_context_rva: Option<u32>,
    pub file_raw_key_hex: String,
    pub layer_raw_key_hex: Option<String>,
    /// Mapped-image RVA of the optional controller layer AL program.
    pub layer_program_rva: Option<u32>,
    pub layer_program_length: Option<usize>,
    pub layer_byte_map: Option<Vec<u8>>,
    /// Mapped-image RVA of the controller's file AL program.
    pub file_program_rva: u32,
    pub file_program_length: usize,
    pub file_byte_map: Vec<u8>,
    pub terminal_profile: Option<RootedNativeControllerTerminalProfile>,
}
/// Controller-specific evidence retained after controller-provider authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectedController {
    ShellDirectoryManifest(SelectedShellDirectoryManifestController),
    CodecRelocation(SelectedCodecRelocationController),
    CodecControlPayload(SelectedCodecControlPayloadController),
    StateAssetSelection(SelectedRootedNativeController),
    CodecOperationDispatch(SelectedRootedNativeController),
    ImageBaseMetadataBinding(SelectedRootedNativeController),
    CodecControlMetadata(SelectedRootedNativeController),
    PayloadChecksumManifest(SelectedRootedNativeController),
    TerminalProfileDispatch(SelectedRootedNativeController),
}

/// Bounded evidence and the unique fully authenticated payload replay.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DecryptionDetails {
    pub plan_provenance: Option<PayloadPlanProvenance>,
    pub selected_stream: Option<SelectedPayloadStream>,
    pub provider_attempts: Vec<PayloadProviderAttempt>,
    pub block_count: usize,
    pub copied_block_count: usize,
    pub decoded_block_count: usize,
    pub aes_key_candidates: usize,
    pub decoder_candidates: usize,
    pub byte_transform_candidates: usize,
    /// Present only for evidence-search selection, whose AES and decoder
    /// coordinates are observed packed-file offsets. Exact controller routes
    /// report their rooted mapped-image RVAs through `selected_controller`.
    pub selected_chain: Option<SelectedDecryptionChain>,
    pub selected_controller: Option<SelectedController>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeTransform {
    Unchanged,
    PageIndex,
    PageRvaOrTextSizeMask,
    PageRvaRol { rotation: u32 },
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StartupKind {
    I386CrtHandoff,
    I386MsvcStandalone,
    Amd64ImportHandoff,
    Amd64MsvcUnwind,
    NativeDllEntry,
    ManagedDll,
    ManagedExe,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RecoveredProgram {
    pub code_transform: CodeTransform,
    pub startup_kind: StartupKind,
    pub startup_rva: u32,
    pub handoff_rva: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    CrackproofLoader,
    PeImportTable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ImportSummary {
    pub source: ImportSource,
    pub module_count: usize,
    pub function_count: usize,
}

/// Explicit label for generated semantic CLR output; never original-bootstrap provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedSemanticClrContainer {
    pub generated_architecture: &'static str,
    pub entry_rva: u32,
    pub import_rva: u32,
    pub iat_rva: u32,
    pub reloc_rva: u32,
    pub cor20_rva: u32,
    pub cor20_size: u32,
    pub metadata_rva: u32,
}

/// Authenticated attributes of the protected source map. This remains separate
/// from the generated PE32 container it produces.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManagedSemanticClrSource {
    pub source_architecture: &'static str,
    pub source_pe_entry_rva: u32,
    pub source_import_rva: u32,
    pub source_iat_rva: u32,
    pub source_cor20_rva: u32,
    pub source_metadata_rva: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactSummary {
    pub path: String,
    pub size: usize,
    pub sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeSummary {
    pub kind: &'static str,
    pub machine: &'static str,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub section_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputArtifactSummary {
    pub path: Option<String>,
    pub size: usize,
    pub sha256: Option<String>,
    pub written: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StageTiming {
    pub stage: Stage,
    pub elapsed_ms: u128,
}

impl StageTiming {
    pub fn new(stage: Stage, duration: Duration) -> Self {
        Self {
            stage,
            elapsed_ms: duration.as_millis(),
        }
    }
}

/// Authoritative semantic result assembled from completed stage outputs.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RunSummary {
    pub input_artifact: Option<ArtifactSummary>,
    pub sidecar_artifact: Option<ArtifactSummary>,
    pub input_pe: Option<PeSummary>,
    pub output_artifact: Option<OutputArtifactSummary>,
    pub output_pe: Option<PeSummary>,
    pub dry_run: bool,
    pub protector: Option<ProtectorInfo>,
    pub decryption: Option<DecryptionDetails>,
    pub recovered_program: Option<RecoveredProgram>,
    pub imports: Option<ImportSummary>,
    pub generated_semantic_clr_container: Option<GeneratedSemanticClrContainer>,
    pub managed_semantic_clr_source: Option<ManagedSemanticClrSource>,
    pub rebuilt_file_size: Option<usize>,
    pub stage_timings: Vec<StageTiming>,
    pub elapsed_ms: u128,
}

#[derive(Debug)]
pub struct PipelineOutput {
    pub image: Vec<u8>,
    pub summary: RunSummary,
}
