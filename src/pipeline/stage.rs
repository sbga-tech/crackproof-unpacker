use std::fmt;

use serde::Serialize;

/// Stable top-level lifecycle stage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    ReadInput,
    InputValidation,
    ProtectorDetection,
    PayloadRecovery,
    ImageValidation,
    StartupRecovery,
    ImportRecovery,
    OutputRebuild,
    WriteOutput,
}

impl Stage {
    pub const COUNT: u8 = 9;

    pub const fn ordinal(self) -> u8 {
        match self {
            Self::ReadInput => 1,
            Self::InputValidation => 2,
            Self::ProtectorDetection => 3,
            Self::PayloadRecovery => 4,
            Self::ImageValidation => 5,
            Self::StartupRecovery => 6,
            Self::ImportRecovery => 7,
            Self::OutputRebuild => 8,
            Self::WriteOutput => 9,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadInput => "read_input",
            Self::InputValidation => "input_validation",
            Self::ProtectorDetection => "protector_detection",
            Self::PayloadRecovery => "payload_recovery",
            Self::ImageValidation => "image_validation",
            Self::StartupRecovery => "startup_recovery",
            Self::ImportRecovery => "import_recovery",
            Self::OutputRebuild => "output_rebuild",
            Self::WriteOutput => "write_output",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ReadInput => "Read input",
            Self::InputValidation => "Input validation",
            Self::ProtectorDetection => "Protector detection",
            Self::PayloadRecovery => "Payload recovery",
            Self::ImageValidation => "Image validation",
            Self::StartupRecovery => "Startup recovery",
            Self::ImportRecovery => "Import recovery",
            Self::OutputRebuild => "Output rebuild",
            Self::WriteOutput => "Write output",
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Named operation inside a lifecycle stage.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    ReadInput,
    ReadSidecar,
    ParseInputPe,
    ScanDescriptors,
    BindPayloadSource,
    ReplayOuter,
    DiscoverRecords,
    DiscoverAesContexts,
    DiscoverDecoders,
    RecoverByteMaps,
    SelectDecryptionChain,
    MaterializeImage,
    ParseRecoveredPe,
    ScanStartup,
    TestCodeProfiles,
    DiscoverImports,
    SelectRebuildStrategy,
    RecoverDirectories,
    RecoverRelocations,
    SerializeOutput,
    VerifyOutput,
    CommitOutput,
    WriteOutput,
}

impl Operation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadInput => "read_input",
            Self::ReadSidecar => "read_sidecar",
            Self::ParseInputPe => "parse_input_pe",
            Self::ScanDescriptors => "scan_descriptors",
            Self::BindPayloadSource => "bind_payload_source",
            Self::ReplayOuter => "replay_outer",
            Self::DiscoverRecords => "discover_records",
            Self::DiscoverAesContexts => "discover_aes_contexts",
            Self::DiscoverDecoders => "discover_decoders",
            Self::RecoverByteMaps => "recover_byte_maps",
            Self::SelectDecryptionChain => "select_decryption_chain",
            Self::MaterializeImage => "materialize_image",
            Self::ParseRecoveredPe => "parse_recovered_pe",
            Self::ScanStartup => "scan_startup",
            Self::TestCodeProfiles => "test_code_profiles",
            Self::DiscoverImports => "discover_imports",
            Self::SelectRebuildStrategy => "select_rebuild_strategy",
            Self::RecoverDirectories => "recover_directories",
            Self::RecoverRelocations => "recover_relocations",
            Self::SerializeOutput => "serialize_output",
            Self::VerifyOutput => "verify_output",
            Self::CommitOutput => "commit_output",
            Self::WriteOutput => "write_output",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::ReadInput => "Reading input",
            Self::ReadSidecar => "Reading sidecar",
            Self::ParseInputPe => "Parsing input PE",
            Self::ScanDescriptors => "Scanning KONN descriptors",
            Self::BindPayloadSource => "Binding payload source",
            Self::ReplayOuter => "Replaying outer layer",
            Self::DiscoverRecords => "Discovering A records",
            Self::DiscoverAesContexts => "Discovering AES contexts",
            Self::DiscoverDecoders => "Discovering decoders",
            Self::RecoverByteMaps => "Recovering byte maps",
            Self::SelectDecryptionChain => "Selecting decryption chain",
            Self::MaterializeImage => "Materializing image",
            Self::ParseRecoveredPe => "Parsing recovered PE",
            Self::ScanStartup => "Scanning startup",
            Self::TestCodeProfiles => "Testing code profiles",
            Self::DiscoverImports => "Recovering imports",
            Self::SelectRebuildStrategy => "Selecting rebuild strategy",
            Self::RecoverDirectories => "Recovering directories",
            Self::RecoverRelocations => "Recovering relocations",
            Self::SerializeOutput => "Serializing output",
            Self::VerifyOutput => "Verifying output",
            Self::CommitOutput => "Committing output",
            Self::WriteOutput => "Writing output",
        }
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
