use serde::Serialize;

/// Ordered unpacking step used to identify the first unsupported boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStep {
    InputPe,
    ProtectorDetection,
    PayloadDecryption,
    DecryptedPe,
    StartupDetection,
    ImportRecovery,
    PeRebuild,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Complete,
    Failed,
}

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ByteTransform {
    Identity,
    FixedF8,
    ByteMap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CandidateRejection {
    pub chunk_index: usize,
    pub reason: String,
}

/// Bounded evidence collected while selecting the A-record replay chain.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct DecryptionDetails {
    pub chunk_count: usize,
    pub copied_chunk_count: usize,
    pub decoded_chunk_count: usize,
    pub aes_key_candidates: usize,
    pub decoder_candidates: usize,
    pub byte_transform_candidates: usize,
    pub candidate_combinations_tested: usize,
    pub candidate_combinations_rejected: usize,
    pub selected_byte_transform: Option<ByteTransform>,
    pub sample_rejections: Vec<CandidateRejection>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisError {
    pub step: AnalysisStep,
    pub message: String,
}

/// Machine-readable decryption evidence, available on both success and failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnalysisReport {
    pub schema: &'static str,
    pub status: AnalysisStatus,
    pub last_completed_step: Option<AnalysisStep>,
    pub protector: Option<ProtectorInfo>,
    pub decryption: Option<DecryptionDetails>,
    pub recovered_program: Option<RecoveredProgram>,
    pub imports: Option<ImportSummary>,
    pub rebuilt_file_size: Option<usize>,
    pub error: Option<AnalysisError>,
}

impl Default for AnalysisReport {
    fn default() -> Self {
        Self {
            schema: "crackproof-analysis/v2",
            status: AnalysisStatus::Failed,
            last_completed_step: None,
            protector: None,
            decryption: None,
            recovered_program: None,
            imports: None,
            rebuilt_file_size: None,
            error: None,
        }
    }
}

impl AnalysisReport {
    pub(crate) fn completed(&mut self, step: AnalysisStep) {
        self.last_completed_step = Some(step);
    }

    pub(crate) fn fail(&mut self, step: AnalysisStep, message: String) {
        self.status = AnalysisStatus::Failed;
        self.error = Some(AnalysisError { step, message });
    }

    pub(crate) fn finish(&mut self, rebuilt_file_size: usize) {
        self.status = AnalysisStatus::Complete;
        self.last_completed_step = Some(AnalysisStep::Complete);
        self.rebuilt_file_size = Some(rebuilt_file_size);
        self.error = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_keys(value: &serde_json::Value, expected: &[&str]) {
        let keys = value
            .as_object()
            .expect("serialized report value is an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            keys,
            expected
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
        );
    }

    fn assert_no_key(value: &serde_json::Value, key: &str) {
        match value {
            serde_json::Value::Object(object) => {
                assert!(!object.contains_key(key), "obsolete key {key}");
                for nested in object.values() {
                    assert_no_key(nested, key);
                }
            }
            serde_json::Value::Array(values) => {
                for nested in values {
                    assert_no_key(nested, key);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn serializes_the_complete_v2_plain_language_schema() {
        let report = AnalysisReport {
            schema: "crackproof-analysis/v2",
            status: AnalysisStatus::Complete,
            last_completed_step: Some(AnalysisStep::Complete),
            protector: Some(ProtectorInfo {
                format: "cp-konn1",
                descriptor_file_offset: 1,
                key: 2,
                packed_entry_rva: 3,
                destination_rva: 4,
                source_offset: 5,
                length: 6,
                source_rva: 7,
                destination_section_index: 8,
            }),
            decryption: Some(DecryptionDetails {
                chunk_count: 1,
                copied_chunk_count: 2,
                decoded_chunk_count: 3,
                aes_key_candidates: 4,
                decoder_candidates: 5,
                byte_transform_candidates: 6,
                candidate_combinations_tested: 7,
                candidate_combinations_rejected: 8,
                selected_byte_transform: Some(ByteTransform::FixedF8),
                sample_rejections: vec![CandidateRejection {
                    chunk_index: 9,
                    reason: "rejected".to_owned(),
                }],
            }),
            recovered_program: Some(RecoveredProgram {
                code_transform: CodeTransform::PageRvaRol { rotation: 3 },
                startup_kind: StartupKind::Amd64ImportHandoff,
                startup_rva: 10,
                handoff_rva: Some(11),
            }),
            imports: Some(ImportSummary {
                source: ImportSource::CrackproofLoader,
                module_count: 12,
                function_count: 13,
            }),
            rebuilt_file_size: Some(14),
            error: Some(AnalysisError {
                step: AnalysisStep::PayloadDecryption,
                message: "failed".to_owned(),
            }),
        };

        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["schema"], "crackproof-analysis/v2");
        assert_eq!(json["last_completed_step"], "complete");
        assert_eq!(json["error"]["step"], "payload_decryption");
        assert_keys(
            &json,
            &[
                "schema",
                "status",
                "last_completed_step",
                "protector",
                "decryption",
                "recovered_program",
                "imports",
                "rebuilt_file_size",
                "error",
            ],
        );
        assert_keys(
            &json["decryption"],
            &[
                "chunk_count",
                "copied_chunk_count",
                "decoded_chunk_count",
                "aes_key_candidates",
                "decoder_candidates",
                "byte_transform_candidates",
                "candidate_combinations_tested",
                "candidate_combinations_rejected",
                "selected_byte_transform",
                "sample_rejections",
            ],
        );
        assert_keys(
            &json["recovered_program"],
            &[
                "code_transform",
                "startup_kind",
                "startup_rva",
                "handoff_rva",
            ],
        );
        assert_keys(
            &json["protector"],
            &[
                "format",
                "descriptor_file_offset",
                "key",
                "packed_entry_rva",
                "destination_rva",
                "source_offset",
                "length",
                "source_rva",
                "destination_section_index",
            ],
        );
        assert_keys(
            &json["imports"],
            &["source", "module_count", "function_count"],
        );
        assert_keys(&json["error"], &["step", "message"]);
        assert_keys(
            &json["decryption"]["sample_rejections"][0],
            &["chunk_index", "reason"],
        );

        for old_key in [
            "last_completed_stage",
            "family",
            concat!("material", "ization"),
            "output_profile",
            "output_size",
            "failure",
            "profile",
            "record_count",
            "direct_record_count",
            "custom_record_count",
            "aes_context_candidates",
            "post_transform_candidates",
            "attempted_chains",
            "rejected_chains",
            "selected_post_transform",
            "first_rejections",
            "record_index",
            "text",
            "entry",
            "entry_rva",
            "predecessor_rva",
            "stage",
        ] {
            assert_no_key(&json, old_key);
        }
    }
}
