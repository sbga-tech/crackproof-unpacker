use std::path::PathBuf;

/// Filesystem request consumed by the complete unpacking pipeline.
#[derive(Clone, Debug)]
pub struct PipelineRequest {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub dry_run: bool,
    pub hash_artifacts: bool,
}
