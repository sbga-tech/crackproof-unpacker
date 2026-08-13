use std::path::PathBuf;

use clap::Parser;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "crackproof-unpacker",
    version,
    about = "Statically reconstruct a CrackProof-protected PE"
)]
pub(crate) struct Args {
    /// Emit detailed crackproof-event/v1 JSONL on stdout.
    #[arg(long, conflicts_with = "silent")]
    pub(crate) events: bool,

    /// Emit nothing on success and one fatal JSON object on failure.
    #[arg(long, conflicts_with = "events")]
    pub(crate) silent: bool,

    /// Rebuild and verify in memory without writing an output file.
    #[arg(long, conflicts_with = "output")]
    pub(crate) dry_run: bool,

    /// Packed PE input.
    pub(crate) input: PathBuf,

    /// Reconstructed PE destination.
    pub(crate) output: Option<PathBuf>,
}

impl Args {
    pub(crate) fn machine_mode_requested(arguments: &[std::ffi::OsString]) -> bool {
        arguments
            .iter()
            .any(|argument| argument == "--events" || argument == "--silent")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_modes_are_mutually_exclusive() {
        let error =
            Args::try_parse_from(["crackproof-unpacker", "--events", "--silent", "packed.exe"])
                .expect_err("machine modes must conflict");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn dry_run_refuses_an_output_path() {
        let error = Args::try_parse_from([
            "crackproof-unpacker",
            "--dry-run",
            "packed.exe",
            "output.exe",
        ])
        .expect_err("dry-run must not accept a destination");
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn machine_mode_detection_covers_parse_failures() {
        let arguments = ["tool".into(), "--events".into(), "--bad".into()];
        assert!(Args::machine_mode_requested(&arguments));
        let plain = ["tool".into(), "--bad".into()];
        assert!(!Args::machine_mode_requested(&plain));
    }

    #[test]
    fn obsolete_forensic_evidence_search_flag_is_rejected() {
        let error = Args::try_parse_from([
            "crackproof-unpacker",
            "--forensic-evidence-search",
            "packed.exe",
        ])
        .expect_err("evidence search is automatic and has no CLI switch");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
