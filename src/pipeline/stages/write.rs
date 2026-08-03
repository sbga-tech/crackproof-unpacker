use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

use crate::pipeline::cancellation::CancellationToken;

const WRITE_CHUNK_SIZE: usize = 1 << 20;

fn parent_or_current(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

pub(crate) fn default_output_path(input: &Path) -> Result<PathBuf> {
    let file_stem = input
        .file_stem()
        .context("input path has no file stem")?
        .to_string_lossy();
    let file_name = match input.extension() {
        Some(extension) => format!("{file_stem}_unpacked.{}", extension.to_string_lossy()),
        None => format!("{file_stem}_unpacked"),
    };
    Ok(input.with_file_name(file_name))
}

pub(crate) fn ensure_distinct_paths(input: &Path, output: &Path) -> Result<()> {
    let input = fs::canonicalize(input)
        .with_context(|| format!("canonicalizing input {}", input.display()))?;
    let output = if output.exists() {
        fs::canonicalize(output)
            .with_context(|| format!("canonicalizing output {}", output.display()))?
    } else {
        let parent = parent_or_current(output);
        let parent = fs::canonicalize(parent)
            .with_context(|| format!("canonicalizing output directory {}", parent.display()))?;
        let name = output.file_name().context("output path has no file name")?;
        parent.join(name)
    };
    ensure!(
        input != output,
        "input and output paths refer to the same file"
    );
    Ok(())
}

pub(crate) fn digest(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub(crate) fn commit(
    path: &Path,
    data: &[u8],
    cancellation: &CancellationToken,
    hash: bool,
) -> Result<Option<String>> {
    cancellation.checkpoint()?;
    let parent = parent_or_current(path);
    let temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary output in {}", parent.display()))?;
    let mut hasher = hash.then(Sha256::new);
    {
        let mut writer = BufWriter::with_capacity(WRITE_CHUNK_SIZE, temporary.as_file());
        for chunk in data.chunks(WRITE_CHUNK_SIZE) {
            cancellation.checkpoint()?;
            writer
                .write_all(chunk)
                .with_context(|| format!("writing temporary output for {}", path.display()))?;
            if let Some(hasher) = &mut hasher {
                hasher.update(chunk);
            }
        }
        writer
            .flush()
            .with_context(|| format!("flushing temporary output for {}", path.display()))?;
    }
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("syncing temporary output for {}", path.display()))?;
    cancellation.checkpoint()?;
    temporary.persist(path).map_err(|error| {
        anyhow::Error::new(error.error).context(format!("committing output {}", path.display()))
    })?;

    // The atomic rename is the commit point. A later directory-sync failure
    // cannot be rolled back safely, so report it as a durability warning rather
    // than falsely claiming that the previous output was preserved.
    if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
        tracing::warn!(
            path = %parent.display(),
            error = %error,
            "output committed, but the containing directory could not be synced"
        );
    }
    Ok(hasher.map(|hasher| hex::encode(hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_output_filename_uses_current_directory() {
        assert_eq!(parent_or_current(Path::new("output.exe")), Path::new("."));
    }

    #[test]
    fn default_output_preserves_extension() {
        assert_eq!(
            default_output_path(Path::new("sample.exe")).unwrap(),
            Path::new("sample_unpacked.exe")
        );
    }

    #[test]
    fn input_cannot_alias_output() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("sample.exe");
        fs::write(&input, b"packed").unwrap();

        ensure_distinct_paths(&input, &input).expect_err("input alias must be rejected");
    }

    #[test]
    fn commit_atomically_replaces_and_hashes_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.exe");
        fs::write(&output, b"old").unwrap();
        let data = b"complete reconstructed image";

        let digest = commit(&output, data, &CancellationToken::default(), true)
            .expect("atomic commit succeeds")
            .expect("hashing requested");

        assert_eq!(fs::read(output).unwrap(), data);
        assert_eq!(digest, hex::encode(Sha256::digest(data)));
    }

    #[test]
    fn cancellation_preserves_existing_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.exe");
        fs::write(&output, b"old").unwrap();
        let cancellation = CancellationToken::default();
        cancellation.cancel();

        commit(&output, b"new", &cancellation, false)
            .expect_err("cancelled output must not commit");

        assert_eq!(fs::read(output).unwrap(), b"old");
    }
}
