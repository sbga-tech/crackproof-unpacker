use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

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

pub(crate) fn write_output(path: &Path, data: &[u8], hash: bool) -> Result<Option<String>> {
    fs::write(path, data).with_context(|| format!("writing output {}", path.display()))?;
    Ok(hash.then(|| digest(data)))
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
    fn write_output_replaces_and_hashes_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.exe");
        fs::write(&output, b"old").unwrap();
        let data = b"complete reconstructed image";

        let digest = write_output(&output, data, true)
            .expect("output write succeeds")
            .expect("hashing requested");

        assert_eq!(fs::read(output).unwrap(), data);
        assert_eq!(digest, hex::encode(Sha256::digest(data)));
    }
}
