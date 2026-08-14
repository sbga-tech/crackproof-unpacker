use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::outcome::ArtifactSummary;

pub(crate) const MAX_INPUT_SIZE: u64 = 512 << 20;
const READ_CHUNK_SIZE: usize = 1 << 20;

pub(crate) fn read_bounded(path: &Path, cancellation: &CancellationToken) -> Result<Vec<u8>> {
    cancellation.checkpoint()?;
    let mut file = File::open(path).with_context(|| format!("opening input {}", path.display()))?;
    let length = file
        .metadata()
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .len();
    ensure!(
        length <= MAX_INPUT_SIZE,
        "input {} is {length} bytes; limit is {MAX_INPUT_SIZE}",
        path.display()
    );
    let length = usize::try_from(length).context("input length does not fit host address space")?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .with_context(|| format!("reserving {length} input bytes"))?;
    let mut chunk = vec![0u8; READ_CHUNK_SIZE];
    loop {
        cancellation.checkpoint()?;
        let read = file
            .read(&mut chunk)
            .with_context(|| format!("reading input {}", path.display()))?;
        if read == 0 {
            break;
        }
        ensure!(
            bytes.len().saturating_add(read) <= length,
            "input {} grew while it was being read",
            path.display()
        );
        bytes.extend_from_slice(&chunk[..read]);
    }
    ensure!(
        bytes.len() == length,
        "input {} changed length while it was being read",
        path.display()
    );
    Ok(bytes)
}

pub(crate) fn sidecar_path(input: &Path) -> PathBuf {
    let mut name: OsString = input.as_os_str().to_owned();
    name.push("._");
    PathBuf::from(name)
}

pub(crate) fn summarize(path: &Path, bytes: &[u8], hash: bool) -> ArtifactSummary {
    ArtifactSummary {
        path: path.display().to_string(),
        size: bytes.len(),
        sha256: hash.then(|| hex::encode(Sha256::digest(bytes))),
    }
}
