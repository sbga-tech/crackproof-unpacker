use std::ops::Range;

use anyhow::{Context, Result};

use crate::pe::Pe;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::stages::payload::bootstrap::PackedBootstrap;

use super::DecryptedImage;
use super::router::recover_payload;
use super::source::bind_payload_source;

pub(crate) fn decrypt_packed_image_with_cancellation(
    packed: &[u8],
    pe: &Pe,
    bootstrap: PackedBootstrap,
    cancellation: &CancellationToken,
) -> Result<DecryptedImage> {
    let security_range = pe
        .security_directory_file_range(packed.len())
        .context("validating packed Security Directory against payload sources")?;
    decrypt_packed_image_from_source_with_cancellation(
        packed,
        pe,
        packed,
        bootstrap,
        security_range.as_ref(),
        cancellation,
    )
}

pub(crate) fn decrypt_packed_image_from_source_with_cancellation(
    packed: &[u8],
    pe: &Pe,
    payload_source: &[u8],
    bootstrap: PackedBootstrap,
    source_security_range: Option<&Range<usize>>,
    cancellation: &CancellationToken,
) -> Result<DecryptedImage> {
    let source = bind_payload_source(
        packed,
        pe,
        payload_source,
        bootstrap,
        source_security_range,
        Some(cancellation),
    )?;
    recover_payload(&source, Some(cancellation))
}
