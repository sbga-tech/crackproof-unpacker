use std::{mem::size_of, ops::Range};

use anyhow::{Context, Result, ensure};

use crate::pe::Pe;
use crate::pipeline::cancellation::CancellationToken;
use crate::pipeline::stages::payload::bootstrap::{
    PackedBootstrap, bootstrap_source_file_range, derive_outer_source,
};

use super::records::ensure_source_excludes_security;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PayloadStreamProvenance {
    pub(super) locator_file_offset: usize,
    pub(super) base_file_offset: usize,
    pub(super) gap_after_outer_source: usize,
}

/// Immutable packed bytes and outer-layer evidence shared by every payload provider.
pub(crate) struct BoundPayloadSource<'a> {
    pub(super) packed: &'a [u8],
    pub(super) pe: &'a Pe,
    pub(super) payload_source: &'a [u8],
    pub(super) bootstrap: PackedBootstrap,
    pub(super) source_security_range: Option<&'a Range<usize>>,

    pub(super) source_file_range: Range<usize>,

    pub(super) source_start: usize,
    pub(super) stream: PayloadStreamProvenance,
    pub(super) outer: Vec<u8>,
}

pub(super) fn derive_payload_stream_provenance(
    payload_source: &[u8],
    bootstrap: PackedBootstrap,
    source_file_range: &Range<usize>,
    source_security_range: Option<&Range<usize>>,
) -> Result<PayloadStreamProvenance> {
    let locator_file_offset = bootstrap
        .descriptor_file_offset
        .checked_add(0x80)
        .context("payload block stream-base field offset overflows")?;
    let locator_end = locator_file_offset
        .checked_add(size_of::<u32>())
        .context("payload block stream-base field end overflows")?;
    let locator_file_range = locator_file_offset..locator_end;
    ensure!(
        locator_end <= source_file_range.start,
        "payload block stream-base field overlaps the outer source"
    );
    ensure_source_excludes_security(&locator_file_range, source_security_range)?;
    let encoded_base = u32::from_le_bytes(
        payload_source
            .get(locator_file_range)
            .context("payload source does not contain the payload block stream-base field")?
            .try_into()
            .expect("stream-base field has four bytes"),
    );
    let descriptor_offset = u32::try_from(bootstrap.descriptor_file_offset)
        .context("KONN descriptor file offset exceeds u32")?;
    let base_file_offset = usize::try_from((!encoded_base).wrapping_add(descriptor_offset))
        .context("payload block stream base does not fit host address space")?;
    let gap_after_outer_source = base_file_offset
        .checked_sub(source_file_range.end)
        .context("payload block stream base precedes the outer source end")?;
    ensure!(
        base_file_offset <= payload_source.len(),
        "payload block stream base exceeds the payload source"
    );
    Ok(PayloadStreamProvenance {
        locator_file_offset,
        base_file_offset,
        gap_after_outer_source,
    })
}

pub(crate) fn bind_payload_source<'a>(
    packed: &'a [u8],
    pe: &'a Pe,
    payload_source: &'a [u8],
    bootstrap: PackedBootstrap,
    source_security_range: Option<&'a Range<usize>>,
    cancellation: Option<&CancellationToken>,
) -> Result<BoundPayloadSource<'a>> {
    if let Some(cancellation) = cancellation {
        cancellation.checkpoint()?;
    }
    let source_file_range = bootstrap_source_file_range(payload_source, bootstrap)?;
    let (source_start, outer) = derive_outer_source(payload_source, bootstrap)?;
    ensure_source_excludes_security(&source_file_range, source_security_range)?;
    let stream = derive_payload_stream_provenance(
        payload_source,
        bootstrap,
        &source_file_range,
        source_security_range,
    )?;
    Ok(BoundPayloadSource {
        packed,
        pe,
        payload_source,
        bootstrap,
        source_security_range,

        source_file_range,

        source_start,
        stream,
        outer,
    })
}
