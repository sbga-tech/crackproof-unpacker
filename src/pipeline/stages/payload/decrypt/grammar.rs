use std::{mem::size_of, ops::Range};

use anyhow::{Context, Result, bail, ensure};
use tracing::{debug, info};

use crate::pe::{Machine, Pe};
use crate::pipeline::cancellation::{CancellationToken, Cancelled};
use crate::pipeline::outcome::{PayloadGrammar, SelectedPayloadStream};
use crate::pipeline::stages::payload::bootstrap::{
    PackedBootstrap, bootstrap_source_file_range, derive_outer_source,
};

use super::DecryptedImage;
use super::records::ensure_source_excludes_security;
use super::replay::recover_a_record_payload;
use super::staged::{recognizes_staged_table_payload, recover_staged_table_payload};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PayloadStreamProvenance {
    pub(super) locator_file_offset: usize,
    pub(super) base_file_offset: usize,
    pub(super) gap_after_outer_source: usize,
}

/// Source bytes and common outer-layer evidence shared by every payload grammar.
pub(super) struct BoundPayloadSource<'a> {
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

trait PayloadGrammarFrontend {
    fn grammar(&self) -> PayloadGrammar;

    fn recover(
        &self,
        source: &BoundPayloadSource<'_>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<DecryptedImage>;
}

struct ARecordGrammar;

impl PayloadGrammarFrontend for ARecordGrammar {
    fn grammar(&self) -> PayloadGrammar {
        PayloadGrammar::ARecord
    }

    fn recover(
        &self,
        source: &BoundPayloadSource<'_>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<DecryptedImage> {
        recover_a_record_payload(source, cancellation)
    }
}
struct StagedTableGrammar;

impl PayloadGrammarFrontend for StagedTableGrammar {
    fn grammar(&self) -> PayloadGrammar {
        PayloadGrammar::StagedTable
    }

    fn recover(
        &self,
        source: &BoundPayloadSource<'_>,
        cancellation: Option<&CancellationToken>,
    ) -> Result<DecryptedImage> {
        recover_staged_table_payload(source, cancellation)
    }
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
        .context("A-record stream-base field offset overflows")?;
    let locator_end = locator_file_offset
        .checked_add(size_of::<u32>())
        .context("A-record stream-base field end overflows")?;
    let locator_file_range = locator_file_offset..locator_end;
    ensure!(
        locator_end <= source_file_range.start,
        "A-record stream-base field overlaps the outer source"
    );
    ensure_source_excludes_security(&locator_file_range, source_security_range)?;
    let encoded_base = u32::from_le_bytes(
        payload_source
            .get(locator_file_range)
            .context("payload source does not contain the A-record stream-base field")?
            .try_into()
            .expect("stream-base field has four bytes"),
    );
    let descriptor_offset = u32::try_from(bootstrap.descriptor_file_offset)
        .context("KONN descriptor file offset exceeds u32")?;
    let base_file_offset = usize::try_from((!encoded_base).wrapping_add(descriptor_offset))
        .context("A-record stream base does not fit host address space")?;
    let gap_after_outer_source = base_file_offset
        .checked_sub(source_file_range.end)
        .context("A-record stream base precedes the outer source end")?;
    ensure!(
        base_file_offset <= payload_source.len(),
        "A-record stream base exceeds the payload source"
    );
    Ok(PayloadStreamProvenance {
        locator_file_offset,
        base_file_offset,
        gap_after_outer_source,
    })
}

fn bind_payload_source<'a>(
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

pub(super) fn select_payload_grammar(
    source: &BoundPayloadSource<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<DecryptedImage> {
    let a_record = ARecordGrammar;
    let staged_table = StagedTableGrammar;
    let staged_table_prefix_valid =
        source.pe.machine_kind() == Machine::I386 && recognizes_staged_table_payload(source);
    // A valid staged prefix is a priority hint, not authentication. Complete staged replay
    // runs first because it is the more specific grammar; an incidental prefix collision
    // falls back to complete A-record authentication. If the prefix is invalid, staged
    // recovery would fail at that same prerequisite and is not a viable candidate.
    let frontends: Vec<&dyn PayloadGrammarFrontend> = if staged_table_prefix_valid {
        vec![&staged_table, &a_record]
    } else {
        vec![&a_record]
    };
    let mut failures = Vec::with_capacity(frontends.len());

    for (priority, frontend) in frontends.into_iter().enumerate() {
        if let Some(cancellation) = cancellation {
            cancellation.checkpoint()?;
        }
        let grammar = frontend.grammar();
        debug!(
            ?grammar,
            priority, staged_table_prefix_valid, "trying payload grammar"
        );
        match frontend.recover(source, cancellation) {
            Ok(mut recovered) => {
                recovered.decryption_details.payload_grammar = Some(grammar);
                recovered.decryption_details.selected_stream = Some(SelectedPayloadStream {
                    locator_file_offset: source.stream.locator_file_offset,
                    base_file_offset: source.stream.base_file_offset,
                    gap_after_outer_source: source.stream.gap_after_outer_source,
                });
                info!(
                    ?grammar,
                    fallback = priority != 0,
                    "selected authenticated payload grammar"
                );
                return Ok(recovered);
            }
            Err(error) if error.downcast_ref::<Cancelled>().is_some() => return Err(error),
            Err(error) => failures.push((grammar, error)),
        }
    }

    if failures.len() == 1 {
        let (grammar, error) = failures.pop().expect("one recorded grammar failure");
        return Err(error).with_context(|| format!("replaying {grammar:?} payload grammar"));
    }
    let diagnostics = failures
        .into_iter()
        .map(|(grammar, error)| format!("{grammar:?}: {error:#}"))
        .collect::<Vec<_>>()
        .join("; ");
    bail!("no payload grammar authenticated the packed source: {diagnostics}")
}

#[cfg(test)]
pub(crate) fn decrypt_packed_image(
    packed: &[u8],
    pe: &Pe,
    bootstrap: PackedBootstrap,
) -> Result<DecryptedImage> {
    let security_range = pe
        .security_directory_file_range(packed.len())
        .context("validating packed Security Directory against payload sources")?;
    decrypt_packed_image_from_source(packed, pe, packed, bootstrap, security_range.as_ref())
}

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

#[cfg(test)]
pub(crate) fn decrypt_packed_image_from_source(
    packed: &[u8],
    pe: &Pe,
    payload_source: &[u8],
    bootstrap: PackedBootstrap,
    source_security_range: Option<&Range<usize>>,
) -> Result<DecryptedImage> {
    let source = bind_payload_source(
        packed,
        pe,
        payload_source,
        bootstrap,
        source_security_range,
        None,
    )?;
    select_payload_grammar(&source, None)
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
    select_payload_grammar(&source, Some(cancellation))
}
