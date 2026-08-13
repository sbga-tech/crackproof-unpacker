use anyhow::Result;

use anyhow::{Context, bail, ensure};

use super::records::{f2a0_byte, f2a0_transform_from_dl};

pub(super) const CUSTOM_DECODER_NODE_SIZE: usize = 3;

use crate::pipeline::cancellation::CancellationToken;
pub(super) const CUSTOM_DECODER_ROOT_NODES: usize = 256;
pub(super) const CUSTOM_DECODER_MAX_CODE_BITS: usize = 24;

const MAX_DECODER_PRECURSOR_CANDIDATES: usize = 1 << 28;

const MAX_DECODER_TABLE_NODES: usize = 65_536;

const MAX_STRUCTURAL_DECODER_CANDIDATES: usize = 64;

const DECODER_CHEAP_ROOT_PREFILTER: usize = 16;

const MAX_DECODER_FULL_VALIDATION_ATTEMPTS: usize = 65_536;

const MAX_DECODER_VALIDATION_NODE_WORK: usize = 8 << 20;

#[derive(Clone, Debug)]
pub(crate) struct DecoderCandidate {
    #[allow(dead_code)]
    pub(crate) source_file_offset: usize,
    #[allow(dead_code)]
    pub(crate) phase: u8,
    pub(crate) table: Vec<u8>,
}

pub(super) struct DecoderValidationBudget {
    full_attempt_limit: usize,
    node_work_limit: usize,
    pub(super) full_attempts: usize,
    pub(super) node_work: usize,
}

impl Default for DecoderValidationBudget {
    fn default() -> Self {
        Self {
            full_attempt_limit: MAX_DECODER_FULL_VALIDATION_ATTEMPTS,
            node_work_limit: MAX_DECODER_VALIDATION_NODE_WORK,
            full_attempts: 0,
            node_work: 0,
        }
    }
}

impl DecoderValidationBudget {
    #[cfg(test)]
    pub(super) fn with_limits(full_attempt_limit: usize, node_work_limit: usize) -> Self {
        Self {
            full_attempt_limit,
            node_work_limit,
            full_attempts: 0,
            node_work: 0,
        }
    }

    fn charge_full_attempt(&mut self) -> Result<()> {
        ensure!(
            self.full_attempts < self.full_attempt_limit,
            "decoder full validation exceeds its {}-attempt work cap",
            self.full_attempt_limit
        );
        self.full_attempts = self
            .full_attempts
            .checked_add(1)
            .context("decoder full-validation attempt counter overflows")?;
        Ok(())
    }

    fn charge_node_work(&mut self) -> Result<()> {
        ensure!(
            self.node_work < self.node_work_limit,
            "decoder full validation exceeds its {}-node work cap",
            self.node_work_limit
        );
        self.node_work = self
            .node_work
            .checked_add(1)
            .context("decoder full-validation node-work counter overflows")?;
        Ok(())
    }
}

pub(super) struct DecoderValidationScratch {
    pub(super) seen_generations: Vec<u16>,
    pub(super) generation: u16,
    pending: [(usize, usize); CUSTOM_DECODER_MAX_CODE_BITS + 1],
    pending_length: usize,
}

impl DecoderValidationScratch {
    pub(super) fn new(maximum_nodes: usize) -> Result<Self> {
        let seen_states = maximum_nodes
            .checked_mul(CUSTOM_DECODER_MAX_CODE_BITS + 1)
            .context("decoder validation seen-state count overflows")?;
        Ok(Self {
            seen_generations: vec![0; seen_states],
            generation: 0,
            pending: [(0, 0); CUSTOM_DECODER_MAX_CODE_BITS + 1],
            pending_length: 0,
        })
    }

    fn begin_full_validation(&mut self) {
        let next_generation = self.generation.wrapping_add(1);
        if next_generation == 0 {
            self.seen_generations.fill(0);
            self.generation = 1;
        } else {
            self.generation = next_generation;
        }
        self.pending_length = 0;
    }

    fn mark_seen(&mut self, index: usize, bits: usize) -> Option<bool> {
        let seen_index = index
            .checked_mul(CUSTOM_DECODER_MAX_CODE_BITS + 1)?
            .checked_add(bits)?;
        let generation = self.seen_generations.get_mut(seen_index)?;
        let was_seen = *generation == self.generation;
        *generation = self.generation;
        Some(was_seen)
    }

    fn push_pending(&mut self, state: (usize, usize)) -> bool {
        let Some(slot) = self.pending.get_mut(self.pending_length) else {
            return false;
        };
        *slot = state;
        self.pending_length += 1;
        true
    }

    fn pop_pending(&mut self) -> Option<(usize, usize)> {
        self.pending_length = self.pending_length.checked_sub(1)?;
        Some(self.pending[self.pending_length])
    }
}

/// Successful consumption counters for [`decode_custom_stream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CustomDecodeStats {
    pub source_bits_consumed: usize,
    pub source_bytes_consumed: usize,
    pub destination_bytes_written: usize,
}

/// A checked failure from [`decode_custom_stream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CustomDecodeError {
    TableTooShort {
        nodes: usize,
    },
    NodeOutOfBounds {
        index: usize,
        nodes: usize,
    },
    InvalidOrCyclicCode {
        bits: usize,
    },
    EmptySource,
    EmptyDestination,
    SourceExhausted {
        bit_offset: usize,
    },
    PendingPrefix {
        pending: usize,
    },
    InvalidRepeatWidth {
        width: usize,
    },
    HistoryUnderflow {
        required: usize,
        written: usize,
    },
    ArithmeticOverflow,
    DestinationOverflow {
        requested: usize,
        remaining: usize,
    },
    SourceLengthMismatch {
        consumed_bytes: usize,
        source_bytes: usize,
    },
}

impl std::fmt::Display for CustomDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::TableTooShort { nodes } => write!(
                formatter,
                "decoder table has {nodes} complete nodes; at least {CUSTOM_DECODER_ROOT_NODES} are required"
            ),
            Self::NodeOutOfBounds { index, nodes } => {
                write!(
                    formatter,
                    "decoder node {index} exceeds {nodes} complete nodes"
                )
            }
            Self::InvalidOrCyclicCode { bits } => write!(
                formatter,
                "decoder code is zero-length, cyclic, or exceeds {CUSTOM_DECODER_MAX_CODE_BITS} bits (reached {bits})"
            ),
            Self::EmptySource => formatter.write_str("decoder source is empty"),
            Self::EmptyDestination => formatter.write_str("decoder destination is empty"),
            Self::SourceExhausted { bit_offset } => {
                write!(formatter, "decoder source is exhausted at bit {bit_offset}")
            }
            Self::PendingPrefix { pending } => write!(
                formatter,
                "decoder completed with unconsumed pending prefix {pending:#x}"
            ),
            Self::InvalidRepeatWidth { width } => write!(
                formatter,
                "decoder repeat/copy width {width} is not implemented by this format"
            ),
            Self::HistoryUnderflow { required, written } => write!(
                formatter,
                "decoder token requires {required} history bytes after only {written} bytes"
            ),
            Self::ArithmeticOverflow => formatter.write_str("decoder size arithmetic overflow"),
            Self::DestinationOverflow {
                requested,
                remaining,
            } => write!(
                formatter,
                "decoder token requests {requested} destination bytes with {remaining} remaining"
            ),
            Self::SourceLengthMismatch {
                consumed_bytes,
                source_bytes,
            } => write!(
                formatter,
                "decoder consumed {consumed_bytes} source bytes but was given {source_bytes}"
            ),
        }
    }
}

impl std::error::Error for CustomDecodeError {}

#[derive(Clone, Copy)]
pub(super) struct CustomDecoderNode {
    pub(super) tag: u16,
    pub(super) auxiliary: u8,
}

pub(super) trait CustomDecoderSource {
    fn len(&self) -> usize;
    fn byte(&mut self, index: usize) -> u8;
}

struct SliceDecoderSource<'a>(&'a [u8]);

impl CustomDecoderSource for SliceDecoderSource<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn byte(&mut self, index: usize) -> u8 {
        self.0[index]
    }
}

#[inline]
fn custom_decoder_node_bounded(
    table: &[u8],
    index: usize,
    nodes: usize,
) -> Result<CustomDecoderNode, CustomDecodeError> {
    if index >= nodes {
        return Err(CustomDecodeError::NodeOutOfBounds { index, nodes });
    }
    // `index < table.len() / node_size` proves this multiplication and slice are bounded.
    let offset = index * CUSTOM_DECODER_NODE_SIZE;
    let bytes = &table[offset..offset + CUSTOM_DECODER_NODE_SIZE];
    Ok(CustomDecoderNode {
        tag: u16::from_le_bytes([bytes[0], bytes[1]]),
        auxiliary: bytes[2],
    })
}

pub(super) fn custom_decoder_symbol(
    table: &[u8],
    source: &[u8],
    bit_offset: usize,
    total_bits: usize,
) -> Result<(u16, usize), CustomDecodeError> {
    let mut source = SliceDecoderSource(source);
    custom_decoder_symbol_with_nodes(
        table,
        table.len() / CUSTOM_DECODER_NODE_SIZE,
        &mut source,
        bit_offset,
        total_bits,
    )
}

#[inline]
fn custom_decoder_symbol_with_nodes(
    table: &[u8],
    nodes: usize,
    source: &mut impl CustomDecoderSource,
    bit_offset: usize,
    total_bits: usize,
) -> Result<(u16, usize), CustomDecodeError> {
    if bit_offset >= total_bits {
        return Err(CustomDecodeError::SourceExhausted { bit_offset });
    }

    let source_byte = bit_offset / 8;
    let shift = bit_offset % 8;
    let window = u16::from(source.byte(source_byte))
        | (u16::from(if source_byte + 1 < source.len() {
            source.byte(source_byte + 1)
        } else {
            0
        }) << 8);
    let root_index = usize::from(((window >> shift) & 0xff) as u8);
    let root = custom_decoder_node_bounded(table, root_index, nodes)?;

    if root.tag & 0x8000 != 0 {
        let bits = usize::from(root.auxiliary);
        if bits == 0 || bits > CUSTOM_DECODER_MAX_CODE_BITS {
            return Err(CustomDecodeError::InvalidOrCyclicCode { bits });
        }
        let end = bit_offset
            .checked_add(bits)
            .ok_or(CustomDecodeError::ArithmeticOverflow)?;
        if end > total_bits {
            return Err(CustomDecodeError::SourceExhausted {
                bit_offset: total_bits,
            });
        }
        return Ok((root.tag & 0x7fff, bits));
    }

    let mut bits = usize::from(root.auxiliary);
    let mut node = root;
    loop {
        if bits >= CUSTOM_DECODER_MAX_CODE_BITS {
            return Err(CustomDecodeError::InvalidOrCyclicCode {
                bits: bits.saturating_add(1),
            });
        }
        let branch_offset = bit_offset
            .checked_add(bits)
            .ok_or(CustomDecodeError::ArithmeticOverflow)?;
        if branch_offset >= total_bits {
            return Err(CustomDecodeError::SourceExhausted {
                bit_offset: branch_offset,
            });
        }
        let branch = usize::from((source.byte(branch_offset / 8) >> (branch_offset % 8)) & 1);
        bits += 1;
        let child = usize::from(node.tag & 0x7fff) + branch;
        node = custom_decoder_node_bounded(table, child, nodes)?;
        if node.tag & 0x8000 != 0 {
            return Ok((node.tag & 0x7fff, bits));
        }
    }
}

/// Returns `false` only when the first decoder token would make a full decode fail.
/// An incomplete caller prefix is accepted conservatively to preserve compatibility.
pub(crate) fn custom_decoder_prefix_is_viable(
    table: &[u8],
    source_prefix: &[u8],
    source_len: usize,
    history_len: usize,
    destination_len: usize,
    allow_zero_width_controls: bool,
) -> bool {
    if table.len() / CUSTOM_DECODER_NODE_SIZE < CUSTOM_DECODER_ROOT_NODES
        || source_len == 0
        || destination_len == 0
    {
        return false;
    }
    let required_prefix = source_len.min(CUSTOM_DECODER_MAX_CODE_BITS.div_ceil(8));
    if source_prefix.len() < required_prefix {
        return true;
    }
    let Some(total_bits) = source_len.checked_mul(8) else {
        return false;
    };
    let Ok((symbol, _)) = custom_decoder_symbol(table, source_prefix, 0, total_bits) else {
        return false;
    };
    let argument = usize::from(symbol & 0xff);
    match symbol & 0x300 {
        0 => true,
        0x100 => argument != 0 || allow_zero_width_controls,
        0x200 => {
            matches!(argument, 0 | 1 | 2 | 4)
                && (argument != 0 || allow_zero_width_controls)
                && argument <= destination_len
                && argument <= history_len
        }
        0x300 => {
            (argument != 0 || allow_zero_width_controls)
                && argument <= destination_len
                && argument <= history_len
        }
        _ => unreachable!("token class is masked to two bits"),
    }
}

pub(crate) fn decode_custom_stream_with_history_mode(
    table: &[u8],
    source: &[u8],
    history: &[u8],
    destination: &mut [u8],
    allow_zero_width_controls: bool,
) -> Result<CustomDecodeStats, CustomDecodeError> {
    let mut source = SliceDecoderSource(source);
    decode_custom_stream_with_history_source_mode(
        table,
        &mut source,
        history,
        destination,
        allow_zero_width_controls,
    )
}

pub(super) fn decode_custom_stream_with_history_source_mode(
    table: &[u8],
    source: &mut impl CustomDecoderSource,
    history: &[u8],
    destination: &mut [u8],
    allow_zero_width_controls: bool,
) -> Result<CustomDecodeStats, CustomDecodeError> {
    let nodes = table.len() / CUSTOM_DECODER_NODE_SIZE;
    if nodes < CUSTOM_DECODER_ROOT_NODES {
        return Err(CustomDecodeError::TableTooShort { nodes });
    }
    if source.len() == 0 {
        return Err(CustomDecodeError::EmptySource);
    }
    if destination.is_empty() {
        return Err(CustomDecodeError::EmptyDestination);
    }
    let total_bits = source
        .len()
        .checked_mul(8)
        .ok_or(CustomDecodeError::ArithmeticOverflow)?;

    let mut source_bits = 0usize;
    let mut written = 0usize;
    let mut pending = 0usize;
    while written < destination.len() {
        let (symbol, symbol_bits) =
            custom_decoder_symbol_with_nodes(table, nodes, source, source_bits, total_bits)?;
        source_bits = source_bits
            .checked_add(symbol_bits)
            .ok_or(CustomDecodeError::ArithmeticOverflow)?;

        let argument = usize::from(symbol & 0xff);
        match symbol & 0x300 {
            0 => {
                destination[written] = argument as u8;
                written += 1;
            }
            0x100 => {
                if argument == 0 && !allow_zero_width_controls {
                    return Err(CustomDecodeError::InvalidRepeatWidth { width: argument });
                }
                if pending >= 0x100 {
                    return Err(CustomDecodeError::PendingPrefix { pending });
                }
                pending = if pending == 0 {
                    argument
                } else {
                    (pending << 8) | argument
                };
            }
            0x200 => {
                if !matches!(argument, 0 | 1 | 2 | 4)
                    || (argument == 0 && !allow_zero_width_controls)
                {
                    return Err(CustomDecodeError::InvalidRepeatWidth { width: argument });
                }
                let repetitions = if pending == 0 { 1 } else { pending };
                pending = 0;
                let amount = repetitions
                    .checked_mul(argument)
                    .ok_or(CustomDecodeError::ArithmeticOverflow)?;
                let remaining = destination.len() - written;
                if amount > remaining {
                    return Err(CustomDecodeError::DestinationOverflow {
                        requested: amount,
                        remaining,
                    });
                }
                if matches!(argument, 1 | 2 | 4) {
                    let history_needed = argument.saturating_sub(written);
                    if history_needed > history.len() {
                        return Err(CustomDecodeError::HistoryUnderflow {
                            required: argument,
                            written: written
                                .checked_add(history.len())
                                .ok_or(CustomDecodeError::ArithmeticOverflow)?,
                        });
                    }
                    let mut pattern = [0u8; 4];
                    for (index, byte) in pattern[..argument].iter_mut().enumerate() {
                        *byte = if index < history_needed {
                            history[history.len() - history_needed + index]
                        } else {
                            destination[written + index - argument]
                        };
                    }
                    for index in 0..amount {
                        destination[written + index] = pattern[index % argument];
                    }
                }
                written += amount;
            }
            0x300 => {
                let length = argument;
                if length == 0 && !allow_zero_width_controls {
                    return Err(CustomDecodeError::InvalidRepeatWidth { width: length });
                }
                let gap = pending;
                pending = 0;
                let remaining = destination.len() - written;
                if length > remaining {
                    return Err(CustomDecodeError::DestinationOverflow {
                        requested: length,
                        remaining,
                    });
                }
                let distance = gap
                    .checked_add(length)
                    .ok_or(CustomDecodeError::ArithmeticOverflow)?;
                let history_needed = distance.saturating_sub(written);
                if history_needed > history.len() {
                    return Err(CustomDecodeError::HistoryUnderflow {
                        required: distance,
                        written: written
                            .checked_add(history.len())
                            .ok_or(CustomDecodeError::ArithmeticOverflow)?,
                    });
                }
                for index in 0..length {
                    destination[written + index] = if index < history_needed {
                        history[history.len() - history_needed + index]
                    } else {
                        destination[written + index - distance]
                    };
                }
                written += length;
            }
            _ => unreachable!("token class is masked to two bits"),
        }
    }

    if pending != 0 {
        return Err(CustomDecodeError::PendingPrefix { pending });
    }
    let consumed_bytes = source_bits / 8 + usize::from(!source_bits.is_multiple_of(8));
    if consumed_bytes != source.len() {
        return Err(CustomDecodeError::SourceLengthMismatch {
            consumed_bytes,
            source_bytes: source.len(),
        });
    }
    Ok(CustomDecodeStats {
        source_bits_consumed: source_bits,
        source_bytes_consumed: consumed_bytes,
        destination_bytes_written: written,
    })
}

pub(crate) fn decode_custom_stream_with_history(
    table: &[u8],
    source: &[u8],
    history: &[u8],
    destination: &mut [u8],
) -> Result<CustomDecodeStats, CustomDecodeError> {
    decode_custom_stream_with_history_mode(table, source, history, destination, true)
}

/// Decodes the native custom Huffman/LZ/RLE stream into caller-owned storage.
///
/// This standalone form has no bytes before `destination`; image-backed
/// decryption uses the internal history-aware form because native
/// one-, two-, and four-byte repeats may read immediately before the target.
#[cfg(test)]
pub(super) fn decode_custom_stream(
    table: &[u8],
    source: &[u8],
    destination: &mut [u8],
) -> Result<CustomDecodeStats, CustomDecodeError> {
    decode_custom_stream_with_history(table, source, &[], destination)
}

pub(super) fn transformed_precursor_node(
    source: &[u8],
    offset: usize,
    phase: u8,
    index: usize,
) -> Option<CustomDecoderNode> {
    let node_offset = index.checked_mul(CUSTOM_DECODER_NODE_SIZE)?;
    let position = offset.checked_add(node_offset)?;
    let bytes = source.get(position..position.checked_add(CUSTOM_DECODER_NODE_SIZE)?)?;
    let state = phase.wrapping_add(node_offset as u8);
    let first = f2a0_byte(bytes[0], state);
    let second = f2a0_byte(bytes[1], state.wrapping_add(1));
    let third = f2a0_byte(bytes[2], state.wrapping_add(2));
    Some(CustomDecoderNode {
        tag: u16::from_le_bytes([first, second]),
        auxiliary: third,
    })
}

pub(super) fn root_node_is_plausible(node: CustomDecoderNode, available_nodes: usize) -> bool {
    if node.tag & 0x8000 != 0 {
        return node.tag & 0x7fff <= 0x03ff
            && (1..=CUSTOM_DECODER_MAX_CODE_BITS).contains(&usize::from(node.auxiliary));
    }
    let base = usize::from(node.tag & 0x7fff);
    node.auxiliary < CUSTOM_DECODER_MAX_CODE_BITS as u8
        && base
            .checked_add(1)
            .is_some_and(|child| child < available_nodes)
}

pub(super) fn validate_decoder_candidate(
    source: &[u8],
    offset: usize,
    phase: u8,
    scratch: &mut DecoderValidationScratch,
    validation_budget: &mut DecoderValidationBudget,
) -> Result<Option<usize>> {
    let Some(remaining) = source.len().checked_sub(offset) else {
        return Ok(None);
    };
    let available_nodes = (remaining / CUSTOM_DECODER_NODE_SIZE).min(MAX_DECODER_TABLE_NODES);
    if available_nodes < CUSTOM_DECODER_ROOT_NODES {
        return Ok(None);
    }

    // Cheap, progressive rejection keeps a full 256-node decode restricted to
    // the rare starts whose first roots already look like valid codec nodes.
    for root_index in 0..DECODER_CHEAP_ROOT_PREFILTER {
        let Some(root) = transformed_precursor_node(source, offset, phase, root_index) else {
            return Ok(None);
        };
        if !root_node_is_plausible(root, available_nodes) {
            return Ok(None);
        }
    }

    validation_budget.charge_full_attempt()?;
    scratch.begin_full_validation();

    let mut roots = [None; CUSTOM_DECODER_ROOT_NODES];
    let mut maximum_index = CUSTOM_DECODER_ROOT_NODES - 1;
    for (root_index, root_slot) in roots.iter_mut().enumerate() {
        validation_budget.charge_node_work()?;
        let Some(root) = transformed_precursor_node(source, offset, phase, root_index) else {
            return Ok(None);
        };
        if !root_node_is_plausible(root, available_nodes) {
            return Ok(None);
        }
        if root.tag & 0x8000 == 0 {
            let base = usize::from(root.tag & 0x7fff);
            let Some(child) = base.checked_add(1) else {
                return Ok(None);
            };
            maximum_index = maximum_index.max(child);
        }
        *root_slot = Some(root);
    }

    for root in roots.into_iter().flatten() {
        if root.tag & 0x8000 != 0 {
            continue;
        }
        let base = usize::from(root.tag & 0x7fff);
        let Some(child) = base.checked_add(1) else {
            return Ok(None);
        };
        let Some(next_bits) = usize::from(root.auxiliary).checked_add(1) else {
            return Ok(None);
        };
        if !scratch.push_pending((base, next_bits)) || !scratch.push_pending((child, next_bits)) {
            return Ok(None);
        }

        while let Some((index, bits)) = scratch.pop_pending() {
            if index >= available_nodes || bits > CUSTOM_DECODER_MAX_CODE_BITS {
                return Ok(None);
            }
            let Some(was_seen) = scratch.mark_seen(index, bits) else {
                return Ok(None);
            };
            if was_seen {
                continue;
            }

            validation_budget.charge_node_work()?;
            let Some(node) = transformed_precursor_node(source, offset, phase, index) else {
                return Ok(None);
            };
            if node.tag & 0x8000 != 0 {
                if node.tag & 0x7fff > 0x03ff {
                    return Ok(None);
                }
                continue;
            }
            if bits >= CUSTOM_DECODER_MAX_CODE_BITS {
                return Ok(None);
            }
            let base = usize::from(node.tag & 0x7fff);
            let Some(child) = base.checked_add(1) else {
                return Ok(None);
            };
            if child >= available_nodes {
                return Ok(None);
            }
            maximum_index = maximum_index.max(child);
            let Some(next_bits) = bits.checked_add(1) else {
                return Ok(None);
            };
            if !scratch.push_pending((base, next_bits)) || !scratch.push_pending((child, next_bits))
            {
                return Ok(None);
            }
        }
    }
    Ok(maximum_index.checked_add(1))
}

pub(super) fn decode_precursor_table(
    source: &[u8],
    offset: usize,
    phase: u8,
    nodes: usize,
) -> Option<Vec<u8>> {
    let length = nodes.checked_mul(CUSTOM_DECODER_NODE_SIZE)?;
    let raw = source.get(offset..offset.checked_add(length)?)?;
    let mut table = raw.to_vec();
    f2a0_transform_from_dl(&mut table, phase);
    Some(table)
}

pub(super) fn discover_decoder_candidates(
    source_start: usize,
    packed: &[u8],
    source_length: usize,
) -> Result<Vec<DecoderCandidate>> {
    discover_decoder_candidates_impl(source_start, packed, source_length, None)
}

pub(super) fn discover_decoder_candidates_with_cancellation(
    source_start: usize,
    packed: &[u8],
    source_length: usize,
    cancellation: &CancellationToken,
) -> Result<Vec<DecoderCandidate>> {
    discover_decoder_candidates_impl(source_start, packed, source_length, Some(cancellation))
}

fn discover_decoder_candidates_impl(
    source_start: usize,
    packed: &[u8],
    source_length: usize,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<DecoderCandidate>> {
    let source_end = source_start
        .checked_add(source_length)
        .context("bootstrap-source region end overflows")?;
    let source = packed
        .get(source_start..source_end)
        .context("packed input does not contain the bootstrap-source region")?;
    let minimum_length = CUSTOM_DECODER_ROOT_NODES
        .checked_mul(CUSTOM_DECODER_NODE_SIZE)
        .expect("fixed decoder root size");
    let Some(last_offset) = source.len().checked_sub(minimum_length) else {
        bail!("bootstrap-source region cannot contain a decoder root table");
    };
    let attempts = last_offset
        .checked_add(1)
        .and_then(|starts| starts.checked_mul(usize::from(u8::MAX) + 1))
        .context("decoder precursor candidate count overflows")?;
    ensure!(
        attempts <= MAX_DECODER_PRECURSOR_CANDIDATES,
        "decoder precursor discovery exceeds its bounded candidate work"
    );

    let maximum_nodes = (source.len() / CUSTOM_DECODER_NODE_SIZE).min(MAX_DECODER_TABLE_NODES);
    let mut scratch = DecoderValidationScratch::new(maximum_nodes)?;
    let mut validation_budget = DecoderValidationBudget::default();
    let mut candidates = Vec::new();
    for offset in 0..=last_offset {
        if offset & 0x0fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        for phase in u8::MIN..=u8::MAX {
            let Some(nodes) = validate_decoder_candidate(
                source,
                offset,
                phase,
                &mut scratch,
                &mut validation_budget,
            )?
            else {
                continue;
            };
            ensure!(
                candidates.len() < MAX_STRUCTURAL_DECODER_CANDIDATES,
                "decoder precursor discovery produced too many structural candidates"
            );
            let table = decode_precursor_table(source, offset, phase, nodes)
                .expect("validated decoder precursor remains in bounds");
            candidates.push(DecoderCandidate {
                table,
                source_file_offset: source_start + offset,
                phase,
            });
        }
    }
    ensure!(
        !candidates.is_empty(),
        "no structurally valid decoder precursor exists"
    );
    Ok(candidates)
}
