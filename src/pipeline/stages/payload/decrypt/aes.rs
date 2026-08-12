use std::collections::HashMap;
use std::ops::Range;

use crate::pipeline::cancellation::CancellationToken;
use ::aes::Aes256;
use ::aes::cipher::{Block, BlockDecrypt, KeyInit};
use anyhow::{Context, Result, ensure};

pub(super) const AES_256_KEY_SIZE: usize = 32;
pub(super) const AES_256_EXPANDED_WORDS: usize = 60;
pub(super) const AES_256_ROUNDS: usize = 14;
pub(super) const AES_CONTEXT_HEADER: [u8; 4] = [0x00, 0x01, 0x0e, 0x00];
pub(super) const AES_DECRYPT_SCHEDULE_SIZE: usize = 240;
pub(super) const AES_CONTEXT_SIZE: usize = AES_CONTEXT_HEADER.len() + AES_DECRYPT_SCHEDULE_SIZE;
pub(super) const MAX_AES_CONTEXT_SCAN_BYTES: usize = 32 << 20;
const MAX_AES_CONTEXT_MATCHES: usize = 64;
const MAX_AES_CONTEXT_VALIDATION_CANDIDATES: usize = 65_536;

/// A transformed, self-validating AES-256 context found in packed input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AesContextMatch {
    pub(crate) file_offset: usize,
    pub(crate) seed: u8,
    pub(crate) raw_key: [u8; AES_256_KEY_SIZE],
}

pub(super) struct AesContextValidationBudget {
    limit: usize,
    pub(super) candidates: usize,
}

impl Default for AesContextValidationBudget {
    fn default() -> Self {
        Self {
            limit: MAX_AES_CONTEXT_VALIDATION_CANDIDATES,
            candidates: 0,
        }
    }
}

impl AesContextValidationBudget {
    #[cfg(test)]
    pub(super) fn with_limit(limit: usize) -> Self {
        Self {
            limit,
            candidates: 0,
        }
    }

    fn charge(&mut self) -> Result<()> {
        ensure!(
            self.candidates < self.limit,
            "AES-context discovery exceeds its {}-candidate validation work cap",
            self.limit
        );
        self.candidates = self
            .candidates
            .checked_add(1)
            .context("AES-context validation candidate counter overflows")?;
        Ok(())
    }
}

pub(super) fn gf_mul(mut left: u8, mut right: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if right & 1 != 0 {
            result ^= left;
        }
        left = if left & 0x80 != 0 {
            (left << 1) ^ 0x1b
        } else {
            left << 1
        };
        right >>= 1;
    }
    result
}

pub(super) fn gf_pow(mut value: u8, mut exponent: u16) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = gf_mul(result, value);
        }
        value = gf_mul(value, value);
        exponent >>= 1;
    }
    result
}

pub(super) fn aes_sbox(value: u8) -> u8 {
    let inverse = if value == 0 { 0 } else { gf_pow(value, 254) };
    inverse
        ^ inverse.rotate_left(1)
        ^ inverse.rotate_left(2)
        ^ inverse.rotate_left(3)
        ^ inverse.rotate_left(4)
        ^ 0x63
}

pub(super) fn mix_column(column: [u8; 4]) -> [u8; 4] {
    let [a, b, c, d] = column;
    [
        gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d,
        a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d,
        a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3),
        gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2),
    ]
}

pub(super) fn inverse_mix_column(column: [u8; 4]) -> [u8; 4] {
    let [a, b, c, d] = column;
    [
        gf_mul(a, 14) ^ gf_mul(b, 11) ^ gf_mul(c, 13) ^ gf_mul(d, 9),
        gf_mul(a, 9) ^ gf_mul(b, 14) ^ gf_mul(c, 11) ^ gf_mul(d, 13),
        gf_mul(a, 13) ^ gf_mul(b, 9) ^ gf_mul(c, 14) ^ gf_mul(d, 11),
        gf_mul(a, 11) ^ gf_mul(b, 13) ^ gf_mul(c, 9) ^ gf_mul(d, 14),
    ]
}

pub(super) fn expand_aes256_key(key: &[u8; AES_256_KEY_SIZE]) -> [u32; AES_256_EXPANDED_WORDS] {
    let mut words = [0u32; AES_256_EXPANDED_WORDS];
    for index in 0..8 {
        words[index] = u32::from_be_bytes(
            key[index * 4..index * 4 + 4]
                .try_into()
                .expect("four-byte key word"),
        );
    }
    let mut round_constant = 1u8;
    for index in 8..AES_256_EXPANDED_WORDS {
        let mut temporary = words[index - 1];
        if index % 8 == 0 {
            let bytes = temporary.to_be_bytes();
            temporary = u32::from_be_bytes([
                aes_sbox(bytes[1]),
                aes_sbox(bytes[2]),
                aes_sbox(bytes[3]),
                aes_sbox(bytes[0]),
            ]) ^ ((round_constant as u32) << 24);
            round_constant = gf_mul(round_constant, 2);
        } else if index % 8 == 4 {
            temporary = u32::from_be_bytes(temporary.to_be_bytes().map(aes_sbox));
        }
        words[index] = words[index - 8] ^ temporary;
    }
    words
}

pub(super) fn make_openssl_decrypt_schedule(
    key: &[u8; AES_256_KEY_SIZE],
) -> [u8; AES_DECRYPT_SCHEDULE_SIZE] {
    let encryption_words = expand_aes256_key(key);
    let mut output = [0u8; AES_DECRYPT_SCHEDULE_SIZE];
    let mut cursor = 0;
    for decrypt_round in 0..=AES_256_ROUNDS {
        let encrypt_round = AES_256_ROUNDS - decrypt_round;
        for column_index in 0..4 {
            let mut column = encryption_words[encrypt_round * 4 + column_index].to_be_bytes();
            if decrypt_round > 0 && decrypt_round < AES_256_ROUNDS {
                column = inverse_mix_column(column);
            }
            column.reverse();
            output[cursor..cursor + 4].copy_from_slice(&column);
            cursor += 4;
        }
    }
    output
}

pub(super) fn recover_raw_key(
    schedule: &[u8; AES_DECRYPT_SCHEDULE_SIZE],
) -> [u8; AES_256_KEY_SIZE] {
    let mut key = [0u8; AES_256_KEY_SIZE];
    for index in 0..4 {
        let source = &schedule[224 + index * 4..228 + index * 4];
        key[index * 4..index * 4 + 4]
            .copy_from_slice(&[source[3], source[2], source[1], source[0]]);
        let source: [u8; 4] = schedule[208 + index * 4..212 + index * 4]
            .try_into()
            .expect("four-byte schedule word");
        key[16 + index * 4..20 + index * 4]
            .copy_from_slice(&mix_column([source[3], source[2], source[1], source[0]]));
    }
    key
}

pub(super) fn transform_context_byte(value: u8, seed: u8, index: usize) -> u8 {
    let first = value.rotate_left(3) ^ seed.wrapping_add(index as u8).wrapping_add(1);
    let second = first.rotate_left(3) ^ seed.wrapping_add(index as u8);
    second.rotate_left(3)
}

pub(super) fn ensure_aes_context_scan_bound(length: usize) -> Result<()> {
    ensure!(
        length <= MAX_AES_CONTEXT_SCAN_BYTES,
        "AES-context discovery scans {length} bytes, exceeding its {MAX_AES_CONTEXT_SCAN_BYTES}-byte work cap"
    );
    Ok(())
}

pub(crate) fn scan_aes_contexts_in_range(
    data: &[u8],
    file_range: Range<usize>,
) -> Result<Vec<AesContextMatch>> {
    let mut validation_budget = AesContextValidationBudget::default();
    scan_aes_contexts_in_range_impl(data, file_range, &mut validation_budget, None)
}

pub(crate) fn scan_aes_contexts_in_range_with_cancellation(
    data: &[u8],
    file_range: Range<usize>,
    cancellation: &CancellationToken,
) -> Result<Vec<AesContextMatch>> {
    let mut validation_budget = AesContextValidationBudget::default();
    scan_aes_contexts_in_range_impl(data, file_range, &mut validation_budget, Some(cancellation))
}

#[cfg(test)]
pub(super) fn scan_aes_contexts_in_range_with_budget(
    data: &[u8],
    file_range: Range<usize>,
    validation_budget: &mut AesContextValidationBudget,
) -> Result<Vec<AesContextMatch>> {
    scan_aes_contexts_in_range_impl(data, file_range, validation_budget, None)
}

fn scan_aes_contexts_in_range_impl(
    data: &[u8],
    file_range: Range<usize>,
    validation_budget: &mut AesContextValidationBudget,
    cancellation: Option<&CancellationToken>,
) -> Result<Vec<AesContextMatch>> {
    ensure!(
        file_range.start <= file_range.end && file_range.end <= data.len(),
        "AES-context scan range is outside packed input"
    );
    let source = data
        .get(file_range.clone())
        .expect("validated AES-context scan range");
    ensure_aes_context_scan_bound(source.len())?;

    let mut prefixes: HashMap<u32, Vec<u8>> = HashMap::new();
    for seed in u8::MIN..=u8::MAX {
        let mut prefix = [0u8; AES_CONTEXT_HEADER.len()];
        for (index, expected) in AES_CONTEXT_HEADER.into_iter().enumerate() {
            prefix[index] = (u8::MIN..=u8::MAX)
                .find(|&value| transform_context_byte(value, seed, index) == expected)
                .expect("context byte transform is bijective");
        }
        prefixes
            .entry(u32::from_le_bytes(prefix))
            .or_default()
            .push(seed);
    }

    let Some(last_offset) = source.len().checked_sub(AES_CONTEXT_SIZE) else {
        return Ok(Vec::new());
    };

    let mut matches = Vec::new();
    for local_offset in 0..=last_offset {
        if local_offset & 0x3fff == 0
            && let Some(cancellation) = cancellation
        {
            cancellation.checkpoint()?;
        }
        let prefix = u32::from_le_bytes(
            source[local_offset..local_offset + AES_CONTEXT_HEADER.len()]
                .try_into()
                .expect("bounds-checked context prefix"),
        );
        let Some(seeds) = prefixes.get(&prefix) else {
            continue;
        };
        for &seed in seeds {
            validation_budget.charge()?;
            let encoded_context = &source[local_offset..local_offset + AES_CONTEXT_SIZE];
            let mut context = [0u8; AES_CONTEXT_SIZE];
            for (index, (&value, decoded)) in encoded_context.iter().zip(&mut context).enumerate() {
                *decoded = transform_context_byte(value, seed, index);
            }
            if context[..AES_CONTEXT_HEADER.len()] != AES_CONTEXT_HEADER {
                continue;
            }
            let schedule: [u8; AES_DECRYPT_SCHEDULE_SIZE] = context[AES_CONTEXT_HEADER.len()..]
                .try_into()
                .expect("bounds-checked AES schedule");
            let raw_key = recover_raw_key(&schedule);
            if make_openssl_decrypt_schedule(&raw_key) != schedule {
                continue;
            }
            let file_offset = file_range
                .start
                .checked_add(local_offset)
                .expect("bounded AES-context file offset");
            matches.push(AesContextMatch {
                file_offset,
                seed,
                raw_key,
            });
            ensure!(
                matches.len() <= MAX_AES_CONTEXT_MATCHES,
                "AES-context discovery produced too many matching contexts"
            );
        }
    }
    matches.sort_unstable_by_key(|context| (context.file_offset, context.seed));
    Ok(matches)
}

pub(crate) struct Aes256CbcDecryptor {
    cipher: Aes256,
}

impl Aes256CbcDecryptor {
    pub(crate) fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        Self {
            cipher: Aes256::new_from_slice(key).expect("AES-256 key length is fixed"),
        }
    }

    pub(crate) fn decrypt_full_blocks_in_place(&self, data: &mut [u8]) {
        let mut previous = [0u8; 16];
        let complete_length = data.len() & !0x0f;
        for bytes in data[..complete_length].chunks_exact_mut(16) {
            let ciphertext: [u8; 16] = bytes
                .try_into()
                .expect("AES-CBC chunk is exactly one block");
            self.cipher
                .decrypt_block(Block::<Aes256>::from_mut_slice(bytes));
            for (byte, previous_ciphertext_byte) in bytes.iter_mut().zip(previous) {
                *byte ^= previous_ciphertext_byte;
            }
            previous = ciphertext;
        }
    }
}
