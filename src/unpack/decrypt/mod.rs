use crate::report::DecryptionDetails;
use std::ops::Range;

mod aes;
mod decoder;
mod records;
mod replay;

pub(crate) use aes::{
    AesContextMatch, aes256_cbc_decrypt_full_blocks_in_place, scan_aes_contexts_in_range,
};
use decoder::discover_decoder_candidates;
#[cfg(test)]
use decoder::{CustomDecodeError, decode_custom_stream};
pub(crate) use decoder::{
    DecoderCandidate, decode_custom_stream_with_history, decode_custom_stream_with_history_mode,
};
pub(crate) use replay::{DecryptionSelectionError, decrypt_packed_image};

#[cfg(test)]
use aes::*;
#[cfg(test)]
use decoder::*;
use records::*;
#[cfg(test)]
use replay::*;

/// This decryption pipeline combines AES decryption, byte transforms, custom
/// decoding, and destination writes to produce the fully authenticated packed
/// image.
#[derive(Debug)]
pub(crate) struct DecryptedImage {
    pub(crate) destination_ranges: Vec<Range<u32>>,
    pub(crate) image: Vec<u8>,
    pub(crate) decryption_details: DecryptionDetails,
}

#[cfg(test)]
mod tests;
