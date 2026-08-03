use crate::pipeline::outcome::DecryptionDetails;
use std::ops::Range;

mod aes;
mod decoder;
mod records;
mod replay;

pub(crate) use aes::{
    AesContextMatch, aes256_cbc_decrypt_full_blocks_in_place, scan_aes_contexts_in_range,
    scan_aes_contexts_in_range_with_cancellation,
};
#[cfg(test)]
use decoder::{CustomDecodeError, decode_custom_stream};
pub(crate) use decoder::{
    DecoderCandidate, custom_decoder_prefix_is_viable, decode_custom_stream_with_history,
};
use decoder::{discover_decoder_candidates, discover_decoder_candidates_with_cancellation};
pub(crate) use replay::DecryptionSelectionError;
#[cfg(test)]
pub(crate) use replay::{decrypt_packed_image, decrypt_packed_image_from_source};
pub(crate) use replay::{
    decrypt_packed_image_from_source_with_cancellation, decrypt_packed_image_with_cancellation,
};

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
    pub(crate) destination_record_ranges: Vec<Range<u32>>,
    pub(crate) destination_ranges: Vec<Range<u32>>,
    pub(crate) image: Vec<u8>,
    pub(crate) decryption_details: DecryptionDetails,
}

#[cfg(test)]
mod tests;
