use crate::pipeline::outcome::DecryptionDetails;
use std::ops::Range;

mod aes;
mod controller;
mod decoder;

mod evidence;
mod grammar;
mod records;
mod replay;
mod router;
mod source;

pub(crate) use aes::{
    AesContextMatch, scan_aes_contexts_in_range, scan_aes_contexts_in_range_with_cancellation,
};

pub(crate) use decoder::custom_decoder_prefix_is_viable;
#[cfg(test)]
use decoder::{CustomDecodeError, decode_custom_stream};
pub(crate) use decoder::{DecoderCandidate, decode_custom_stream_with_history};

use decoder::{discover_decoder_candidates, discover_decoder_candidates_with_cancellation};
pub(crate) use grammar::{
    decrypt_packed_image_from_source_with_cancellation, decrypt_packed_image_with_cancellation,
};
pub(crate) use replay::{PayloadPlanSelectionError, PayloadRouteError, PayloadRouteErrorKind};
#[cfg(test)]
pub(crate) use router::{ProviderPolicy, recover_payload_with_policy};
#[cfg(test)]
pub(crate) use source::bind_payload_source;

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
