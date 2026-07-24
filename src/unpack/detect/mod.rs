use anyhow::Result;

use crate::pe::Pe;

mod konn;

/// A structurally validated encrypted CrackProof KONN descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KonnDescriptor {
    pub(crate) file_offset: usize,
    pub(crate) key: u32,
    pub(crate) entry_rva: u32,
    pub(crate) destination_rva: u32,
    pub(crate) source_offset: u32,
    pub(crate) length: u32,
    pub(crate) source_rva: u32,
    pub(crate) destination_section_index: usize,
}

/// Independent structural evidence identifying the CrackProof family.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FamilyEvidence {
    pub(crate) descriptor: KonnDescriptor,
}

pub(crate) fn detect_family(packed: &[u8], pe: &Pe) -> Result<FamilyEvidence> {
    konn::detect_family(packed, pe)
}

pub(crate) use konn::KONN_DESCRIPTOR_SIZE;

#[cfg(test)]
pub(crate) use konn::{
    IMAGE_SCN_MEM_EXECUTE, KONN_MAGIC, KONN_WORD_COUNT, MAX_KONN_CANDIDATES, MAX_KONN_MATCHES,
    MAX_KONN_SCAN_BODY_BYTES, combine_family_evidence, decode_konn_words, encode_konn_words,
    ensure_konn_scan_body_bound, reserve_konn_candidate, scan_konn_descriptors,
};
