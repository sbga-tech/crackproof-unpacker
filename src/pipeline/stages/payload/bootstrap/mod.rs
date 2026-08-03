use crate::pipeline::stages::detect::KonnDescriptor;

mod outer;

pub(crate) use outer::{bootstrap_source_file_range, derive_outer_source};

// CrackProof encodes the outer encrypted-prefix byte count as the descriptor
// RVA delta plus this format bias. This is algorithm behavior, not PE/sample
// geometry.
pub(crate) const OUTER_ENCRYPTED_PREFIX_RVA_BIAS: u32 = 0x2000;
// The outer source is cloned and decrypted for each descriptor before its
// structural scans. Keep that allocation and transform bounded by the
// existing AES-context scan limit, independently of packed-input size.
pub(crate) const MAX_OUTER_SOURCE_BYTES: usize = 32 << 20;

/// The independently decoded fields needed to bootstrap packed A decryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PackedBootstrap {
    pub(crate) descriptor_file_offset: usize,
    pub(crate) key: u32,
    pub(crate) destination_rva: u32,
    pub(crate) source_offset: u32,
    pub(crate) length: u32,
    pub(crate) source_rva: u32,
}

impl From<&KonnDescriptor> for PackedBootstrap {
    fn from(descriptor: &KonnDescriptor) -> Self {
        Self {
            descriptor_file_offset: descriptor.file_offset,
            key: descriptor.key,
            destination_rva: descriptor.destination_rva,
            source_offset: descriptor.source_offset,
            length: descriptor.length,
            source_rva: descriptor.source_rva,
        }
    }
}
