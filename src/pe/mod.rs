mod address;
mod checksum;
mod image;
mod model;
mod parse;

pub(crate) use crate::util::bytes::write_u32;
#[cfg(test)]
pub(crate) use crate::util::bytes::{read_u32, read_u64, write_u64};
pub use address::{FileOffset, FileRange, Rva, RvaRange};
pub use checksum::{align_up, pe_checksum};
#[cfg(test)]
pub use model::IMAGE_DIRECTORY_ENTRY_SECURITY;
pub use model::{DataDirectory, Pe};
#[cfg(test)]
pub(crate) use model::{IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386};
pub(crate) use model::{Machine, PeKind, PointerWidth, Section};

#[cfg(test)]
mod tests;
