mod checksum;
mod image;
mod model;
mod parse;

pub use checksum::{align_up, pe_checksum};
pub use image::write_u32;
#[cfg(test)]
pub use image::{read_u32, read_u64, write_u64};
#[cfg(test)]
pub use model::IMAGE_DIRECTORY_ENTRY_SECURITY;
pub use model::{DataDirectory, Pe};
#[cfg(test)]
pub(crate) use model::{
    IMAGE_FILE_DLL, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386, Section,
};
pub(crate) use model::{Machine, PeKind, PointerWidth};

#[cfg(test)]
mod tests;
