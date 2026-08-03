use std::ops::Range;

use anyhow::{Context, Result};
use serde::Serialize;

/// Relative virtual address in a PE image.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct Rva(u32);

impl Rva {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }

    pub fn checked_add(self, length: u32) -> Result<Self> {
        self.0
            .checked_add(length)
            .map(Self)
            .context("RVA addition overflows")
    }

    pub fn to_mapped_offset(self) -> Result<usize> {
        usize::try_from(self.0).context("RVA does not fit host address space")
    }
}

impl From<u32> for Rva {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<Rva> for u32 {
    fn from(value: Rva) -> Self {
        value.0
    }
}

/// Byte offset in a disk file.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(transparent)]
pub struct FileOffset(usize);

impl FileOffset {
    pub const fn new(value: usize) -> Self {
        Self(value)
    }

    pub const fn get(self) -> usize {
        self.0
    }

    pub fn checked_add(self, length: usize) -> Result<Self> {
        self.0
            .checked_add(length)
            .map(Self)
            .context("file-offset addition overflows")
    }
}

impl From<usize> for FileOffset {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl From<FileOffset> for usize {
    fn from(value: FileOffset) -> Self {
        value.0
    }
}

/// Half-open range of PE RVAs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RvaRange(Range<u32>);

impl RvaRange {
    pub fn new(start: Rva, length: u32) -> Result<Self> {
        let end = start.checked_add(length)?;
        Ok(Self(start.get()..end.get()))
    }

    pub const fn start(&self) -> Rva {
        Rva(self.0.start)
    }

    pub const fn end(&self) -> Rva {
        Rva(self.0.end)
    }

    pub const fn len(&self) -> u32 {
        self.0.end - self.0.start
    }

    pub const fn is_empty(&self) -> bool {
        self.0.start == self.0.end
    }

    pub fn as_range(&self) -> &Range<u32> {
        &self.0
    }
}

/// Half-open range of disk-file offsets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileRange(Range<usize>);

impl FileRange {
    pub fn new(start: FileOffset, length: usize) -> Result<Self> {
        let end = start.checked_add(length)?;
        Ok(Self(start.get()..end.get()))
    }

    pub const fn start(&self) -> FileOffset {
        FileOffset(self.0.start)
    }

    pub const fn end(&self) -> FileOffset {
        FileOffset(self.0.end)
    }

    pub const fn len(&self) -> usize {
        self.0.end - self.0.start
    }

    pub const fn is_empty(&self) -> bool {
        self.0.start == self.0.end
    }

    pub fn as_range(&self) -> &Range<usize> {
        &self.0
    }
}
