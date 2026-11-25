use std::fmt;

use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};

use super::{ImportSymbol, LoaderDiscovery, Pe, SourceDefect, rva_slice};
use crate::pe::Machine;

const RSAZ_SHA256: [u8; 32] = [
    110, 18, 201, 20, 1, 115, 84, 153, 187, 105, 148, 189, 41, 134, 73, 107, 41, 103, 126, 35, 214,
    76, 127, 202, 175, 91, 182, 147, 239, 72, 121, 218,
];

struct Routine {
    size: u32,
    body: u32,
    epilogue: u32,
    displacement: usize,
    constant_distance: u32,
}

const ROUTINES: [Routine; 3] = [
    Routine {
        size: 1609,
        body: 31,
        epilogue: 1597,
        displacement: 1124,
        constant_distance: 64,
    },
    Routine {
        size: 1594,
        body: 31,
        epilogue: 1582,
        displacement: 676,
        constant_distance: 64,
    },
    Routine {
        size: 251,
        body: 0,
        epilogue: 0,
        displacement: 33,
        constant_distance: 32,
    },
];

#[derive(Debug)]
pub(super) struct NonExecutableHandler {
    pub(super) unwind: u32,
    pub(super) handler: u32,
}

impl fmt::Display for NonExecutableHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UNWIND_INFO handler is not executable")
    }
}

impl std::error::Error for NonExecutableHandler {}

fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn fingerprint(digest: &mut Sha256, bytes: &[u8], start: u32, disp: usize) -> Option<u32> {
    let relative = dword(bytes, disp) as i32;
    digest.update(&bytes[..disp]);
    digest.update([0; 4]);
    digest.update(&bytes[disp + 4..]);
    start
        .checked_add(disp as u32 + 4)?
        .checked_add_signed(relative)
}

fn is_unwind_import(discovery: &LoaderDiscovery, target: u32) -> bool {
    discovery.modules.iter().any(|module| {
        module.dll.eq_ignore_ascii_case("kernel32.dll") && target.checked_sub(module.destination_rva).is_some_and(|offset| {
            offset.is_multiple_of(8) && matches!(module.symbols.get((offset / 8) as usize), Some(ImportSymbol::Name { name, .. }) if name == "RtlVirtualUnwind")
        })
    })
}

struct Group {
    handler: u32,
    next_record: u32,
    count: usize,
    digest: Sha256,
}

impl Group {
    fn start(
        mapped: &[u8],
        pe: &Pe,
        imports: &LoaderDiscovery,
        record: u32,
        handler: u32,
    ) -> Option<Self> {
        let start = handler.checked_sub(64)?;
        let section = pe.section_for_rva_range(start, 64 + 262).ok()?;
        if pe.machine_kind() != Machine::Amd64
            || section.name_bytes != *b".data\0\0\0"
            || section.characteristics != 0xc0000040
        {
            return None;
        }
        let bytes = rva_slice(mapped, pe, start, 64 + 262)?;
        let mut digest = Sha256::new();
        digest.update(&bytes[..64]);
        let target = fingerprint(&mut digest, &bytes[64..], handler, 234)?;
        if !is_unwind_import(imports, target) {
            return None;
        }
        let marker = b"openssl-3.0.8\\crypto\\";
        let rdata = pe
            .sections
            .iter()
            .find(|s| s.name_bytes == *b".rdata\0\0")?
            .virtual_range()
            .ok()?;
        if !mapped
            .get(rdata.start as usize..rdata.end as usize)?
            .windows(marker.len())
            .any(|s| s == marker)
        {
            return None;
        }
        Some(Self {
            handler,
            next_record: record,
            count: 0,
            digest,
        })
    }
}

#[derive(Default)]
pub(super) struct RsazRows(Option<Group>);

impl RsazRows {
    pub(super) fn accept(
        &mut self,
        mapped: &[u8],
        pe: &Pe,
        imports: &LoaderDiscovery,
        record: u32,
        error: &NonExecutableHandler,
    ) -> Option<u32> {
        let group = match &mut self.0 {
            Some(group) => group,
            slot @ None => slot.insert(Group::start(mapped, pe, imports, record, error.handler)?),
        };
        let routine = ROUTINES.get(group.count)?;
        let row = rva_slice(mapped, pe, record, 12)?;
        let begin = dword(row, 0);
        if record != group.next_record
            || group.handler != error.handler
            || dword(row, 8) != error.unwind
            || dword(row, 4).checked_sub(begin)? != routine.size
        {
            return None;
        }
        let metadata = rva_slice(mapped, pe, error.unwind, 16)?;
        if dword(metadata, 0) != 9
            || dword(metadata, 4) != group.handler
            || dword(metadata, 8).checked_sub(begin)? != routine.body
            || dword(metadata, 12).checked_sub(begin)? != routine.epilogue
        {
            return None;
        }
        let bytes = rva_slice(mapped, pe, begin, routine.size as usize)?;
        let target = fingerprint(&mut group.digest, bytes, begin, routine.displacement)?;
        if target != group.handler.checked_sub(routine.constant_distance)? {
            return None;
        }
        group.next_record = record.checked_add(12)?;
        group.count += 1;
        Some(begin)
    }

    pub(super) fn finish(self) -> Result<Option<SourceDefect>> {
        let Some(group) = self.0 else { return Ok(None) };
        ensure!(
            group.count == ROUTINES.len() && group.digest.finalize()[..] == RSAZ_SHA256,
            "non-executable UNWIND_INFO handler does not match the complete OpenSSL RSAZ implementation"
        );
        Ok(Some(SourceDefect::OpensslRsazUnwind))
    }
}
