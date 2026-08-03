//! Bounded ECMA-335 metadata and IL validation for the semantic CLR container.
//!
//! The validator deliberately accepts only structures whose complete encoding it
//! understands.  It validates metadata independently of stale PE directories;
//! callers supply the bounded CLR metadata blob and the RVA-mapped image.

use std::collections::BTreeSet;
use std::ops::Range;

use crate::pe::Pe;
use anyhow::{Context, Result, bail, ensure};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

fn bytes(data: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    data.get(offset..offset.checked_add(length).context("CLR range overflow")?)
        .context("CLR range exceeds input")
}
fn u16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().context("CLR u16")?,
    ))
}
fn u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().context("CLR u32")?,
    ))
}
fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .context("CLR alignment overflow")
        .map(|v| v & !3)
}

/// Decodes an ECMA-335 compressed unsigned integer without accepting reserved
/// leading-byte forms.
pub(crate) fn compressed(data: &[u8], offset: usize, end: usize) -> Result<(usize, usize)> {
    ensure!(
        offset < end && end <= data.len(),
        "compressed integer is outside heap"
    );
    let first = data[offset];
    match first {
        0x00..=0x7f => Ok((usize::from(first), offset + 1)),
        0x80..=0xbf => {
            ensure!(
                offset.checked_add(2).is_some_and(|v| v <= end),
                "truncated compressed u16"
            );
            Ok((
                usize::from((u16::from(first & 0x3f) << 8) | u16::from(data[offset + 1])),
                offset + 2,
            ))
        }
        0xc0..=0xdf => {
            ensure!(
                offset.checked_add(4).is_some_and(|v| v <= end),
                "truncated compressed u32"
            );
            let value = (u32::from(first & 0x1f) << 24)
                | (u32::from(data[offset + 1]) << 16)
                | (u32::from(data[offset + 2]) << 8)
                | u32::from(data[offset + 3]);
            Ok((usize::try_from(value)?, offset + 4))
        }
        _ => bail!("reserved compressed integer prefix"),
    }
}

#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    String,
    Guid,
    Blob,
    Table(u8),
    List(u8),
    Coded(Coded),
    RequiredCoded(Coded),
}
#[derive(Clone, Copy)]
struct Coded {
    bits: u8,
    // `None` represents a reserved tag, rather than an absent table.
    targets: &'static [Option<u8>],
}

const RESOLUTION_SCOPE: Coded = Coded {
    bits: 2,
    targets: &[Some(0), Some(26), Some(35), Some(1)],
};
const TYPE_DEF_OR_REF: Coded = Coded {
    bits: 2,
    targets: &[Some(2), Some(1), Some(27), None],
};
const HAS_CONSTANT: Coded = Coded {
    bits: 2,
    targets: &[Some(4), Some(8), Some(23), None],
};
const HAS_CUSTOM_ATTRIBUTE: Coded = Coded {
    bits: 5,
    targets: &[
        Some(6),
        Some(4),
        Some(1),
        Some(2),
        Some(8),
        Some(9),
        Some(10),
        Some(0),
        Some(14),
        Some(23),
        Some(20),
        Some(17),
        Some(26),
        Some(27),
        Some(32),
        Some(35),
        Some(38),
        Some(39),
        Some(40),
        Some(42),
        Some(44),
        Some(43),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    ],
};
const HAS_FIELD_MARSHAL: Coded = Coded {
    bits: 1,
    targets: &[Some(4), Some(8)],
};
const HAS_DECL_SECURITY: Coded = Coded {
    bits: 2,
    targets: &[Some(2), Some(6), Some(32), None],
};
const MEMBER_REF_PARENT: Coded = Coded {
    bits: 3,
    targets: &[
        Some(2),
        Some(1),
        Some(26),
        Some(6),
        Some(27),
        None,
        None,
        None,
    ],
};
const HAS_SEMANTICS: Coded = Coded {
    bits: 1,
    targets: &[Some(20), Some(23)],
};
const METHOD_DEF_OR_REF: Coded = Coded {
    bits: 1,
    targets: &[Some(6), Some(10)],
};
const MEMBER_FORWARDED: Coded = Coded {
    bits: 1,
    targets: &[Some(4), Some(6)],
};
const IMPLEMENTATION: Coded = Coded {
    bits: 2,
    targets: &[Some(38), Some(35), Some(39), None],
};
const CUSTOM_ATTRIBUTE_TYPE: Coded = Coded {
    bits: 3,
    targets: &[None, None, Some(6), Some(10), None, None, None, None],
};
const TYPE_OR_METHOD_DEF: Coded = Coded {
    bits: 1,
    targets: &[Some(2), Some(6)],
};

// ECMA-335 II.22.  The table order is significant and each schema contains
// every column, including the pointer tables that are often absent.
const TABLES: [&[Col]; 45] = [
    &[Col::U16, Col::String, Col::Guid, Col::Guid, Col::Guid],
    &[
        Col::RequiredCoded(RESOLUTION_SCOPE),
        Col::String,
        Col::String,
    ],
    &[
        Col::U32,
        Col::String,
        Col::String,
        Col::Coded(TYPE_DEF_OR_REF),
        Col::List(4),
        Col::List(6),
    ],
    &[Col::Table(4)],
    &[Col::U16, Col::String, Col::Blob],
    &[Col::Table(6)],
    &[
        Col::U32,
        Col::U16,
        Col::U16,
        Col::String,
        Col::Blob,
        Col::List(8),
    ],
    &[Col::Table(8)],
    &[Col::U16, Col::U16, Col::String],
    &[Col::Table(2), Col::RequiredCoded(TYPE_DEF_OR_REF)],
    &[
        Col::RequiredCoded(MEMBER_REF_PARENT),
        Col::String,
        Col::Blob,
    ],
    &[Col::U16, Col::RequiredCoded(HAS_CONSTANT), Col::Blob],
    &[
        Col::RequiredCoded(HAS_CUSTOM_ATTRIBUTE),
        Col::RequiredCoded(CUSTOM_ATTRIBUTE_TYPE),
        Col::Blob,
    ],
    &[Col::RequiredCoded(HAS_FIELD_MARSHAL), Col::Blob],
    &[Col::U16, Col::RequiredCoded(HAS_DECL_SECURITY), Col::Blob],
    &[Col::U16, Col::U32, Col::Table(2)],
    &[Col::U32, Col::Table(4)],
    &[Col::Blob],
    &[Col::Table(2), Col::List(20)],
    &[Col::Table(20)],
    &[Col::U16, Col::String, Col::RequiredCoded(TYPE_DEF_OR_REF)],
    &[Col::Table(2), Col::List(23)],
    &[Col::Table(23)],
    &[Col::U16, Col::String, Col::Blob],
    &[Col::U16, Col::Table(6), Col::RequiredCoded(HAS_SEMANTICS)],
    &[
        Col::Table(2),
        Col::RequiredCoded(METHOD_DEF_OR_REF),
        Col::RequiredCoded(METHOD_DEF_OR_REF),
    ],
    &[Col::String],
    &[Col::Blob],
    &[
        Col::U16,
        Col::RequiredCoded(MEMBER_FORWARDED),
        Col::String,
        Col::Table(26),
    ],
    &[Col::U32, Col::Table(4)],
    &[Col::U32, Col::U32],
    &[Col::U32],
    &[
        Col::U32,
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U32,
        Col::Blob,
        Col::String,
        Col::String,
    ],
    &[Col::U32],
    &[Col::U32, Col::U32, Col::U32],
    &[
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U16,
        Col::U32,
        Col::Blob,
        Col::String,
        Col::String,
        Col::Blob,
    ],
    &[Col::U32, Col::Table(35)],
    &[Col::U32, Col::U32, Col::U32, Col::Table(35)],
    &[Col::U32, Col::String, Col::Blob],
    &[
        Col::U32,
        Col::U32,
        Col::String,
        Col::String,
        Col::RequiredCoded(IMPLEMENTATION),
    ],
    &[Col::U32, Col::U32, Col::String, Col::Coded(IMPLEMENTATION)],
    &[Col::Table(2), Col::Table(2)],
    &[
        Col::U16,
        Col::U16,
        Col::RequiredCoded(TYPE_OR_METHOD_DEF),
        Col::String,
    ],
    &[Col::RequiredCoded(METHOD_DEF_OR_REF), Col::Blob],
    &[Col::Table(42), Col::RequiredCoded(TYPE_DEF_OR_REF)],
];

#[derive(Clone, Copy)]
struct Heap {
    start: usize,
    end: usize,
}
#[derive(Clone, Copy)]
struct Heaps {
    strings: Heap,
    blob: Heap,
    guid: Heap,
    user: Heap,
}
struct Metadata<'a> {
    bytes: &'a [u8],
    heaps: Heaps,
}

fn width(column: Col, rows: &[u32; 64], heap_flags: u8) -> usize {
    match column {
        Col::U16 => 2,
        Col::U32 => 4,
        Col::String => {
            if heap_flags & 1 != 0 {
                4
            } else {
                2
            }
        }
        Col::Guid => {
            if heap_flags & 2 != 0 {
                4
            } else {
                2
            }
        }
        Col::Blob => {
            if heap_flags & 4 != 0 {
                4
            } else {
                2
            }
        }
        Col::Table(table) | Col::List(table) => {
            if rows[usize::from(table)] < 0x1_0000 {
                2
            } else {
                4
            }
        }
        Col::Coded(coded) | Col::RequiredCoded(coded) => {
            let ceiling = 1u32 << (16 - u32::from(coded.bits));
            if coded
                .targets
                .iter()
                .flatten()
                .all(|table| rows[usize::from(*table)] < ceiling)
            {
                2
            } else {
                4
            }
        }
    }
}
fn read_index(data: &[u8], at: usize, width: usize) -> Result<u32> {
    match width {
        2 => Ok(u32::from(u16(data, at)?)),
        4 => u32(data, at),
        _ => bail!("invalid metadata index width"),
    }
}
fn validate_string(metadata: &Metadata<'_>, index: u32) -> Result<()> {
    if index == 0 {
        return Ok(());
    }
    let start = metadata
        .heaps
        .strings
        .start
        .checked_add(usize::try_from(index)?)
        .context("string index overflow")?;
    ensure!(
        start < metadata.heaps.strings.end,
        "#Strings index outside heap"
    );
    ensure!(
        metadata.bytes[start..metadata.heaps.strings.end].contains(&0),
        "unterminated #Strings value"
    );
    Ok(())
}
fn validate_blob(metadata: &Metadata<'_>, index: u32) -> Result<()> {
    if index == 0 {
        return Ok(());
    }
    let start = metadata
        .heaps
        .blob
        .start
        .checked_add(usize::try_from(index)?)
        .context("blob index overflow")?;
    ensure!(start < metadata.heaps.blob.end, "#Blob index outside heap");
    let (length, next) = compressed(metadata.bytes, start, metadata.heaps.blob.end)?;
    ensure!(
        next.checked_add(length)
            .is_some_and(|end| end <= metadata.heaps.blob.end),
        "#Blob payload exceeds heap"
    );
    Ok(())
}
fn validate_guid(metadata: &Metadata<'_>, index: u32) -> Result<()> {
    if index == 0 {
        return Ok(());
    }
    let length = usize::try_from(index)?
        .checked_mul(16)
        .context("GUID index overflow")?;
    ensure!(
        length <= metadata.heaps.guid.end - metadata.heaps.guid.start,
        "#GUID index outside heap"
    );
    Ok(())
}
fn validate_coded(rows: &[u32; 64], coded: Coded, value: u32, required: bool) -> Result<()> {
    if value == 0 {
        ensure!(!required, "required coded index is null");
        return Ok(());
    }
    let tag_mask = (1u32 << coded.bits) - 1;
    let tag = usize::try_from(value & tag_mask)?;
    let table = coded
        .targets
        .get(tag)
        .copied()
        .flatten()
        .context("reserved coded-index tag")?;
    let rid = value >> coded.bits;
    ensure!(
        rid != 0 && rid <= rows[usize::from(table)],
        "coded index RID outside target table"
    );
    Ok(())
}

/// Parses the #US heap completely and returns every legal token offset.
/// Offset zero is its sentinel, never a user-string record.
fn validate_user_heap(metadata: &Metadata<'_>) -> Result<BTreeSet<usize>> {
    if metadata.heaps.user.start == metadata.heaps.user.end {
        return Ok(BTreeSet::new());
    }
    ensure!(
        metadata.bytes[metadata.heaps.user.start] == 0,
        "#US heap lacks zero sentinel"
    );
    let mut starts = BTreeSet::new();
    let mut cursor = metadata.heaps.user.start + 1;
    while cursor < metadata.heaps.user.end {
        let record = cursor;
        let (length, next) = compressed(metadata.bytes, cursor, metadata.heaps.user.end)?;
        if length == 0 {
            ensure!(
                next == metadata.heaps.user.end,
                "zero-length #US record is not terminal padding"
            );
            break;
        }
        ensure!(length % 2 == 1, "invalid #US record length");
        cursor = next.checked_add(length).context("#US record overflow")?;
        ensure!(cursor <= metadata.heaps.user.end, "#US record exceeds heap");
        starts.insert(record - metadata.heaps.user.start);
    }
    Ok(starts)
}

fn token_table(token: u32) -> u8 {
    (token >> 24) as u8
}
fn validate_token(rows: &[u32; 64], token: u32, allowed: &[u8], allow_zero: bool) -> Result<()> {
    if token == 0 {
        ensure!(allow_zero, "unexpected null metadata token");
        return Ok(());
    }
    let table = token_table(token);
    let rid = token & 0x00ff_ffff;
    ensure!(
        allowed.contains(&table)
            && rid != 0
            && usize::from(table) < rows.len()
            && rid <= rows[usize::from(table)],
        "invalid IL metadata token {token:#010x} for tables {allowed:?}"
    );
    Ok(())
}

fn one_operand(opcode: u8) -> Result<usize> {
    match opcode {
        0x00..=0x0d
        | 0x14..=0x1e
        | 0x25
        | 0x26
        | 0x2a
        | 0x46..=0x6e
        | 0x76
        | 0x7a
        | 0x82..=0x8b
        | 0x8e
        | 0x90..=0xa2
        | 0xb3..=0xba
        | 0xc3
        | 0xd1..=0xdc
        | 0xdf
        | 0xe0 => Ok(0),
        0x0e..=0x13 | 0x1f | 0x2b..=0x37 | 0xde => Ok(1),
        0x20
        | 0x22
        | 0x27..=0x29
        | 0x38..=0x44
        | 0x6f..=0x75
        | 0x79
        | 0x7b..=0x81
        | 0x8c
        | 0x8d
        | 0x8f
        | 0xa3..=0xa5
        | 0xc2
        | 0xc6
        | 0xd0
        | 0xdd => Ok(4),
        0x21 | 0x23 => Ok(8),
        _ => bail!("undefined IL opcode {opcode:#x}"),
    }
}

fn ext_operand(opcode: u8) -> Result<usize> {
    match opcode {
        0x00..=0x05 | 0x0f | 0x11 | 0x13 | 0x14 | 0x17 | 0x18 | 0x1a | 0x1d | 0x1e => Ok(0),
        0x06 | 0x07 | 0x15 | 0x16 | 0x1c => Ok(4),
        0x09..=0x0e => Ok(2),
        0x12 | 0x19 => Ok(1),
        _ => bail!("undefined two-byte IL opcode {opcode:#x}"),
    }
}

fn validate_extended_immediate(opcode: u8, code: &[u8], at: usize) -> Result<()> {
    match opcode {
        0x12 => ensure!(
            matches!(code[at], 1 | 2 | 4),
            "unaligned. operand is not a legal alignment"
        ),
        0x19 => ensure!(
            code[at] & !0x07 == 0,
            "no. operand contains reserved check-mask bits"
        ),
        _ => {}
    }
    Ok(())
}

/// Validates an IL stream and returns every instruction boundary. It rejects
/// unknown opcodes and truncated operands.
pub(crate) fn il_boundaries(code: &[u8]) -> Result<Vec<usize>> {
    let mut result = vec![0];
    let mut at = 0usize;
    while at < code.len() {
        let opcode = code[at];
        at += 1;
        let (extended, width) = if opcode == 0xfe {
            let extended = *code.get(at).context("truncated two-byte opcode")?;
            at += 1;
            (Some(extended), ext_operand(extended)?)
        } else if opcode == 0x45 {
            ensure!(
                at.checked_add(4).is_some_and(|end| end <= code.len()),
                "truncated switch count"
            );
            let count = usize::try_from(u32(code, at)?)?;
            (
                None,
                4usize
                    .checked_add(count.checked_mul(4).context("switch count overflow")?)
                    .context("switch width overflow")?,
            )
        } else {
            (None, one_operand(opcode)?)
        };
        ensure!(
            at.checked_add(width).is_some_and(|end| end <= code.len()),
            "truncated IL operand"
        );
        if let Some(extended) = extended {
            validate_extended_immediate(extended, code, at)?;
        }
        at += width;
        result.push(at);
    }
    Ok(result)
}

fn validate_code_tokens(
    code: &[u8],
    rows: &[u32; 64],
    user_string_starts: &BTreeSet<usize>,
) -> Result<()> {
    let mut at = 0usize;
    while at < code.len() {
        let opcode = code[at];
        at += 1;
        let (extended, width) = if opcode == 0xfe {
            let ext = *code.get(at).context("truncated two-byte opcode")?;
            at += 1;
            (Some(ext), ext_operand(ext)?)
        } else if opcode == 0x45 {
            let count = usize::try_from(u32(code, at)?)?;
            (
                None,
                4usize
                    .checked_add(count.checked_mul(4).context("switch count overflow")?)
                    .context("switch width overflow")?,
            )
        } else {
            (None, one_operand(opcode)?)
        };
        ensure!(
            at.checked_add(width).is_some_and(|end| end <= code.len()),
            "truncated IL operand"
        );
        if extended.is_none() && width == 4 {
            let token = u32(code, at)?;
            match opcode {
                0x27 | 0x28 | 0x6f | 0x73 => validate_token(rows, token, &[6, 10, 43], false)?,
                0x29 => validate_token(rows, token, &[17], false)?,
                0x70
                | 0x71
                | 0x74
                | 0x79
                | 0x81
                | 0x8c
                | 0x8d
                | 0x8f
                | 0xa3..=0xa5
                | 0xc2
                | 0xc6 => validate_token(rows, token, &[1, 2, 27], false)?,
                0x7b..=0x80 => validate_token(rows, token, &[4, 10], false)?,
                0x72 => {
                    ensure!(
                        token_table(token) == 0x70
                            && user_string_starts.contains(&usize::try_from(token & 0x00ff_ffff)?),
                        "ldstr token is not a #US record start"
                    );
                }
                0xd0 => validate_token(rows, token, &[1, 2, 4, 6, 10, 27, 43], false)?,
                _ => {}
            }
        }
        if let Some(ext) = extended
            && width == 4
        {
            let token = u32(code, at)?;
            match ext {
                0x06 | 0x07 => validate_token(rows, token, &[6, 10, 43], false)?,
                0x15 | 0x16 | 0x1c => validate_token(rows, token, &[1, 2, 27], false)?,
                _ => {}
            }
        }
        at += width;
    }
    Ok(())
}
fn validate_list_starts(values: &[u32], target_rows: u32) -> Result<()> {
    ensure!(
        values.first() == Some(&1),
        "metadata list ownership does not begin at target row one"
    );
    ensure!(
        values.windows(2).all(|pair| pair[0] <= pair[1]),
        "metadata list starts are not monotonic"
    );
    ensure!(
        values.iter().all(|start| *start <= target_rows + 1),
        "metadata list terminal exceeds target table"
    );
    Ok(())
}

fn validate_method_body_section(pe: &Pe, start_rva: u32, end: usize) -> Result<()> {
    let start = usize::try_from(start_rva)?;
    let length = end
        .checked_sub(start)
        .context("MethodDef body range underflows")?;
    let section = pe
        .section_for_rva_range(start_rva, length)
        .context("MethodDef body is not section-backed")?;
    ensure!(
        section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
        "MethodDef body is not in an executable section"
    );
    Ok(())
}
fn boundary(boundaries: &[usize], offset: usize) -> bool {
    boundaries.binary_search(&offset).is_ok()
}
fn signed_i8(code: &[u8], at: usize) -> Result<i64> {
    Ok(i64::from(i8::from_le_bytes([*code
        .get(at)
        .context("short branch")?])))
}
fn signed_i32(code: &[u8], at: usize) -> Result<i64> {
    Ok(i64::from(i32::from_le_bytes(
        bytes(code, at, 4)?.try_into().context("branch")?,
    )))
}

fn method_body_checked(
    image: &[u8],
    offset: usize,
    rows: Option<(&[u32; 64], &BTreeSet<usize>)>,
) -> Result<usize> {
    let first = *bytes(image, offset, 1)?.first().context("method header")?;
    let (code_offset, code_size, more_sections) = match first & 3 {
        2 => (offset + 1, usize::from(first >> 2), false),
        3 => {
            let header = u16(image, offset)?;
            let flags = header & 0x0fff;
            ensure!(flags & !0x1b == 0, "unsupported fat method flags");
            let header_size = usize::from(header >> 12)
                .checked_mul(4)
                .context("fat header size")?;
            ensure!(header_size >= 12, "fat method header too small");
            let local_sig = u32(image, offset + 8)?;
            if let Some((table_rows, _)) = rows {
                validate_token(table_rows, local_sig, &[17], true)?;
            }
            (
                offset
                    .checked_add(header_size)
                    .context("method code offset")?,
                usize::try_from(u32(image, offset + 4)?)?,
                flags & 8 != 0,
            )
        }
        _ => bail!("invalid method header"),
    };
    let code = bytes(image, code_offset, code_size)?;
    let boundaries = il_boundaries(code)?;
    if let Some((table_rows, user)) = rows {
        validate_code_tokens(code, table_rows, user)?;
    }
    let mut at = 0usize;
    while at < code.len() {
        let opcode = code[at];
        let start = at;
        at += 1;
        if opcode == 0x45 {
            let count = usize::try_from(u32(code, at)?)?;
            let operands = at + 4;
            let end = operands
                .checked_add(count.checked_mul(4).context("switch count overflow")?)
                .context("switch end")?;
            for index in 0..count {
                let target = i64::try_from(end)?
                    .checked_add(signed_i32(code, operands + index * 4)?)
                    .context("switch target")?;
                ensure!(
                    target >= 0 && boundary(&boundaries, usize::try_from(target)?),
                    "switch target is not an instruction boundary"
                );
            }
            at = end;
            continue;
        }
        let width = if opcode == 0xfe {
            at += 1;
            ext_operand(*code.get(start + 1).context("truncated two-byte opcode")?)?
        } else {
            one_operand(opcode)?
        };
        if matches!(opcode, 0x2b..=0x37 | 0xde) {
            let target = i64::try_from(at + 1)?
                .checked_add(signed_i8(code, at)?)
                .context("branch target")?;
            ensure!(
                target >= 0 && boundary(&boundaries, usize::try_from(target)?),
                "branch target is not an instruction boundary"
            );
        } else if matches!(opcode, 0x38..=0x44 | 0xdd) {
            let target = i64::try_from(at + 4)?
                .checked_add(signed_i32(code, at)?)
                .context("branch target")?;
            ensure!(
                target >= 0 && boundary(&boundaries, usize::try_from(target)?),
                "branch target is not an instruction boundary"
            );
        }
        at = at.checked_add(width).context("IL cursor overflow")?;
    }
    let mut end = code_offset.checked_add(code_size).context("method end")?;
    if more_sections {
        let mut section = align4(end)?;
        loop {
            let kind = bytes(image, section, 1)?[0];
            ensure!(kind & 0x3f == 1, "unsupported method extra section");
            let fat = kind & 0x40 != 0;
            let more = kind & 0x80 != 0;
            let size = if fat {
                usize::from(image[section + 1])
                    | (usize::from(image[section + 2]) << 8)
                    | (usize::from(image[section + 3]) << 16)
            } else {
                usize::from(image[section + 1])
            };
            let unit = if fat { 24 } else { 12 };
            ensure!(size >= 4 && (size - 4) % unit == 0, "EH section size");
            bytes(image, section, size)?;
            for clause in 0..(size - 4) / unit {
                let at = section + 4 + clause * unit;
                let (
                    flags,
                    try_offset,
                    try_length,
                    handler_offset,
                    handler_length,
                    class_or_filter,
                ) = if fat {
                    (
                        u32(image, at)?,
                        usize::try_from(u32(image, at + 4)?)?,
                        usize::try_from(u32(image, at + 8)?)?,
                        usize::try_from(u32(image, at + 12)?)?,
                        usize::try_from(u32(image, at + 16)?)?,
                        u32(image, at + 20)?,
                    )
                } else {
                    (
                        u32::from(u16(image, at)?),
                        usize::from(u16(image, at + 2)?),
                        usize::from(image[at + 4]),
                        usize::from(u16(image, at + 5)?),
                        usize::from(image[at + 7]),
                        u32(image, at + 8)?,
                    )
                };
                ensure!(matches!(flags, 0 | 1 | 2 | 4), "invalid EH clause flags");
                ensure!(
                    try_length != 0 && handler_length != 0,
                    "empty EH clause range"
                );
                for (begin, length) in [(try_offset, try_length), (handler_offset, handler_length)]
                {
                    let finish = begin.checked_add(length).context("EH range overflow")?;
                    ensure!(
                        finish <= code_size
                            && boundary(&boundaries, begin)
                            && boundary(&boundaries, finish),
                        "EH clause range is not instruction-aligned"
                    );
                }
                match flags {
                    0 => {
                        if let Some((table_rows, _)) = rows {
                            validate_token(table_rows, class_or_filter, &[1, 2, 27], false)?;
                        } else {
                            ensure!(
                                class_or_filter != 0
                                    && matches!(token_table(class_or_filter), 1 | 2 | 27),
                                "invalid catch type token"
                            );
                        }
                    }
                    1 => ensure!(
                        boundary(&boundaries, usize::try_from(class_or_filter)?),
                        "EH filter is not an instruction boundary"
                    ),
                    _ => ensure!(class_or_filter == 0, "finally/fault EH clause has a token"),
                }
            }
            end = section.checked_add(size).context("EH end")?;
            if !more {
                break;
            }
            section = align4(end)?;
        }
    }
    Ok(end)
}

/// Validates one standalone tiny or fat method body.  Production validation
/// additionally supplies metadata rows to validate inline and EH tokens.
#[cfg(test)]
pub(crate) fn method_body(image: &[u8], offset: usize) -> Result<()> {
    method_body_checked(image, offset, None).map(|_| ())
}

fn parse_streams(metadata: &[u8]) -> Result<(Heap, Heap, Heap, Heap, Heap)> {
    ensure!(bytes(metadata, 0, 4)? == b"BSJB", "metadata signature");
    let version_length = usize::try_from(u32(metadata, 12)?)?;
    ensure!(
        version_length.is_multiple_of(4),
        "metadata version length is not aligned"
    );
    let root = align4(
        16usize
            .checked_add(version_length)
            .context("metadata version overflow")?,
    )?;
    let count = usize::from(u16(metadata, root + 2)?);
    let minimum_header_bytes = count
        .checked_mul(12)
        .context("metadata stream-header count overflows")?;
    ensure!(
        count != 0
            && root
                .checked_add(4)
                .and_then(|start| start.checked_add(minimum_header_bytes))
                .is_some_and(|end| end <= metadata.len()),
        "metadata stream count exceeds the bounded root"
    );
    let mut cursor = root + 4;
    let mut tables = None;
    let mut strings = None;
    let mut blob = None;
    let mut guid = None;
    let mut user = None;
    let mut ranges = Vec::new();
    for _ in 0..count {
        let offset = usize::try_from(u32(metadata, cursor)?)?;
        let length = usize::try_from(u32(metadata, cursor + 4)?)?;
        let end = offset
            .checked_add(length)
            .context("metadata stream range overflow")?;
        ensure!(end <= metadata.len(), "metadata stream exceeds root");
        let name_start = cursor
            .checked_add(8)
            .context("metadata stream name overflow")?;
        let name_end = metadata
            .get(name_start..)
            .context("metadata stream name")?
            .iter()
            .position(|b| *b == 0)
            .map(|n| name_start + n)
            .context("unterminated metadata stream name")?;
        let heap = Heap { start: offset, end };
        match bytes(metadata, name_start, name_end - name_start)? {
            b"#~" | b"#-" => {
                ensure!(
                    tables.replace(heap).is_none(),
                    "duplicate metadata tables stream"
                );
            }
            b"#Strings" => {
                ensure!(strings.replace(heap).is_none(), "duplicate #Strings stream");
            }
            b"#Blob" => {
                ensure!(blob.replace(heap).is_none(), "duplicate #Blob stream");
            }
            b"#GUID" => {
                ensure!(guid.replace(heap).is_none(), "duplicate #GUID stream");
            }
            b"#US" => {
                ensure!(user.replace(heap).is_none(), "duplicate #US stream");
            }
            _ => {}
        }
        ranges.push(offset..end);
        cursor = align4(
            name_end
                .checked_add(1)
                .context("metadata stream terminator")?,
        )?;
    }
    ranges.sort_by_key(|range| range.start);
    ensure!(
        ranges.windows(2).all(|pair| pair[0].end <= pair[1].start),
        "metadata streams overlap"
    );
    let empty = Heap { start: 0, end: 0 };
    Ok((
        tables.context("missing #~ or #- metadata tables stream")?,
        strings.unwrap_or(empty),
        blob.unwrap_or(empty),
        guid.unwrap_or(empty),
        user.unwrap_or(empty),
    ))
}

/// Validates all present ECMA-335 tables and all nonzero MethodDef bodies.
/// Method RVAs must belong entirely to executable PE sections.
pub(crate) fn authenticated_method_defs(
    mapped: &[u8],
    pe: &Pe,
    metadata_rva: usize,
    metadata_size: usize,
) -> Result<()> {
    let data = bytes(mapped, metadata_rva, metadata_size)?;
    let (tables, strings, blob, guid, user) = parse_streams(data)?;
    let heaps = Heaps {
        strings,
        blob,
        guid,
        user,
    };
    let metadata_end = tables.end;
    ensure!(
        u32(data, tables.start)? == 0,
        "metadata tables reserved field"
    );
    let heap_flags = data[tables.start + 6];
    ensure!(heap_flags & !7 == 0, "unsupported metadata heap flags");
    let valid = u64::from_le_bytes(
        bytes(data, tables.start + 8, 8)?
            .try_into()
            .context("metadata valid mask")?,
    );
    ensure!(valid >> 45 == 0, "unsupported metadata table present");
    let mut rows = [0u32; 64];
    let mut cursor = tables.start + 24;
    for (table, row_count) in rows.iter_mut().enumerate().take(45) {
        if valid & (1u64 << table) != 0 {
            *row_count = u32(data, cursor)?;
            cursor += 4;
        }
    }
    let metadata = Metadata { bytes: data, heaps };
    let user_string_starts = validate_user_heap(&metadata)?;
    let mut lists: Vec<(u8, Vec<u32>)> = Vec::new();
    let mut methods = Vec::<u32>::new();
    for table in 0..45usize {
        if rows[table] == 0 {
            continue;
        }
        let schema = TABLES[table];
        let row_width = schema.iter().try_fold(0usize, |size, column| {
            size.checked_add(width(*column, &rows, heap_flags))
                .context("metadata row width overflow")
        })?;
        let count = usize::try_from(rows[table])?;
        let table_end = cursor
            .checked_add(
                row_width
                    .checked_mul(count)
                    .context("metadata table length overflow")?,
            )
            .context("metadata table end overflow")?;
        ensure!(
            table_end <= metadata_end,
            "metadata table exceeds #~ stream"
        );
        for row in 0..count {
            let mut at = cursor + row * row_width;
            for column in schema {
                let value = read_index(data, at, width(*column, &rows, heap_flags))?;
                match *column {
                    Col::U16 | Col::U32 => {}
                    Col::String => validate_string(&metadata, value)?,
                    Col::Guid => validate_guid(&metadata, value)?,
                    Col::Blob => validate_blob(&metadata, value)?,
                    Col::Table(target) => ensure!(
                        value != 0 && value <= rows[usize::from(target)],
                        "table index outside target table"
                    ),
                    Col::List(target) => {
                        ensure!(
                            value != 0 && value <= rows[usize::from(target)].saturating_add(1),
                            "list index outside target table"
                        );
                        if let Some((_, values)) =
                            lists.iter_mut().find(|(existing, _)| *existing == target)
                        {
                            values.push(value);
                        } else {
                            lists.push((target, vec![value]));
                        }
                    }
                    Col::Coded(coded) => validate_coded(&rows, coded, value, false)?,
                    Col::RequiredCoded(coded) => validate_coded(&rows, coded, value, true)?,
                }
                if table == 6 && at == cursor + row * row_width {
                    methods.push(value);
                }
                at += width(*column, &rows, heap_flags);
            }
        }
        cursor = table_end;
    }
    ensure!(
        data[cursor..metadata_end].iter().all(|byte| *byte == 0),
        "nonzero trailing bytes in metadata tables stream"
    );
    for (target, values) in lists {
        validate_list_starts(&values, rows[usize::from(target)])?;
    }
    ensure!(
        methods.len() == usize::try_from(rows[6])?,
        "MethodDef count mismatch"
    );
    let metadata_end = metadata_rva
        .checked_add(metadata_size)
        .context("metadata RVA range overflows")?;
    let mut spans = Vec::<Range<usize>>::new();
    for rva in methods {
        if rva == 0 {
            continue;
        }
        let start = usize::try_from(rva)?;
        let start_rva = rva;
        let end = method_body_checked(mapped, start, Some((&rows, &user_string_starts)))?;
        ensure!(
            end <= metadata_rva || start >= metadata_end,
            "MethodDef body overlaps CLR metadata"
        );
        validate_method_body_section(pe, start_rva, end)?;
        spans.push(start..end);
    }
    spans.sort_by_key(|span| (span.start, span.end));
    ensure!(
        spans
            .windows(2)
            .all(|pair| pair[0] == pair[1] || pair[0].end <= pair[1].start),
        "MethodDef bodies overlap without sharing an exact body"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{DataDirectory, Machine, Section};

    fn method_test_pe(characteristics: u32) -> Pe {
        Pe {
            opt: 0x98,
            machine: Machine::I386,
            coff_characteristics: 0x102,
            section_count: 1,
            entry_rva: 0x1000,
            image_base: 0x400000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            size_of_image: 0x2000,
            size_of_headers: 0x200,
            checksum_offset: 0xd8,
            data_directory_table_offset: 0xf8,
            directories: vec![
                DataDirectory {
                    virtual_address: 0,
                    size: 0,
                };
                16
            ],
            sections: vec![Section {
                index: 0,
                header_offset: 0x178,
                name_bytes: *b".text\0\0\0",
                virtual_size: 0x1000,
                virtual_address: 0x1000,
                raw_size: 0x1000,
                raw_pointer: 0x200,
                characteristics,
            }],
            file_len: 0x1200,
        }
    }

    #[test]
    fn compressed_rejects_reserved_and_truncated_forms() {
        assert!(compressed(&[0xe0], 0, 1).is_err());
        assert!(compressed(&[0x80], 0, 1).is_err());
        assert_eq!(compressed(&[0x7f], 0, 1).unwrap(), (127, 1));
    }

    #[test]
    fn accepts_unoptimized_tables_without_optional_heaps_or_methods() {
        let mut metadata = vec![0; 64];
        metadata[..4].copy_from_slice(b"BSJB");
        metadata[12..16].copy_from_slice(&4u32.to_le_bytes());
        metadata[16..20].copy_from_slice(b"v1\0\0");
        metadata[22..24].copy_from_slice(&1u16.to_le_bytes());
        metadata[24..28].copy_from_slice(&40u32.to_le_bytes());
        metadata[28..32].copy_from_slice(&24u32.to_le_bytes());
        metadata[32..35].copy_from_slice(b"#-\0");
        let mut image = vec![0; 0x2000];
        image[0x1100..0x1140].copy_from_slice(&metadata);

        authenticated_method_defs(&image, &method_test_pe(0x6000_0020), 0x1100, 64)
            .expect("minimal unoptimized metadata");
    }
    #[test]
    fn accepts_complete_tiny_method_and_branch_boundary() {
        method_body(&[0x0e, 0x2b, 0x00, 0x2a], 0).unwrap();
    }
    #[test]
    fn validates_extended_opcode_gaps_and_immediates() {
        assert_eq!(
            il_boundaries(&[0xfe, 0x19, 0x07, 0x2a]).unwrap(),
            vec![0, 3, 4]
        );
        assert_eq!(
            il_boundaries(&[0xfe, 0x12, 0x04, 0x2a]).unwrap(),
            vec![0, 3, 4]
        );
        assert!(il_boundaries(&[0xfe, 0x10]).is_err());
        assert!(il_boundaries(&[0xfe, 0x19, 0x80]).is_err());
        assert!(il_boundaries(&[0xfe, 0x12, 0x03]).is_err());
    }

    #[test]
    fn rejects_bad_opcode_and_branch_into_operand() {
        assert!(il_boundaries(&[0xfe, 0x08]).is_err());
        assert!(method_body(&[0x12, 0x2b, 0xff, 0x2a], 0).is_err());
    }
    #[test]
    fn rejects_bad_eh_clause_token() {
        // Fat header, one-byte `ret`, then a small catch clause with a null token.
        let mut body = vec![0x0b, 0x30, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x2a];
        body.resize(16, 0);
        body.extend_from_slice(&[1, 16, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0]);
        assert!(method_body(&body, 0).is_err());
    }

    #[test]
    fn rejects_null_required_coded_relationships() {
        for (table, column) in [
            (1, 0),  // TypeRef.ResolutionScope
            (9, 1),  // InterfaceImpl.Interface
            (12, 0), // CustomAttribute.Parent
            (12, 1), // CustomAttribute.Type
            (13, 0), // FieldMarshal.Parent
            (14, 1), // DeclSecurity.Parent
            (20, 2), // Event.EventType
            (24, 2), // MethodSemantics.Association
            (25, 1), // MethodImpl.MethodBody
            (25, 2), // MethodImpl.MethodDeclaration
            (42, 2), // GenericParam.Owner
            (44, 1), // GenericParamConstraint.Constraint
        ] {
            let Col::RequiredCoded(coded) = TABLES[table][column] else {
                panic!("table {table}, column {column} must be required coded");
            };
            assert!(validate_coded(&[0; 64], coded, 0, true).is_err());
        }
        assert!(validate_coded(&[0; 64], TYPE_DEF_OR_REF, 0, false).is_ok());
    }

    #[test]
    fn validates_refanyval_and_mkrefany_type_tokens() {
        let mut rows = [0; 64];
        rows[1] = 1;
        rows[2] = 1;
        let user = BTreeSet::new();
        let valid = [0xc2, 1, 0, 0, 2, 0xc6, 1, 0, 0, 1, 0x2a];
        assert_eq!(il_boundaries(&valid).unwrap(), vec![0, 5, 10, 11]);
        validate_code_tokens(&valid, &rows, &user).unwrap();

        let invalid = [0xc2, 1, 0, 0, 4];
        assert!(validate_code_tokens(&invalid, &rows, &user).is_err());
        assert!(il_boundaries(&[0xc4]).is_err());
        assert!(il_boundaries(&[0x77]).is_err());
    }

    #[test]
    fn validates_user_string_record_starts_and_encoding() {
        let bytes = [0, 3, b'A', 0, 0, 1, 0, 0];
        let metadata = Metadata {
            bytes: &bytes,
            heaps: Heaps {
                strings: Heap { start: 0, end: 0 },
                blob: Heap { start: 0, end: 0 },
                guid: Heap { start: 0, end: 0 },
                user: Heap {
                    start: 0,
                    end: bytes.len(),
                },
            },
        };
        let starts = validate_user_heap(&metadata).unwrap();
        assert_eq!(starts, BTreeSet::from([1, 5]));
        validate_code_tokens(&[0x72, 1, 0, 0, 0x70], &[0; 64], &starts).unwrap();
        assert!(validate_code_tokens(&[0x72, 2, 0, 0, 0x70], &[0; 64], &starts).is_err());

        let malformed = [0, 2, 0, 0];
        let metadata = Metadata {
            bytes: &malformed,
            heaps: Heaps {
                strings: Heap { start: 0, end: 0 },
                blob: Heap { start: 0, end: 0 },
                guid: Heap { start: 0, end: 0 },
                user: Heap {
                    start: 0,
                    end: malformed.len(),
                },
            },
        };
        assert!(validate_user_heap(&metadata).is_err());
    }

    #[test]
    fn validates_complete_list_ownership() {
        validate_list_starts(&[1, 2], 2).unwrap();
        assert!(validate_list_starts(&[2], 2).is_err());
    }

    #[test]
    fn requires_method_bodies_in_executable_sections() {
        validate_method_body_section(&method_test_pe(0x6000_0020), 0x1000, 0x1002).unwrap();
        assert!(
            validate_method_body_section(&method_test_pe(0x4000_0040), 0x1000, 0x1002).is_err()
        );
        assert!(validate_method_body_section(&method_test_pe(0x6000_0020), 0, 2).is_err());
    }
}
