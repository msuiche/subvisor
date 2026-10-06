// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Decoding the kernel's in-memory `kallsyms` tables.
//!
//! Given the table addresses from VMCOREINFO and a page-table translator, this
//! reconstructs the full symbol table from guest memory. No `/proc/kallsyms`
//! from the guest and no external debug info are needed, so the symbols cannot
//! be falsified by a compromised guest the way a supplied `kallsyms.txt` can.
//!
//! The on-disk format (see the kernel's `kernel/kallsyms.c`):
//! - `kallsyms_num_syms`: a `u32` count.
//! - `kallsyms_names`: a stream of length-prefixed, token-compressed names.
//!   The first character of each decoded name is its `nm`-style type letter.
//! - `kallsyms_token_table` / `kallsyms_token_index`: the compression
//!   dictionary (256 tokens).
//! - `kallsyms_offsets` + `kallsyms_relative_base`: per-symbol addresses,
//!   either base-relative or in the "absolute percpu" encoding. Which one is in
//!   use is detected by checking the decoded `_stext` against VMCOREINFO.

use crate::vmcoreinfo::VmCoreInfo;
use linux_vmi::Error as VmiError;
use linux_vmi::paging::Translator;
use linux_vmi::symbols::Symbol;
use linux_vmi::symbols::SymbolTable;

/// A kallsyms decoding error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// VMCOREINFO lacks a symbol needed to locate the tables.
    #[error("VMCOREINFO is missing SYMBOL({0}); kernel may be too old")]
    MissingSymbol(&'static str),
    /// A table address did not translate through the page tables.
    #[error("kallsyms table {0} at {1:#x} is not mapped")]
    Unmapped(&'static str, u64),
    /// Reading guest memory failed.
    #[error(transparent)]
    Vmi(#[from] VmiError),
    /// The tables were internally inconsistent.
    #[error("kallsyms tables are malformed: {0}")]
    Malformed(&'static str),
}

/// A decoded name with its type letter.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedName {
    kind: char,
    name: String,
}

/// Expands one name from the `kallsyms_names` stream starting at `pos`.
///
/// Returns the decoded `(kind, name)` and the offset of the next entry.
fn expand_one(
    names: &[u8],
    pos: usize,
    token_table: &[u8],
    token_index: &[u16; 256],
) -> Result<(DecodedName, usize), Error> {
    let mut i = pos;
    let mut len = *names.get(i).ok_or(Error::Malformed("names truncated"))? as usize;
    i += 1;
    // A set MSB marks a "big" symbol whose length needs a second byte.
    if len & 0x80 != 0 {
        let hi = *names.get(i).ok_or(Error::Malformed("names truncated"))? as usize;
        len = (len & 0x7f) | (hi << 7);
        i += 1;
    }
    let tokens = names
        .get(i..i + len)
        .ok_or(Error::Malformed("names truncated"))?;
    let mut decoded = String::new();
    for &tok in tokens {
        let start = token_index[tok as usize] as usize;
        let s = token_table
            .get(start..)
            .ok_or(Error::Malformed("token index out of range"))?;
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        decoded.push_str(&String::from_utf8_lossy(&s[..end]));
    }
    let mut chars = decoded.chars();
    let kind = chars.next().ok_or(Error::Malformed("empty symbol name"))?;
    Ok((
        DecodedName {
            kind,
            name: chars.as_str().to_string(),
        },
        i + len,
    ))
}

/// Expands all `count` names from the stream.
fn expand_all(
    names: &[u8],
    count: usize,
    token_table: &[u8],
    token_index: &[u16; 256],
) -> Result<Vec<DecodedName>, Error> {
    let mut out = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        let (name, next) = expand_one(names, pos, token_table, token_index)?;
        out.push(name);
        pos = next;
    }
    Ok(out)
}

/// Computes a symbol address from its offset entry.
///
/// Base-relative kernels (arm64) add the unsigned offset to the base. "Absolute
/// percpu" kernels (common on x86-64) treat a non-negative offset as an
/// absolute address and a negative one as `relative_base - 1 - offset`.
fn symbol_addr(offset: i32, relative_base: u64, absolute_percpu: bool) -> u64 {
    if !absolute_percpu {
        return relative_base.wrapping_add(u64::from(offset as u32));
    }
    if offset >= 0 {
        offset as u64
    } else {
        (relative_base as i128 - 1 - i128::from(offset)) as u64
    }
}

/// Picks the offset encoding that makes the decoded `_stext` match VMCOREINFO.
fn detect_absolute_percpu(
    offsets: &[i32],
    relative_base: u64,
    names: &[DecodedName],
    expected_stext: u64,
) -> Result<bool, Error> {
    let stext_idx = names
        .iter()
        .position(|n| n.name == "_stext")
        .ok_or(Error::Malformed("_stext not found in names"))?;
    let off = *offsets
        .get(stext_idx)
        .ok_or(Error::Malformed("offsets shorter than names"))?;
    for percpu in [false, true] {
        if symbol_addr(off, relative_base, percpu) == expected_stext {
            return Ok(percpu);
        }
    }
    Err(Error::Malformed(
        "decoded _stext does not match VMCOREINFO under either encoding",
    ))
}

/// Builds a [`SymbolTable`] from decoded names and offsets.
fn build_table(
    names: &[DecodedName],
    offsets: &[i32],
    relative_base: u64,
    absolute_percpu: bool,
) -> SymbolTable {
    let symbols = names
        .iter()
        .zip(offsets)
        .map(|(n, &off)| Symbol {
            addr: symbol_addr(off, relative_base, absolute_percpu),
            kind: n.kind,
            name: n.name.clone(),
        })
        .collect();
    SymbolTable::from_symbols(symbols)
}

/// Reads `len` bytes at kernel virtual address `va` through the translator.
fn read_va(t: &mut Translator<'_>, va: u64, len: usize) -> Result<Vec<u8>, Error> {
    const PAGE: u64 = 4096;
    let mut out = vec![0u8; len];
    let mut done = 0;
    while done < len {
        let cur = va + done as u64;
        let gpa = t.translate(cur)?.ok_or(Error::Unmapped("data", cur))?;
        let chunk = ((PAGE - (cur & (PAGE - 1))) as usize).min(len - done);
        t.mem()
            .read_phys(gpa, &mut out[done..done + chunk])
            .map_err(|source| VmiError::Read { gpa, source })?;
        done += chunk;
    }
    Ok(out)
}

fn read_u32(t: &mut Translator<'_>, va: u64) -> Result<u32, Error> {
    let b = read_va(t, va, 4)?;
    Ok(u32::from_le_bytes(b.try_into().unwrap()))
}

fn read_u64(t: &mut Translator<'_>, va: u64) -> Result<u64, Error> {
    let b = read_va(t, va, 8)?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

/// Decodes the full kallsyms table from guest memory.
///
/// `translator` must use the kernel page-table root (from the saved
/// `TTBR1_EL1`/`CR3`). `info` supplies the table addresses.
pub fn decode(t: &mut Translator<'_>, info: &VmCoreInfo) -> Result<SymbolTable, Error> {
    let sym = |name: &'static str| info.symbol(name).ok_or(Error::MissingSymbol(name));

    let num_syms = read_u32(t, sym("kallsyms_num_syms")?)? as usize;
    if num_syms == 0 || num_syms > 4_000_000 {
        return Err(Error::Malformed("implausible kallsyms_num_syms"));
    }
    let relative_base = read_u64(t, sym("kallsyms_relative_base")?)?;

    // The token index is 256 u16 entries.
    let token_index_bytes = read_va(t, sym("kallsyms_token_index")?, 512)?;
    let mut token_index = [0u16; 256];
    for (slot, chunk) in token_index
        .iter_mut()
        .zip(token_index_bytes.as_chunks::<2>().0)
    {
        *slot = u16::from_le_bytes(*chunk);
    }
    // The token table runs from its start to the last token's NUL. Its length
    // is bounded by the final index entry plus the longest token; read a
    // generous fixed window and let indexing stop at NULs.
    let token_table = read_va(t, sym("kallsyms_token_table")?, 0x4000)?;

    // Offsets: num_syms i32 entries.
    let offsets_bytes = read_va(t, sym("kallsyms_offsets")?, num_syms * 4)?;
    let offsets: Vec<i32> = offsets_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| i32::from_le_bytes(*c))
        .collect();

    // Names: variable length. Read a window sized from the symbol count (names
    // average well under 32 bytes each).
    let names_bytes = read_va(t, sym("kallsyms_names")?, num_syms * 32 + 0x1000)?;
    let names = expand_all(&names_bytes, num_syms, &token_table, &token_index)?;

    let expected_stext = sym("_stext")?;
    let absolute_percpu = detect_absolute_percpu(&offsets, relative_base, &names, expected_stext)?;

    Ok(build_table(
        &names,
        &offsets,
        relative_base,
        absolute_percpu,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tiny kallsyms name stream and dictionary for three symbols.
    ///
    /// Tokens: 0 -> "T", 1 -> "t", 2 -> "_stext", 3 -> "helper", 4 -> "_etext".
    fn fixture() -> (Vec<u8>, Vec<u8>, [u16; 256], Vec<DecodedName>) {
        let tokens: [&[u8]; 5] = [b"T", b"t", b"_stext", b"helper", b"_etext"];
        let mut token_table = Vec::new();
        let mut token_index = [0u16; 256];
        for (i, tok) in tokens.iter().enumerate() {
            token_index[i] = token_table.len() as u16;
            token_table.extend_from_slice(tok);
            token_table.push(0);
        }
        // Each name entry: [len][token bytes]. "T"+"_stext" = tokens [0,2].
        let entries: [&[u8]; 3] = [&[0u8, 2], &[1u8, 3], &[0u8, 4]];
        let mut names = Vec::new();
        for e in entries {
            names.push(e.len() as u8);
            names.extend_from_slice(e);
        }
        let decoded = vec![
            DecodedName {
                kind: 'T',
                name: "_stext".into(),
            },
            DecodedName {
                kind: 't',
                name: "helper".into(),
            },
            DecodedName {
                kind: 'T',
                name: "_etext".into(),
            },
        ];
        (names, token_table, token_index, decoded)
    }

    #[test]
    fn expands_names() {
        let (names, tt, ti, expected) = fixture();
        let got = expand_all(&names, 3, &tt, &ti).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn expands_big_symbol() {
        // A name of 200 token bytes needs the two-byte length form.
        let mut token_table = vec![0u8]; // token 0 = empty string at index 0
        token_table.extend_from_slice(b"x\0");
        let mut token_index = [0u16; 256];
        token_index[1] = 1; // token 1 -> "x"
        token_index[0] = 2; // token 0 -> "T"
        token_table.extend_from_slice(b"T\0");
        token_index[0] = (token_table.len() - 2) as u16;

        let len = 200usize;
        let mut names = vec![((len & 0x7f) | 0x80) as u8, (len >> 7) as u8];
        names.push(0); // type token "T"
        names.extend(std::iter::repeat_n(1u8, len - 1)); // 199 "x"
        let got = expand_all(&names, 1, &token_table, &token_index).unwrap();
        assert_eq!(got[0].kind, 'T');
        assert_eq!(got[0].name.len(), len - 1);
        assert!(got[0].name.chars().all(|c| c == 'x'));
    }

    #[test]
    fn base_relative_addresses() {
        let base = 0xffff_ffc0_8000_0000;
        let offsets = [0x10_000i32, 0x10_100, 0x80_0000];
        let addr = |i: usize| symbol_addr(offsets[i], base, false);
        assert_eq!(addr(0), base + 0x10_000);
        assert_eq!(addr(2), base + 0x80_0000);
    }

    #[test]
    fn absolute_percpu_addresses() {
        let base = 0xffff_ffff_8000_0000;
        // Positive offset is absolute; negative uses base - 1 - offset.
        assert_eq!(symbol_addr(0x1000, base, true), 0x1000);
        assert_eq!(symbol_addr(-0x10, base, true), base - 1 + 0x10);
    }

    #[test]
    fn detects_encoding_from_stext() {
        let (_, _, _, names) = fixture();
        let base = 0xffff_ffc0_8000_0000;
        // Encode _stext (index 0) base-relative at +0x10000.
        let offsets = [0x10_000i32, 0x10_100, 0x80_0000];
        let stext = base + 0x10_000;
        assert!(!detect_absolute_percpu(&offsets, base, &names, stext).unwrap());

        // Now encode _stext absolute.
        let offsets_abs = [stext as i32, 0, 0];
        // Low 32 bits only, so pick a base/stext within 32-bit reach for the test.
        let base2 = 0xffff_ffff_8000_0000u64;
        let stext2 = 0x10_0000u64;
        let offsets_abs = [stext2 as i32, offsets_abs[1], offsets_abs[2]];
        assert!(detect_absolute_percpu(&offsets_abs, base2, &names, stext2).unwrap());
    }

    #[test]
    fn builds_sorted_symbol_table() {
        let (_, _, _, names) = fixture();
        let base = 0xffff_ffc0_8000_0000;
        let offsets = [0x10_000i32, 0x10_100, 0x80_0000];
        let table = build_table(&names, &offsets, base, false);
        assert_eq!(table.addr("_stext"), Some(base + 0x10_000));
        assert_eq!(table.addr("helper"), Some(base + 0x10_100));
        assert_eq!(table.describe(base + 0x10_104), "helper+0x4");
    }

    #[test]
    fn mismatch_is_reported() {
        let (_, _, _, names) = fixture();
        let base = 0xffff_ffc0_8000_0000;
        let offsets = [0x10_000i32, 0, 0];
        // Expected _stext that matches neither encoding.
        let err = detect_absolute_percpu(&offsets, base, &names, 0xdead_beef);
        assert!(matches!(err, Err(Error::Malformed(_))));
    }
}
