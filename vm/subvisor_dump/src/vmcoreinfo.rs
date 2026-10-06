// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Finding and parsing the Linux kernel's VMCOREINFO blob.
//!
//! VMCOREINFO is the kernel's self-description for crash tools: `OSRELEASE`,
//! the KASLR offset, a handful of key symbol addresses (including the page
//! table root and the kallsyms tables), struct field offsets, and the kernel
//! build ID. The kernel keeps it as a NUL-terminated block of `KEY=value`
//! lines in RAM so that kdump works without debug info.
//!
//! It is the equivalent of Windows' `KDBG`, and unlike KDBG it is plain text
//! and not obfuscated. Scanning for it needs no registers and no page tables,
//! so it is the first thing the tool does with a Linux snapshot.

use std::collections::HashMap;

/// Keys that reliably appear in a real VMCOREINFO block, used to tell it apart
/// from an unrelated `OSRELEASE=` string elsewhere in memory.
const MARKERS: &[&[u8]] = &[b"PAGESIZE=", b"SYMBOL(", b"NUMBER("];

/// A parsed VMCOREINFO block.
#[derive(Debug, Clone, Default)]
pub struct VmCoreInfo {
    /// Bare `KEY=value` entries (OSRELEASE, PAGESIZE, BUILD-ID, KERNELOFFSET).
    plain: HashMap<String, String>,
    /// `SYMBOL(name)=hexaddr` entries.
    symbols: HashMap<String, u64>,
    /// `NUMBER(name)=value` entries (decimal or `0x`-hex).
    numbers: HashMap<String, u64>,
    /// `OFFSET(struct.field)=decimal` entries.
    offsets: HashMap<String, u64>,
    /// The exact bytes of the block, for copying into an ELF note.
    raw: Vec<u8>,
}

impl VmCoreInfo {
    /// Scans guest memory for the VMCOREINFO block, returning the most
    /// complete one found (the kernel keeps a near-empty template too).
    pub fn find(memory: &[u8]) -> Option<Self> {
        let needle = b"OSRELEASE=";
        let mut best: Option<VmCoreInfo> = None;
        let mut search = 0;
        while let Some(rel) = find_sub(&memory[search..], needle) {
            let start = search + rel;
            search = start + 1;
            let end = memory[start..]
                .iter()
                .position(|&b| b == 0)
                .map_or(memory.len(), |p| start + p);
            let block = &memory[start..end];
            if block.len() > 4096 * 4 {
                continue;
            }
            if !MARKERS.iter().any(|m| find_sub(block, m).is_some()) {
                continue;
            }
            let parsed = Self::parse(block);
            if best
                .as_ref()
                .is_none_or(|b| parsed.symbols.len() > b.symbols.len())
            {
                best = Some(parsed);
            }
        }
        best
    }

    /// Parses a VMCOREINFO block body.
    pub fn parse(block: &[u8]) -> Self {
        let mut info = VmCoreInfo {
            raw: block.to_vec(),
            ..Default::default()
        };
        for line in block.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let line = String::from_utf8_lossy(line);
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if let Some(name) = parenthesized(key, "SYMBOL") {
                if let Some(v) = parse_u64(value) {
                    info.symbols.insert(name, v);
                }
            } else if let Some(name) = parenthesized(key, "NUMBER") {
                if let Some(v) = parse_u64(value) {
                    info.numbers.insert(name, v);
                }
            } else if let Some(name) = parenthesized(key, "OFFSET") {
                if let Some(v) = parse_u64(value) {
                    info.offsets.insert(name, v);
                }
            } else {
                info.plain.insert(key.to_string(), value.to_string());
            }
        }
        info
    }

    /// Returns a bare value such as `OSRELEASE`.
    pub fn plain(&self, key: &str) -> Option<&str> {
        self.plain.get(key).map(String::as_str)
    }

    /// The kernel release, e.g. `6.18.33`.
    pub fn osrelease(&self) -> Option<&str> {
        self.plain("OSRELEASE")
    }

    /// The kernel build ID, as a lowercase hex string, if present.
    pub fn build_id(&self) -> Option<&str> {
        self.plain("BUILD-ID")
    }

    /// The KASLR offset (`KERNELOFFSET`), defaulting to 0 when absent.
    pub fn kernel_offset(&self) -> u64 {
        self.plain("KERNELOFFSET").and_then(parse_u64).unwrap_or(0)
    }

    /// The guest page size, defaulting to 4096.
    pub fn page_size(&self) -> u64 {
        self.plain("PAGESIZE").and_then(parse_u64).unwrap_or(4096)
    }

    /// A `SYMBOL(name)` address.
    pub fn symbol(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    /// A `NUMBER(name)` value.
    pub fn number(&self, name: &str) -> Option<u64> {
        self.numbers.get(name).copied()
    }

    /// An `OFFSET(struct.field)` value.
    pub fn offset(&self, key: &str) -> Option<u64> {
        self.offsets.get(key).copied()
    }

    /// The exact block bytes, for an ELF `VMCOREINFO` note.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// The number of `SYMBOL` entries.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }
}

/// Extracts `name` from `KIND(name)`.
fn parenthesized(key: &str, kind: &str) -> Option<String> {
    let rest = key.strip_prefix(kind)?;
    let inner = rest.strip_prefix('(')?.strip_suffix(')')?;
    Some(inner.to_string())
}

/// Parses a decimal or `0x`-prefixed hex number. SYMBOL values are bare hex.
fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_digit()) {
        s.parse().ok()
    } else {
        // Bare hex (the SYMBOL form, e.g. `ffffffc080010000`).
        u64::from_str_radix(s, 16).ok()
    }
}

/// Finds the first occurrence of `needle` in `haystack`.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &str = "OSRELEASE=6.18.33\n\
         BUILD-ID=b89f5b19c7c1dec1509a816bef994a3ba6c8525b\n\
         PAGESIZE=4096\n\
         KERNELOFFSET=0\n\
         SYMBOL(swapper_pg_dir)=ffffffc08103c000\n\
         SYMBOL(_stext)=ffffffc080010000\n\
         SYMBOL(kallsyms_names)=ffffffc080d8e7f0\n\
         NUMBER(VA_BITS)=39\n\
         NUMBER(kimage_voffset)=0xffffffc03ee00000\n\
         OFFSET(task_struct.comm)=1544\n";

    #[test]
    fn parses_all_kinds() {
        let info = VmCoreInfo::parse(BLOCK.as_bytes());
        assert_eq!(info.osrelease(), Some("6.18.33"));
        assert_eq!(
            info.build_id(),
            Some("b89f5b19c7c1dec1509a816bef994a3ba6c8525b")
        );
        assert_eq!(info.page_size(), 4096);
        assert_eq!(info.kernel_offset(), 0);
        assert_eq!(info.symbol("swapper_pg_dir"), Some(0xffff_ffc0_8103_c000));
        assert_eq!(info.symbol("_stext"), Some(0xffff_ffc0_8001_0000));
        assert_eq!(info.number("VA_BITS"), Some(39));
        assert_eq!(info.number("kimage_voffset"), Some(0xffff_ffc0_3ee0_0000));
        assert_eq!(info.offset("task_struct.comm"), Some(1544));
        assert_eq!(info.symbol_count(), 3);
    }

    #[test]
    fn finds_block_in_memory() {
        let mut mem = vec![0u8; 0x4000];
        // Junk OSRELEASE= without markers earlier in memory should be skipped.
        mem[0x100..0x10a].copy_from_slice(b"OSRELEASE=");
        mem[0x10a..0x110].copy_from_slice(b"junk?\0");
        // Real block later, NUL-terminated.
        let at = 0x2000;
        mem[at..at + BLOCK.len()].copy_from_slice(BLOCK.as_bytes());
        mem[at + BLOCK.len()] = 0;

        let info = VmCoreInfo::find(&mem).expect("block found");
        assert_eq!(info.osrelease(), Some("6.18.33"));
        assert_eq!(info.symbol("_stext"), Some(0xffff_ffc0_8001_0000));
        assert_eq!(info.raw(), BLOCK.as_bytes());
    }

    #[test]
    fn prefers_block_with_more_symbols() {
        let mut mem = vec![0u8; 0x6000];
        let sparse = "OSRELEASE=6.1.0\nPAGESIZE=4096\n";
        mem[0x1000..0x1000 + sparse.len()].copy_from_slice(sparse.as_bytes());
        let at = 0x3000;
        mem[at..at + BLOCK.len()].copy_from_slice(BLOCK.as_bytes());
        let info = VmCoreInfo::find(&mem).unwrap();
        // The richer block (3 symbols) must win over the 2-line one.
        assert_eq!(info.osrelease(), Some("6.18.33"));
    }

    #[test]
    fn no_block_returns_none() {
        let mem = vec![0u8; 0x1000];
        assert!(VmCoreInfo::find(&mem).is_none());
    }

    #[test]
    fn number_parses_decimal_and_hex() {
        assert_eq!(parse_u64("39"), Some(39));
        assert_eq!(parse_u64("0xdead"), Some(0xdead));
        assert_eq!(parse_u64("ffffffc080010000"), Some(0xffff_ffc0_8001_0000));
        assert_eq!(parse_u64("not-a-number"), None);
    }
}
