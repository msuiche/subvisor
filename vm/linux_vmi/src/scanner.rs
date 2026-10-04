// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Passive kernel integrity scanner.
//!
//! The first scan records a baseline: a SHA-256 hash of every page of kernel
//! text and rodata, plus the contents of `sys_call_table`. Later scans compare
//! against it. The baseline is only as trustworthy as the kernel at the time
//! of the first scan, so take it as early as possible.
//!
//! Some kernel text legitimately changes after boot (static keys and jump
//! labels, ftrace, alternatives applied late). Such changes are reported like
//! any other, with the symbol containing the change, so they can be triaged.

use crate::Error;
use crate::PhysMemory;
use crate::paging::PagingRoot;
use crate::paging::Translator;
use crate::symbols::SymbolTable;
use sha2::Digest;
use sha2::Sha256;
use std::fmt;

const PAGE_SIZE: u64 = 4096;
/// The largest physically contiguous run read in one request.
const MAX_RUN: u64 = 1024 * 1024;
/// Upper bound on the number of system call table entries.
const MAX_SYSCALLS: u64 = 2048;
/// Upper bound on the size of a hashed region.
const MAX_REGION: u64 = 1 << 30;

type PageHash = [u8; 32];

/// A hashed kernel region.
#[derive(Debug, Clone)]
struct Region {
    name: &'static str,
    start: u64,
    end: u64,
}

/// The kernel layout derived from the symbol table.
#[derive(Debug, Clone)]
struct Layout {
    regions: Vec<Region>,
    text: (u64, u64),
    syscall_table: Option<(u64, u64)>,
}

impl Region {
    /// Builds a page-aligned region, rejecting empty, inverted, or oversized
    /// ranges. The symbols come from the guest, so they are not trusted.
    fn new(name: &'static str, start: u64, end: u64) -> Result<Self, Error> {
        let start = start & !(PAGE_SIZE - 1);
        let end = end
            .checked_next_multiple_of(PAGE_SIZE)
            .ok_or(Error::InvalidRegion(name))?;
        if start >= end || end - start > MAX_REGION {
            return Err(Error::InvalidRegion(name));
        }
        Ok(Self { name, start, end })
    }
}

impl Layout {
    fn new(symbols: &SymbolTable) -> Result<Self, Error> {
        let sym = |name: &'static str| symbols.addr(name).ok_or(Error::MissingSymbol(name));
        let stext = sym("_stext")?;
        let etext = sym("_etext")?;
        let mut regions = vec![Region::new("text", stext, etext)?];
        if let (Some(start), Some(end)) =
            (symbols.addr("__start_rodata"), symbols.addr("__end_rodata"))
        {
            regions.push(Region::new("rodata", start, end)?);
        }

        let syscall_table = symbols.addr("sys_call_table").map(|addr| {
            let count = symbols
                .next_addr_after("sys_call_table")
                .map_or(MAX_SYSCALLS, |end| (end - addr) / 8);
            (addr, count.min(MAX_SYSCALLS))
        });
        let syscall_table =
            syscall_table.filter(|&(addr, count)| addr.checked_add(count * 8).is_some());

        Ok(Self {
            regions,
            text: (stext, etext),
            syscall_table,
        })
    }
}

/// A difference from the baseline, or a structural violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A page's contents differ from the baseline.
    PageModified {
        /// The region name.
        region: &'static str,
        /// The page's virtual address.
        va: u64,
        /// The symbol at the start of the page.
        symbol: String,
    },
    /// A page's mapping state differs from the baseline.
    PageMappingChanged {
        /// The region name.
        region: &'static str,
        /// The page's virtual address.
        va: u64,
        /// Whether the page is mapped now.
        mapped: bool,
    },
    /// A system call table entry points outside kernel text.
    SyscallOutsideText {
        /// The table index.
        index: u64,
        /// The entry's target.
        target: u64,
    },
    /// A system call table entry differs from the baseline.
    SyscallChanged {
        /// The table index.
        index: u64,
        /// The baseline target, as `symbol+offset`.
        old: String,
        /// The current target, as `symbol+offset` or an address.
        new: String,
    },
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Finding::PageModified { region, va, symbol } => {
                write!(f, "{region} page {va:#x} ({symbol}) modified")
            }
            Finding::PageMappingChanged { region, va, mapped } => {
                let state = if *mapped { "mapped" } else { "unmapped" };
                write!(f, "{region} page {va:#x} is now {state}")
            }
            Finding::SyscallOutsideText { index, target } => {
                write!(
                    f,
                    "sys_call_table[{index}] = {target:#x} is outside kernel text"
                )
            }
            Finding::SyscallChanged { index, old, new } => {
                write!(f, "sys_call_table[{index}] changed: {old} -> {new}")
            }
        }
    }
}

/// Per-region scan statistics.
#[derive(Debug, Clone)]
pub struct RegionSummary {
    /// The region name.
    pub name: &'static str,
    /// The region's start address.
    pub start: u64,
    /// The guest physical address of the region's first page, if mapped.
    pub start_gpa: Option<u64>,
    /// The number of pages in the region.
    pub pages: usize,
    /// The number of pages that are not mapped.
    pub unmapped: usize,
}

/// The result of a scan.
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// True if this scan recorded the baseline.
    pub baseline: bool,
    /// The regions that were hashed.
    pub regions: Vec<RegionSummary>,
    /// The number of system call table entries checked.
    pub syscalls: usize,
    /// The guest physical address of the system call table, if present.
    pub syscall_table_gpa: Option<u64>,
    /// Everything that differs from the baseline.
    pub findings: Vec<Finding>,
}

impl fmt::Display for ScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.baseline { "baseline" } else { "scan" };
        writeln!(f, "{kind}: {} finding(s)", self.findings.len())?;
        for r in &self.regions {
            write!(f, "  {}: {} pages at {:#x}", r.name, r.pages, r.start)?;
            if let Some(gpa) = r.start_gpa {
                write!(f, " (gpa {gpa:#x})")?;
            }
            writeln!(f, ", {} unmapped", r.unmapped)?;
        }
        write!(f, "  sys_call_table: {} entries", self.syscalls)?;
        if let Some(gpa) = self.syscall_table_gpa {
            write!(f, " (gpa {gpa:#x})")?;
        }
        writeln!(f)?;
        for finding in &self.findings {
            writeln!(f, "  {finding}")?;
        }
        Ok(())
    }
}

struct Baseline {
    pages: Vec<Vec<Option<PageHash>>>,
    syscalls: Vec<u64>,
}

/// Scans a Linux kernel for changes to code and read-only data.
pub struct Scanner {
    symbols: SymbolTable,
    layout: Layout,
    baseline: Option<Baseline>,
}

impl Scanner {
    /// Creates a scanner from the kernel's symbol table.
    ///
    /// `_stext` and `_etext` are required. Rodata and the system call table
    /// are checked when their symbols are present.
    pub fn new(symbols: SymbolTable) -> Result<Self, Error> {
        let layout = Layout::new(&symbols)?;
        Ok(Self {
            symbols,
            layout,
            baseline: None,
        })
    }

    /// Returns true if a baseline has been recorded.
    pub fn has_baseline(&self) -> bool {
        self.baseline.is_some()
    }

    /// Discards the baseline so that the next scan records a new one.
    pub fn reset_baseline(&mut self) {
        self.baseline = None;
    }

    /// Scans the kernel through `root`. The first scan records the baseline.
    pub fn scan(
        &mut self,
        mem: &mut dyn PhysMemory,
        root: PagingRoot,
    ) -> Result<ScanReport, Error> {
        let root = self.kernel_root(mem, root)?;
        let mut t = Translator::new(mem, root);

        let mut pages = Vec::new();
        let mut regions = Vec::new();
        for region in &self.layout.regions {
            let hashes = hash_region(&mut t, region)?;
            regions.push(RegionSummary {
                name: region.name,
                start: region.start,
                start_gpa: t.translate(region.start)?,
                pages: hashes.len(),
                unmapped: hashes.iter().filter(|h| h.is_none()).count(),
            });
            pages.push(hashes);
        }

        let (syscalls, syscall_table_gpa) = match self.layout.syscall_table {
            Some((addr, count)) => (read_u64s(&mut t, addr, count)?, t.translate(addr)?),
            None => (Vec::new(), None),
        };

        let mut findings = Vec::new();
        let (stext, etext) = self.layout.text;
        for (index, &target) in syscalls.iter().enumerate() {
            if !(stext..etext).contains(&target) {
                findings.push(Finding::SyscallOutsideText {
                    index: index as u64,
                    target,
                });
            }
        }

        let report_baseline = self.baseline.is_none();
        match &self.baseline {
            None => {
                self.baseline = Some(Baseline {
                    pages,
                    syscalls: syscalls.clone(),
                });
            }
            Some(baseline) => {
                self.diff_pages(baseline, &pages, &mut findings);
                for (index, (&old, &new)) in baseline.syscalls.iter().zip(&syscalls).enumerate() {
                    if old != new {
                        findings.push(Finding::SyscallChanged {
                            index: index as u64,
                            old: self.symbols.describe(old),
                            new: self.symbols.describe(new),
                        });
                    }
                }
            }
        }

        Ok(ScanReport {
            baseline: report_baseline,
            regions,
            syscalls: syscalls.len(),
            syscall_table_gpa,
            findings,
        })
    }

    fn diff_pages(
        &self,
        baseline: &Baseline,
        pages: &[Vec<Option<PageHash>>],
        findings: &mut Vec<Finding>,
    ) {
        for ((region, old), new) in self.layout.regions.iter().zip(&baseline.pages).zip(pages) {
            for (i, (old, new)) in old.iter().zip(new).enumerate() {
                let va = region.start + i as u64 * PAGE_SIZE;
                match (old, new) {
                    (Some(old), Some(new)) if old != new => {
                        findings.push(Finding::PageModified {
                            region: region.name,
                            va,
                            symbol: self.symbols.describe(va),
                        });
                    }
                    (Some(_), None) | (None, Some(_)) => {
                        findings.push(Finding::PageMappingChanged {
                            region: region.name,
                            va,
                            mapped: new.is_some(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    /// Returns a root that maps kernel text, trying alternates if needed.
    fn kernel_root(&self, mem: &mut dyn PhysMemory, root: PagingRoot) -> Result<PagingRoot, Error> {
        let (stext, _) = self.layout.text;
        for candidate in std::iter::once(root).chain(root.alternates()) {
            if Translator::new(mem, candidate).translate(stext)?.is_some() {
                return Ok(candidate);
            }
        }
        Err(Error::KernelNotMapped(stext))
    }
}

/// Hashes each page of `region`, reading physically contiguous runs at once.
fn hash_region(t: &mut Translator<'_>, region: &Region) -> Result<Vec<Option<PageHash>>, Error> {
    let count = ((region.end - region.start) / PAGE_SIZE) as usize;
    let mut gpas = Vec::with_capacity(count);
    for i in 0..count {
        gpas.push(t.translate(region.start + i as u64 * PAGE_SIZE)?);
    }

    let mut hashes = vec![None; count];
    let mut buf = Vec::new();
    let mut i = 0;
    while i < count {
        let Some(start) = gpas[i] else {
            i += 1;
            continue;
        };
        let mut n = 1;
        while i + n < count
            && (n as u64) * PAGE_SIZE < MAX_RUN
            && gpas[i + n] == Some(start + n as u64 * PAGE_SIZE)
        {
            n += 1;
        }
        buf.resize(n * PAGE_SIZE as usize, 0);
        t.mem()
            .read_phys(start, &mut buf)
            .map_err(|source| Error::Read { gpa: start, source })?;
        for (j, page) in buf
            .as_chunks::<{ PAGE_SIZE as usize }>()
            .0
            .iter()
            .enumerate()
        {
            hashes[i + j] = Some(Sha256::digest(page).into());
        }
        i += n;
    }
    Ok(hashes)
}

/// Reads `count` little-endian u64s at virtual address `va`.
fn read_u64s(t: &mut Translator<'_>, va: u64, count: u64) -> Result<Vec<u64>, Error> {
    let mut bytes = vec![0u8; (count * 8) as usize];
    let mut done = 0;
    while done < bytes.len() {
        let cur = va + done as u64;
        let gpa = t.translate(cur)?.ok_or(Error::KernelNotMapped(cur))?;
        let len = ((PAGE_SIZE - (cur & (PAGE_SIZE - 1))) as usize).min(bytes.len() - done);
        t.mem()
            .read_phys(gpa, &mut bytes[done..done + len])
            .map_err(|source| Error::Read { gpa, source })?;
        done += len;
    }
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| u64::from_le_bytes(*b))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::tests::FakeMemory;
    use crate::paging::tests::TCR_39;
    use crate::paging::tests::map_aarch64_39;

    const ROOT: u64 = 0x10_0000;
    const TEXT: u64 = 0xffff_ffc0_0801_0000;
    const TEXT_PA: u64 = 0x4001_0000;
    const RODATA: u64 = TEXT + 0x4000;
    const RODATA_PA: u64 = TEXT_PA + 0x4000;

    fn setup() -> (FakeMemory, Scanner, PagingRoot) {
        let mut mem = FakeMemory::default();
        for i in 0..6 {
            map_aarch64_39(
                &mut mem,
                ROOT,
                TEXT + i * PAGE_SIZE,
                TEXT_PA + i * PAGE_SIZE,
            );
            mem.write(TEXT_PA + i * PAGE_SIZE, &[i as u8 + 1; 4096]);
        }
        // Two syscalls pointing into text.
        mem.write_u64(RODATA_PA, TEXT + 0x10);
        mem.write_u64(RODATA_PA + 8, TEXT + 0x2000);

        let symbols = SymbolTable::parse(&format!(
            "{:x} T _stext\n{:x} T do_thing\n{:x} T _etext\n\
             {:x} D __start_rodata\n{:x} D sys_call_table\n{:x} D after_table\n\
             {:x} D __end_rodata\n",
            TEXT,
            TEXT + 0x2000,
            TEXT + 0x4000,
            RODATA,
            RODATA,
            RODATA + 16,
            RODATA + 0x2000,
        ));
        let root = PagingRoot::Aarch64 {
            ttbr1: ROOT,
            tcr: TCR_39,
        };
        (mem, Scanner::new(symbols).unwrap(), root)
    }

    #[test]
    fn clean_rescan_has_no_findings() {
        let (mut mem, mut scanner, root) = setup();
        let report = scanner.scan(&mut mem, root).unwrap();
        assert!(report.baseline);
        assert!(report.findings.is_empty(), "{report}");
        assert_eq!(report.regions[0].pages, 4);
        assert_eq!(report.regions[1].pages, 2);
        assert_eq!(report.syscalls, 2);

        let report = scanner.scan(&mut mem, root).unwrap();
        assert!(!report.baseline);
        assert!(report.findings.is_empty(), "{report}");
    }

    #[test]
    fn detects_text_and_syscall_changes() {
        let (mut mem, mut scanner, root) = setup();
        scanner.scan(&mut mem, root).unwrap();

        mem.write(TEXT_PA + 0x2000 + 0x40, &[0xd4, 0x20, 0x00, 0x00]);
        mem.write_u64(RODATA_PA + 8, 0xffff_ff80_0000_1000);

        let report = scanner.scan(&mut mem, root).unwrap();
        assert_eq!(
            report.findings,
            vec![
                Finding::SyscallOutsideText {
                    index: 1,
                    target: 0xffff_ff80_0000_1000,
                },
                Finding::PageModified {
                    region: "text",
                    va: TEXT + 0x2000,
                    symbol: "do_thing".into(),
                },
                Finding::PageModified {
                    region: "rodata",
                    va: RODATA,
                    symbol: "sys_call_table".into(),
                },
                Finding::SyscallChanged {
                    index: 1,
                    old: "do_thing".into(),
                    new: "0xffffff8000001000".into(),
                },
            ]
        );
    }

    #[test]
    fn rejects_invalid_layout() {
        let inverted = SymbolTable::parse("ffffffc008800000 T _stext\nffffffc008000000 T _etext\n");
        assert!(matches!(
            Scanner::new(inverted),
            Err(Error::InvalidRegion("text"))
        ));
        let huge = SymbolTable::parse("ffffffc000000000 T _stext\nfffffffffffff000 T _etext\n");
        assert!(matches!(
            Scanner::new(huge),
            Err(Error::InvalidRegion("text"))
        ));
    }

    #[test]
    fn detects_unmapped_page() {
        let (mut mem, mut scanner, root) = setup();
        scanner.scan(&mut mem, root).unwrap();
        // Clear the L3 entry for the second text page.
        let l3 = ((TEXT + PAGE_SIZE) >> 12) & 0x1ff;
        mem.write_u64(ROOT + 0x2000 + l3 * 8, 0);
        let report = scanner.scan(&mut mem, root).unwrap();
        assert_eq!(
            report.findings,
            vec![Finding::PageMappingChanged {
                region: "text",
                va: TEXT + PAGE_SIZE,
                mapped: false,
            }]
        );
    }
}
