// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Guest page table walking for kernel virtual addresses.

use crate::Error;
use crate::PhysMemory;
use std::collections::HashMap;

const PAGE_SIZE: u64 = 4096;

/// The root of a guest address space, as captured from VP registers.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PagingRoot {
    /// AArch64, translating upper-half addresses through `TTBR1_EL1`.
    Aarch64 {
        /// `TTBR1_EL1`.
        ttbr1: u64,
        /// `TCR_EL1`.
        tcr: u64,
    },
    /// x86-64 with 4- or 5-level paging.
    X86_64 {
        /// `CR3`.
        cr3: u64,
        /// Whether `CR4.LA57` is set.
        la57: bool,
    },
}

impl PagingRoot {
    /// Returns alternate roots to try when the kernel is not mapped by this
    /// one.
    ///
    /// With x86 page table isolation, a VP in user mode runs on the user page
    /// table, which maps almost none of the kernel. The kernel page table is
    /// the 8KiB-aligned page just below it.
    pub fn alternates(&self) -> Vec<PagingRoot> {
        match *self {
            PagingRoot::X86_64 { cr3, la57 } if cr3 & 0x1000 != 0 => {
                vec![PagingRoot::X86_64 {
                    cr3: cr3 & !0x1000,
                    la57,
                }]
            }
            _ => Vec::new(),
        }
    }
}

/// Translates kernel virtual addresses, caching page table pages.
///
/// The cache assumes page tables do not change while the translator is alive,
/// so create a new translator for each scan.
pub struct Translator<'a> {
    mem: &'a mut dyn PhysMemory,
    root: PagingRoot,
    tables: HashMap<u64, Box<[u64; 512]>>,
}

impl<'a> Translator<'a> {
    /// Creates a translator for `root`.
    pub fn new(mem: &'a mut dyn PhysMemory, root: PagingRoot) -> Self {
        Self {
            mem,
            root,
            tables: HashMap::new(),
        }
    }

    /// Returns the underlying memory.
    pub fn mem(&mut self) -> &mut dyn PhysMemory {
        self.mem
    }

    /// Translates `va` to a guest physical address, or `None` if unmapped.
    pub fn translate(&mut self, va: u64) -> Result<Option<u64>, Error> {
        match self.root {
            PagingRoot::Aarch64 { ttbr1, tcr } => self.translate_aarch64(ttbr1, tcr, va),
            PagingRoot::X86_64 { cr3, la57 } => self.translate_x86_64(cr3, la57, va),
        }
    }

    fn entry(&mut self, table: u64, index: u64) -> Result<u64, Error> {
        let page = table & !(PAGE_SIZE - 1);
        let base = ((table - page) / 8) as usize;
        if !self.tables.contains_key(&page) {
            let mut buf = [0u8; PAGE_SIZE as usize];
            self.mem
                .read_phys(page, &mut buf)
                .map_err(|source| Error::Read { gpa: page, source })?;
            let mut entries = Box::new([0u64; 512]);
            for (entry, bytes) in entries.iter_mut().zip(buf.as_chunks::<8>().0) {
                *entry = u64::from_le_bytes(*bytes);
            }
            self.tables.insert(page, entries);
        }
        Ok(self.tables[&page][base + index as usize])
    }

    fn translate_aarch64(&mut self, ttbr1: u64, tcr: u64, va: u64) -> Result<Option<u64>, Error> {
        const OA_MASK: u64 = 0x0000_ffff_ffff_f000;

        let t1sz = (tcr >> 16) & 0x3f;
        let tg1 = (tcr >> 30) & 3;
        if tg1 != 2 {
            return Err(Error::UnsupportedPaging("TTBR1 granule is not 4KiB"));
        }
        if !(16..=39).contains(&t1sz) {
            return Err(Error::UnsupportedPaging("unsupported TCR_EL1.T1SZ"));
        }
        let va_bits = 64 - t1sz;
        // TTBR1 covers only addresses whose upper bits are all ones.
        if va >> va_bits != (1u64 << t1sz) - 1 {
            return Ok(None);
        }

        let levels = (va_bits - 12).div_ceil(9);
        let start_level = 4 - levels;
        // Mask off CnP (bit 0) and the ASID (bits 63:48).
        let mut table = ttbr1 & 0x0000_ffff_ffff_fffe;
        for level in start_level..=3 {
            let shift = 12 + 9 * (3 - level);
            let bits = if level == start_level {
                va_bits - shift
            } else {
                9
            };
            let index = (va >> shift) & ((1 << bits) - 1);
            let desc = self.entry(table, index)?;
            if desc & 1 == 0 {
                return Ok(None);
            }
            if level == 3 {
                if desc & 2 == 0 {
                    return Ok(None);
                }
                return Ok(Some((desc & OA_MASK) | (va & (PAGE_SIZE - 1))));
            }
            if desc & 2 == 0 {
                // Block descriptor, valid at levels 1 and 2.
                if level == 0 {
                    return Ok(None);
                }
                let size = 1u64 << shift;
                return Ok(Some((desc & OA_MASK & !(size - 1)) | (va & (size - 1))));
            }
            table = desc & OA_MASK;
        }
        unreachable!()
    }

    fn translate_x86_64(&mut self, cr3: u64, la57: bool, va: u64) -> Result<Option<u64>, Error> {
        const ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;
        const PRESENT: u64 = 1;
        const LARGE: u64 = 1 << 7;

        let levels: u32 = if la57 { 5 } else { 4 };
        let va_bits = 12 + 9 * levels;
        // Require a canonical address.
        let upper = (va as i64) >> (va_bits - 1);
        if upper != 0 && upper != -1 {
            return Ok(None);
        }

        let mut table = cr3 & ADDR_MASK;
        for level in (1..=levels).rev() {
            let shift = 12 + 9 * (level - 1);
            let index = (va >> shift) & 0x1ff;
            let entry = self.entry(table, index)?;
            if entry & PRESENT == 0 {
                return Ok(None);
            }
            if level == 1 || (entry & LARGE != 0 && level <= 3) {
                let size = 1u64 << shift;
                return Ok(Some((entry & ADDR_MASK & !(size - 1)) | (va & (size - 1))));
            }
            table = entry & ADDR_MASK;
        }
        unreachable!()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Sparse guest memory for tests.
    #[derive(Default)]
    pub struct FakeMemory {
        pub pages: BTreeMap<u64, Vec<u8>>,
    }

    impl FakeMemory {
        pub fn write(&mut self, gpa: u64, data: &[u8]) {
            for (i, b) in data.iter().enumerate() {
                let addr = gpa + i as u64;
                let page = self
                    .pages
                    .entry(addr & !0xfff)
                    .or_insert_with(|| vec![0; 4096]);
                page[(addr & 0xfff) as usize] = *b;
            }
        }

        pub fn write_u64(&mut self, gpa: u64, v: u64) {
            self.write(gpa, &v.to_le_bytes());
        }
    }

    impl PhysMemory for FakeMemory {
        fn read_phys(&mut self, gpa: u64, buf: &mut [u8]) -> std::io::Result<()> {
            for (i, b) in buf.iter_mut().enumerate() {
                let addr = gpa + i as u64;
                *b = self
                    .pages
                    .get(&(addr & !0xfff))
                    .map_or(0, |p| p[(addr & 0xfff) as usize]);
            }
            Ok(())
        }
    }

    /// Builds a 3-level, 39-bit TTBR1 mapping of `va` to `pa` with 4K pages.
    pub fn map_aarch64_39(mem: &mut FakeMemory, root: u64, va: u64, pa: u64) {
        let l1 = (va >> 30) & 0x1ff;
        let l2 = (va >> 21) & 0x1ff;
        let l3 = (va >> 12) & 0x1ff;
        let l2_table = root + 0x1000;
        let l3_table = root + 0x2000;
        mem.write_u64(root + l1 * 8, l2_table | 3);
        mem.write_u64(l2_table + l2 * 8, l3_table | 3);
        mem.write_u64(l3_table + l3 * 8, pa | 0x703);
    }

    pub const TCR_39: u64 = (25 << 16) | (2 << 30);

    #[test]
    fn aarch64_page_and_block() {
        let mut mem = FakeMemory::default();
        let root = 0x10_0000;
        let va = 0xffff_ffc0_0801_2345;
        map_aarch64_39(&mut mem, root, va, 0x4000_0000);
        // A 2MiB block one L2 entry above.
        let block_va = va + 0x20_0000;
        let l2 = (block_va >> 21) & 0x1ff;
        mem.write_u64(root + 0x1000 + l2 * 8, 0x8020_0000 | 0x701);

        let mut t = Translator::new(
            &mut mem,
            PagingRoot::Aarch64 {
                ttbr1: root | 1,
                tcr: TCR_39,
            },
        );
        assert_eq!(t.translate(va).unwrap(), Some(0x4000_0345));
        assert_eq!(
            t.translate(block_va).unwrap(),
            Some(0x8020_0000 | (block_va & 0x1f_ffff))
        );
        assert_eq!(t.translate(va + 0x1000).unwrap(), None);
        // Lower-half addresses are not translated through TTBR1.
        assert_eq!(t.translate(0x1000).unwrap(), None);
    }

    #[test]
    fn x86_64_four_level() {
        let mut mem = FakeMemory::default();
        let cr3 = 0x20_0000;
        let va: u64 = 0xffff_ffff_8100_0123;
        let idx = |level: u32| (va >> (12 + 9 * (level - 1))) & 0x1ff;
        mem.write_u64(cr3 + idx(4) * 8, 0x20_1000 | 1);
        mem.write_u64(0x20_1000 + idx(3) * 8, 0x20_2000 | 1);
        // 2MiB large page.
        mem.write_u64(0x20_2000 + idx(2) * 8, 0x0100_0000 | 0x81);

        let mut t = Translator::new(&mut mem, PagingRoot::X86_64 { cr3, la57: false });
        assert_eq!(
            t.translate(va).unwrap(),
            Some(0x0100_0000 | (va & 0x1f_ffff))
        );
        // Non-canonical.
        assert_eq!(t.translate(0x0000_8000_0000_0000).unwrap(), None);
    }
}
