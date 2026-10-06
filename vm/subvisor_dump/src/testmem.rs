// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Shared test helpers: a sparse fake guest memory and a small AArch64
//! page-table builder, used by module tests that need a [`Translator`].

#![cfg(test)]

use linux_vmi::PhysMemory;
use std::collections::BTreeMap;

/// Sparse, page-granular guest physical memory.
#[derive(Default)]
pub struct FakeMem {
    pages: BTreeMap<u64, Vec<u8>>,
}

impl FakeMem {
    /// Writes bytes at a guest physical address.
    pub fn write(&mut self, gpa: u64, data: &[u8]) {
        for (i, b) in data.iter().enumerate() {
            let addr = gpa + i as u64;
            self.pages
                .entry(addr & !0xfff)
                .or_insert_with(|| vec![0; 4096])[(addr & 0xfff) as usize] = *b;
        }
    }

    /// Writes a little-endian u64.
    pub fn write_u64(&mut self, gpa: u64, v: u64) {
        self.write(gpa, &v.to_le_bytes());
    }

    /// Maps `va` to `pa` (4KiB page) in a 3-level, 39-bit TTBR1 table rooted at
    /// `root`, allocating intermediate tables at `root+0x1000`/`root+0x2000`.
    pub fn map_39(&mut self, root: u64, va: u64, pa: u64) {
        let l1 = (va >> 30) & 0x1ff;
        let l2 = (va >> 21) & 0x1ff;
        let l3 = (va >> 12) & 0x1ff;
        let l2_table = root + 0x1000;
        let l3_table = root + 0x2000;
        self.write_u64(root + l1 * 8, l2_table | 3);
        self.write_u64(l2_table + l2 * 8, l3_table | 3);
        self.write_u64(l3_table + l3 * 8, pa | 0x703);
    }
}

impl PhysMemory for FakeMem {
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

/// `TCR_EL1` for a 39-bit VA with a 4KiB TTBR1 granule.
pub const TCR_39: u64 = (25 << 16) | (2 << 30);
