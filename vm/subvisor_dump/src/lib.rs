// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Offline analysis of OpenVMM guest snapshots.
//!
//! `subvisor_dump` reads an OpenVMM snapshot directory (`manifest.bin`,
//! `state.bin`, `memory.bin`) and, without any help from inside the guest:
//!
//! - **Linux**: finds the kernel's VMCOREINFO block, uses it to decode the full
//!   `kallsyms` table from memory, and writes a kdump-style ELF core that
//!   `crash` and `drgn` can open.
//! - **Windows**: finds `ntoskrnl` from the saved `IDTR`, and reads the PDB
//!   identity needed to fetch symbols from the Microsoft symbol server.
//!
//! The symbol bootstrap is the hard part of converting a raw memory image into
//! something a debugger understands; everything else is container plumbing.

#![forbid(unsafe_code)]

#[cfg(test)]
mod testmem;

pub mod elf;
pub mod kallsyms;
pub mod proto;
pub mod snapshot;
pub mod vmcoreinfo;
pub mod windows;

use linux_vmi::paging::PagingRoot;
use linux_vmi::paging::Translator;
use snapshot::Arch;
use snapshot::RamLayout;
use snapshot::Snapshot;
use vmcoreinfo::VmCoreInfo;

/// A top-level analysis error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A snapshot could not be read.
    #[error(transparent)]
    Snapshot(#[from] snapshot::Error),
    /// kallsyms decoding failed.
    #[error(transparent)]
    Kallsyms(#[from] kallsyms::Error),
    /// Windows discovery failed.
    #[error(transparent)]
    Windows(#[from] windows::Error),
    /// The snapshot had no VPs, so there are no registers to analyze.
    #[error("snapshot contains no processor state")]
    NoVps,
    /// The guest paging root did not map the kernel; the snapshot may have
    /// been taken in an unusual state, or the RAM base is unknown.
    #[error("could not locate the guest kernel in the snapshot")]
    KernelNotFound,
}

/// The detected guest operating system.
#[derive(Debug, Clone)]
pub enum GuestOs {
    /// A Linux guest, with its decoded VMCOREINFO.
    Linux(Box<VmCoreInfo>),
    /// A Windows guest.
    Windows,
    /// The OS could not be determined (no VMCOREINFO, no Windows kernel found).
    Unknown,
}

/// Builds a page-table root for VP 0 from its saved registers.
///
/// Masks the architecture-specific control bits so the value is a clean
/// physical address of the top-level table.
fn paging_root(snap: &Snapshot) -> Result<PagingRoot, Error> {
    let vp = snap.vps.first().ok_or(Error::NoVps)?;
    if let Some(a) = &vp.aarch64 {
        // Page-align the table root, dropping the ASID, CnP, and reserved bits.
        let ttbr1 = a.ttbr1_el1 & 0x0000_ffff_ffff_f000;
        Ok(PagingRoot::Aarch64 {
            ttbr1,
            tcr: a.tcr_el1,
        })
    } else if let Some(x) = &vp.x86 {
        Ok(PagingRoot::X86_64 {
            cr3: x.cr3 & 0x000f_ffff_ffff_f000,
            la57: x.cr4 & (1 << 12) != 0,
        })
    } else {
        Err(Error::NoVps)
    }
}

/// Chooses a RAM base for a Linux guest and verifies the kernel is mapped.
///
/// Prefers VMCOREINFO's `PHYS_OFFSET`; otherwise tries common bases and keeps
/// the one under which `_stext` translates.
fn calibrate_linux_ram(
    snap: &mut Snapshot,
    info: &VmCoreInfo,
    root: PagingRoot,
) -> Result<(), Error> {
    let stext = info.symbol("_stext").ok_or(Error::KernelNotFound)?;
    let size = snap.ram.total();
    let mut candidates = Vec::new();
    if let Some(phys) = info.number("PHYS_OFFSET") {
        candidates.push(phys);
    }
    candidates.extend([0, 0x4000_0000, 0x8000_0000]);

    for base in candidates {
        let layout = RamLayout::reconstruct(snap.manifest.arch, base, size);
        snap.set_ram(layout);
        let mut t = Translator::new(snap, root);
        if matches!(t.translate(stext), Ok(Some(_))) {
            return Ok(());
        }
    }
    Err(Error::KernelNotFound)
}

/// The result of analyzing a snapshot.
pub struct Analysis {
    /// The opened snapshot.
    pub snapshot: Snapshot,
    /// The detected guest OS.
    pub os: GuestOs,
    /// The page-table root used for the guest kernel.
    pub root: PagingRoot,
}

impl Analysis {
    /// Opens and analyzes a snapshot directory.
    pub fn open(dir: &std::path::Path) -> Result<Self, Error> {
        let mut snapshot = Snapshot::open(dir)?;
        let root = paging_root(&snapshot)?;

        // Linux first: scan for VMCOREINFO in the raw image.
        if let Some(info) = VmCoreInfo::find(snapshot.memory()) {
            calibrate_linux_ram(&mut snapshot, &info, root)?;
            return Ok(Self {
                snapshot,
                os: GuestOs::Linux(Box::new(info)),
                root,
            });
        }

        // Otherwise try to find a Windows kernel from the IDT.
        let os = {
            let idtr = snapshot
                .vps
                .first()
                .and_then(|v| v.x86.as_ref())
                .map(|x| x.idtr_base);
            match idtr {
                Some(idtr) if idtr != 0 => {
                    let mut t = Translator::new(&mut snapshot, root);
                    if windows::find_kernel_base(&mut t, idtr).is_ok() {
                        GuestOs::Windows
                    } else {
                        GuestOs::Unknown
                    }
                }
                _ => GuestOs::Unknown,
            }
        };
        Ok(Self { snapshot, os, root })
    }

    /// Decodes the Linux kernel symbol table, if this is a Linux guest.
    pub fn linux_symbols(&mut self) -> Result<linux_vmi::symbols::SymbolTable, Error> {
        let GuestOs::Linux(info) = &self.os else {
            return Err(Error::KernelNotFound);
        };
        let info = info.clone();
        let mut t = Translator::new(&mut self.snapshot, self.root);
        Ok(kallsyms::decode(&mut t, &info)?)
    }

    /// Finds the Windows kernel's PDB identity, if this is a Windows guest.
    pub fn windows_pdb(&mut self) -> Result<windows::PdbInfo, Error> {
        let idtr = self
            .snapshot
            .vps
            .first()
            .and_then(|v| v.x86.as_ref())
            .map(|x| x.idtr_base)
            .ok_or(Error::KernelNotFound)?;
        let mut t = Translator::new(&mut self.snapshot, self.root);
        let base = windows::find_kernel_base(&mut t, idtr)?;
        Ok(windows::pdb_info(&mut t, base)?)
    }

    /// Writes a kdump-style ELF core for a Linux guest.
    pub fn write_linux_core<W: std::io::Write>(&self, out: W) -> Result<(), Error> {
        let GuestOs::Linux(info) = &self.os else {
            return Err(Error::KernelNotFound);
        };
        let machine = match self.snapshot.manifest.arch {
            Arch::X86_64 => elf::Machine::X86_64,
            Arch::Aarch64 => elf::Machine::Aarch64,
        };
        let mut writer = elf::CoreWriter::new(machine);
        for r in self.snapshot.ram.ranges() {
            writer.add_range(elf::LoadRange {
                addr: r.gpa,
                file_offset: r.file_offset,
                len: r.len,
            });
        }
        writer.add_vmcoreinfo(info.raw());
        self.add_prstatus_notes(&mut writer);

        let memory = self.snapshot.memory().to_vec();
        writer
            .write(out, |off, n| {
                memory
                    .get(off as usize..off as usize + n)
                    .map(|s| s.to_vec())
                    .ok_or_else(|| std::io::Error::other("core: read past end of memory.bin"))
            })
            .map_err(|e| {
                Error::Snapshot(snapshot::Error::Io {
                    path: "<core output>".into(),
                    source: e,
                })
            })
    }

    /// Adds one NT_PRSTATUS note per VP.
    fn add_prstatus_notes(&self, writer: &mut elf::CoreWriter) {
        for vp in &self.snapshot.vps {
            if let Some(a) = &vp.aarch64 {
                // pt_regs: x0..x30 (0..31), sp (31), pc (32), pstate (33).
                let mut regs = [0u64; 34];
                regs[32] = a.pc;
                writer.add_prstatus(elf::aarch64_prstatus(&regs));
            } else if let Some(x) = &vp.x86 {
                writer.add_prstatus(elf::x86_64_prstatus(&elf::x86_64_user_regs {
                    rip: x.rip,
                    ..Default::default()
                }));
            }
        }
    }
}
