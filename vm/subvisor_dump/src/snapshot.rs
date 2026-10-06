// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Reading OpenVMM snapshot directories (`manifest.bin`, `state.bin`,
//! `memory.bin`).
//!
//! The snapshot format is OpenVMM's own, not WinDbg's `.vmrs`. `memory.bin` is
//! flat guest RAM; `state.bin` is `mesh`-encoded device and VP state. This
//! module decodes the manifest, extracts per-VP registers, and models how file
//! offsets map to guest physical addresses.

use crate::proto::Reader;
use crate::proto::Value;
use std::path::Path;
use std::path::PathBuf;

/// A snapshot error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A snapshot file could not be read.
    #[error("failed to read {path:?}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A file's protobuf contents were malformed.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// The architecture string was not recognized.
    #[error("unknown architecture {0:?}")]
    UnknownArch(String),
    /// A read fell outside guest RAM.
    #[error("guest physical address {0:#x} is not backed by RAM")]
    Unbacked(u64),
}

/// The guest architecture.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Arch {
    /// x86-64.
    X86_64,
    /// AArch64.
    Aarch64,
}

/// The decoded snapshot manifest.
#[derive(Debug, Clone)]
pub struct Manifest {
    /// Manifest format version.
    pub version: u64,
    /// OpenVMM version string.
    pub openvmm_version: String,
    /// Guest RAM size in bytes.
    pub memory_size: u64,
    /// Virtual processor count.
    pub vp_count: u32,
    /// Guest architecture.
    pub arch: Arch,
}

impl Manifest {
    /// Parses a `manifest.bin` body.
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        let malformed = || Error::Malformed("manifest.bin");
        let version = Reader::varint_field(buf, 1)
            .map_err(|_| malformed())?
            .unwrap_or(0);
        let openvmm_version = Reader::bytes_field(buf, 3)
            .map_err(|_| malformed())?
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        let memory_size = Reader::varint_field(buf, 4)
            .map_err(|_| malformed())?
            .ok_or_else(malformed)?;
        let vp_count = Reader::varint_field(buf, 5)
            .map_err(|_| malformed())?
            .unwrap_or(1) as u32;
        let arch = match Reader::bytes_field(buf, 7).map_err(|_| malformed())? {
            Some(b"x86_64") => Arch::X86_64,
            Some(b"aarch64") => Arch::Aarch64,
            Some(other) => {
                return Err(Error::UnknownArch(
                    String::from_utf8_lossy(other).into_owned(),
                ));
            }
            None => return Err(malformed()),
        };
        Ok(Self {
            version,
            openvmm_version,
            memory_size,
            vp_count,
            arch,
        })
    }
}

/// The subset of VP register state the tool needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpRegisters {
    /// x86-64 general and control registers, if this is an x86 VP.
    pub x86: Option<X86Registers>,
    /// AArch64 registers, if this is an AArch64 VP.
    pub aarch64: Option<Aarch64Registers>,
}

/// x86-64 registers used for paging and kernel discovery.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct X86Registers {
    /// Instruction pointer.
    pub rip: u64,
    /// `CR3` (page-table root).
    pub cr3: u64,
    /// `CR4`.
    pub cr4: u64,
    /// `IDTR` base (points into the kernel image).
    pub idtr_base: u64,
    /// `GDTR` base.
    pub gdtr_base: u64,
}

/// AArch64 registers used for paging.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Aarch64Registers {
    /// Program counter.
    pub pc: u64,
    /// `TTBR1_EL1` (upper-half page-table root).
    pub ttbr1_el1: u64,
    /// `TCR_EL1`.
    pub tcr_el1: u64,
}

const VP_STATE_X86: &[u8] = b"type.googleapis.com/virt.x86.VpSavedState";
const VP_STATE_AARCH64: &[u8] = b"type.googleapis.com/virt.aarch64.VpSavedState";

/// Extracts each VP's registers from a `state.bin` body, in VP order.
///
/// `state.bin` is a tree of `mesh` `Any` messages. Rather than depend on the
/// VMM's type registry, this walks the tree and decodes every `VpSavedState`
/// by its type URL.
pub fn parse_vp_registers(state: &[u8]) -> Vec<VpRegisters> {
    let mut out = Vec::new();
    collect_vps(state, &mut out);
    out
}

/// A `mesh` `Any` is `{ 1: type_url (string), 2: value (bytes) }`. We scan for
/// `Any` messages whose type URL names a `VpSavedState` and decode the value.
fn collect_vps(buf: &[u8], out: &mut Vec<VpRegisters>) {
    let mut r = Reader::new(buf);
    while let Ok(Some((_field, value))) = r.next_field() {
        let Value::Bytes(inner) = value else { continue };
        // Check whether `inner` is itself an Any naming a VpSavedState;
        // otherwise recurse. A type-URL string is not valid nested protobuf,
        // so recursing into one simply finds nothing.
        if let Some(regs) = try_decode_vp(inner) {
            out.push(regs);
        } else {
            collect_vps(inner, out);
        }
    }
}

/// If `buf` is an `Any { 1: <VpSavedState url>, 2: <value> }`, decode it.
fn try_decode_vp(buf: &[u8]) -> Option<VpRegisters> {
    let url = Reader::bytes_field(buf, 1).ok().flatten()?;
    let value = Reader::bytes_field(buf, 2).ok().flatten()?;
    if url == VP_STATE_X86 {
        Some(VpRegisters {
            x86: Some(decode_x86(value)),
            aarch64: None,
        })
    } else if url == VP_STATE_AARCH64 {
        Some(VpRegisters {
            x86: None,
            aarch64: Some(decode_aarch64(value)),
        })
    } else {
        None
    }
}

/// Decodes `virt.x86.VpSavedState`. Registers is field 1; control registers
/// live inside it.
fn decode_x86(value: &[u8]) -> X86Registers {
    let regs = Reader::bytes_field(value, 1)
        .ok()
        .flatten()
        .unwrap_or_default_slice();
    let table_base = |field: u32| {
        Reader::bytes_field(regs, field)
            .ok()
            .flatten()
            .and_then(|t| Reader::varint_field(t, 1).ok().flatten())
            .unwrap_or(0)
    };
    X86Registers {
        rip: Reader::varint_field(regs, 17).ok().flatten().unwrap_or(0),
        cr3: Reader::varint_field(regs, 31).ok().flatten().unwrap_or(0),
        cr4: Reader::varint_field(regs, 32).ok().flatten().unwrap_or(0),
        gdtr_base: table_base(27),
        idtr_base: table_base(28),
    }
}

/// Decodes `virt.aarch64.VpSavedState`. Registers is field 1 (pc), system
/// registers are field 2 (ttbr1/tcr).
fn decode_aarch64(value: &[u8]) -> Aarch64Registers {
    let regs = Reader::bytes_field(value, 1)
        .ok()
        .flatten()
        .unwrap_or_default_slice();
    let sregs = Reader::bytes_field(value, 2)
        .ok()
        .flatten()
        .unwrap_or_default_slice();
    Aarch64Registers {
        pc: Reader::varint_field(regs, 35).ok().flatten().unwrap_or(0),
        ttbr1_el1: Reader::varint_field(sregs, 3).ok().flatten().unwrap_or(0),
        tcr_el1: Reader::varint_field(sregs, 4).ok().flatten().unwrap_or(0),
    }
}

/// Helper so missing optional nested messages decode as empty.
trait OrDefaultSlice<'a> {
    fn unwrap_or_default_slice(self) -> &'a [u8];
}
impl<'a> OrDefaultSlice<'a> for Option<&'a [u8]> {
    fn unwrap_or_default_slice(self) -> &'a [u8] {
        self.unwrap_or(&[])
    }
}

/// One contiguous guest RAM range and where it sits in `memory.bin`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamRange {
    /// Starting guest physical address.
    pub gpa: u64,
    /// Byte offset in `memory.bin`.
    pub file_offset: u64,
    /// Length in bytes.
    pub len: u64,
}

/// Maps between guest physical addresses and `memory.bin` offsets.
///
/// OpenVMM packs RAM ranges contiguously in `memory.bin`, skipping MMIO holes.
/// The manifest records only the total size, so the ranges are reconstructed
/// from the architecture's layout, or supplied explicitly.
#[derive(Debug, Clone)]
pub struct RamLayout {
    ranges: Vec<RamRange>,
}

/// The AArch64 reserved zone below 4 GiB (RAM splits around it).
const AARCH64_RESERVED_START: u64 = 0xEF00_0000;
/// The x86-64 reserved zone below 4 GiB.
const X86_RESERVED_START: u64 = 0xFE00_0000;
const FOUR_GIB: u64 = 0x1_0000_0000;

impl RamLayout {
    /// Builds a layout from explicit ranges, sorted by GPA.
    pub fn from_ranges(mut ranges: Vec<RamRange>) -> Self {
        ranges.sort_by_key(|r| r.gpa);
        Self { ranges }
    }

    /// A single contiguous range starting at `base`.
    pub fn single(base: u64, len: u64) -> Self {
        Self::from_ranges(vec![RamRange {
            gpa: base,
            file_offset: 0,
            len,
        }])
    }

    /// Reconstructs the default layout OpenVMM uses for `arch` and `size`.
    ///
    /// Below the architectural reserved zone RAM is contiguous from `base`;
    /// anything above spills past 4 GiB. `base` is 0 for the standard layout,
    /// but Linux direct-boot guests have used other bases, so callers that have
    /// a VMCOREINFO `PHYS_OFFSET` should prefer [`RamLayout::single`] or
    /// [`RamLayout::from_ranges`].
    pub fn reconstruct(arch: Arch, base: u64, size: u64) -> Self {
        let reserved = match arch {
            Arch::X86_64 => X86_RESERVED_START,
            Arch::Aarch64 => AARCH64_RESERVED_START,
        };
        // The low split point is the reserved zone, but never below `base`.
        let low_limit = reserved.saturating_sub(base);
        if size <= low_limit {
            return Self::single(base, size);
        }
        let low = RamRange {
            gpa: base,
            file_offset: 0,
            len: low_limit,
        };
        let high = RamRange {
            gpa: FOUR_GIB,
            file_offset: low_limit,
            len: size - low_limit,
        };
        Self::from_ranges(vec![low, high])
    }

    /// The RAM ranges, sorted by GPA.
    pub fn ranges(&self) -> &[RamRange] {
        &self.ranges
    }

    /// Total RAM size.
    pub fn total(&self) -> u64 {
        self.ranges.iter().map(|r| r.len).sum()
    }

    /// Translates a guest physical address to a `memory.bin` offset, if backed.
    pub fn to_file_offset(&self, gpa: u64) -> Option<u64> {
        let r = self
            .ranges
            .iter()
            .find(|r| gpa >= r.gpa && gpa < r.gpa + r.len)?;
        Some(r.file_offset + (gpa - r.gpa))
    }

    /// Returns the length of the backed run starting at `gpa`.
    pub fn backed_run(&self, gpa: u64) -> Option<u64> {
        let r = self
            .ranges
            .iter()
            .find(|r| gpa >= r.gpa && gpa < r.gpa + r.len)?;
        Some(r.gpa + r.len - gpa)
    }
}

/// A snapshot opened for reading.
pub struct Snapshot {
    /// The decoded manifest.
    pub manifest: Manifest,
    /// Each VP's registers, in order.
    pub vps: Vec<VpRegisters>,
    /// The guest RAM layout.
    pub ram: RamLayout,
    memory: Vec<u8>,
}

impl Snapshot {
    /// Opens a snapshot directory, reading `memory.bin` fully into memory.
    ///
    /// Agent snapshots are small (hundreds of MiB to a couple of GiB), so the
    /// whole image is read up front. A memory-mapped backend could be added for
    /// very large guests.
    pub fn open(dir: &Path) -> Result<Self, Error> {
        let read = |name: &str| {
            let path = dir.join(name);
            std::fs::read(&path).map_err(|source| Error::Io { path, source })
        };
        let manifest = Manifest::parse(&read("manifest.bin")?)?;
        let vps = parse_vp_registers(&read("state.bin")?);
        let memory = read("memory.bin")?;
        let ram = Self::choose_layout(&manifest, &memory);
        Ok(Self {
            manifest,
            vps,
            ram,
            memory,
        })
    }

    /// Builds a snapshot from already-read parts (used by tests and callers
    /// that supply their own RAM layout).
    pub fn from_parts(
        manifest: Manifest,
        vps: Vec<VpRegisters>,
        ram: RamLayout,
        memory: Vec<u8>,
    ) -> Self {
        Self {
            manifest,
            vps,
            ram,
            memory,
        }
    }

    /// Picks a RAM layout. For a size that fits below the reserved zone this is
    /// one range; the base is refined later from VMCOREINFO when available.
    fn choose_layout(manifest: &Manifest, memory: &[u8]) -> RamLayout {
        let size = manifest.memory_size.min(memory.len() as u64);
        RamLayout::reconstruct(manifest.arch, 0, size)
    }

    /// Replaces the RAM layout (for example after learning `PHYS_OFFSET`).
    pub fn set_ram(&mut self, ram: RamLayout) {
        self.ram = ram;
    }

    /// The raw `memory.bin` contents.
    pub fn memory(&self) -> &[u8] {
        &self.memory
    }
}

impl linux_vmi::PhysMemory for Snapshot {
    fn read_phys(&mut self, gpa: u64, buf: &mut [u8]) -> std::io::Result<()> {
        let mut done = 0;
        while done < buf.len() {
            let cur = gpa + done as u64;
            let offset = self
                .ram
                .to_file_offset(cur)
                .ok_or_else(|| std::io::Error::other(Error::Unbacked(cur)))?;
            let run = self.ram.backed_run(cur).unwrap();
            let n = (buf.len() - done).min(run as usize);
            let src = self
                .memory
                .get(offset as usize..offset as usize + n)
                .ok_or_else(|| std::io::Error::other(Error::Unbacked(cur)))?;
            buf[done..done + n].copy_from_slice(src);
            done += n;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }
    fn field_varint(f: u32, v: u64) -> Vec<u8> {
        let mut o = varint(u64::from(f) << 3);
        o.extend(varint(v));
        o
    }
    fn field_bytes(f: u32, b: &[u8]) -> Vec<u8> {
        let mut o = varint(u64::from(f) << 3 | 2);
        o.extend(varint(b.len() as u64));
        o.extend(b);
        o
    }

    #[test]
    fn manifest_round_trip() {
        let mut m = Vec::new();
        m.extend(field_varint(1, 1));
        m.extend(field_bytes(3, b"0.0.0"));
        m.extend(field_varint(4, 0x4000_0000));
        m.extend(field_varint(5, 2));
        m.extend(field_bytes(7, b"aarch64"));
        let parsed = Manifest::parse(&m).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.memory_size, 0x4000_0000);
        assert_eq!(parsed.vp_count, 2);
        assert_eq!(parsed.arch, Arch::Aarch64);
    }

    #[test]
    fn manifest_rejects_unknown_arch() {
        let mut m = field_varint(4, 1024);
        m.extend(field_bytes(7, b"riscv64"));
        assert!(matches!(Manifest::parse(&m), Err(Error::UnknownArch(_))));
    }

    /// Wraps a VpSavedState value in an Any with the given type URL.
    fn any(url: &[u8], value: &[u8]) -> Vec<u8> {
        let mut o = field_bytes(1, url);
        o.extend(field_bytes(2, value));
        o
    }

    #[test]
    fn extracts_aarch64_registers() {
        // VpSavedState { 1: Registers{35: pc}, 2: SystemRegisters{3: ttbr1, 4: tcr} }
        let regs = field_varint(35, 0xffff_0000_1234);
        let mut sregs = field_varint(3, 0x1c00_0000_4223_c000);
        sregs.extend(field_varint(4, 0x19));
        let mut vp = field_bytes(1, &regs);
        vp.extend(field_bytes(2, &sregs));
        // Nest the Any inside an outer message, like partition.vps[0].
        let outer = field_bytes(2, &any(VP_STATE_AARCH64, &vp));

        let vps = parse_vp_registers(&outer);
        assert_eq!(vps.len(), 1);
        let a = vps[0].aarch64.as_ref().unwrap();
        assert_eq!(a.pc, 0xffff_0000_1234);
        assert_eq!(a.ttbr1_el1, 0x1c00_0000_4223_c000);
        assert_eq!(a.tcr_el1, 0x19);
    }

    #[test]
    fn extracts_x86_registers() {
        // Registers{17: rip, 28: idtr{1: base}, 31: cr3, 32: cr4}
        let idtr = field_varint(1, 0xffff_f800_0000_0000);
        let mut regs = field_varint(17, 0xffff_f800_1111_0000);
        regs.extend(field_bytes(28, &idtr));
        regs.extend(field_varint(31, 0x1aa_000));
        regs.extend(field_varint(32, 0x20));
        let vp = field_bytes(1, &regs);
        let outer = field_bytes(2, &any(VP_STATE_X86, &vp));

        let vps = parse_vp_registers(&outer);
        let x = vps[0].x86.as_ref().unwrap();
        assert_eq!(x.rip, 0xffff_f800_1111_0000);
        assert_eq!(x.cr3, 0x1aa_000);
        assert_eq!(x.cr4, 0x20);
        assert_eq!(x.idtr_base, 0xffff_f800_0000_0000);
    }

    #[test]
    fn layout_single_range() {
        let l = RamLayout::single(0x4000_0000, 0x4000_0000);
        assert_eq!(l.to_file_offset(0x4000_0000), Some(0));
        assert_eq!(l.to_file_offset(0x4223_c000), Some(0x223_c000));
        assert_eq!(l.to_file_offset(0x8000_0000), None);
        assert_eq!(l.to_file_offset(0x3fff_ffff), None);
        assert_eq!(l.backed_run(0x7fff_f000), Some(0x1000));
    }

    #[test]
    fn layout_splits_large_x86() {
        // 6 GiB: 0..0xFE000000 in file, then 4 GiB.. for the rest.
        let size = 6 * FOUR_GIB / 4;
        let l = RamLayout::reconstruct(Arch::X86_64, 0, size);
        assert_eq!(l.ranges().len(), 2);
        assert_eq!(l.ranges()[0].gpa, 0);
        assert_eq!(l.ranges()[0].len, X86_RESERVED_START);
        assert_eq!(l.ranges()[1].gpa, FOUR_GIB);
        // A GPA just above 4 GiB maps right after the low range in the file.
        assert_eq!(l.to_file_offset(FOUR_GIB), Some(X86_RESERVED_START));
        assert_eq!(l.total(), size);
    }

    #[test]
    fn phys_memory_reads_across_offset() {
        let mut mem = vec![0u8; 0x2000];
        mem[0x1000..0x1008].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        let snap = Snapshot::from_parts(
            Manifest {
                version: 1,
                openvmm_version: "t".into(),
                memory_size: 0x2000,
                vp_count: 1,
                arch: Arch::Aarch64,
            },
            vec![],
            RamLayout::single(0x4000_0000, 0x2000),
            mem,
        );
        let mut snap = snap;
        let mut buf = [0u8; 8];
        linux_vmi::PhysMemory::read_phys(&mut snap, 0x4000_1000, &mut buf).unwrap();
        assert_eq!(u64::from_le_bytes(buf), 0x1122_3344_5566_7788);

        let mut buf = [0u8; 4];
        assert!(linux_vmi::PhysMemory::read_phys(&mut snap, 0x8000_0000, &mut buf).is_err());
    }
}
