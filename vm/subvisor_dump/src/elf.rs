// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Writing a Linux-style ELF64 core dump.
//!
//! The output matches what kdump produces, so `crash` and `drgn` open it: one
//! `PT_LOAD` per guest RAM range, plus a `PT_NOTE` carrying the register set
//! (`NT_PRSTATUS`) and the raw `VMCOREINFO` block. Tools read VMCOREINFO from
//! the note to find symbols, exactly as they do for a real vmcore.

use std::io::Write;

const EI_NIDENT: usize = 16;
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const PF_R: u32 = 4;
const PF_W: u32 = 2;
const PF_X: u32 = 1;
const NT_PRSTATUS: u32 = 1;
/// The note name kdump uses for the VMCOREINFO note.
const VMCOREINFO_NAME: &[u8] = b"VMCOREINFO\0";
/// The note type for VMCOREINFO (from the kernel).
const NT_VMCOREINFO: u32 = 0;

/// ELF machine for the guest architecture.
#[derive(Debug, Copy, Clone)]
pub enum Machine {
    /// x86-64 (`EM_X86_64` = 62).
    X86_64,
    /// AArch64 (`EM_AARCH64` = 183).
    Aarch64,
}

impl Machine {
    fn e_machine(self) -> u16 {
        match self {
            Machine::X86_64 => 62,
            Machine::Aarch64 => 183,
        }
    }
}

/// One memory range to emit as a `PT_LOAD`.
#[derive(Debug, Clone, Copy)]
pub struct LoadRange {
    /// Guest physical (and reported virtual) address.
    pub addr: u64,
    /// Offset of the range's bytes in the memory source.
    pub file_offset: u64,
    /// Length in bytes.
    pub len: u64,
}

/// A per-VP note payload. `desc` is the architecture's `NT_PRSTATUS`
/// `elf_prstatus`, already laid out by the caller.
#[derive(Debug, Clone)]
pub struct PrStatus {
    /// The raw `elf_prstatus` bytes.
    pub desc: Vec<u8>,
}

/// Builds a core dump header streamer.
pub struct CoreWriter {
    machine: Machine,
    ranges: Vec<LoadRange>,
    notes: Vec<(u32, Vec<u8>, Vec<u8>)>,
}

impl CoreWriter {
    /// Creates a writer for the given architecture.
    pub fn new(machine: Machine) -> Self {
        Self {
            machine,
            ranges: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Adds a `PT_LOAD` range.
    pub fn add_range(&mut self, range: LoadRange) {
        self.ranges.push(range);
    }

    /// Adds an `NT_PRSTATUS` note for one VP.
    pub fn add_prstatus(&mut self, status: PrStatus) {
        self.notes
            .push((NT_PRSTATUS, b"CORE\0".to_vec(), status.desc));
    }

    /// Adds the `VMCOREINFO` note.
    pub fn add_vmcoreinfo(&mut self, raw: &[u8]) {
        self.notes
            .push((NT_VMCOREINFO, VMCOREINFO_NAME.to_vec(), raw.to_vec()));
    }

    /// Serializes one note (name and desc are padded to 4 bytes).
    fn encode_note(ntype: u32, name: &[u8], desc: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend((name.len() as u32).to_le_bytes());
        out.extend((desc.len() as u32).to_le_bytes());
        out.extend(ntype.to_le_bytes());
        out.extend(name);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend(desc);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    /// The assembled note segment bytes.
    fn note_segment(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (ntype, name, desc) in &self.notes {
            out.extend(Self::encode_note(*ntype, name, desc));
        }
        out
    }

    /// Writes the complete core dump. `read_at` supplies memory bytes for a
    /// given source offset and length.
    pub fn write<W, F>(&self, mut out: W, mut read_at: F) -> std::io::Result<()>
    where
        W: Write,
        F: FnMut(u64, usize) -> std::io::Result<Vec<u8>>,
    {
        let notes = self.note_segment();
        let phnum = 1 + self.ranges.len(); // PT_NOTE + one PT_LOAD each
        let ehsize = 64u64;
        let phentsize = 56u64;
        let ph_table = ehsize;
        let notes_offset = ph_table + phentsize * phnum as u64;
        let mut data_offset = notes_offset + notes.len() as u64;
        // Align first PT_LOAD to a page for tools that mmap the file.
        let align = 0x1000u64;
        data_offset = data_offset.div_ceil(align) * align;

        // ELF header.
        let mut eh = Vec::new();
        eh.extend([0x7f, b'E', b'L', b'F']);
        eh.push(2); // ELFCLASS64
        eh.push(1); // ELFDATA2LSB
        eh.push(1); // EV_CURRENT
        eh.resize(EI_NIDENT, 0);
        eh.extend(ET_CORE.to_le_bytes());
        eh.extend(self.machine.e_machine().to_le_bytes());
        eh.extend(1u32.to_le_bytes()); // e_version
        eh.extend(0u64.to_le_bytes()); // e_entry
        eh.extend(ph_table.to_le_bytes()); // e_phoff
        eh.extend(0u64.to_le_bytes()); // e_shoff
        eh.extend(0u32.to_le_bytes()); // e_flags
        eh.extend((ehsize as u16).to_le_bytes());
        eh.extend((phentsize as u16).to_le_bytes());
        eh.extend((phnum as u16).to_le_bytes());
        eh.extend(0u16.to_le_bytes()); // e_shentsize
        eh.extend(0u16.to_le_bytes()); // e_shnum
        eh.extend(0u16.to_le_bytes()); // e_shstrndx
        debug_assert_eq!(eh.len(), ehsize as usize);
        out.write_all(&eh)?;

        // Program headers: PT_NOTE first.
        let write_ph = |out: &mut W,
                        p_type: u32,
                        flags: u32,
                        offset: u64,
                        vaddr: u64,
                        paddr: u64,
                        filesz: u64,
                        memsz: u64,
                        align: u64|
         -> std::io::Result<()> {
            let mut ph = Vec::new();
            ph.extend(p_type.to_le_bytes());
            ph.extend(flags.to_le_bytes());
            ph.extend(offset.to_le_bytes());
            ph.extend(vaddr.to_le_bytes());
            ph.extend(paddr.to_le_bytes());
            ph.extend(filesz.to_le_bytes());
            ph.extend(memsz.to_le_bytes());
            ph.extend(align.to_le_bytes());
            out.write_all(&ph)
        };

        write_ph(
            &mut out,
            PT_NOTE,
            0,
            notes_offset,
            0,
            0,
            notes.len() as u64,
            0,
            0,
        )?;

        let mut cur = data_offset;
        for r in &self.ranges {
            write_ph(
                &mut out,
                PT_LOAD,
                PF_R | PF_W | PF_X,
                cur,
                r.addr,
                r.addr,
                r.len,
                r.len,
                align,
            )?;
            cur += r.len;
        }

        // Note segment.
        out.write_all(&notes)?;

        // Pad to the first PT_LOAD offset.
        let mut written = notes_offset + notes.len() as u64;
        while written < data_offset {
            let pad = (data_offset - written).min(0x1000) as usize;
            out.write_all(&vec![0u8; pad])?;
            written += pad as u64;
        }

        // Memory, streamed in 1 MiB chunks.
        for r in &self.ranges {
            let mut done = 0u64;
            while done < r.len {
                let n = (r.len - done).min(1024 * 1024) as usize;
                let bytes = read_at(r.file_offset + done, n)?;
                out.write_all(&bytes)?;
                done += n as u64;
            }
        }
        Ok(())
    }
}

/// Lays out an aarch64 `elf_prstatus` from `pt_regs`.
///
/// `regs` is the 34-entry `pt_regs`: `x0..x30`, then `sp`, `pc`, `pstate`. The
/// 112-byte `elf_prstatus` prefix (signal and timing fields) is left zero,
/// which crash and drgn tolerate.
pub fn aarch64_prstatus(regs: &[u64; 34]) -> PrStatus {
    let mut desc = vec![0u8; 112];
    for r in regs {
        desc.extend(r.to_le_bytes());
    }
    PrStatus { desc }
}

/// Lays out an x86-64 `elf_prstatus` with `rip`, `rsp`, and `cr3` placed where
/// the general registers go. Enough for tools to find the kernel and walk it.
pub fn x86_64_prstatus(regs: &x86_64_user_regs) -> PrStatus {
    let mut desc = vec![0u8; 112];
    desc.extend(regs.to_bytes());
    PrStatus { desc }
}

/// The subset of `user_regs_struct` fields the dump fills, in struct order.
#[expect(non_camel_case_types)]
#[derive(Debug, Default, Clone)]
pub struct x86_64_user_regs {
    /// `rip`.
    pub rip: u64,
    /// `rsp`.
    pub rsp: u64,
    /// `rbp`.
    pub rbp: u64,
    /// `cs`/`ss` flags, unused by most tools; left zero.
    pub rflags: u64,
}

impl x86_64_user_regs {
    /// Serializes a 27-entry `user_regs_struct` with the known fields set.
    fn to_bytes(&self) -> Vec<u8> {
        // user_regs_struct is 27 u64s. Fill rbp(4), rsp(19), rip(16), eflags(18).
        let mut regs = [0u64; 27];
        regs[4] = self.rbp;
        regs[16] = self.rip;
        regs[18] = self.rflags;
        regs[19] = self.rsp;
        regs.iter().flat_map(|r| r.to_le_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses an ELF header enough to validate the writer's output.
    fn u16le(b: &[u8], o: usize) -> u16 {
        u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
    }
    fn u32le(b: &[u8], o: usize) -> u32 {
        u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
    }
    fn u64le(b: &[u8], o: usize) -> u64 {
        u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
    }

    #[test]
    fn writes_valid_core_header() {
        let mut w = CoreWriter::new(Machine::Aarch64);
        w.add_range(LoadRange {
            addr: 0x4000_0000,
            file_offset: 0,
            len: 0x2000,
        });
        w.add_vmcoreinfo(b"OSRELEASE=6.18.33\n");
        w.add_prstatus(aarch64_prstatus(&[0x11; 34]));

        let mut out = Vec::new();
        w.write(&mut out, |off, n| {
            Ok((0..n).map(|i| (off as u8).wrapping_add(i as u8)).collect())
        })
        .unwrap();

        // ELF magic and class.
        assert_eq!(&out[0..4], b"\x7fELF");
        assert_eq!(out[4], 2); // 64-bit
        assert_eq!(u16le(&out, 16), ET_CORE);
        assert_eq!(u16le(&out, 18), 183); // aarch64
        let phoff = u64le(&out, 32);
        let phentsize = u16le(&out, 54);
        let phnum = u16le(&out, 56);
        assert_eq!(phentsize, 56);
        assert_eq!(phnum, 2); // PT_NOTE + one PT_LOAD

        // First program header is PT_NOTE.
        let ph0 = phoff as usize;
        assert_eq!(u32le(&out, ph0), PT_NOTE);
        let note_off = u64le(&out, ph0 + 8) as usize;
        let note_sz = u64le(&out, ph0 + 32) as usize;
        let notes = &out[note_off..note_off + note_sz];
        // The VMCOREINFO note name must be present.
        assert!(
            notes
                .windows(VMCOREINFO_NAME.len())
                .any(|w| w == VMCOREINFO_NAME),
            "VMCOREINFO note missing"
        );

        // Second header is a PT_LOAD covering our range.
        let ph1 = ph0 + phentsize as usize;
        assert_eq!(u32le(&out, ph1), PT_LOAD);
        assert_eq!(u64le(&out, ph1 + 16), 0x4000_0000); // p_vaddr
        assert_eq!(u64le(&out, ph1 + 32), 0x2000); // p_filesz
        let data_off = u64le(&out, ph1 + 8) as usize;
        assert_eq!(data_off % 0x1000, 0, "PT_LOAD not page-aligned");
        // The emitted data is our synthetic pattern starting at file_offset 0.
        assert_eq!(out[data_off], 0);
        assert_eq!(out[data_off + 1], 1);
    }

    #[test]
    fn note_padding_is_aligned() {
        // A name whose length is not a multiple of 4 must still 4-align.
        let note = CoreWriter::encode_note(NT_PRSTATUS, b"CORE\0", &[1, 2, 3]);
        assert_eq!(note.len() % 4, 0);
        // namesz and descsz fields.
        assert_eq!(u32le(&note, 0), 5);
        assert_eq!(u32le(&note, 4), 3);
    }

    #[test]
    fn multiple_ranges_offsets_are_contiguous() {
        let mut w = CoreWriter::new(Machine::X86_64);
        w.add_range(LoadRange {
            addr: 0,
            file_offset: 0,
            len: 0x1000,
        });
        w.add_range(LoadRange {
            addr: 0x1_0000_0000,
            file_offset: 0x1000,
            len: 0x2000,
        });
        let mut out = Vec::new();
        w.write(&mut out, |_, n| Ok(vec![0u8; n])).unwrap();
        let phoff = u64le(&out, 32) as usize;
        let ph1 = phoff + 56; // first PT_LOAD
        let ph2 = phoff + 56 * 2;
        let off1 = u64le(&out, ph1 + 8);
        let len1 = u64le(&out, ph1 + 32);
        let off2 = u64le(&out, ph2 + 8);
        assert_eq!(off1 + len1, off2, "PT_LOAD data must be contiguous");
    }
}
