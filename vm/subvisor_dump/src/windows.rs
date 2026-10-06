// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! Windows guest kernel discovery.
//!
//! For a Windows guest there is no VMCOREINFO. Instead the tool finds the
//! kernel image (`ntoskrnl.exe`) from the saved `IDTR` base, then reads the
//! image's debug directory to recover the PDB identity (name, GUID, age). That
//! identity is what a debugger uses to fetch symbols from the Microsoft symbol
//! server, the same way DumpIt-style tools bootstrap an analysis.
//!
//! This module parses the PE purely from bytes, so it is unit-testable without
//! a live guest. Decoding `KdDebuggerDataBlock` for a native `.dmp` is a
//! further step and is intentionally not done here.

use linux_vmi::Error as VmiError;
use linux_vmi::paging::Translator;

/// A Windows discovery error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The kernel image could not be located near the IDT.
    #[error("could not find the Windows kernel image near IDTR {0:#x}")]
    KernelNotFound(u64),
    /// The PE or debug directory was malformed.
    #[error("malformed PE image: {0}")]
    BadPe(&'static str),
    /// No RSDS debug record was present.
    #[error("no CodeView (RSDS) debug record found")]
    NoCodeView,
    /// A memory read failed.
    #[error(transparent)]
    Vmi(#[from] VmiError),
}

/// The symbol identity needed to fetch a PDB from a symbol server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbInfo {
    /// Virtual address where the kernel image was found.
    pub image_base: u64,
    /// The PDB file name, e.g. `ntkrnlmp.pdb`.
    pub pdb_name: String,
    /// The symbol-server path component: GUID (no dashes, uppercase) + age.
    pub signature: String,
    /// `SizeOfImage` from the PE optional header.
    pub image_size: u32,
}

/// Searches downward from `idtr_base` for the kernel image base.
///
/// Windows aligns `ntoskrnl` on a large boundary and the IDT lives inside the
/// image's data, so scanning down page by page for a valid `MZ`/`PE` header
/// finds the base. The search is bounded to avoid runaway reads.
pub fn find_kernel_base(t: &mut Translator<'_>, idtr_base: u64) -> Result<u64, Error> {
    const PAGE: u64 = 0x1000;
    const MAX_PAGES: u64 = 0x4000; // 64 MiB of search
    let start = idtr_base & !(PAGE - 1);
    for i in 0..MAX_PAGES {
        let va = start - i * PAGE;
        if is_pe_image(t, va)? {
            return Ok(va);
        }
        if va < PAGE {
            break;
        }
    }
    Err(Error::KernelNotFound(idtr_base))
}

/// Reads `len` bytes at virtual address `va`, or `None` if unmapped.
fn read_va(t: &mut Translator<'_>, va: u64, len: usize) -> Result<Option<Vec<u8>>, Error> {
    const PAGE: u64 = 0x1000;
    let mut out = vec![0u8; len];
    let mut done = 0;
    while done < len {
        let cur = va + done as u64;
        let Some(gpa) = t.translate(cur)? else {
            return Ok(None);
        };
        let chunk = ((PAGE - (cur & (PAGE - 1))) as usize).min(len - done);
        t.mem()
            .read_phys(gpa, &mut out[done..done + chunk])
            .map_err(|source| VmiError::Read { gpa, source })?;
        done += chunk;
    }
    Ok(Some(out))
}

/// Returns true if `va` begins a PE image (MZ + PE signatures).
fn is_pe_image(t: &mut Translator<'_>, va: u64) -> Result<bool, Error> {
    let Some(hdr) = read_va(t, va, 0x40)? else {
        return Ok(false);
    };
    if &hdr[0..2] != b"MZ" {
        return Ok(false);
    }
    let pe_off = u32::from_le_bytes(hdr[0x3c..0x40].try_into().unwrap()) as u64;
    if pe_off > 0x1000 {
        return Ok(false);
    }
    let Some(sig) = read_va(t, va + pe_off, 4)? else {
        return Ok(false);
    };
    Ok(&sig == b"PE\0\0")
}

/// Extracts the PDB identity from the kernel image at `image_base`.
pub fn pdb_info(t: &mut Translator<'_>, image_base: u64) -> Result<PdbInfo, Error> {
    // Read the first part of the image: headers plus the debug directory
    // target usually sits within the first 0x2000 bytes for ntoskrnl.
    let headers = read_va(t, image_base, 0x400)?.ok_or(Error::BadPe("headers unmapped"))?;
    let pe_off = u32::from_le_bytes(headers[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe_off + 24; // optional header follows the 24-byte COFF header
    let magic = u16::from_le_bytes(pe_slice(&headers, opt, 2)?.try_into().unwrap());
    if magic != 0x20b {
        return Err(Error::BadPe("not a PE32+ image"));
    }
    let image_size = u32::from_le_bytes(pe_slice(&headers, opt + 56, 4)?.try_into().unwrap());
    // Data directories begin at optional-header offset 112 for PE32+.
    // The debug directory is index 6: 8 bytes each (RVA, size).
    let debug_dir_off = opt + 112 + 6 * 8;
    let debug_rva = u32::from_le_bytes(pe_slice(&headers, debug_dir_off, 4)?.try_into().unwrap());
    let debug_size = u32::from_le_bytes(
        pe_slice(&headers, debug_dir_off + 4, 4)?
            .try_into()
            .unwrap(),
    );
    if debug_rva == 0 || debug_size == 0 {
        return Err(Error::NoCodeView);
    }

    // Each IMAGE_DEBUG_DIRECTORY entry is 28 bytes; type 2 is CodeView.
    let entries = read_va(t, image_base + u64::from(debug_rva), debug_size as usize)?
        .ok_or(Error::BadPe("debug directory unmapped"))?;
    for entry in entries.as_chunks::<28>().0 {
        let kind = u32::from_le_bytes(entry[12..16].try_into().unwrap());
        if kind != 2 {
            continue;
        }
        // IMAGE_DEBUG_DIRECTORY: SizeOfData at +16, AddressOfRawData at +20.
        let data_size = u32::from_le_bytes(entry[16..20].try_into().unwrap());
        let data_rva = u32::from_le_bytes(entry[20..24].try_into().unwrap());
        let cv = read_va(t, image_base + u64::from(data_rva), data_size as usize)?
            .ok_or(Error::BadPe("CodeView data unmapped"))?;
        return parse_rsds(&cv, image_base, image_size);
    }
    Err(Error::NoCodeView)
}

/// Parses an RSDS CodeView record into a [`PdbInfo`].
///
/// Layout: `"RSDS"`, a 16-byte GUID, a 4-byte age, then a NUL-terminated PDB
/// name. The symbol-server signature is the GUID with specific byte ordering
/// plus the age, all uppercase hex.
fn parse_rsds(cv: &[u8], image_base: u64, image_size: u32) -> Result<PdbInfo, Error> {
    if cv.len() < 24 || &cv[0..4] != b"RSDS" {
        return Err(Error::NoCodeView);
    }
    let g = &cv[4..20];
    // GUID is stored mixed-endian: first three fields little-endian.
    let d1 = u32::from_le_bytes(g[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes(g[4..6].try_into().unwrap());
    let d3 = u16::from_le_bytes(g[6..8].try_into().unwrap());
    let age = u32::from_le_bytes(cv[20..24].try_into().unwrap());
    let mut signature = format!("{d1:08X}{d2:04X}{d3:04X}");
    for b in &g[8..16] {
        signature.push_str(&format!("{b:02X}"));
    }
    // The age is appended in lowercase hex with no padding.
    signature.push_str(&format!("{age:x}"));

    let name_bytes = &cv[24..];
    let end = name_bytes
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_bytes.len());
    let pdb_name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();

    Ok(PdbInfo {
        image_base,
        pdb_name,
        signature,
        image_size,
    })
}

/// Bounds-checked slice of PE header bytes.
fn pe_slice(buf: &[u8], off: usize, len: usize) -> Result<&[u8], Error> {
    buf.get(off..off + len)
        .ok_or(Error::BadPe("header too short"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rsds_record() {
        // GUID 11223344-5566-7788-99aa-bbccddeeff00, age 1, name "ntkrnlmp.pdb".
        let mut cv = Vec::new();
        cv.extend(b"RSDS");
        cv.extend(0x1122_3344u32.to_le_bytes());
        cv.extend(0x5566u16.to_le_bytes());
        cv.extend(0x7788u16.to_le_bytes());
        cv.extend([0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]);
        cv.extend(1u32.to_le_bytes());
        cv.extend(b"ntkrnlmp.pdb\0");

        let info = parse_rsds(&cv, 0xffff_f800_0000_0000, 0x90_0000).unwrap();
        assert_eq!(info.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(info.signature, "112233445566778899AABBCCDDEEFF001");
        assert_eq!(info.image_size, 0x90_0000);
    }

    #[test]
    fn rejects_non_rsds() {
        let cv = b"NB10somethingelse";
        assert!(matches!(parse_rsds(cv, 0, 0), Err(Error::NoCodeView)));
    }

    /// Builds a minimal PE32+ image with a debug directory and RSDS record,
    /// then exercises base discovery and PDB extraction through a fake guest.
    #[test]
    fn finds_base_and_pdb_end_to_end() {
        use crate::testmem::FakeMem;
        use crate::testmem::TCR_39;
        use linux_vmi::paging::PagingRoot;

        // Lay the image out in guest physical memory with an identity-ish map.
        let image_base_va = 0xffff_ffc0_8000_0000u64;
        let image_base_pa = 0x4100_0000u64;
        let root = 0x4000_0000u64;

        let mut image = vec![0u8; 0x3000];
        image[0..2].copy_from_slice(b"MZ");
        let pe_off = 0x100usize;
        image[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        image[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let opt = pe_off + 24;
        image[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
        image[opt + 56..opt + 60].copy_from_slice(&0x90_0000u32.to_le_bytes()); // SizeOfImage
        // Debug data directory (index 6) at opt+112+48.
        let dd = opt + 112 + 6 * 8;
        let debug_rva = 0x1000u32;
        image[dd..dd + 4].copy_from_slice(&debug_rva.to_le_bytes());
        image[dd + 4..dd + 8].copy_from_slice(&28u32.to_le_bytes());
        // One debug directory entry (type 2 CodeView) pointing at RVA 0x2000.
        let de = debug_rva as usize;
        image[de + 12..de + 16].copy_from_slice(&2u32.to_le_bytes()); // Type
        let cv_rva = 0x2000u32;
        let mut cv = Vec::new();
        cv.extend(b"RSDS");
        cv.extend(0xdead_beefu32.to_le_bytes());
        cv.extend(0x1234u16.to_le_bytes());
        cv.extend(0x5678u16.to_le_bytes());
        cv.extend([1, 2, 3, 4, 5, 6, 7, 8]);
        cv.extend(5u32.to_le_bytes());
        cv.extend(b"ntkrnlmp.pdb\0");
        // SizeOfData (+16) and AddressOfRawData (+20).
        image[de + 16..de + 20].copy_from_slice(&(cv.len() as u32).to_le_bytes());
        image[de + 20..de + 24].copy_from_slice(&cv_rva.to_le_bytes());
        image[cv_rva as usize..cv_rva as usize + cv.len()].copy_from_slice(&cv);

        // Map the three image pages and the IDT page (inside the image).
        let mut mem = FakeMem::default();
        for p in 0..3u64 {
            mem.map_39(root, image_base_va + p * 0x1000, image_base_pa + p * 0x1000);
            mem.write(
                image_base_pa + p * 0x1000,
                &image[(p * 0x1000) as usize..((p + 1) * 0x1000) as usize],
            );
        }

        let page_root = PagingRoot::Aarch64 {
            ttbr1: root,
            tcr: TCR_39,
        };
        let mut t = Translator::new(&mut mem, page_root);

        // IDTR points one page into the image.
        let base = find_kernel_base(&mut t, image_base_va + 0x800).unwrap();
        assert_eq!(base, image_base_va);
        let info = pdb_info(&mut t, base).unwrap();
        assert_eq!(info.pdb_name, "ntkrnlmp.pdb");
        assert_eq!(
            info.signature,
            "DEADBEEF123456780102030405060708".to_string() + "5"
        );
        assert_eq!(info.image_size, 0x90_0000);
    }
}
