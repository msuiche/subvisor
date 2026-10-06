// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! `subvisor` — offline analysis of OpenVMM guest snapshots.

#![forbid(unsafe_code)]

use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;
use subvisor_dump::Analysis;
use subvisor_dump::GuestOs;

/// Offline analysis of OpenVMM snapshots: identify the guest, recover kernel
/// symbols, and convert memory into a debugger-readable core dump.
#[derive(Parser)]
#[command(name = "subvisor", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Identify the guest OS, kernel, and symbol source.
    Info {
        /// Snapshot directory (contains manifest.bin, state.bin, memory.bin).
        snapshot: PathBuf,
    },
    /// Decode and print the guest kernel symbol table (Linux).
    Symbols {
        /// Snapshot directory.
        snapshot: PathBuf,
        /// Print only the first N symbols.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Write a kdump-style ELF core dump (Linux) that crash/drgn can open.
    Dump {
        /// Snapshot directory.
        snapshot: PathBuf,
        /// Output core file.
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Info { snapshot } => info(&snapshot),
        Command::Symbols { snapshot, limit } => symbols(&snapshot, limit),
        Command::Dump { snapshot, output } => dump(&snapshot, &output),
    }
}

fn info(dir: &std::path::Path) -> anyhow::Result<()> {
    let mut analysis = Analysis::open(dir)?;
    let m = &analysis.snapshot.manifest;
    println!("snapshot:       {}", dir.display());
    println!("openvmm:        {}", m.openvmm_version);
    println!(
        "architecture:   {}",
        match m.arch {
            subvisor_dump::snapshot::Arch::X86_64 => "x86_64",
            subvisor_dump::snapshot::Arch::Aarch64 => "aarch64",
        }
    );
    println!("memory:         {} MiB", m.memory_size / (1024 * 1024));
    println!("vcpus:          {}", analysis.snapshot.vps.len());
    for r in analysis.snapshot.ram.ranges() {
        println!(
            "  ram:          gpa {:#x}..{:#x} at file {:#x}",
            r.gpa,
            r.gpa + r.len,
            r.file_offset
        );
    }

    match &analysis.os {
        GuestOs::Linux(vci) => {
            println!("guest os:       Linux");
            if let Some(rel) = vci.osrelease() {
                println!("kernel:         {rel}");
            }
            if let Some(id) = vci.build_id() {
                println!("build-id:       {id}");
            }
            println!("kaslr offset:   {:#x}", vci.kernel_offset());
            println!("vmcoreinfo:     {} symbols", vci.symbol_count());
            match analysis.linux_symbols() {
                Ok(table) => println!("kallsyms:       {} symbols decoded", table.len()),
                Err(e) => println!("kallsyms:       decode failed: {e}"),
            }
        }
        GuestOs::Windows => {
            println!("guest os:       Windows");
            match analysis.windows_pdb() {
                Ok(pdb) => {
                    println!("kernel base:    {:#x}", pdb.image_base);
                    println!("pdb:            {}", pdb.pdb_name);
                    println!("signature:      {}", pdb.signature);
                    println!(
                        "symbol url:     https://msdl.microsoft.com/download/symbols/{}/{}/{}",
                        pdb.pdb_name, pdb.signature, pdb.pdb_name
                    );
                }
                Err(e) => println!("pdb:            lookup failed: {e}"),
            }
        }
        GuestOs::Unknown => println!("guest os:       unknown (no VMCOREINFO or Windows kernel)"),
    }
    Ok(())
}

fn symbols(dir: &std::path::Path, limit: Option<usize>) -> anyhow::Result<()> {
    let mut analysis = Analysis::open(dir)?;
    if !matches!(analysis.os, GuestOs::Linux(_)) {
        anyhow::bail!("symbol decoding is currently implemented for Linux guests only");
    }
    let table = analysis.linux_symbols()?;
    // Emit in /proc/kallsyms order (by address).
    for (count, sym) in table.iter().enumerate() {
        if limit.is_some_and(|l| count >= l) {
            break;
        }
        println!("{:016x} {} {}", sym.addr, sym.kind, sym.name);
    }
    Ok(())
}

fn dump(dir: &std::path::Path, output: &std::path::Path) -> anyhow::Result<()> {
    let analysis = Analysis::open(dir)?;
    match &analysis.os {
        GuestOs::Linux(_) => {
            let file = std::fs::File::create(output)?;
            let writer = std::io::BufWriter::new(file);
            analysis.write_linux_core(writer)?;
            println!("wrote ELF core dump to {}", output.display());
            println!("open with: crash <vmlinux> {}", output.display());
            println!("       or: drgn -c {}", output.display());
            Ok(())
        }
        GuestOs::Windows => {
            anyhow::bail!(
                "Windows core conversion (.dmp) is not yet implemented; use `subvisor info` \
                 to get the kernel's PDB identity for symbol loading"
            )
        }
        GuestOs::Unknown => anyhow::bail!("could not identify the guest OS; no dump written"),
    }
}
