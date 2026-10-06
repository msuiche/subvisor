# Subvisor

[![Subvisor CI](https://github.com/msuiche/subvisor/actions/workflows/subvisor-ci.yml/badge.svg?branch=main)](https://github.com/msuiche/subvisor/actions/workflows/subvisor-ci.yml)

Subvisor inspects a virtual machine from underneath it. It reads the guest's
memory and CPU state from the virtual machine monitor, walks the guest's page
tables itself, and makes sense of the kernel without any agent inside the guest.
It does this two ways:

- **Live**, as an OpenVMM worker that watches a running Linux guest's kernel for
  tampering (`--vmi-symbols` / `vmi-scan`).
- **Offline**, as the `subvisor` tool, which reads an OpenVMM snapshot, recovers
  the guest's symbols, and converts its memory into a debugger-readable dump.

Nothing runs inside the guest, so a compromised kernel cannot hide from it or
turn it off.

It is built on [OpenVMM](https://github.com/microsoft/openvmm), Microsoft's
open-source VMM written in Rust. This repository is a fork of OpenVMM with the
introspection layer added.

> Status: early and experimental. The live checks and the offline tool both work
> end to end on an arm64 Linux guest under macOS (Hypervisor.framework). Expect
> changes.

## What it checks

The first scan records a baseline. Every later scan reports what changed:

| Check | What it catches |
|---|---|
| Kernel text, hashed per 4KiB page (SHA-256) | Inline hooks and patched kernel code |
| Kernel rodata, hashed per page | Changes to read-only kernel data, including tables kernel code depends on |
| `sys_call_table` entries | Syscall hooks: entries that point outside kernel text or differ from the baseline |
| Page mappings | Text or rodata pages that become mapped or unmapped |

Findings name the kernel symbol involved, for example:

```text
scan: 3 finding(s)
  text: 3152 pages at 0xffffffc080010000 (gpa 0x41210000), 0 unmapped
  rodata: 974 pages at 0xffffffc080c60000 (gpa 0x41e60000), 0 unmapped
  sys_call_table: 470 entries (gpa 0x41e60be8)
  text page 0xffffffc080183000 (acct_write_process+0xe4) modified
  rodata page 0xffffffc080c60000 (__start_rodata) modified
  sys_call_table[89] changed: __arm64_sys_acct -> __arm64_sys_io_setup
```

A scan of about 4,100 pages and 470 syscall entries takes roughly 0.25 seconds.

## How it works

```text
 guest kernel (untrusted)
 ─────────────────────────────────────────────
 OpenVMM partition ──debug requests──▶ vmi_worker ──▶ linux_vmi engine
   (guest RAM, VP registers)          (own process)   (page walk, hashing,
                                                       symbol resolution)
```

- **`vm/linux_vmi`**: the engine. It needs only two things from its host: a way
  to read guest physical memory, and the paging root from VP registers
  (`TTBR1_EL1`/`TCR_EL1` on arm64, `CR3`/`CR4` on x86-64). It has no OpenVMM
  dependencies, so it can later run inside a paravisor (OpenHCL VTL2,
  COCONUT-SVSM) or against a memory dump.
- **`workers/vmi_worker`**: an OpenVMM worker that runs the engine periodically
  and on demand. It shares the debug request channel used by OpenVMM's gdbstub,
  so the VM core is unchanged.
- **OpenVMM integration**: the `--vmi-symbols` and `--vmi-interval` flags, and
  the `vmi-scan` command in the interactive console.

## Quick start

Requires Rust and, on macOS, Xcode command line tools. From the repository root:

```shell
cargo xflowey restore-packages   # build tools and the Linux test guest
cargo build -p openvmm
python3 scripts/subvisor_e2e.py  # boots the test guest and runs the checks
```

The script boots the bundled Linux test guest, captures its `/proc/kallsyms`,
takes a baseline, modifies a syscall handler and its table entry through
OpenVMM's `write-memory` command, and confirms both changes are detected while
the guest keeps running.

To use it with your own guest:

```shell
openvmm --vmi-symbols kallsyms.txt --vmi-interval 30 <usual VM options>
```

- `kallsyms.txt` is the guest's `/proc/kallsyms` (read as root, from the same
  boot because of KASLR) or the kernel's `System.map`. It is read on the first
  scan, so you can copy it out after the guest boots.
- Periodic scans log findings as warnings. Press Ctrl-Q for the OpenVMM
  console, then run `vmi-scan` (or `vmi-scan --reset` to take a new baseline).

More detail: [Guest Introspection](Guide/src/user_guide/openvmm/vm_introspection.md).

## Offline snapshot analysis

The `subvisor` tool reads an OpenVMM snapshot directory (`manifest.bin`,
`state.bin`, `memory.bin`) and makes sense of it with no agent and no
guest-supplied symbols. It is a separate binary, so it works on snapshots from
any OpenVMM fork without modifying the VMM.

```shell
cargo build -p subvisor_dump

# Identify the guest, kernel, and symbol source.
subvisor info   path/to/snapshot

# Print the kernel symbol table, recovered from memory.
subvisor symbols path/to/snapshot

# Convert memory into a kdump-style ELF core for crash / drgn.
subvisor dump   path/to/snapshot -o guest.core
```

How the symbols are recovered, which is the hard part of turning a raw image
into something a debugger understands:

- **Linux.** The tool scans `memory.bin` for the kernel's **VMCOREINFO** block
  (the kernel's self-description for kdump, the Linux counterpart of Windows'
  `KdDebuggerDataBlock`). That block gives the KASLR offset, the page-table
  root, and the exact addresses of the `kallsyms` tables, which the tool then
  decodes from memory. On the arm64 test guest it recovers all 78,534 symbols,
  matching the guest's own `/proc/kallsyms`. The ELF core embeds VMCOREINFO as a
  note, so `crash` and `drgn` read symbols from it exactly as from a real
  vmcore.
- **Windows.** There is no VMCOREINFO, so the tool finds `ntoskrnl` from the
  saved `IDTR`, then reads the image's CodeView (`RSDS`) record to report the
  PDB name and signature. That is the identity a debugger uses to fetch symbols
  from the Microsoft symbol server. (Writing a native `.dmp` is future work; see
  the roadmap.)

`subvisor info` is also an integrity signal in its own right: a snapshot whose
VMCOREINFO, page tables, and kallsyms do not agree has been tampered with.

## Limitations

- **The live worker still takes supplied symbols.** It reads `/proc/kallsyms`
  via `--vmi-symbols`, which a compromised kernel could falsify. The offline
  tool already recovers symbols from memory via VMCOREINFO; folding that into
  the live worker is next, which also removes the flag.
- **Per-page findings.** A finding names the symbol at the start of the
  modified page, not necessarily the modified function.
- **No process or module checks yet.** Walking kernel structures needs type
  information (BTF), which the test kernel does not include.
- **Live reads.** Memory is read while the guest runs, so a single finding can
  be a page caught mid-update. Rescan before acting on it.
- **x86-64 is only unit-tested.** The page walker supports it, but only arm64
  has been tested against a real guest.

## Roadmap

1. Use the offline tool's VMCOREINFO-based symbol recovery in the live worker,
   removing the `--vmi-symbols` dependency on guest-supplied symbols.
2. Byte-level diffs against a stored baseline, giving the exact offset plus
   original and modified bytes.
3. Process, module, and eBPF cross-view checks using in-memory BTF.
4. Event telemetry from hardware breakpoints that does not stop the guest.
5. A native Windows `.dmp` writer (decode `KdDebuggerDataBlock`), and signed
   verification records for snapshot templates before they are shared.
6. Run the engine inside a paravisor (OpenHCL VTL2 or COCONUT-SVSM) to monitor
   confidential VMs, where the host cannot read guest memory.

## Repository layout

Everything outside the paths below is upstream OpenVMM. The fork tracks
`microsoft/openvmm` and is rebased onto it periodically.

| Path | Contents |
|---|---|
| `vm/linux_vmi/` | Introspection engine (page walk, symbols, scanner) |
| `vm/subvisor_dump/` | Offline snapshot tool: VMCOREINFO, kallsyms, ELF core, Windows PDB |
| `workers/vmi_worker/`, `workers/vmi_worker_defs/` | Live OpenVMM worker and its definitions |
| `openvmm/openvmm_entry/` | CLI flags, `vmi-scan` command, worker launch |
| `scripts/subvisor_e2e.py` | Live end-to-end test |
| `.github/workflows/subvisor-ci.yml` | CI for the Subvisor crates |

The OpenVMM workflows inherited from upstream are disabled in this repository:
they rely on Microsoft's self-hosted runners and secrets.

## License

MIT, like OpenVMM. See [LICENSE](LICENSE). Subvisor code is Copyright (c) Matt
Suiche; OpenVMM code is Copyright (c) Microsoft Corporation.
