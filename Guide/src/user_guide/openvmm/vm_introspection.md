# Guest Introspection

OpenVMM can check the integrity of a running Linux guest kernel from the
host, without an agent inside the guest. The introspection worker reads guest
physical memory and VP registers, walks the guest page tables itself, and
compares the kernel against a baseline.

## What is checked

The first scan records a baseline. Later scans report differences from it:

- **Kernel text and rodata**: a SHA-256 hash of every page between `_stext`
  and `_etext`, and between `__start_rodata` and `__end_rodata`. Pages that
  change, or that become mapped or unmapped, are reported with the symbol at
  the start of the page.
- **System call table**: every `sys_call_table` entry must point into kernel
  text, and must match the baseline. Changed entries are reported as
  `old_symbol -> new_symbol`.

Take the baseline as early as possible: it is only as trustworthy as the
kernel at that moment. Some kernel text changes legitimately after boot
(static keys, ftrace), and those changes are reported like any other.

Memory is read while the guest runs, so a scan can observe a page in the
middle of an update. Rescan before treating a single finding as conclusive.

## Usage

The worker needs the guest kernel's symbols, in `/proc/kallsyms` or
`System.map` format. Copy `/proc/kallsyms` out of the guest (as root, so the
addresses are not zeroed), or use the `System.map` that matches the guest
kernel. Because of KASLR, `/proc/kallsyms` must come from the same boot.

```shell
openvmm --vmi-symbols path/to/kallsyms.txt --vmi-interval 30 ...
```

The file is read on the first scan, so it can be created after the VM starts.
Periodic scans log findings as warnings. To scan on demand, use the
interactive console:

```text
vmi-scan
vmi-scan --reset
```

`--reset` discards the baseline and records a new one. Example output after
a syscall handler was patched and its table entry redirected:

```text
scan: 3 finding(s)
  text: 3152 pages at 0xffffffc080010000 (gpa 0x41210000), 0 unmapped
  rodata: 974 pages at 0xffffffc080c60000 (gpa 0x41e60000), 0 unmapped
  sys_call_table: 470 entries (gpa 0x41e60be8)
  text page 0xffffffc080183000 (acct_write_process+0xe4) modified
  rodata page 0xffffffc080c60000 (__start_rodata) modified
  sys_call_table[89] changed: __arm64_sys_acct -> __arm64_sys_io_setup
```

`scripts/subvisor_e2e.py` runs this whole flow against the Linux direct-boot
test guest.

## Limitations

- The symbols are supplied by the guest, which a compromised kernel could
  falsify. Recovering kallsyms directly from guest memory is planned.
- Findings are per page; the reported symbol is the one at the start of the
  page, not necessarily the modified function.
- Supported paging: AArch64 `TTBR1_EL1` with a 4KiB granule, and x86-64 4- and
  5-level paging. Only AArch64 has been tested against a real guest.
- The worker shares the debug request channel with `--gdb`; both can be
  enabled together.
