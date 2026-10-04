# Copyright (c) Matt Suiche.
# Licensed under the MIT License.

"""End-to-end check for the Subvisor introspection worker.

Boots the Linux direct-boot test guest from `cargo xflowey restore-packages`,
captures /proc/kallsyms over the serial console, and runs `vmi-scan` from the
OpenVMM REPL:

1. A clean scan must report no findings.
2. The script then uses the REPL's `write-memory` command to patch the first
   instruction of the (unused) acct syscall handler and to point its
   sys_call_table slot at another handler. The next scan must report both.
3. The guest must still respond afterwards.

Usage: python3 scripts/subvisor_e2e.py   (after `cargo build -p openvmm`)

Only tested on macOS/arm64 (HVF). The x86_64 values below are untested.
"""

import os
import platform
import pty
import re
import select
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ARCH = {
    "arm64": {
        "pkg": "aarch64",
        "kernel": "Image",
        "nop": "1f2003d5",
        "acct": ("__arm64_sys_acct", 89),
        "other": "__arm64_sys_io_setup",
    },
    "x86_64": {
        "pkg": "x64",
        "kernel": "vmlinux",
        "nop": "90",
        "acct": ("__x64_sys_acct", 163),
        "other": "__x64_sys_io_setup",
    },
}
ARCH["aarch64"] = ARCH["arm64"]
ARCH["AMD64"] = ARCH["x86_64"]

REPORT_END = rb"sys_call_table: \d+ entries[^\n]*\n(  [^\n]*\n)*"


class Vm:
    def __init__(self, args, log_path):
        self.master, slave = pty.openpty()
        self.proc = subprocess.Popen(
            args, stdin=slave, stdout=slave, stderr=slave, cwd=REPO, close_fds=True
        )
        os.close(slave)
        self.buf = bytearray()
        self.log = open(log_path, "wb")

    def pump(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.2)
            if not r:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return
            if not data:
                return
            self.buf.extend(data)
            self.log.write(data)
            self.log.flush()

    def wait_for(self, pattern, timeout, start=None):
        start = len(self.buf) if start is None else start
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.5)
            m = re.search(pattern, bytes(self.buf[start:]))
            if m:
                return start + m.end()
            if self.proc.poll() is not None:
                break
        tail = bytes(self.buf[-2000:]).decode(errors="replace")
        raise SystemExit(f"FAIL: timed out waiting for {pattern!r}; output tail:\n{tail}")

    def send(self, data):
        os.write(self.master, data.encode() if isinstance(data, str) else data)

    def command(self, line, timeout=60):
        mark = len(self.buf)
        self.send(line + "\n")
        self.wait_for(REPORT_END, timeout, start=mark)
        self.pump(1)
        return bytes(self.buf[mark:]).decode(errors="replace")

    def close(self):
        self.send(b"\x11")
        self.pump(0.5)
        self.send("q\n")
        self.pump(3)
        if self.proc.poll() is None:
            self.proc.kill()
        self.log.close()


def main():
    arch = ARCH.get(platform.machine())
    if arch is None:
        raise SystemExit(f"unsupported host architecture {platform.machine()}")
    pkg = os.path.join(REPO, ".packages", "underhill-deps-private", arch["pkg"])
    openvmm = os.path.join(REPO, "target", "debug", "openvmm")
    for path in (openvmm, os.path.join(pkg, arch["kernel"])):
        if not os.path.exists(path):
            raise SystemExit(f"missing {path}; run `cargo xflowey restore-packages` and `cargo build -p openvmm`")
    if sys.platform == "darwin":
        entitlements = os.path.join(REPO, "build_support", "macos", "entitlements.xml")
        subprocess.run(
            ["codesign", "--entitlements", entitlements, "-f", "-s", "-", openvmm],
            check=True,
            capture_output=True,
        )

    work = tempfile.mkdtemp(prefix="subvisor-e2e-")
    symbols_path = os.path.join(work, "kallsyms.txt")
    log_path = os.path.join(work, "console.log")
    print(f"work dir: {work}")

    vm = Vm(
        [
            openvmm,
            "--kernel", os.path.join(pkg, arch["kernel"]),
            "--initrd", os.path.join(pkg, "initrd"),
            "--vmi-symbols", symbols_path,
            "--vmi-interval", "0",
        ],
        log_path,
    )
    try:
        # Wait for the initrd shell.
        vm.pump(15)
        vm.send("\n")
        vm.pump(2)

        mark = len(vm.buf)
        vm.send("echo KS_BEGIN; cat /proc/kallsyms; echo KS_END\n")
        end = vm.wait_for(rb"\nKS_END", 600, start=mark)
        text = bytes(vm.buf[mark:end]).decode(errors="replace").replace("\r", "")
        body = text[text.rindex("KS_BEGIN") :].split("\n", 1)[1]
        lines = [l for l in body.splitlines() if re.match(r"^[0-9a-f]{8,16} \S \S+", l)]
        with open(symbols_path, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"captured {len(lines)} symbols")

        vm.send(b"\x11")  # Ctrl-Q: command mode
        vm.pump(1)
        baseline = vm.command("vmi-scan")
        clean = vm.command("vmi-scan")
        print(clean)
        if "scan: 0 finding(s)" not in clean:
            raise SystemExit("FAIL: clean rescan reported findings")

        syms = {}
        for l in lines:
            addr, _, name = l.split()[:3]
            syms.setdefault(name, int(addr, 16))
        text_gpa = int(re.search(r"text: \d+ pages at 0x[0-9a-f]+ \(gpa (0x[0-9a-f]+)\)", baseline).group(1), 16)
        table_gpa = int(re.search(r"sys_call_table: \d+ entries \(gpa (0x[0-9a-f]+)\)", baseline).group(1), 16)
        handler, nr = arch["acct"]
        handler_gpa = text_gpa + (syms[handler] - (syms["_stext"] & ~0xFFF))
        other = syms[arch["other"]].to_bytes(8, "little").hex()

        vm.send(f"write-memory {handler_gpa:#x} {arch['nop']}\n")
        vm.pump(1)
        vm.send(f"write-memory {table_gpa + nr * 8:#x} {other}\n")
        vm.pump(1)

        modified = vm.command("vmi-scan")
        print(modified)
        expected = f"sys_call_table[{nr}] changed: {handler} -> {arch['other']}"
        if expected not in modified or "text page" not in modified:
            raise SystemExit("FAIL: modification not detected")

        vm.send("I\n")  # back to the guest console
        vm.pump(1)
        vm.send("echo ALIVE_$((40+2))\n")
        vm.wait_for(rb"ALIVE_42", 20)
        print("PASS: clean scan, modification detected, guest still running")
    finally:
        vm.close()


if __name__ == "__main__":
    main()
