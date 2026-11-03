#!/usr/bin/env python3
"""Host-only tests and BPF compilation; never load an eBPF program."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tmpdir", type=Path, required=True)
    args = p.parse_args()
    pins = json.loads((ROOT / "pins.json").read_text())
    for name, key in (("program.patch", "patch_sha256"), ("budget.h", "budget_header_sha256")):
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == pins[key], name
    with tempfile.TemporaryDirectory(prefix="argument-budget-", dir=args.tmpdir) as d:
        out = Path(d)
        subprocess.run(["clang", "-std=c11", "-D_XOPEN_SOURCE=700", "-O2", "-Wall", "-Wextra",
                        "-Werror", "-pthread", str(ROOT / "budget_test.c"), "-o", str(out / "host-test")], check=True)
        subprocess.run([str(out / "host-test")], check=True, timeout=30)
        subprocess.run(["clang", "-O2", "-target", pins["bpf_target"], "-mcpu=" + pins["bpf_cpu"],
                        "-c", str(ROOT / "budget_compile.bpf.c"), "-o", str(out / "isa.o")], check=True)
        assembly = subprocess.run(["llvm-objdump", "-d", str(out / "isa.o")], check=True,
                                  capture_output=True, text=True).stdout
        assert "cmpxchg_64" in assembly, "BPF atomic instruction missing"
        # Reproducible preparation refuses source substitution before creating output.
        wrong = out / "wrong.c"
        wrong.write_text("not the pinned program\n")
        result = subprocess.run(["python3", str(ROOT / "prepare.py"), str(out / "rejected"),
                                 "--upstream", str(wrong)], capture_output=True, text=True)
        assert result.returncode != 0 and "source digest mismatch" in result.stderr
        assert not (out / "rejected").exists()
    print("PASS: pinned-input refusal and compile-only BPF CMPXCHG check; no kernel qualification")


if __name__ == "__main__":
    main()
