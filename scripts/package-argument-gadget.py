#!/usr/bin/env python3
"""Build the pinned local argument object for a collector image; never load/push it."""
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("output", type=Path, help="new collector gadgets/traceloop-arguments directory")
parser.add_argument("--tmpdir", type=Path, required=True)
args = parser.parse_args()
pins = json.loads((ROOT / "experiments/syscall-argument-budget/pins.json").read_text())
if args.output.exists():
    raise SystemExit("output already exists; do not replace a packaged engine")
with tempfile.TemporaryDirectory(prefix="arguments-package-", dir=args.tmpdir) as directory:
    build = Path(directory) / "build"
    subprocess.run([
        "python3", str(ROOT / "experiments/syscall-argument-budget/prepare.py"),
        str(build), "--compile",
    ], check=True)
    raw = (build / "program.bpf.o").read_bytes()
    if hashlib.sha256(raw).hexdigest() != pins["compiled_object_sha256"]:
        raise SystemExit("object pin mismatch")
    args.output.mkdir(parents=True)
    shutil.copyfile(build / "program.bpf.o", args.output / "program.bpf.o")
    (args.output / "source-pins.json").write_text(json.dumps(pins, indent=2) + "\n")
print("Packaged verified local ELF only; no registry, BPF load, capability or public activation")
