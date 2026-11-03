#!/usr/bin/env python3
"""Prepare or compile the pinned prototype. Never loads/attaches any BPF program."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require_digest(data, expected, label):
    if digest(data) != expected:
        raise ValueError(f"{label}: source digest mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new directory on a filesystem with build space")
    parser.add_argument("--upstream", type=Path, help="use an already downloaded, verified source")
    parser.add_argument("--compile", action="store_true", help="compile only in the digest-pinned builder")
    args = parser.parse_args()
    pins = json.loads((ROOT / "pins.json").read_text())
    for name, key in (("program.patch", "patch_sha256"), ("budget.h", "budget_header_sha256")):
        require_digest((ROOT / name).read_bytes(), pins[key], name)
    if args.upstream:
        upstream = args.upstream.read_bytes()
    else:
        url = ("https://raw.githubusercontent.com/inspektor-gadget/inspektor-gadget/"
               + pins["upstream_commit"] + "/gadgets/traceloop/program.bpf.c")
        with urllib.request.urlopen(url, timeout=30) as response:
            upstream = response.read(1 << 20)
    require_digest(upstream, pins["upstream_program_sha256"], "upstream")
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    (output / "program.bpf.c").write_bytes(upstream)
    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(ROOT / "program.patch")],
                   cwd=output, check=True)
    require_digest((output / "program.bpf.c").read_bytes(), pins["patched_program_sha256"], "patched program")
    shutil.copyfile(ROOT / "budget.h", output / "budget.h")
    if args.compile:
        # Build-only container: no host PID/netns, devices, capabilities or BPF mounts.
        subprocess.run([
            "docker", "run", "--rm", "--platform=linux/amd64", "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "--mount", f"type=bind,src={output},dst=/work",
            pins["builder_linux_amd64"], "clang", "-O2", "-g", "-target", pins["bpf_target"],
            "-mcpu=" + pins["bpf_cpu"], "-D__TARGET_ARCH_" + pins["target_arch"],
            "-I/usr/include/gadget/amd64", "-I/usr/include", "-fdebug-prefix-map=/work=.",
            "-c", "/work/program.bpf.c", "-o", "/work/program.bpf.o",
        ], check=True)
        require_digest((output / "program.bpf.o").read_bytes(), pins["compiled_object_sha256"], "compiled object")
        print("BPF object SHA-256:", pins["compiled_object_sha256"])
        print("Compiled only: verifier, kernel behavior, OCI packaging and runtime authority remain unqualified.")
    else:
        print("Pinned source prepared; no BPF compilation, load or execution.")


if __name__ == "__main__":
    main()
