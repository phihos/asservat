#!/usr/bin/env python3
"""Build one test fixture against two untouched, pinned production trees."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

OLD = "eed8594020645fe6d10f8c6565e69a6235c7507d"
NEW = "fa69b01948edf9d7baf1f00453e1482a224fd4ea"
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "test/fixtures/native-version-helper/main.go"


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def build(root, revision, destination, source, env):
    # Qualification source may add tests/docs, but the compiled product and all
    # embedded contracts must match the pinned production tree without patches.
    if git(root, "rev-parse", revision) != revision:
        raise ValueError("missing pinned production revision")
    changed = git(root, "diff", "--name-only", revision, "--", "api", "cmd", "internal", "migrations", "go.mod", "go.sum", "vendor")
    if changed:
        raise ValueError("production sources differ from the pinned revision")
    untracked = git(root, "ls-files", "--others", "--exclude-standard", "--", "api", "cmd", "internal", "migrations", "vendor")
    if untracked:
        raise ValueError("untracked production sources would change the pinned build")
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=".native-version-fixture-", dir=root) as directory:
        fixture = Path(directory) / "main.go"
        fixture.write_bytes(source)
        subprocess.run(["go", "build", "-mod=readonly", "-ldflags", "-X main.productionRevision=" + revision,
                        "-o", str(destination), str(fixture)], cwd=root, env=env, timeout=120, check=True)
    destination.chmod(0o700)
    return {"path": str(destination), "production_revision": revision,
            "production_tree": git(root, "rev-parse", revision + "^{tree}"),
            "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(),
            "build_seconds": time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old-worktree", type=Path, required=True)
    parser.add_argument("--new-worktree", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700)  # Never replace a previously frozen executable.
    source = SOURCE.read_bytes()
    env = os.environ.copy()
    env.update({"GOWORK": "off", "GOPROXY": "off", "GOFLAGS": "-p=2", "GOMAXPROCS": "2"})
    # Modules are pinned by each tree's own go.mod/go.sum; this repository's
    # vendor directory is a local profiler replacement, not a go-mod-vendor tree.
    report = {"format": "native-version-build/v1", "fixture_sha256": hashlib.sha256(source).hexdigest(),
              "go_version": subprocess.check_output(["go", "version"], env=env, text=True).strip(), "binaries": {}}
    for name, root, revision in (("old", args.old_worktree.resolve(), OLD), ("new", args.new_worktree.resolve(), NEW)):
        report["binaries"][name] = build(root, revision, output / (name + "-native-helper"), source, env)
    manifest = output / "manifest.json"
    manifest.write_text(json.dumps(report, indent=2) + "\n")
    manifest.chmod(0o600)
    print(manifest)


if __name__ == "__main__":
    main()
