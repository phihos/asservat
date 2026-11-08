#!/usr/bin/env python3
"""Pre-push: run the Go tests a diff can affect, with CI's test-shard flags.

Selects every package containing a changed file (committed since the merge
base with origin/main, staged, unstaged or untracked), every package whose
build or tests import one transitively, and every package whose tests read a
changed repository path through a relative literal ("../../examples", ...).
go.mod or go.sum changes select everything. Flags match CI's test shards
(-race, 15m timeout), but Go's test cache stays on, so unchanged test inputs
are not rerun.

Each package is one `go test` process; the Kubernetes adapter (CI's
duration-balanced partitions) and the other packages that dominate CI's
shard 0 run as several partitions; SLOTS processes run at once, changed
packages and the longest jobs first. When the Kubernetes adapter is only a
reverse dependency, its tests above HEAVY_SECONDS on CI (the time budget: ~30
of ~700 tests, over half its run time) are skipped and listed;
ASSERVAT_AFFECTED_FULL=1 runs them. Many tests are timing-bound,
so a test that fails under parallel load is rerun once alone: a stale
assertion fails again, a load-induced timeout does not.
"""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("go_tests", Path(__file__).with_name("check-go-tests.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

MODULE = "asservat.local/asservat/"
KUBERNETES = gate.KUBERNETES
FLAGS = ["-race", "-timeout=15m"]
EVERYTHING = {"go.mod", "go.sum"}
HEAVY_SECONDS = 20
SLOTS = int(os.environ.get("ASSERVAT_AFFECTED_SLOTS", "8"))
KUBERNETES_PARTS = 8
# CI shard 0's longest packages (seconds under -race on CI): partitions.
SPLIT = {"internal/transport/presentation": (5, 520), "internal/transport/native": (2, 146),
         "internal/bootstrap": (3, 135), "internal/transport/mcp": (2, 123)}
# pcap-check's libpcap-tagged selections (package dir, -run pattern or None).
PCAP_TESTS = [
    ("internal/adapters/pcap", None),
    ("internal/bootstrap", "^TestPacketQueryPinnedLibpcapWireLengthAndTruncation$"),
    ("internal/adapters/postgres", "^TestRawPolicyApprovedTimingReplayIgnoresRequireAllSwitch$"),
]
RELATIVE = re.compile(r'"((?:\.\./)+[A-Za-z0-9_.-]+)|Join\(((?:"\.\.",\s*)+)"([A-Za-z0-9_.-]+)"')


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, text=True, check=True, stdout=subprocess.PIPE).stdout.split("\n")


def changed_files(base_ref):
    base = git("merge-base", base_ref, "HEAD")[0]
    files = git("diff", "--name-only", "--no-renames", base) + git("ls-files", "--others", "--exclude-standard")
    return sorted({f for f in files if f})


def go_packages():
    out = subprocess.run(["go", "list", "-json", "./..."], cwd=ROOT, text=True, check=True, stdout=subprocess.PIPE).stdout
    decoder, index, packages = json.JSONDecoder(), 0, {}
    while index < len(out):
        if out[index].isspace():
            index += 1
            continue
        item, index = decoder.raw_decode(out, index)
        packages[item["ImportPath"]] = item
    return packages


def relative_reads(package):
    """Repository paths a package's tests name through relative literals."""
    directory = Path(package["Dir"])
    paths = set()
    for name in package.get("TestGoFiles", []) + package.get("XTestGoFiles", []):
        for match in RELATIVE.finditer((directory / name).read_text()):
            text = match.group(1) or "../" * match.group(2).count('".."') + match.group(3)
            resolved = (directory / text).resolve()
            if resolved.is_relative_to(ROOT) and resolved != ROOT:
                paths.add(resolved.relative_to(ROOT).as_posix())
    return paths


def affected(files, packages):
    """Return (directly changed, reverse dependencies) import-path sets of packages with tests."""
    with_tests = {path for path, p in packages.items() if p.get("TestGoFiles") or p.get("XTestGoFiles")}
    if EVERYTHING & set(files):
        return with_tests, set()
    by_dir = {Path(p["Dir"]).relative_to(ROOT).as_posix(): path for path, p in packages.items()}
    direct = set()
    for name in files:
        parent = Path(name).parent
        while parent.as_posix() not in by_dir and parent != Path("."):
            parent = parent.parent
        if parent.as_posix() in by_dir:
            direct.add(by_dir[parent.as_posix()])
    for path, p in packages.items():
        prefixes = relative_reads(p)
        if any(name == prefix or name.startswith(prefix + "/") for name in files for prefix in prefixes):
            direct.add(path)
    # Packages whose (non-test) build reaches a changed package.
    reaching = set(direct)
    grew = True
    while grew:
        grew = False
        for path, p in packages.items():
            if path not in reaching and reaching & set(p.get("Imports", [])):
                reaching.add(path)
                grew = True
    tested = {path for path, p in packages.items()
              if reaching & set(p.get("Imports", []) + p.get("TestImports", []) + p.get("XTestImports", []))}
    selected = (reaching | tested) & with_tests
    return direct & selected, selected - direct


class Job:
    def __init__(self, label, package, direct, names=None, weight=0.0, tags=(), env=None, run=None, json_output=True):
        self.label, self.package, self.direct, self.names, self.weight = label, package, direct, names, weight
        self.tags, self.env, self.run, self.json_output = list(tags), env, run, json_output

    def command(self):
        pattern = self.run or (self.names and "^(" + "|".join(re.escape(n) for n in self.names) + ")$")
        return ["go", "test", *FLAGS, *self.tags, *(["-json"] if self.json_output else ["-count=1"]),
                *(["-run", pattern] if pattern else []), self.package]


def listed(package):
    out = subprocess.run(["go", "test", *FLAGS, "-list", "^(Test|Fuzz|Example)", package],
                         cwd=ROOT, text=True, check=True, stdout=subprocess.PIPE).stdout
    return gate.discovered_names(out, package)


def package_jobs(path, direct, full):
    """(jobs, skipped heavy test names) for one selected package."""
    short = path.removeprefix(MODULE)
    if path == KUBERNETES:
        names = listed(path)
        weights = json.loads(gate.DURATIONS.read_text())
        skipped = [] if direct or full else sorted(n for n in names if weights.get(n, 5) > HEAVY_SECONDS)
        kept = [n for n in names if n not in skipped]
        parts = gate.balanced(kept, weights, min(KUBERNETES_PARTS, len(kept)))
        return [Job(f"{short} {i}/{len(parts)}", path, direct, part, sum(weights.get(n, 5) for n in part))
                for i, part in enumerate(parts, 1)], [f"{short}.{n}" for n in skipped]
    if short in SPLIT:
        names = listed(path)
        count, seconds = min(SPLIT[short][0], len(names)), SPLIT[short][1]
        parts = gate.balanced(names, {}, count)
        return [Job(f"{short} {i}/{count}", path, direct, part, seconds / count) for i, part in enumerate(parts, 1)], []
    return [Job(short, path, direct)], []


def pcap_jobs(selected):
    """pcap-check's libpcap-tagged tests (CI's go job) for affected packages."""
    wanted = [(MODULE + path, run) for path, run in PCAP_TESTS if MODULE + path in selected]
    if not wanted:
        return []
    prefix = Path(os.environ.get("LIBPCAP_PREFIX", Path.home() / ".cache/asservat-build/libpcap-1.11.0"))
    if not (prefix / "lib/libpcap.a").is_file():
        print(f"affected Go tests: no {prefix}/lib/libpcap.a (make libpcap); skipping libpcap-tagged tests", flush=True)
        return []
    env = {**os.environ, "CGO_ENABLED": "1", "CGO_CFLAGS": f"-I{prefix}/include", "CGO_LDFLAGS": f"-L{prefix}/lib"}
    return [Job(f"libpcap {path.removeprefix(MODULE)}", path, True, tags=["-tags", "libpcap"], env=env, run=run)
            for path, run in wanted]


def results(stream):
    """(failed top-level tests, output of failures and package-level lines) of a -json stream."""
    events = [json.loads(line) for line in stream.splitlines() if line.startswith("{")]
    failed = sorted({e["Test"].split("/")[0] for e in events if e.get("Action") == "fail" and e.get("Test")})
    output = "".join(e.get("Output", "") for e in events
                     if e.get("Test") is None or e.get("Test", "").split("/")[0] in failed)
    output += "".join(line + "\n" for line in stream.splitlines() if not line.startswith("{"))
    return failed, output


def execute(job):
    started = time.monotonic()
    # stderr (build diagnostics, linker warnings) stays out of the -json stream.
    result = subprocess.run(job.command(), cwd=ROOT, env=job.env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode, result.stdout, result.stderr, time.monotonic() - started


def main():
    base_ref = os.environ.get("ASSERVAT_AFFECTED_BASE", "origin/main")
    files = changed_files(base_ref)
    packages = go_packages()
    direct, reverse = affected(files, packages)
    selected = direct | reverse
    print(f"affected Go tests vs {base_ref}: {len(files)} changed files, {len(direct)} changed packages, "
          f"{len(reverse)} reverse dependencies", flush=True)
    for path in sorted(selected):
        print(f"  {'changed' if path in direct else 'reverse'} {path.removeprefix(MODULE)}", flush=True)
    if not selected or sys.argv[1:] == ["--list"]:
        return 0
    full = os.environ.get("ASSERVAT_AFFECTED_FULL") == "1"
    jobs, skipped = pcap_jobs(selected), []
    for path in sorted(selected):
        more, heavy = package_jobs(path, path in direct, full)
        jobs += more
        skipped += heavy
    # Changed packages first, then the longest jobs.
    jobs.sort(key=lambda j: (not j.direct, -j.weight, j.label))
    started, failures = time.monotonic(), []
    with concurrent.futures.ThreadPoolExecutor(SLOTS) as pool:
        futures = {pool.submit(execute, job): job for job in jobs}
        for future in concurrent.futures.as_completed(futures):
            job = futures[future]
            code, stream, errors, seconds = future.result()
            failed, output = results(stream)
            output += errors
            if job.names is not None and code == 0:
                try:
                    gate.checked_shard_events(stream, job.package, job.names)
                except ValueError as error:
                    code, failed, output = 1, [], f"{error}\n"
            if code == 0:
                print(f"ok   {job.label} {seconds:.0f}s", flush=True)
                continue
            print(f"FAIL {job.label} {seconds:.0f}s: {' '.join(failed) or 'package or build failure'}", flush=True)
            failures.append((job, failed, output))
    hard, flaky = [], []
    for job, failed, output in failures:
        if failed:
            retry = Job(job.label, job.package, job.direct, tags=job.tags, env=job.env, json_output=False,
                        run="^(" + "|".join(re.escape(n) for n in failed) + ")$")
            print(f"rerunning alone: {job.label}: {' '.join(failed)}", flush=True)
            code, alone, alone_errors, _ = execute(retry)
            alone += alone_errors
            if code == 0:
                flaky.append(f"{job.label}: {' '.join(failed)}")
                continue
            output += f"--- rerun alone\n{alone}"
        hard.append(job.label)
        print(f"--- {job.label}\n{output}", end="", flush=True)
    if skipped:
        print(f"affected Go tests: skipped {len(skipped)} Kubernetes tests above {HEAVY_SECONDS}s on CI "
              f"(reverse dependency only): {' '.join(skipped)}", flush=True)
        print("affected Go tests: ASSERVAT_AFFECTED_FULL=1 runs them; CI always does", flush=True)
    for item in flaky:
        print(f"affected Go tests: failed under parallel load, passed alone: {item}", flush=True)
    print(f"affected Go tests: {'FAILED ' + ', '.join(sorted(hard)) if hard else 'passed'} in "
          f"{time.monotonic() - started:.0f}s", flush=True)
    return 1 if hard else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"affected Go tests failed: {error}", file=sys.stderr)
        sys.exit(1)
