#!/usr/bin/env python3
"""Run all Go tests once; bound the large Kubernetes package in serial groups."""
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KUBERNETES = "asservat.local/asservat/internal/adapters/kubernetes"
FLAGS = ["-race", "-count=1", "-timeout=15m"]
# Gates 3 and 4 (adr193-go-check-3/4) ran the alphabetically adjacent owner
# projection tests in one group of 80; under host load that group exceeded
# its 15-minute timeout with no test hung. 40 keeps every test, flag and the
# per-run timeout unchanged.
SHARD_SIZE = 40
# CI splits the gate across jobs (--shard I/N): job 0 runs every other
# package, jobs 1..N-1 a duration-balanced part of the Kubernetes inventory.
# Durations come from a recorded local gate; unknown tests weigh 5 s.
DURATIONS = Path(__file__).with_name("go-test-durations.json")
NAME = re.compile(r"(?:Test|Fuzz|Example)[A-Za-z0-9_]*\Z")


def discovered_names(output, package):
    names = []
    summaries = 0
    for line in output.splitlines():
        if NAME.fullmatch(line):
            names.append(line)
        elif re.fullmatch(r"ok\s+" + re.escape(package) + r"\s+.+", line):
            summaries += 1
        elif line:
            raise ValueError(f"Unexpected Go test discovery output: {line}")
    if not names or len(names) != len(set(names)) or summaries != 1:
        raise ValueError("Go discovery must contain unique runnable names and one positive package summary")
    return sorted(names)


def shards(names):
    if not names or len(names) != len(set(names)) or any(not NAME.fullmatch(n) for n in names):
        raise ValueError("Invalid complete test inventory")
    groups = [sorted(names)[i:i + SHARD_SIZE] for i in range(0, len(names), SHARD_SIZE)]
    if Counter(n for group in groups for n in group) != Counter(names):
        raise ValueError("Shards do not cover the discovered inventory exactly once")
    return groups


def balanced(names, weights, count):
    """Longest-processing-time partition; deterministic, complete and disjoint."""
    if count < 1 or len(names) < count or len(names) != len(set(names)):
        raise ValueError("Invalid CI partition")
    bins = [[0.0, index, []] for index in range(count)]
    for name in sorted(names, key=lambda n: (-weights.get(n, 5), n)):
        part = min(bins, key=lambda b: (b[0], b[1]))
        part[0] += weights.get(name, 5)
        part[2].append(name)
    parts = [sorted(b[2]) for b in bins]
    if Counter(n for part in parts for n in part) != Counter(names):
        raise ValueError("CI partition does not cover the inventory exactly once")
    return parts


def checked_shard_events(output, package, expected):
    runs, completed = Counter(), Counter()
    package_passes = 0
    skipped = []
    for line in output.splitlines():
        event = json.loads(line)
        name, action = event.get("Test"), event.get("Action")
        if action in ("fail", "build-fail"):
            raise ValueError("Go test reported a failing event")
        # Go 1.24+ may interleave build diagnostics for dependency packages.
        # They are printed by run(), but cannot count as test execution.
        if action == "build-output" and isinstance(event.get("ImportPath"), str):
            continue
        if event.get("Package") != package:
            raise ValueError("Unexpected package in Kubernetes shard")
        if not name:
            package_passes += action == "pass"
        elif "/" not in name:
            if action == "run":
                runs[name] += 1
            elif action in ("pass", "skip"):
                completed[name] += 1
                if action == "skip":
                    skipped.append(name)
    wanted = Counter(expected)
    if runs != wanted or completed != wanted or package_passes != 1:
        raise ValueError("Actual shard test runs/results do not match its exact discovered selection")
    return skipped


def run(command, capture=False):
    print("+ " + " ".join(command), flush=True)
    # Inherit the invoking gate's process group, CPU/TMP settings, source
    # freeze and signal ownership. Do not create a second detached supervisor.
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE if capture else None)
    if capture:
        print(result.stdout, end="", flush=True)
    result.check_returncode()
    return result.stdout


def selected_shard(argv):
    if not argv:
        return None
    if len(argv) != 2 or argv[0] != "--shard" or not re.fullmatch(r"[0-9]+/[0-9]+", argv[1]):
        raise ValueError("This gate takes no test-selection or framework arguments except --shard I/N")
    index, count = map(int, argv[1].split("/"))
    if not 2 <= count <= 32 or not 0 <= index < count:
        raise ValueError("--shard needs 0 <= I < N and 2 <= N <= 32")
    return index, count


def main():
    shard = selected_shard(sys.argv[1:])
    packages = run(["go", "list", "./..."], capture=True).splitlines()
    if len(packages) != len(set(packages)) or packages.count(KUBERNETES) != 1:
        raise ValueError("Incomplete or ambiguous package inventory")
    # Keep every other package under the original complete-package selection.
    other = [p for p in packages if p != KUBERNETES]
    if not other:
        raise ValueError("Missing non-Kubernetes packages")
    if not shard or shard[0] == 0:
        run(["go", "test", *FLAGS, *other])
    if shard and shard[0] == 0:
        print(f"CI shard 0/{shard[1]}: {len(other)} full packages", flush=True)
        return
    names = discovered_names(run(["go", "test", *FLAGS, "-list", "^(Test|Fuzz|Example)", KUBERNETES], capture=True), KUBERNETES)
    selected = balanced(names, json.loads(DURATIONS.read_text()), shard[1] - 1)[shard[0] - 1] if shard else names
    groups = shards(selected)
    completed = []
    for index, group in enumerate(groups, 1):
        pattern = "^(" + "|".join(re.escape(name) for name in group) + ")$"
        print(f"Kubernetes group {index}/{len(groups)}: {len(group)} exact top-level tests", flush=True)
        output = run(["go", "test", *FLAGS, "-json", "-run", pattern, KUBERNETES], capture=True)
        skipped = checked_shard_events(output, KUBERNETES, group)
        print(f"Verified group {index}: {len(group)} run/results, {len(skipped)} explicit skips", flush=True)
        completed.extend(group)
    if Counter(completed) != Counter(selected):
        raise ValueError("Completed groups do not cover the selected inventory exactly once")
    if shard:
        print(f"CI shard {shard[0]}/{shard[1]}: {len(selected)} of {len(names)} Kubernetes tests in {len(groups)} sequential groups", flush=True)
        return
    print(f"Go tests complete: {len(other)} full packages and {len(names)} Kubernetes tests in {len(groups)} sequential groups", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Go test gate failed: {error}", file=sys.stderr)
        sys.exit(1)
