#!/usr/bin/env python3
"""Run all Go tests once; bound the large Kubernetes package in serial groups.

Local gate (no arguments): every other package in one `go test`, then the
Kubernetes package's discovered top-level tests in serial groups.

CI (--shard I/N): the complete inventory is a set of units, each whole small
package and each top-level test of the SPLIT packages, partitioned by CI
weights (DURATIONS) into N deterministic, disjoint parts. Every shard
discovers the same inventory and checks that the partition covers it exactly
once; its own whole packages and test groups must then report exactly one
terminal result per unit. With ASSERVAT_GO_TEST_RECORD=<file> a shard writes
the plan, its executed units and the measured times; --verify-union N DIR
checks that N such records share one plan and together executed every unit
exactly once (the ci-ok job), and --update-weights DIR... refreshes DURATIONS
from downloaded records.
"""
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULE = "asservat.local/asservat/"
KUBERNETES = MODULE + "internal/adapters/kubernetes"
FLAGS = ["-race", "-count=1", "-timeout=15m"]
# Gates 3 and 4 (adr193-go-check-3/4) ran the alphabetically adjacent owner
# projection tests in one group of 80; under host load that group exceeded
# its 15-minute timeout with no test hung. 40 keeps every test, flag and the
# per-run timeout unchanged.
SHARD_SIZE = 40
# CI packages split by top-level test: each takes longer under -race on CI
# than a balanced shard should, or is close to it.
SPLIT = {KUBERNETES} | {MODULE + p for p in (
    "internal/transport/presentation", "internal/bootstrap", "internal/transport/native", "internal/transport/mcp",
    "internal/transport/browser", "test/integration", "internal/adapters/mtls", "internal/application/capture")}
# {"packages": {short path: s}, "tests": {short path: {test: s}}}, measured on
# CI; unknown packages and tests weigh DEFAULT_WEIGHT.
DURATIONS = Path(__file__).with_name("go-test-durations.json")
DEFAULT_WEIGHT = 5
# Measured on CI (run 42460940268): a shard's step time minus its tests'
# elapsed time is about this much per `go test` run.
GROUP_SECONDS = 4
NAME = re.compile(r"(?:Test|Fuzz|Example)[A-Za-z0-9_]*\Z")


def short(package):
    return package.removeprefix(MODULE)


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


def discovered_inventory(output, packages):
    """{package: sorted names} from one multi-package `go test -list` run."""
    lines = {p: [] for p in packages}
    current = []
    for line in output.splitlines():
        match = re.fullmatch(r"ok\s+(\S+)\s+.+", line)
        if match and match.group(1) in lines:
            if lines[match.group(1)]:
                raise ValueError(f"Repeated Go discovery summary for {match.group(1)}")
            lines[match.group(1)] = current + [line]
            current = []
        else:
            current.append(line)
    if any(current) or len(lines) != len(packages):
        raise ValueError("Go discovery output does not end in one summary per package")
    return {p: discovered_names("\n".join(text), p) for p, text in lines.items()}


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
    for name in sorted(names, key=lambda n: (-weights.get(n, DEFAULT_WEIGHT), n)):
        part = min(bins, key=lambda b: (b[0], b[1]))
        part[0] += weights.get(name, DEFAULT_WEIGHT)
        part[2].append(name)
    parts = [sorted(b[2]) for b in bins]
    if Counter(n for part in parts for n in part) != Counter(names):
        raise ValueError("CI partition does not cover the inventory exactly once")
    return parts


def planned(weights, count):
    """Longest-first partition of units that also charges each `go test` run.

    Each shard pays about GROUP_SECONDS (link, start, discovery) for its one
    whole-package run and for every group of up to SHARD_SIZE tests of a split
    package, so a unit goes to the shard where its weight plus any new run
    costs least. This keeps a package's many short tests together instead of
    leaving one shard with dozens of nearly empty groups.
    """
    if count < 1 or len(weights) < count:
        raise ValueError("Invalid CI partition")
    bins = [[0.0, index, Counter(), []] for index in range(count)]

    def cost(part, unit):
        package, name = unit
        key = package if name else ""
        opens = part[2][key] % SHARD_SIZE == 0 if name else part[2][key] == 0
        return part[0] + weights[unit] + (GROUP_SECONDS if opens else 0)

    for unit in sorted(weights, key=lambda u: (-weights[u], u)):
        part = min(bins, key=lambda b: (cost(b, unit), b[1]))
        part[0] = cost(part, unit)
        part[2][unit[0] if unit[1] else ""] += 1
        part[3].append(unit)
    parts = [sorted(b[3]) for b in bins]
    if Counter(u for part in parts for u in part) != Counter(weights.keys()):
        raise ValueError("CI partition does not cover the inventory exactly once")
    return parts


def units(packages, inventory, durations):
    """{(package, test or ""): weight}: whole packages and split packages' tests."""
    if set(inventory) - set(packages):
        raise ValueError("Discovered a split package outside the package inventory")
    weights = {}
    for package in packages:
        if package in inventory:
            tests = durations["tests"].get(short(package), {})
            weights.update({(package, name): tests.get(name, DEFAULT_WEIGHT) for name in inventory[package]})
        else:
            weights[(package, "")] = durations["packages"].get(short(package), DEFAULT_WEIGHT)
    return weights


def plan_digest(parts):
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()


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
            raise ValueError("Unexpected package in exact test group")
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


def checked_package_events(output, packages):
    """Exactly one passing (or no-test-files skip) package result per whole package."""
    results = Counter()
    for line in output.splitlines():
        event = json.loads(line)
        action = event.get("Action")
        if action in ("fail", "build-fail"):
            raise ValueError("Go test reported a failing event")
        if action == "build-output" and isinstance(event.get("ImportPath"), str):
            continue
        if event.get("Package") not in packages:
            raise ValueError("Unexpected package in whole-package run")
        if not event.get("Test") and action in ("pass", "skip"):
            results[event["Package"]] += 1
    if results != Counter(packages):
        raise ValueError("Whole-package run did not report exactly one result per selected package")


def timings(output):
    """({package: elapsed}, {package: {top-level test: elapsed}}) of a -json stream."""
    packages, tests = {}, {}
    for line in output.splitlines():
        event = json.loads(line)
        if event.get("Action") not in ("pass", "skip", "fail") or "Elapsed" not in event or "Package" not in event:
            continue
        name, package = event.get("Test"), short(event["Package"])
        if not name:
            packages[package] = packages.get(package, 0) + event["Elapsed"]
        elif "/" not in name:
            tests.setdefault(package, {})[name] = event["Elapsed"]
    return packages, tests


def text_of(output):
    """What `go test` without -v prints: package lines and failed tests' output."""
    events = [json.loads(line) if line.startswith("{") else {"Output": line + "\n"} for line in output.splitlines()]
    failed = {(e.get("Package"), e["Test"].split("/")[0]) for e in events if e.get("Action") == "fail" and e.get("Test")}
    return "".join(e.get("Output", "") for e in events
                   if not e.get("Test") or (e.get("Package"), e["Test"].split("/")[0]) in failed)


def run(command, capture=False, json_stream=False):
    print("+ " + " ".join(command), flush=True)
    # Inherit the invoking gate's process group, CPU/TMP settings, source
    # freeze and signal ownership. Do not create a second detached supervisor.
    result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE if capture or json_stream else None)
    if json_stream:
        try:
            print(text_of(result.stdout), end="", flush=True)
        except ValueError:
            print(result.stdout, end="", flush=True)
            raise
    elif capture:
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


def run_groups(package, names):
    """Serial groups of exact top-level tests; returns (packages, tests) timings."""
    groups = shards(names)
    measured = ({}, {})
    for index, group in enumerate(groups, 1):
        pattern = "^(" + "|".join(re.escape(name) for name in group) + ")$"
        print(f"{short(package)} group {index}/{len(groups)}: {len(group)} exact top-level tests", flush=True)
        output = run(["go", "test", *FLAGS, "-json", "-run", pattern, package], json_stream=True)
        skipped = checked_shard_events(output, package, group)
        packages, tests = timings(output)
        print(f"Verified group {index}: {len(group)} run/results, {len(skipped)} explicit skips, "
              f"{sum(packages.values()):.0f}s", flush=True)
        measured[1].setdefault(short(package), {}).update(tests.get(short(package), {}))
    return measured


def run_shard(packages, index, count):
    split = sorted(p for p in packages if p in SPLIT)
    if set(SPLIT) - set(split):
        raise ValueError("A split package is missing from the package inventory")
    # One parallel discovery; -p overrides the shard's GOFLAGS=-p=2.
    inventory = discovered_inventory(run(["go", "test", *FLAGS, "-p=4", "-list", "^(Test|Fuzz|Example)", *split], capture=True), split)
    weights = units(packages, inventory, json.loads(DURATIONS.read_text()))
    parts = planned(weights, count)
    part = parts[index]
    whole = [p for p, name in part if not name]
    tests = {}
    for package, name in part:
        if name:
            tests.setdefault(package, []).append(name)
    runs = bool(whole) + sum(len(shards(names)) for names in tests.values())
    print(f"CI shard {index}/{count}: {len(whole)} whole packages, {sum(map(len, tests.values()))} tests of "
          f"{len(tests)} split packages in {runs} runs, estimated {sum(weights[u] for u in part) + runs * GROUP_SECONDS:.0f}s",
          flush=True)
    measured_packages, measured_tests = {}, {}
    if whole:
        output = run(["go", "test", *FLAGS, "-json", *whole], json_stream=True)
        checked_package_events(output, whole)
        measured_packages, measured_tests = timings(output)
    for package in sorted(tests):
        measured_tests.update(run_groups(package, tests[package])[1])
    executed = [[p, n] for p, n in part]
    record = Path(os.environ.get("ASSERVAT_GO_TEST_RECORD", ""))
    if record.name:
        record.write_text(json.dumps({
            "shard": [index, count], "plan": plan_digest(parts), "units": sorted([p, n] for p, n in weights),
            "executed": executed, "packages": measured_packages, "tests": measured_tests}, sort_keys=True))
    print(f"CI shard {index}/{count} complete: {len(executed)} of {len(weights)} units, plan {plan_digest(parts)[:12]}", flush=True)


def verified_union(records, count):
    """Check N shard records against one plan; return the number of units."""
    if sorted(r["shard"][0] for r in records) != list(range(count)) or any(r["shard"][1] != count for r in records):
        raise ValueError(f"Expected exactly one record for each of {count} shards")
    if len({r["plan"] for r in records}) != 1 or len({json.dumps(r["units"]) for r in records}) != 1:
        raise ValueError("Shards computed different plans")
    executed = Counter(tuple(u) for r in records for u in r["executed"])
    if executed != Counter(tuple(u) for u in records[0]["units"]):
        raise ValueError("Shards did not execute every planned unit exactly once")
    return len(records[0]["units"])


def updated_weights(records, old):
    """DURATIONS with every measured value replaced, rounded to 0.1 s."""
    packages, tests = dict(old["packages"]), {p: dict(t) for p, t in old["tests"].items()}
    for record in records:
        for package, seconds in record["packages"].items():
            packages[package] = round(seconds, 1)
        for package, measured in record["tests"].items():
            if MODULE + package in SPLIT:
                tests.setdefault(package, {}).update({n: round(s, 1) for n, s in measured.items()})
    for package, measured in tests.items():
        packages[package] = round(sum(measured.values()), 1)
    return {"packages": dict(sorted(packages.items())), "tests": {p: dict(sorted(t.items())) for p, t in sorted(tests.items())}}


def read_records(paths):
    return [json.loads(path.read_text()) for root in paths for path in sorted(Path(root).rglob("*.json"))]


def main():
    argv = sys.argv[1:]
    if argv[:1] == ["--verify-union"]:
        if len(argv) != 3 or not argv[1].isdigit():
            raise ValueError("--verify-union takes N DIR")
        total = verified_union(read_records(argv[2:]), int(argv[1]))
        print(f"Go test shards: {argv[1]} shards executed all {total} planned units exactly once", flush=True)
        return
    if argv[:1] == ["--update-weights"]:
        records = read_records(argv[1:])
        if not records:
            raise ValueError("--update-weights found no shard records")
        DURATIONS.write_text(json.dumps(updated_weights(records, json.loads(DURATIONS.read_text())), indent=0) + "\n")
        print(f"Updated {DURATIONS} from {len(records)} shard records", flush=True)
        return
    shard = selected_shard(argv)
    packages = run(["go", "list", "./..."], capture=True).splitlines()
    if len(packages) != len(set(packages)) or packages.count(KUBERNETES) != 1:
        raise ValueError("Incomplete or ambiguous package inventory")
    if shard:
        run_shard(packages, *shard)
        return
    # Keep every other package under the original complete-package selection.
    other = [p for p in packages if p != KUBERNETES]
    if not other:
        raise ValueError("Missing non-Kubernetes packages")
    run(["go", "test", *FLAGS, *other])
    names = discovered_names(run(["go", "test", *FLAGS, "-list", "^(Test|Fuzz|Example)", KUBERNETES], capture=True), KUBERNETES)
    run_groups(KUBERNETES, names)
    print(f"Go tests complete: {len(other)} full packages and {len(names)} Kubernetes tests in "
          f"{len(shards(names))} sequential groups", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Go test gate failed: {error}", file=sys.stderr)
        sys.exit(1)
