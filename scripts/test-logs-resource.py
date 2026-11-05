#!/usr/bin/env python3
"""Measure the synthetic encrypted logs reader in one owned, limited container.

The generator runs outside the measured process. This qualifies neither SQL/key
authority nor an installed workflow. CPU quota values alone are not enforcement.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path.home() / ".cache/asservat-build"


def source_hashes():
    paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=ROOT).decode().split("\0")
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in sorted(set(paths)) if name and not name.startswith("test/results/")
            and Path(name).suffix in {".go", ".py", ".json", ".sql", ".mod", ".sum", ".yaml", ".yml", ".sh"}}


def run(command, *, env=None, stdout=None, timeout=180):
    return subprocess.run(command, cwd=ROOT, env=env, stdout=stdout or subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=timeout, check=False)


def main():
    CACHE.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="logs-resource-", dir=CACHE))
    env = dict(os.environ, TMPDIR=str(work), GOTMPDIR=str(work), CGO_ENABLED="0")
    env.setdefault("GOFLAGS", "-buildvcs=false -p=2")
    report = {"scope": "Synthetic encrypted reader/parser and in-process TLS source; not installed or SQL/key-service qualification",
              "work": str(work), "cases": [], "cleanupFailures": []}
    report["sourceHashes"] = source_hashes()
    image = None
    container = None
    try:
        binary = work / "reader.test"
        with (work / "build.log").open("wb") as log:
            built = run(["go", "test", "-c", "-o", str(binary), "./internal/adapters/objectstore"], env=env, stdout=log)
        report["buildExit"] = built.returncode
        if built.returncode:
            raise RuntimeError("reader test binary build failed")
        report["binarySHA256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        (work / "Dockerfile").write_text("FROM scratch\nCOPY reader.test /reader.test\nUSER " + str(os.getuid()) + ":" + str(os.getgid()) + "\nENTRYPOINT [\"/reader.test\"]\n")
        tag = "asservat-logs-resource:" + work.name
        with (work / "image-build.log").open("wb") as log:
            result = run(["docker", "build", "--network=none", "--label", "asservat.test=" + work.name, "-t", tag, str(work)], stdout=log)
        if result.returncode:
            raise RuntimeError("local scratch image build failed")
        image = subprocess.check_output(["docker", "image", "inspect", tag, "--format", "{{.Id}}"], text=True).strip()
        report["imageID"], report["imageTag"] = image, tag
        for shape in ("dense", "long", "origins"):
            case = {"shape": shape}
            folder = work / shape
            folder.mkdir()
            started = time.monotonic()
            with (folder / "generate.log").open("wb") as log:
                result = run([str(binary), "-test.run", "^TestLogQueryEncryptedProcess$", "-test.count=1", "-test.v"],
                             env=dict(env, ASSERVAT_LOG_STREAM_GENERATE=str(folder), ASSERVAT_LOG_STREAM_SHAPE=shape), stdout=log)
            usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            case["generation"] = {"exit": result.returncode, "elapsedSeconds": time.monotonic() - started,
                                  "cumulativeChildPeakRSSKiB": usage.ru_maxrss, "outsideMeasuredWorker": True}
            if result.returncode:
                raise RuntimeError("synthetic fixture generation failed: " + shape)
            started = time.monotonic()
            command = ["docker", "create", "--name", work.name + "-" + shape, "--label", "asservat.test=" + work.name,
                       "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64",
                       "--memory=256m", "--memory-swap=256m", "--cpus=0.5", "--mount", "type=bind,src=" + str(folder) + ",dst=/fixture,readonly",
                       "--env", "ASSERVAT_LOG_STREAM_FIXTURE=/fixture", image,
                       "-test.run", "^TestLogQueryEncryptedProcess$", "-test.count=1", "-test.v"]
            case["command"] = command
            container = subprocess.check_output(command, text=True).strip()
            case["containerID"] = container
            subprocess.run(["docker", "start", container], check=True, stdout=subprocess.PIPE)
            waited = run(["docker", "wait", container], timeout=45)
            case["processExit"] = int(waited.stdout.decode().strip())
            output = subprocess.check_output(["docker", "logs", container], stderr=subprocess.STDOUT)
            (folder / "worker.log").write_bytes(output)
            details = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            (folder / "container.json").write_text(json.dumps(details, indent=2) + "\n")
            case["elapsedSeconds"] = time.monotonic() - started
            case["oomKilled"] = details["State"]["OOMKilled"]
            metrics = {}
            for line in output.decode().splitlines():
                match = re.search(r'worker cgroup ([a-z.]+)=(".*")$', line)
                if match:
                    metrics[match[1]] = json.loads(match[2])
            case["cgroup"] = metrics
            stats = dict(line.split() for line in metrics.get("cpu.stat", "").splitlines())
            case["cpuSeconds"] = int(stats.get("usage_usec", "0")) / 1e6
            # A sustained loaded reader may consume at most its 0.5-core wall
            # allowance plus one period's startup tolerance. This detects the
            # observed local sched_ext case where cpu.max was not sufficient.
            case["quotaConsistent"] = case["cpuSeconds"] > 0 and case["cpuSeconds"] <= .5 * case["elapsedSeconds"] + .1
            case["passed"] = (case["processExit"] == 0 and not case["oomKilled"] and case["quotaConsistent"]
                              and metrics.get("memory.max", "").strip() == "268435456"
                              and int(metrics.get("memory.peak", "0")) <= 268435456
                              and metrics.get("memory.swap.max", "").strip() == "0"
                              and metrics.get("memory.swap.current", "").strip() == "0"
                              and metrics.get("cpu.max", "").strip() == "50000 100000"
                              and "threeKeys=true valid=true refusal=false" in output.decode())
            removed = run(["docker", "rm", container])
            if removed.returncode:
                raise RuntimeError("owned container cleanup failed")
            container = None
            report["cases"].append(case)
            print(json.dumps(case), flush=True)
            (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        report["passed"] = all(case["passed"] for case in report["cases"])
    except Exception as exc:
        report["error"], report["passed"] = str(exc), False
    finally:
        if container and run(["docker", "rm", "-f", container]).returncode:
            report["cleanupFailures"].append(container)
        if image and run(["docker", "image", "rm", report["imageTag"]]).returncode:
            report["cleanupFailures"].append(image)
        report["sourceUnchanged"] = source_hashes() == report["sourceHashes"]
        report["passed"] = report.get("passed", False) and report["sourceUnchanged"]
        (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        destination = ROOT / "test/results/logs-resource"
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        # Keep fixed diagnostic outputs for hosted artifacts; never include the
        # synthetic key material, object fixtures, executable or image context.
        for name in ("build.log", "image-build.log"):
            if (work / name).exists():
                (destination / name).write_bytes((work / name).read_bytes())
        for shape in ("dense", "long", "origins"):
            for name in ("generate.log", "worker.log", "container.json"):
                if (work / shape / name).exists():
                    (destination / (shape + "-" + name)).write_bytes((work / shape / name).read_bytes())
        # Fixture objects and synthetic keys are useful only during this run.
        # Preserve the fixed diagnostics above, then remove the owned scratch.
        try:
            shutil.rmtree(work)
            report["scratchRemoved"] = True
        except OSError as exc:
            report["scratchRemoved"] = False
            report["cleanupFailures"].append(str(exc))
        report["passed"] = report.get("passed", False) and not report["cleanupFailures"]
        (destination / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print("Resource report:", destination / "report.json", flush=True)
    return 0 if report.get("passed") and not report["cleanupFailures"] else 1


if __name__ == "__main__":
    sys.exit(main())
