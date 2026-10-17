#!/usr/bin/env python3
"""Owned Kubernetes Helm lifecycle fixture; no product runtime or collector."""
import copy
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/asservat"
NODE = "kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
HELM = os.environ.get("HELM", "helm")


def run(args, data=None, ok=True):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=180)
    if (result.returncode == 0) != ok:
        raise RuntimeError(f"unexpected result for {args}: {result.stdout}\n{result.stderr}")
    return result.stdout if ok else result.stdout + result.stderr


def hashes():
    paths = [p for p in CHART.rglob("*") if p.is_file()]
    paths.extend([Path(__file__), ROOT / "scripts/check-helm.py", ROOT / "examples/access-binding.yaml"])
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def main():
    cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
    cache.mkdir(parents=True, exist_ok=True)
    results = ROOT / "test/results"
    results.mkdir(exist_ok=True)
    report = {"scope": "Helm configuration foundation only; no runtime, identity acceptance, collection or disclosure", "image": NODE, "sourceHashes": hashes(), "checks": [], "testExit": 1}
    owned = False
    with tempfile.TemporaryDirectory(prefix="helm-", dir=cache) as directory:
        work = Path(directory)
        name = "asservat-" + work.name.replace("_", "-")
        config = work / "kubeconfig"
        try:
            if name in run(["kind", "get", "clusters"]).splitlines():
                raise RuntimeError("refusing an existing cluster")
            owned = True
            run(["kind", "create", "cluster", "--name", name, "--image", NODE, "--kubeconfig", str(config), "--wait", "90s"])
            config.chmod(0o600)
            run(["docker", "update", "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", name + "-control-plane"])
            k = ["kubectl", "--kubeconfig", str(config), "--request-timeout=15s"]
            h = [HELM, "--kubeconfig", str(config)]
            report["helmVersion"] = run([HELM, "version", "--short"]).strip()
            report["kubernetesVersion"] = json.loads(run(k + ["version", "-o", "json"]))["serverVersion"]["gitVersion"]
            run([HELM, "package", str(CHART), "--destination", str(work)])
            archive, = work.glob("*.tgz")
            # A genuine version/schema upgrade without changing source files or
            # weakening any validation rule. The description is inside the
            # atomic CRD versions field, so it exercises field ownership too.
            upgrade_chart = work / "upgrade/asservat"
            shutil.copytree(CHART, upgrade_chart)
            chart_meta = yaml.safe_load((upgrade_chart / "Chart.yaml").read_text())
            chart_meta["version"] = "0.1.0-dev.2"
            (upgrade_chart / "Chart.yaml").write_text(yaml.safe_dump(chart_meta))
            upgrade_crd = upgrade_chart / "crds/evidenceretentionpolicies.yaml"
            upgraded = yaml.safe_load(upgrade_crd.read_text())
            upgraded["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["description"] = "Synthetic compatible chart upgrade."
            upgrade_crd.write_text(json.dumps(upgraded))
            run([HELM, "package", str(upgrade_chart), "--destination", str(work / "upgrade")])
            upgrade_archive, = (work / "upgrade").glob("*.tgz")
            # Documented install: establish the same CRD manager used for
            # subsequent upgrades, then let Helm own release resources only.
            run(k + ["apply", "--server-side", "--field-manager=asservat-crd-upgrade", "-f", str(CHART / "crds")])
            # This workload namespace must not be touched by any release.
            run(k + ["create", "namespace", "synthetic-workload"])
            run(k + ["label", "namespace", "synthetic-workload", "pod-security.kubernetes.io/enforce=restricted"])
            original_ns = json.loads(run(k + ["get", "namespace", "synthetic-workload", "-o", "json"]))
            saved_crds = {}
            for index, mode in enumerate(["hub", "cluster", "combined"]):
                namespace = "asservat-" + mode
                output = run(h + ["install", "asservat", str(archive), "--namespace", namespace, "--create-namespace", "--skip-crds", "--set", "mode=" + mode, "--wait", "--timeout", "60s"])
                assert "does not run the hub" in output
                run(k + ["label", "namespace", namespace, "pod-security.kubernetes.io/enforce=restricted"])
                for path in sorted((CHART / "crds").glob("*.yaml")):
                    crd_name = yaml.safe_load(path.read_text())["metadata"]["name"]
                    run(k + ["wait", "--for=condition=Established", "crd/" + crd_name, "--timeout=30s"])
                    crd = json.loads(run(k + ["get", "crd", crd_name, "-o", "json"]))
                    if index == 0:
                        desired = yaml.safe_load(path.read_text())["spec"]
                        diff = list(difflib.unified_diff(json.dumps(desired, indent=2, sort_keys=True).splitlines(), json.dumps(crd["spec"], indent=2, sort_keys=True).splitlines(), fromfile="chart", tofile="API"))
                        report.setdefault("apiDefaulting", {})[crd_name] = diff
                        saved_crds[crd_name] = crd["metadata"]["uid"]
                    assert saved_crds[crd_name] == crd["metadata"]["uid"]
                cm = json.loads(run(k + ["get", "cm", "asservat-install", "-n", namespace, "-o", "json"]))
                assert cm["data"]["mode"] == mode and cm["data"]["runtimeAvailable"] == "false"
                manifest = list(yaml.safe_load_all(run(h + ["get", "manifest", "asservat", "-n", namespace])))
                assert len(manifest) == 1 and manifest[0]["kind"] == "ConfigMap"
                sample = yaml.safe_load((ROOT / "examples/access-binding.yaml").read_text())
                sample["metadata"]["namespace"] = namespace
                created = json.loads(run(k + ["create", "-f", "-", "-o", "json"], json.dumps(sample)))
                uid = created["metadata"]["uid"]
                invalid = copy.deepcopy(sample)
                invalid["spec"]["roles"] = ["cluster-admin"]
                msg = run(k + ["apply", "--dry-run=server", "-f", "-"], json.dumps(invalid), ok=False)
                assert "Unsupported value" in msg, msg
                # Exact reviewed CRD bundle, separate from ordinary Helm upgrade.
                run(k + ["apply", "--server-side", "--field-manager=asservat-crd-upgrade", "-f", str(upgrade_chart / "crds")])
                run(h + ["upgrade", "asservat", str(upgrade_archive), "-n", namespace, "--reset-values", "--skip-crds", "--set", "mode=" + mode, "--wait", "--timeout", "60s"])
                assert json.loads(run(k + ["get", "cm", "asservat-install", "-n", namespace, "-o", "json"]))["data"]["chartVersion"] == "0.1.0-dev.2"
                revision = json.loads(run(h + ["status", "asservat", "-n", namespace, "-o", "json"]))["version"]
                run(h + ["upgrade", "asservat", str(archive), "-n", namespace, "--set", "runtime.enabled=true"], ok=False)
                assert json.loads(run(h + ["status", "asservat", "-n", namespace, "-o", "json"]))["version"] == revision
                run(h + ["rollback", "asservat", "1", "-n", namespace, "--wait", "--timeout", "60s"])
                assert json.loads(run(k + ["get", "cm", "asservat-install", "-n", namespace, "-o", "json"]))["data"]["chartVersion"] == "0.1.0-dev.1"
                # Helm rollback must not implicitly reverse the CRD schema.
                live = json.loads(run(k + ["get", "crd", "evidenceretentionpolicies.asservat.io", "-o", "json"]))
                assert live["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["description"] == "Synthetic compatible chart upgrade."
                run(h + ["uninstall", "asservat", "-n", namespace, "--wait", "--timeout", "60s"])
                assert not run(k + ["get", "cm", "asservat-install", "-n", namespace, "--ignore-not-found", "-o", "name"]).strip()
                assert json.loads(run(k + ["get", "accessbinding", sample["metadata"]["name"], "-n", namespace, "-o", "json"]))["metadata"]["uid"] == uid
                for crd_name, crd_uid in saved_crds.items():
                    assert json.loads(run(k + ["get", "crd", crd_name, "-o", "json"]))["metadata"]["uid"] == crd_uid
                report["checks"].append(mode + ": packaged install, structural rejection, changed CRD/schema version upgrade without forced ownership, rollback preserves upgraded CRD, invalid upgrade without revision change, uninstall preserves CRDs/custom-resource UID")
                print("Helm lifecycle passed:", mode, flush=True)
            final_ns = json.loads(run(k + ["get", "namespace", "synthetic-workload", "-o", "json"]))
            assert final_ns["metadata"] == original_ns["metadata"], "workload namespace was changed"
            report["checks"].append("workload namespace unchanged")
            report["testExit"] = 0
        finally:
            report["sourceUnchangedDuringTest"] = hashes() == report["sourceHashes"]
            if not report["sourceUnchangedDuringTest"]:
                report["testExit"] = 1
            failures = []
            if owned:
                try:
                    run(["kind", "delete", "cluster", "--name", name])
                    if name in run(["kind", "get", "clusters"]).splitlines():
                        failures.append("owned cluster still exists")
                except Exception as exc:
                    failures.append(str(exc))
            report["cleanupFailures"] = failures
            if failures:
                report["testExit"] = 1
            (results / "helm-environment.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Helm foundation integration exit:", report["testExit"], flush=True)
    return report["testExit"]


if __name__ == "__main__":
    raise SystemExit(main())
