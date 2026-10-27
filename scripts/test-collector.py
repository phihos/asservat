#!/usr/bin/env python3
"""Native node-collector suites (ADR-246; S-04 plan §5).

Runs only on a disposable host: a GitHub-hosted runner via native.yml or a
disposable VM. Kind nodes share the host kernel, and the collector loads BPF
programs, so the harness refuses to start unless the host carries the
disposable-host guard file that only those environments create. Never run it
on a workstation, not even with kind.

  test-collector.py packet   the collector-packet skeleton (increment 3):
                             chart-rendered DaemonSet, enrollment, real
                             probe facts, status cadence, restart epoch,
                             Restricted negative, uninstall leaves workloads
"""
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
GUARD = Path("/etc/asservat-disposable-host")
# The context harness's pinned kind node and pause images.
NODE = "kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
PAUSE = "registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
INSTALLATION = "10000000-0000-4000-8000-000000000001"
CLUSTER = "50000000-0000-4000-8000-000000000001"
PORT = 18444


def run(args, *, data=None, env=None, cwd=None):
    return subprocess.check_output(args, text=True, input=data, env=env, cwd=cwd, stderr=subprocess.PIPE).strip()


def runner_facts():
    btf = Path("/sys/kernel/btf/vmlinux")
    cgroup = run(["stat", "-f", "-c", "%T", "/sys/fs/cgroup"])
    return {"kernelRelease": platform.release(), "btf": btf.is_file() and btf.stat().st_size > 0, "cgroup2": cgroup == "cgroup2fs",
            "os": Path("/etc/os-release").read_text().split("PRETTY_NAME=")[1].split("\n")[0].strip('"') if Path("/etc/os-release").exists() else "",
            "cpus": os.cpu_count()}


def certificates(work, address):
    ca, leaf = work / "ca", work / "server"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=synthetic node-channel root",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign", "-keyout", str(ca) + "-key.pem", "-out", str(ca) + ".pem"],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    subprocess.run(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=asservat-connector-nodes",
                    "-keyout", str(leaf) + "-key.pem", "-out", str(leaf) + ".csr"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    (work / "san.ext").write_text(f"subjectAltName=DNS:asservat-connector-nodes,IP:{address}\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n")
    subprocess.run(["openssl", "x509", "-req", "-in", str(leaf) + ".csr", "-CA", str(ca) + ".pem", "-CAkey", str(ca) + "-key.pem", "-CAcreateserial", "-days", "1",
                    "-extfile", str(work / "san.ext"), "-out", str(leaf) + ".pem"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    for p in (str(ca) + "-key.pem", str(leaf) + "-key.pem"):
        os.chmod(p, 0o600)
    return Path(str(ca) + ".pem").read_text(), Path(str(leaf) + ".pem"), Path(str(leaf) + "-key.pem")


def loaded_digest(node, tag):
    """The repository digest of the image kind imported into the node."""
    ref = "docker.io/library/" + tag
    repo = ref.rsplit(":", 1)[0]
    for line in run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls"]).splitlines()[1:]:
        fields = line.split()
        if fields and fields[0] == ref:
            digest = fields[2]
            assert digest.startswith("sha256:") and len(digest) == 71, digest
            pinned = repo + "@" + digest
            if subprocess.run(["docker", "exec", node, "crictl", "inspecti", pinned], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "tag", ref, pinned])
            return pinned
    raise RuntimeError("loaded collector image not found in the kind node")


def packet(work, report):
    run_id = secrets.token_hex(4)
    name = "asservat-collector-" + run_id
    env = dict(os.environ, TMPDIR=str(work), CGO_ENABLED="0")
    # The collector image: the product binary with the embedded engine.
    image_dir = work / "image"
    image_dir.mkdir()
    started = time.monotonic()
    subprocess.run(["go", "build", "-tags", "gadget,netgo,osusergo", "-trimpath", "-buildvcs=false", "-o", str(image_dir / "asservat"), "./cmd/asservat"], cwd=ROOT, env=env, check=True)
    (image_dir / "Dockerfile").write_text("FROM scratch\nCOPY asservat /asservat\n")
    tag = "asservat-collector:" + run_id
    run(["docker", "build", "--network=none", "--label", "asservat.test=" + run_id, "-t", tag, str(image_dir)])
    report["build"] = {"seconds": round(time.monotonic() - started, 1), "binaryBytes": (image_dir / "asservat").stat().st_size, "tags": "gadget,netgo,osusergo"}
    config = work / "kind.json"
    config.write_text(json.dumps({"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4",
                                  "nodes": [{"role": "control-plane", "extraMounts": [{"hostPath": str(GUARD), "containerPath": str(GUARD), "readOnly": True}]}]}))
    kubeconfig = work / "kubeconfig"
    try:
        started = time.monotonic()
        run(["kind", "create", "cluster", "--name", name, "--image", NODE, "--config", str(config), "--kubeconfig", str(kubeconfig), "--wait", "120s"])
        run(["kind", "load", "docker-image", tag, "--name", name])
        report["cluster"] = {"seconds": round(time.monotonic() - started, 1), "node": NODE,
                             "kubernetes": json.loads(run(["kubectl", "--kubeconfig", str(kubeconfig), "version", "-o", "json"]))["serverVersion"]["gitVersion"]}
        node = name + "-control-plane"
        image = loaded_digest(node, tag)
        network = json.loads(run(["docker", "network", "inspect", "kind"]))[0]
        gateway = next(c["Gateway"] for c in network["IPAM"]["Config"] if "." in c.get("Gateway", ""))
        roots, cert, key = certificates(work, gateway)
        values = {"mode": "cluster", "collector": {"enabled": True, "image": image, "installationID": INSTALLATION, "clusterID": CLUSTER,
                  "connector": {"endpoint": f"https://{gateway}:{PORT}", "serverName": "asservat-connector-nodes", "rootsPEM": roots}}}
        (work / "values.yaml").write_text(json.dumps(values))
        rendered = run(["helm", "template", "asservat", str(ROOT / "charts/asservat"), "--namespace", "asservat-region", "--kube-version", "1.37.0", "-f", str(work / "values.yaml")])
        manifests = work / "collector.yaml"
        manifests.write_text(rendered)
        run(["kubectl", "--kubeconfig", str(kubeconfig), "create", "namespace", "asservat-region"])
        run(["kubectl", "--kubeconfig", str(kubeconfig), "apply", "-f", str(manifests)])
        fixture = {"kubeconfig": str(kubeconfig), "collectorNamespace": "asservat-collector", "daemonSet": "asservat-node", "serviceAccount": "asservat-node",
                   "installationID": INSTALLATION, "clusterID": CLUSTER, "listen": f"{gateway}:{PORT}", "serverCertificate": str(cert), "serverKey": str(key),
                   "pause": PAUSE, "runner": report["runner"], "results": str(work / "native-results.json")}
        (work / "fixture.json").write_text(json.dumps(fixture))
        started = time.monotonic()
        test = subprocess.run(["go", "test", "-count=1", "-v", "-timeout", "12m", "-run", "^TestNodeCollectorWithRealKubernetes$", "./test/integration"],
                              cwd=ROOT, env=dict(env, ASSERVAT_COLLECTOR_FIXTURES=str(work / "fixture.json")))
        report["testSeconds"] = round(time.monotonic() - started, 1)
        if (work / "native-results.json").exists():
            report["native"] = json.loads((work / "native-results.json").read_text())
        report["testExit"] = test.returncode
        if test.returncode != 0:
            subprocess.run(["kubectl", "--kubeconfig", str(kubeconfig), "-n", "asservat-collector", "logs", "-l", "app.kubernetes.io/name=asservat-node", "--tail", "200", "--prefix"])
            subprocess.run(["kubectl", "--kubeconfig", str(kubeconfig), "get", "pods", "-A", "-o", "wide"])
            subprocess.run(["kubectl", "--kubeconfig", str(kubeconfig), "-n", "asservat-collector", "describe", "pods"])
            raise SystemExit("collector-packet failed")
    finally:
        subprocess.run(["kind", "delete", "cluster", "--name", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "image", "rm", "-f", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        report["cleanup"] = {"cluster": name not in run(["kind", "get", "clusters"]).split(), "image": subprocess.run(["docker", "image", "inspect", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0}


def main():
    if len(sys.argv) != 2 or sys.argv[1] != "packet":
        raise SystemExit("usage: test-collector.py packet")
    if not GUARD.is_file():
        raise SystemExit(f"refused: {GUARD} is absent. Collector suites load BPF programs and run only on disposable CI runners or VMs.")
    results = ROOT / "test/results"
    results.mkdir(parents=True, exist_ok=True)
    report = {"suite": "collector-" + sys.argv[1], "runner": runner_facts(), "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    print(json.dumps({"runner": report["runner"]}), flush=True)
    base = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="collector-", dir=base))
    try:
        packet(work, report)
        report["result"] = "passed"
    except BaseException:
        report["result"] = "failed"
        raise
    finally:
        report["finished"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        (results / ("collector-" + sys.argv[1] + "-report.json")).write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
