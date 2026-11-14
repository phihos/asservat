#!/usr/bin/env python3
"""Owned, synthetic component integration fixtures; never uses current kube context.

Creates two disposable Kind clusters plus private S3/OpenBao/PostgreSQL
fixtures, runs the Go integration tests and removes only resources it created,
even on failure. No host kernel configuration or privileged collector is
installed.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEAWEED = "chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d"
BAO = "quay.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
NODE = "kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
PAUSE = "registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
POSTGRES = "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
NATIVE_TRAFFIC_PROBE = "^TestNativePacingTrafficWithRealKubernetes$"
RESULTS = ROOT/"test/results"
CLUSTERS = 2


def run(args, *, data=None):
    return subprocess.check_output(args, text=True, input=data, stderr=subprocess.PIPE).strip()


def postgres_fixture_options(regional_context_start=None):
    if regional_context_start not in (None, "first", "continuation", "journey"):
        raise ValueError("unknown regional context qualification")
    options = ["-c", "max_connections=48", "-c", "shared_buffers=128MB", "-c", "fsync=on", "-c", "synchronous_commit=on"]
    if regional_context_start == "journey":
        # Diagnose a refused connection without statement or parameter logging.
        options += ["-c", "log_line_prefix=%m [%p] role=%u sqlstate=%e ",
                    "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
                    "-c", "log_error_verbosity=terse",
                    "-c", "log_parameter_max_length=0", "-c", "log_parameter_max_length_on_error=0"]
    return options


def selection(test_pattern, regional_context_start):
    """The Go test pattern and the subtest that must pass, if any."""
    if regional_context_start is not None:
        if test_pattern is not None:
            raise ValueError("Regional context qualification owns its exact test selection")
        required = "TestContextAdmissionWithRealServices/native-regional-api-" + regional_context_start
        return "^TestContextAdmissionWithRealServices$/^native-regional-api-" + regional_context_start + "$", required
    return test_pattern, None


def write_report(report):
    """Keep the last complete report readable if this process is killed mid-write."""
    path = RESULTS/"context-storage-environment.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def record_go_output(command, env):
    """Write the child output and elapsed line times as they arrive."""
    began = time.monotonic()
    with (RESULTS/"context-storage.log").open("wb", buffering=0) as log, (RESULTS/"context-storage-timing.log").open("wb", buffering=0) as timing:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with process.stdout:
            for line in process.stdout:
                log.write(line)
                timing.write(("%8.1f " % (time.monotonic() - began)).encode() + line)
        return process.wait()


def build_images(image_dir, build_env):
    # The product binary links the pinned static libpcap filter compiler
    # (ADR-243), built as make pcap-check builds it. The fixture helper is cgo-free.
    subprocess.run(["make", "--no-print-directory", "hub-binary", "HUB_BINARY="+str(image_dir/"asservat"), "ASSERVAT_BUILD_TMP="+build_env["TMPDIR"]], cwd=ROOT, env=build_env, check=True)
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(image_dir/"provider-proxy"), "./test/fixtures/provider-proxy/main.go"], cwd=ROOT, env=build_env, check=True)
    (image_dir/"Dockerfile").write_text("FROM scratch\nCOPY asservat /asservat\nCOPY provider-proxy /provider-proxy\nUSER 65532:65532\n")


def source_hashes():
    files = [ROOT/"go.mod", ROOT/"go.sum", Path(__file__), ROOT/"scripts/ci-native.sh", ROOT/".github/workflows/native.yml"]
    files += list((ROOT/"cmd").rglob("*.go")) + list((ROOT/"internal").rglob("*.go")) + list((ROOT/"test/integration").rglob("*.go"))
    files += list((ROOT/"internal").rglob("*.json")) + list((ROOT/"migrations").rglob("*")) + list((ROOT/"test/fixtures").rglob("*"))
    files = [p for p in files if p.is_file()]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def install_native_traffic_helper(binary, cluster, fixture, report):
    nodes = run(["kind", "get", "nodes", "--name", cluster]).splitlines()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    for node in nodes:
        if run(["docker", "inspect", "--format", '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', node]) != cluster:
            raise RuntimeError("traffic helper node ownership differs")
        run(["docker", "cp", str(binary), node+":/asservat-fixture-traffic"])
        if run(["docker", "exec", node, "sha256sum", "/asservat-fixture-traffic"]).split()[0] != digest:
            raise RuntimeError("traffic helper bytes differ")
    fixture["nativeTrafficHelper"] = report["nativeTrafficHelper"] = {"cluster": cluster, "sha256": digest, "nodes": nodes}


# Seconds kept free after go test for failure diagnostics, cleanup and the CI
# job's artifact upload (measured: well under a minute together).
CI_JOB_CLEANUP_MARGIN = 60


def ci_bounded_go_timeout(static, environ=os.environ, now=None):
    """Bound go test -timeout by the CI job deadline, so Go's own timeout fires
    (printing every goroutine) and this harness still records results before
    the runner cancels the job. ASSERVAT_CI_JOB_DEADLINE is the job's Unix end
    time, set by .github/workflows/native.yml; local runs keep the static value."""
    deadline = environ.get("ASSERVAT_CI_JOB_DEADLINE", "")
    if not deadline:
        return static
    remaining = int(deadline) - int(time.time() if now is None else now) - CI_JOB_CLEANUP_MARGIN
    if remaining < 60:
        raise RuntimeError("CI job deadline leaves under one minute for go test")
    match = re.fullmatch(r"(\d+)m", static)
    if not match:
        raise ValueError("static go timeout must be whole minutes")
    return str(min(remaining, int(match.group(1)) * 60)) + "s"


def load_image(tag, cluster, node):
    """Load the worker image into one owned cluster and return its digest reference."""
    run(["kind", "load", "docker-image", tag, "--name", cluster])
    native = "docker.io/library/"+tag
    rows = run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls"]).splitlines()
    matches = [row.split()[2] for row in rows if row.split()[0] == native]
    if len(matches) != 1 or not matches[0].startswith("sha256:"):
        raise RuntimeError("loaded worker image identity unavailable")
    reference = "docker.io/library/asservat-context-worker@"+matches[0]
    run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "tag", native, reference])
    return reference


def prepare_cluster(config, fixture, report, name):
    pause = PAUSE
    k = ["kubectl", "--kubeconfig", str(config), "--request-timeout=15s"]
    resources = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "synthetic", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "fixture", "namespace": "synthetic"}, "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "fixture"}}, "template": {"metadata": {"labels": {"app": "fixture"}, "annotations": {"synthetic-user-data": "MUST-NOT-LEAK"}}, "spec": {"securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "fixture", "image": pause, "imagePullPolicy": "IfNotPresent", "env": [{"name": "SYNTHETIC_SECRET", "value": "MUST-NOT-LEAK"}], "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}, "resources": {"requests": {"memory": "8Mi", "cpu": "5m"}, "limits": {"memory": "32Mi", "cpu": "50m"}}}]}}}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "context-reader", "namespace": "synthetic"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "context-reader", "namespace": "synthetic"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "context-reader", "namespace": "synthetic"}, "subjects": [{"kind": "ServiceAccount", "name": "context-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "context-reader"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "context-reader"}, "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["synthetic"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "context-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "context-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "context-reader"}},
    ]
    resources.extend([
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "target-reader", "namespace": "synthetic"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "target-reader", "namespace": "synthetic"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}, {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets", "replicasets"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "target-reader", "namespace": "synthetic"}, "subjects": [{"kind": "ServiceAccount", "name": "target-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "target-reader"}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "target-reader"}, "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["synthetic"], "verbs": ["get"]}, {"apiGroups": [""], "resources": ["nodes"], "resourceNames": [name+"-control-plane"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "target-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "target-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "target-reader"}},
    ])
    run(k+["apply", "-f", "-"], data=json.dumps({"apiVersion": "v1", "kind": "List", "items": resources}))
    try:
        run(k+["-n", "synthetic", "rollout", "status", "deployment/fixture", "--timeout=90s"])
    except subprocess.CalledProcessError:
        for extra in (["-n", "synthetic", "describe", "pods"], ["-n", "synthetic", "get", "events", "--sort-by=.lastTimestamp"], ["get", "nodes", "-o", "wide"]):
            try:
                print(run(k+extra), file=sys.stderr)
            except subprocess.CalledProcessError as error:
                print(error.stderr, file=sys.stderr)
        raise
    pod = json.loads(run(k+["-n", "synthetic", "get", "pod", "-l", "app=fixture", "-o", "json"]))["items"][0]
    ns = json.loads(run(k+["get", "namespace", "synthetic", "-o", "json"]))
    node = json.loads(run(k+["get", "node", pod["spec"]["nodeName"], "-o", "json"]))
    deployment = json.loads(run(k+["-n", "synthetic", "get", "deployment", "fixture", "-o", "json"]))
    token = run(k+["-n", "synthetic", "create", "token", "context-reader", "--duration=1h"])
    target_token = run(k+["-n", "synthetic", "create", "token", "target-reader", "--duration=1h"])
    fixture["clusters"].append({"config": str(config), "token": token, "targetToken": target_token, "nodeUID":node["metadata"]["uid"], "nodeBootID":node["status"]["nodeInfo"]["bootID"], "workloadUID":deployment["metadata"]["uid"], "pod": {"Namespace": "synthetic", "NamespaceUID": ns["metadata"]["uid"], "Name": pod["metadata"]["name"], "UID": pod["metadata"]["uid"], "NodeName": pod["spec"]["nodeName"], "ControllerUID": pod["metadata"]["ownerReferences"][0]["uid"]}})
    report["clusters"].append({"name": name, "nodeImage": NODE, "workloadImage": pause, "podUID": pod["metadata"]["uid"]})


def service(network, run_id, containers, name, image, command, extra):
    full = network+"-"+name
    run(["docker", "create", "--name", full, "--network", network,
         "--label", "asservat.test="+run_id, "--memory", "768m", "--cpus", "1",
         "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         *extra, image, *command])
    containers.append(full)
    run(["docker", "start", full])
    info = json.loads(run(["docker", "inspect", full]))[0]
    return info["NetworkSettings"]["Networks"][network]["IPAddress"]


def wait_until(probe, attempts, interval, failure):
    for _ in range(attempts):
        result = probe()
        if result is not None:
            return result
        time.sleep(interval)
    raise RuntimeError(failure)


def main(test_pattern=None, regional_context_start=None):
    test_pattern, required = selection(test_pattern, regional_context_start)
    traffic_probe = test_pattern == NATIVE_TRAFFIC_PROBE
    cluster_count = 1 if traffic_probe else CLUSTERS
    go_timeout = "2m" if traffic_probe else "30m"
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home()/".cache"))/"asservat-build"
    cache.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="context-", dir=cache)).absolute()
    work.chmod(0o700)
    run_id = work.name.replace("_", "-")
    network = "asservat-"+run_id
    # Kind nodes join an owned network instead of the shared "kind" network.
    kind_network = network+"-kind"
    containers, clusters, networks = [], [], []
    worker_tag = None
    compile_ahead = None
    cluster_pool = None
    exit_code = 1
    began = time.monotonic()
    report = {"scope": "component integration", "images": {"s3": SEAWEED, "kms": BAO, "kubernetes": NODE, "postgres": POSTGRES},
              "clusters": [], "testPattern": test_pattern, "regionalContextStart": regional_context_start, "phaseSeconds": {},
              "goTestExit": None, "testExit": None, "cleanupComplete": False}

    def phase(name):
        report["phaseSeconds"][name] = round(time.monotonic()-began, 1)
    try:
        report["goVersion"] = run(["go", "version"])
        report["sourceHashes"] = source_hashes()
        write_report(report)
        for name, internal in ((network, True), (kind_network, False)):
            run(["docker", "network", "create", *(["--internal"] if internal else []), "--label", "asservat.test="+run_id, name])
            networks.append(name)
        os.environ["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = kind_network
        # Create the clusters concurrently while the images build and the
        # services start; they need neither.
        existing = run(["kind", "get", "clusters"]).splitlines()
        creates = []
        for index in range(cluster_count):
            name = network+"-"+str(index)
            if name in existing:
                raise RuntimeError("cluster name collision")
            clusters.append(name)
            creates.append(["kind", "create", "cluster", "--name", name, "--image", NODE, "--kubeconfig", str(work/("kube-"+str(index))), "--wait", "90s", "--retain"])
        cluster_pool = concurrent.futures.ThreadPoolExecutor(max_workers=len(creates))
        cluster_futures = [cluster_pool.submit(run, create) for create in creates]
        image_dir = work/"worker-image"
        image_dir.mkdir()
        build_env = dict(os.environ, TMPDIR=str(work), CGO_ENABLED="0")
        build_images(image_dir, build_env)
        worker_tag = "asservat-context-worker:"+run_id
        run(["docker", "build", "--network=none", "--label", "asservat.test="+run_id, "-t", worker_tag, str(image_dir)])
        phase("imagesBuilt")
        # Fill the Go build cache while the fixtures start.
        compile_ahead = subprocess.Popen(["go", "test", "-race", "-count=1", "-run", "^$", "./test/integration"], cwd=ROOT, env=dict(os.environ, TMPDIR=str(work)),
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        s3ip = service(network, run_id, containers, "s3", SEAWEED, ["mini", "-dir=/data", "-ip.bind=0.0.0.0", "-admin.ui=false", "-s3.port=8333"], ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-v", "/data", "-e", "AWS_ACCESS_KEY_ID=synthetic-only", "-e", "AWS_SECRET_ACCESS_KEY=synthetic-only-secret", "--entrypoint", "/usr/bin/weed"])
        baoip = service(network, run_id, containers, "kms", BAO, ["server", "-dev", "-dev-no-store-token", "-dev-root-token-id=synthetic-root", "-dev-listen-address=0.0.0.0:8200"], ["--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-e", "SKIP_SETCAP=true", "-e", "BAO_DISABLE_MLOCK=true", "--entrypoint", "/usr/bin/bao"])
        pgip = service(network, run_id, containers, "postgres", POSTGRES, postgres_fixture_options(regional_context_start), ["--user", "postgres", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777", "-v", "/var/lib/postgresql", "-e", "POSTGRES_PASSWORD=synthetic-only", "-e", "POSTGRES_DB=custody_test"])
        service(network, run_id, containers, "tls", worker_tag, ["http://"+s3ip+":8333", "http://"+baoip+":8200", pgip+":5432"], ["--user", "65532:65532", "--read-only", "--entrypoint", "/provider-proxy"])

        def providers():
            try:
                return json.loads(run(["docker", "logs", network+"-tls"]))
            except (json.JSONDecodeError, subprocess.CalledProcessError):
                return None
        native_providers = wait_until(providers, 50, .1, "native TLS fixture unavailable")
        pgname = network+"-postgres"
        wait_until(lambda: True if subprocess.run(["docker", "exec", pgname, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "custody_test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0 else None,
                   100, .1, "PostgreSQL fixture not ready")
        dsn = "postgres://postgres:synthetic-only@"+pgip+":5432/custody_test?sslmode=disable"
        subprocess.run([str(cache/"bin/goose"), "-dir", str(ROOT/"migrations"), "up"], env=dict(os.environ, GOOSE_DRIVER="postgres", GOOSE_DBSTRING=dsn, TMPDIR=str(work)),
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
        run(["docker", "exec", pgname, "psql", "-U", "postgres", "-d", "custody_test", "-v", "ON_ERROR_STOP=1", "-c", (ROOT/"test/fixtures/sql/runtime-roles.sql").read_text()])
        for url in ["http://"+s3ip+":8333", "http://"+baoip+":8200/v1/sys/health"]:
            def ready(url=url):
                try:
                    with urllib.request.urlopen(url, timeout=1):
                        return True
                except urllib.error.HTTPError as exc:
                    return True if exc.code in (403, 404) else None
                except OSError:
                    return None
            wait_until(ready, 40, .25, "fixture did not become ready")
        fixture = {"s3": "http://"+s3ip+":8333", "kms": "http://"+baoip+":8200", "postgres": dsn, "postgresContainer": pgname,
                   "nativeProviders": native_providers, "clusters": [], "twoClusterPods": False}
        phase("servicesStarted")
        for future in cluster_futures:
            future.result()
        phase("clustersCreated")
        for index, name in enumerate(clusters):
            config = work/("kube-"+str(index))
            config.chmod(0o600)
            node_name = name+"-control-plane"
            if traffic_probe:
                install_native_traffic_helper(image_dir/"provider-proxy", name, fixture, report)
            run(["docker", "update", "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", node_name])
            if index == 0:
                # Product Pods run only in the first cluster.
                run(["docker", "network", "connect", network, node_name])
                fixture["workerImage"] = report["workerImage"] = load_image(worker_tag, name, node_name)
            prepare_cluster(config, fixture, report, name)
        phase("clustersPrepared")
        path = work/"fixtures.json"
        path.touch(mode=0o600)
        path.write_text(json.dumps(fixture))
        env = dict(os.environ, ASSERVAT_CONTEXT_FIXTURES=str(path), TMPDIR=str(work))
        env.pop("ASSERVAT_CONTEXT_REGIONAL_START_NATIVE", None)
        if regional_context_start is not None:
            env["ASSERVAT_CONTEXT_REGIONAL_START_NATIVE"] = regional_context_start
        compile_ahead.wait()
        command = ["go", "test", "-race", "-count=1", "-v", "-timeout", ci_bounded_go_timeout(go_timeout)]
        if test_pattern:
            command += ["-run", test_pattern]
        command += ["./test/integration"]
        phase("goTestStart")
        exit_code = record_go_output(command, env)
        phase("goTestEnd")
        report["goTestExit"] = exit_code
        output = (RESULTS/"context-storage.log").read_bytes().decode("utf-8", errors="replace")
        passed = [line.strip().split()[2] for line in output.splitlines() if line.strip().startswith("--- PASS: Test")]
        report["passedTests"] = passed
        # A run that selected no test, or missed its required subtest, fails.
        if not passed or (required and required not in passed):
            exit_code = 1
        report["sourceUnchangedDuringTest"] = report["sourceHashes"] == source_hashes()
        if not report["sourceUnchangedDuringTest"]:
            exit_code = 1
        if exit_code:
            with (RESULTS/"context-storage-kubelet.log").open("w") as diagnostics:
                for name in clusters:
                    diagnostics.write("Owned node: "+name+"-control-plane\n")
                    result = subprocess.run(["docker", "exec", name+"-control-plane", "journalctl", "--unit", "kubelet", "--since", "-5min", "--no-pager", "-n", "80"], capture_output=True, text=True, timeout=10)
                    diagnostics.write(result.stdout[-32768:])
            pg = subprocess.run(["docker", "logs", "--tail", "200", network+"-postgres"], text=True, capture_output=True, timeout=10)
            (RESULTS/"context-storage-postgres.log").write_text(pg.stdout+pg.stderr)
        print("Component test exit:", exit_code, flush=True)
    except subprocess.CalledProcessError as exc:
        (RESULTS/"context-storage-fixture-error.log").write_text(exc.stderr or str(exc.returncode))
        print("Fixture command failed:", exc.stderr[-4000:] if exc.stderr else exc.returncode, flush=True)
        raise
    finally:
        report["testExit"] = exit_code
        failures = []
        if cluster_pool is not None:
            cluster_pool.shutdown(wait=True)
        if compile_ahead is not None and compile_ahead.poll() is None:
            os.killpg(compile_ahead.pid, signal.SIGKILL)
            compile_ahead.wait()
        for name in reversed(clusters):
            try: run(["kind", "delete", "cluster", "--name", name])
            except Exception: failures.append(name)
        for kind, names in (("container", reversed(containers)), ("image", [worker_tag] if worker_tag else []), ("network", reversed(networks))):
            for name in names:
                try:
                    info = json.loads(run(["docker", kind, "inspect", name]))[0]
                    labels = info["Config"]["Labels"] if kind != "network" else info["Labels"]
                    assert labels["asservat.test"] == run_id
                    run(["docker", kind, "rm", *(["-f", "-v"] if kind == "container" else []), name])
                except Exception: failures.append(name)
        os.environ.pop("KIND_EXPERIMENTAL_DOCKER_NETWORK", None)
        shutil.rmtree(work, ignore_errors=True)
        report["cleanupFailures"] = failures
        report["cleanupComplete"] = not failures
        phase("cleanedUp")
        print("Harness phases (seconds since start):", report["phaseSeconds"], flush=True)
        write_report(report)
        if failures: raise RuntimeError("Owned fixtures need cleanup: "+", ".join(failures))
    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", dest="test_pattern", help="Go test pattern; default runs the whole ./test/integration package.")
    parser.add_argument("--regional-context-start", choices=("first", "continuation", "journey"), help="Run the signed same-port H2 context-start subtest; journey adds publication and native download.")
    args = parser.parse_args()
    if args.test_pattern is not None and not 1 <= len(args.test_pattern) <= 256:
        parser.error("--run must contain 1 to 256 characters")
    RESULTS.mkdir(parents=True, exist_ok=True)
    try:
        raise SystemExit(main(args.test_pattern, args.regional_context_start))
    except ValueError as exc:
        parser.error(str(exc))
