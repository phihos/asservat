#!/usr/bin/env python3
"""Owned real Kubernetes observation and admission fixture; no collector.

The permissive test CRDs deliberately let malformed specs reach the reader.
They are replaced by generated structural CRDs for a separate admission phase.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
# Same reviewed pinned Kind node as the context component fixture.
NODE = "kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"

def run(args, data=None, env=None):
    return subprocess.check_output(args, input=data, text=True, stderr=subprocess.PIPE, timeout=180, env=env).strip()

def sources():
    paths = [ROOT/"go.mod", ROOT/"go.sum", Path(__file__)]
    paths.extend((ROOT/"migrations").rglob("*.sql"))
    paths.extend((ROOT/"migrations").rglob("*.go"))
    paths.append(ROOT/"test/fixtures/sql/runtime-roles.sql")
    for directory in ["api", "internal", "test/integration"]:
        paths.extend((ROOT/directory).rglob("*.go"))
    paths.extend((ROOT/"internal/adapters/kubernetes/permission-schemas").glob("*.json"))
    paths.extend((ROOT/"internal/adapters/kubernetes/policy-schemas").glob("*.json"))
    paths.extend((ROOT/"examples").glob("*.json"))
    paths.extend((ROOT/"examples").glob("*.yaml"))
    paths.extend((ROOT/"charts/asservat/crds").glob("*.yaml"))
    paths.append(ROOT/"scripts/permission-crds.py")
    paths.append(ROOT/"scripts/start-crd.py")
    paths.append(ROOT/"specs/contracts/local-start.schema.json")
    paths.append(ROOT/"specs/contracts/retention-policy.schema.json")
    paths.append(ROOT/"scripts/retention-crd.py")
    paths.extend((ROOT/"migrations").rglob("*.sql"))
    paths.extend((ROOT/"migrations").rglob("*.go"))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}

def main():
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home()/".cache"))/"asservat-build"
    cache.mkdir(parents=True, exist_ok=True)
    results = ROOT/"test/results"
    results.mkdir(exist_ok=True)
    report = {"scope": "permission observation, native admission and explicit-binding reconciliation with real SQL/encrypted audit; synthetic KMS; no public execution authority", "image": NODE}
    exit_code, owned = 1, False
    containers = []
    with tempfile.TemporaryDirectory(prefix="permissions-", dir=cache) as directory:
        work = Path(directory)
        name = "asservat-"+work.name.replace("_", "-")
        config = work/"kubeconfig"
        try:
            if name in run(["kind", "get", "clusters"]).splitlines():
                raise RuntimeError("refusing existing cluster")
            owned = True
            run(["kind", "create", "cluster", "--name", name, "--image", NODE, "--kubeconfig", str(config), "--wait", "90s"])
            config.chmod(0o600)
            run(["docker", "update", "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", name+"-control-plane"])
            k = ["kubectl", "--kubeconfig", str(config), "--request-timeout=15s"]
            resources = []
            for ns in ["asservat-system", "payments", "other"]:
                resources.append({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": {"pod-security.kubernetes.io/enforce": "restricted", "example.invalid/managed": "true"}, "annotations": {"example.invalid/owner": "payments", "unrelated": "MUST-NOT-LEAK"}}})
            for kind, plural in [("AccessBinding", "accessbindings"), ("PermissionSource", "permissionsources")]:
                resources.append({"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition", "metadata": {"name": plural+".asservat.io"}, "spec": {"group": "asservat.io", "names": {"kind": kind, "plural": plural}, "scope": "Namespaced", "versions": [{"name": "v1alpha1", "served": True, "storage": True, "subresources": {"status": {}}, "schema": {"openAPIV3Schema": {"type": "object", "properties": {"spec": {"type": "object", "x-kubernetes-preserve-unknown-fields": True}, "status": {"type": "object", "x-kubernetes-preserve-unknown-fields": True}}}}}]}})
            resources.extend([
                {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "permission-reader", "namespace": "asservat-system"}},
                {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "permission-reader", "namespace": "asservat-system"}, "rules": [{"apiGroups": ["asservat.io"], "resources": ["accessbindings", "permissionsources"], "verbs": ["list", "watch"]}]},
                {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "permission-reader", "namespace": "asservat-system"}, "subjects": [{"kind": "ServiceAccount", "name": "permission-reader", "namespace": "asservat-system"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "permission-reader"}},
                {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "permission-reader"}, "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["asservat-system", "payments"], "verbs": ["get"]}]},
                {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "permission-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "permission-reader", "namespace": "asservat-system"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "permission-reader"}},
            ])
            run(k+["apply", "-f", "-"], json.dumps({"apiVersion": "v1", "kind": "List", "items": resources}))
            run(k+["wait", "--for=condition=Established", "--timeout=30s", "crd/accessbindings.asservat.io", "crd/permissionsources.asservat.io"])
            token = run(k+["-n", "asservat-system", "create", "token", "permission-reader", "--duration=1h"])
            fixture = work/"fixture.json"
            fixture.touch(mode=0o600)
            # Reuse this owned Kind network: no additional Docker subnet and no
            # access to another cluster. Services retain independent credentials.
            network = next(iter(json.loads(run(["docker", "inspect", name+"-control-plane"]))[0]["NetworkSettings"]["Networks"]))
            def service(suffix, image, extra, command):
                service_name = name+"-"+suffix
                run(["docker", "create", "--name", service_name, "--network", network, "--label", "asservat.test="+work.name,
                     "--memory", "768m", "--cpus", "2", "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", *extra, image, *command])
                containers.append(service_name)
                run(["docker", "start", service_name])
                info = json.loads(run(["docker", "inspect", service_name]))[0]
                report.setdefault("services", {})[suffix] = {"requested": image, "imageID": info["Image"], "containerID": info["Id"]}
                return info["NetworkSettings"]["Networks"][network]["IPAddress"], service_name
            pgip, pgname = service("postgres", "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c", ["--user", "postgres", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777", "-v", "/var/lib/postgresql", "-e", "POSTGRES_PASSWORD=synthetic-only", "-e", "POSTGRES_DB=custody_test"], ["-c", "max_connections=32", "-c", "shared_buffers=128MB", "-c", "fsync=on"])
            s3ip, _ = service("s3", "chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d", ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-v", "/data", "-e", "AWS_ACCESS_KEY_ID=synthetic-only", "-e", "AWS_SECRET_ACCESS_KEY=synthetic-only-secret", "--entrypoint", "/usr/bin/weed"], ["mini", "-dir=/data", "-ip.bind=0.0.0.0", "-admin.ui=false", "-s3.port=8333"])
            for _ in range(100):
                if subprocess.run(["docker", "exec", pgname, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "custody_test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
                time.sleep(.1)
            else: raise RuntimeError("PostgreSQL fixture not ready")
            for _ in range(80):
                try:
                    urllib.request.urlopen("http://"+s3ip+":8333", timeout=1).close()
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code in (403, 404): break
                except OSError: pass
                time.sleep(.25)
            else: raise RuntimeError("S3 fixture not ready")
            dsn = "postgres://postgres:synthetic-only@"+pgip+":5432/custody_test?sslmode=disable"
            migration_env = os.environ.copy()
            migration_env.update({"GOOSE_DRIVER": "postgres", "GOOSE_DBSTRING": dsn, "TMPDIR": str(work)})
            report["migration"] = run([str(cache/"bin/goose"), "-dir", str(ROOT/"migrations"), "up"], env=migration_env)
            run(["docker", "exec", pgname, "psql", "-U", "postgres", "-d", "custody_test", "-v", "ON_ERROR_STOP=1", "-c", (ROOT/"test/fixtures/sql/runtime-roles.sql").read_text()])
            fixture.write_text(json.dumps({"config": str(config), "token": token, "postgres": dsn, "s3": "http://"+s3ip+":8333"}))
            env = os.environ.copy()
            env.update({"TMPDIR": str(work), "ASSERVAT_PERMISSION_FIXTURE": str(fixture)})
            report["cluster"] = name
            report["sourceHashes"] = sources()
            with (results/"permission-kubernetes.log").open("w") as log:
                result = subprocess.run(["go", "test", "-race", "-v", "-count=1", "-run", "TestPermissionsWithRealKubernetes", "./test/integration"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            exit_code = result.returncode
            report["observationExit"] = exit_code
            if exit_code == 0:
                # The policy-source test installs its own permissive DebugPolicy
                # CRD so malformed specs reach the product reader; the chart's
                # structural one (ADR-228) would make that create collide.
                chart_crds = sorted(p for p in (ROOT/"charts/asservat/crds").glob("*.yaml") if p.name != "debugpolicies.yaml")
                run(k+["apply", "--server-side", "--force-conflicts", "--field-manager=asservat-owned-fixture"]+[a for p in chart_crds for a in ("-f", str(p))])
                run(k+["wait", "--for=condition=Established", "--timeout=30s", "crd/evidenceretentionpolicies.asservat.io"])
                with (results/"permission-admission.log").open("w") as log:
                    result = subprocess.run(["go", "test", "-race", "-v", "-count=1", "-run", "TestPermissionAdmissionWithRealKubernetes|TestLocalStartWithRealKubernetes|TestRetentionWithRealKubernetes", "./test/integration"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180)
                exit_code = result.returncode
                report["admissionExit"] = exit_code
            report["sourceUnchangedDuringTest"] = sources() == report["sourceHashes"]
            if not report["sourceUnchangedDuringTest"]: exit_code = 1
        except subprocess.CalledProcessError as exc:
            # Setup uses synthetic-only fixtures; never print token-producing stdout.
            print("Fixture command failed:", exc.stderr[-2000:] if exc.stderr else exc.returncode, flush=True)
            raise
        finally:
            report["testExit"] = exit_code
            failures = []
            for container in reversed(containers):
                try:
                    info = json.loads(run(["docker", "inspect", container]))[0]
                    assert info["Config"]["Labels"]["asservat.test"] == work.name
                    run(["docker", "rm", "-f", "-v", container])
                except Exception: failures.append(container)
            if owned:
                try: run(["kind", "delete", "cluster", "--name", name])
                except Exception: failures.append(name)
            report["cleanupFailures"] = failures
            (results/"permission-kubernetes-environment.json").write_text(json.dumps(report, indent=2)+"\n")
            if failures: raise RuntimeError("Owned fixture needs cleanup: "+", ".join(failures))
        print("Permission Kubernetes component exit:", exit_code, flush=True)
        return exit_code

if __name__ == "__main__":
    raise SystemExit(main())
