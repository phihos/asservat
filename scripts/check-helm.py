#!/usr/bin/env python3
"""Offline chart render/schema/package checks; no Kubernetes API calls."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/asservat"
HELM = os.environ.get("HELM", "helm")
DIGEST = "sha256:" + "a" * 64
COMPONENTS = ["hub-api", "hub-worker", "federation", "publisher", "key-service"]


def run(args, ok=True):
    result = subprocess.run([HELM, *args], text=True, capture_output=True, timeout=45)
    if (result.returncode == 0) != ok:
        raise RuntimeError(f"unexpected Helm result for {args}: {result.stdout}\n{result.stderr}")
    return result.stdout + result.stderr if not ok else result.stdout


def hub_values():
    """Minimal hub values with external providers (render fixtures only)."""
    return {
        "image": {"repository": "registry.example/asservat", "digest": DIGEST, "pullPolicy": "IfNotPresent", "pullSecrets": []},
        "origin": "https://asservat.example.org",
        "services": {
            "postgres": {"external": {"host": "postgres.example", "port": 5432, "database": "asservat", "rootsPEM": "PUBLIC-CA", "adminSecret": "operator-postgres-admin"}},
            "objectStore": {"external": {"endpoint": "https://s3.example", "region": "r", "bucket": "audit", "rootsPEM": "PUBLIC-CA"}},
            "keyService": {"external": {"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"}},
        },
    }


def bundled_values(mode="combined"):
    v = hub_values()
    v["mode"] = mode
    v["services"] = {
        "postgres": {"provider": "bundled", "bundled": {"image": "registry.example/postgres@sha256:" + "b" * 64}},
        "objectStore": {"provider": "seaweedfs"},
        "keyService": {"provider": "openbao"},
        "identity": {"provider": "keycloak", "keycloak": {"hostname": "https://login.example.org", "tlsSecretName": "kc-tls"}},
    }
    return v


class Renderer:
    def __init__(self, directory):
        self.path = Path(directory) / "values.yaml"

    def __call__(self, values, *, ok=True, namespace="asservat-system", files=()):
        self.path.write_text(yaml.safe_dump(values))
        args = ["template", "asservat", str(CHART), "--namespace", namespace, "--kube-version", "1.35.0", *[a for f in files for a in ("-f", str(f))], "-f", str(self.path)]
        result = run(args, ok=ok)
        if not ok:
            return result
        assert result == run(args), "render depends on ambient state or randomness"
        return [r for r in yaml.safe_load_all(result) if r]


def named(docs, kind, name):
    found = [r for r in docs if r["kind"] == kind and r["metadata"]["name"] == name]
    assert len(found) == 1, (kind, name, [r["metadata"]["name"] for r in docs if r["kind"] == kind])
    return found[0]


def check_secrets(render):
    # The secrets hook: a bounded Job with a Secrets-only Role.
    for mode in ["hub", "combined"]:
        docs = render(bundled_values(mode))
        job = named(docs, "Job", "asservat-secrets")
        hook = job["metadata"]["annotations"]
        assert hook["helm.sh/hook"] == "pre-install,pre-upgrade" and hook["helm.sh/hook-delete-policy"] == "before-hook-creation,hook-succeeded"
        assert job["spec"]["backoffLimit"] >= 1 and job["spec"]["ttlSecondsAfterFinished"] > 0
        pod = job["spec"]["template"]["spec"]
        assert pod["containers"][0]["command"] == ["/asservat", "secrets"]
        assert pod["containers"][0]["image"] == "registry.example/asservat@" + DIGEST
        assert pod["serviceAccountName"] == "asservat-secrets" and pod["restartPolicy"] == "Never"
        role = named(docs, "Role", "asservat-secrets")
        assert role["rules"][0] == {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}
        assert role["rules"][1]["verbs"] == ["get", "patch"] and len(role["rules"]) == 2
        names = set(role["rules"][1]["resourceNames"])
        expected = {"asservat-ids", "asservat-audit-mac", "asservat-artifact-key", "asservat-objectstore-iam"} | {f"asservat-sql-{c}" for c in COMPONENTS} \
            | {f"asservat-{s}-state" for s in ["postgres", "keycloak", "objectstore", "openbao"]}
        assert expected <= names, expected - names
        assert ("asservat-s3-regional-write" in names) == (mode == "combined")
        for hooked in [named(docs, k, "asservat-secrets") for k in ("ServiceAccount", "Role", "RoleBinding", "ConfigMap")]:
            assert hooked["metadata"]["annotations"]["helm.sh/hook"] == "pre-install,pre-upgrade"
        plan = json.loads(named(docs, "ConfigMap", "asservat-secrets")["data"]["secrets.json"])
        assert plan["format"] == "asservat-secrets/v1" and plan["ids"] == {"secret": "asservat-ids", "generate": True}
        assert [s["component"] for s in plan["sql"]] == COMPONENTS
    # existingSecret overrides leave the plan and stay readable.
    v = bundled_values("hub")
    v["secrets"] = {"ids": {"existingSecret": "operator-ids"}, "sql-hub-api": {"existingSecret": "operator-sql"}, "audit-mac": {"existingSecret": "operator-mac"}}
    docs = render(v)
    plan = json.loads(named(docs, "ConfigMap", "asservat-secrets")["data"]["secrets.json"])
    assert plan["ids"] == {"secret": "operator-ids", "generate": False} and "auditMAC" not in plan and "hub-api" not in [s["component"] for s in plan["sql"]]
    assert "operator-ids" in named(docs, "Role", "asservat-secrets")["rules"][1]["resourceNames"]
    setup = [r for r in docs if r["kind"] == "Job" and r["metadata"]["name"].startswith("asservat-setup-")][0]
    volumes = {x["name"]: x for x in setup["spec"]["template"]["spec"]["volumes"]}
    assert volumes["ids"]["secret"]["secretName"] == "operator-ids" and volumes["sql-hub-api"]["secret"]["secretName"] == "operator-sql"
    bad = bundled_values("hub")
    bad["secrets"] = {"s3-owner-audit": {"existingSecret": "operator-s3"}}
    assert "bundled SeaweedFS generates its own" in render(bad, ok=False)
    render({**bundled_values("hub"), "secrets": {"unknown": {"existingSecret": "x"}}}, ok=False)
    # A workload-cluster release generates no hub Secrets.
    assert not any(r["kind"] == "Job" for r in render({"mode": "cluster"}))


def check_setup(render):
    docs = render(bundled_values("combined"))
    jobs = [r for r in docs if r["kind"] == "Job" and r["metadata"]["name"].startswith("asservat-setup-")]
    assert len(jobs) == 1
    job = jobs[0]
    assert "helm.sh/hook" not in job["metadata"].get("annotations", {}), "setup must be an ordinary Job"
    pod = job["spec"]["template"]["spec"]
    assert pod["containers"][0]["command"] == ["/asservat", "setup"] and pod["serviceAccountName"] == "asservat-setup"
    sources = [s for v in pod["volumes"] if "projected" in v for s in v["projected"]["sources"]]
    assert {"serviceAccountToken": {"path": "openbao-setup.token", "audience": "https://asservat.io/openbao/setup", "expirationSeconds": 600}} in sources
    mounts = {m["mountPath"] for m in pod["containers"][0]["volumeMounts"]}
    assert {"/run/asservat/ids", "/run/asservat/setup/config", "/run/asservat/setup/postgres"} | {f"/run/asservat/setup/sql/{c}" for c in COMPONENTS} <= mounts
    assert named(docs, "Role", "asservat-setup")["rules"] == [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]
    cluster = named(docs, "ClusterRole", "asservat-system-asservat-setup")["rules"]
    assert cluster == [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["asservat-system"], "verbs": ["get"]}]
    # The name follows chart version, image and values.
    changed = bundled_values("combined")
    changed["identity"] = {"maxSessions": 9}
    other = [r for r in render(changed) if r["kind"] == "Job" and r["metadata"]["name"].startswith("asservat-setup-")][0]
    assert other["metadata"]["name"] != job["metadata"]["name"]
    config = json.loads(named(docs, "ConfigMap", "asservat-setup-config")["data"]["config.json"])
    assert config["postgres"]["provider"] == "bundled" and config["keyService"]["provider"] == "openbao"
    external = hub_values()
    external["services"]["postgres"]["external"]["adminSecret"] = ""
    assert "services.postgres.external requires" in render(external, ok=False)


def check_exposure(render):
    v = hub_values()
    assert not any(r["kind"] in ("Ingress", "HTTPRoute") for r in render(v))
    v["exposure"] = {"ingress": {"enabled": True, "className": "example", "annotations": {"a": "b"}, "tls": [{"hosts": ["asservat.example.org"], "secretName": "t"}]},
                     "httpRoute": {"enabled": True, "parentRefs": [{"name": "gw", "namespace": "infra"}]}}
    docs = render(v)
    ingress = named(docs, "Ingress", "asservat-hub-api")
    assert ingress["spec"]["ingressClassName"] == "example" and ingress["metadata"]["annotations"] == {"a": "b"}
    rule, = ingress["spec"]["rules"]
    assert rule["host"] == "asservat.example.org"
    assert rule["http"]["paths"][0]["backend"]["service"] == {"name": "asservat-hub-api", "port": {"number": 9445}}
    route = named(docs, "HTTPRoute", "asservat-hub-api")
    assert route["spec"]["hostnames"] == ["asservat.example.org"] and route["spec"]["parentRefs"] == [{"name": "gw", "namespace": "infra"}]
    assert route["spec"]["rules"][0]["backendRefs"] == [{"name": "asservat-hub-api", "port": 9445}]
    for key in ["ingress", "httpRoute"]:
        bad = copy.deepcopy(v)
        bad["origin"] = "https://asservat.example.org:8443"
        bad["exposure"] = {key: v["exposure"][key]}
        assert "must not carry a port" in render(bad, ok=False)
    bad = copy.deepcopy(v)
    bad["exposure"] = {"httpRoute": {"enabled": True, "parentRefs": []}}
    render(bad, ok=False)


def check_examples(render, directory):
    profile = ROOT / "examples/helm/context-trial-profile.yaml"
    site = ROOT / "examples/helm/context-trial-site.example.yaml"
    pem = {"services": {k: {"external": {"rootsPEM": "PUBLIC-CA"}} for k in ("postgres", "objectStore", "keyService")}, "image": {"digest": DIGEST}}
    docs = render(pem, files=(profile, site))
    assert any(r["kind"] == "Job" and r["metadata"]["name"] == "asservat-secrets" for r in docs)
    small = Path(directory) / "small.yaml"
    small.write_text((ROOT / "examples/helm/small-profile-values.yaml").read_text()
                     .replace("sha256:REPLACE_PRODUCT_MANIFEST_DIGEST", DIGEST).replace("REPLACE_PG_MANIFEST_DIGEST", "b" * 64))
    docs = render({}, files=(profile, small))
    assert {"asservat-postgres", "asservat-objectstore", "asservat-openbao"} <= {r["metadata"]["name"] for r in docs if r["kind"] == "StatefulSet"}


def check_collector(directory):
    # ADR-246: the node collector DaemonSet, rendered statically. Off by
    # default; the only privileged Pod Security exception is its namespace.
    path = Path(directory) / "collector-values.yaml"
    roots = "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n"
    base = {"mode": "cluster", "collector": {"enabled": True, "image": "registry.example/asservat@sha256:" + "a" * 64,
            "installationID": "10000000-0000-4000-8000-000000000001", "clusterID": "50000000-0000-4000-8000-000000000001",
            "connector": {"endpoint": "https://asservat-connector-nodes.asservat-connector.svc:8444", "serverName": "asservat-connector-nodes", "rootsPEM": roots}}}

    def render(v, ok=True, namespace="asservat-region", collector_only=False):
        path.write_text(yaml.safe_dump(v))
        args = ["template", "asservat", str(CHART), "--namespace", namespace, "--kube-version", "1.37.0", "-f", str(path)]
        if collector_only:
            args += ["--show-only", "templates/collector.yaml"]
        result = run(args, ok=ok)
        return result if not ok else [r for r in yaml.safe_load_all(result) if r]

    docs = render(base)
    collector = [r for r in docs if r["metadata"].get("namespace") == "asservat-collector" or r["kind"] == "Namespace"]
    assert sorted(r["kind"] for r in collector) == ["ConfigMap", "DaemonSet", "Namespace", "ServiceAccount"], [r["kind"] for r in collector]
    assert not any(r["kind"] in ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "Secret") for r in docs), "the collector account gets no API permission"
    # The installed CLI connector already owns its guarded namespace. Its
    # collector stage applies only the official four collector resources;
    # no unrelated installation-intent ConfigMap may target a release namespace.
    stage = render(base, namespace="asservat-connector", collector_only=True)
    assert stage == collector, "collector stage changed the official resources or includes installation intent"
    assert all(r["kind"] == "Namespace" and r["metadata"]["name"] == "asservat-collector"
               or r["metadata"].get("namespace") == "asservat-collector" for r in stage), "collector stage writes outside its dedicated namespace"

    namespace = next(r for r in collector if r["kind"] == "Namespace")
    assert namespace["metadata"]["name"] == "asservat-collector"
    assert {k: v for k, v in namespace["metadata"]["labels"].items() if k.startswith("pod-security")} == {f"pod-security.kubernetes.io/{m}": "privileged" for m in ("enforce", "audit", "warn")}
    account = next(r for r in collector if r["kind"] == "ServiceAccount")
    assert account["automountServiceAccountToken"] is False
    data = next(r for r in collector if r["kind"] == "ConfigMap")
    assert data["immutable"] is True
    node = json.loads(data["data"]["node.json"])
    assert node["format"] == "asservat-node-deployment/v1" and node["ceilings"] == {"maxActiveSources": 16, "inputBytesPerSecond": 16777216, "inputBurstBytes": 16777216, "ringBytes": 268435456, "frozenBytes": 268435456, "uploadBytesPerSecond": 33554432, "uploadBurstBytes": 67108864}
    # Existing typed node-processing ceilings, independent of the hub's
    # delivery.liveRead viewer policy. Omission/null preserves every old byte.
    assert "live" not in node
    disabled_live = copy.deepcopy(base)
    disabled_live["collector"]["live"] = None
    assert render(disabled_live) == docs, "null live processing changed old resources"
    live_bounds = {"subscriptions": (1, 16), "memoryBytes": (1048576, 16777216),
                   "eventsPerSecond": (1, 100000), "bytesPerSecond": (1, 268435456),
                   "processingNanosPerSecond": (1, 100000000)}
    for edge in (0, 1):
        requested = {name: bounds[edge] for name, bounds in live_bounds.items()}
        enabled_live = copy.deepcopy(base)
        enabled_live["collector"]["live"] = requested
        rendered_live = render(enabled_live)
        live_node = json.loads(next(r for r in rendered_live if r["kind"] == "ConfigMap")["data"]["node.json"])
        assert live_node == {**node, "live": requested}, "node processing bounds were dropped or changed"
        live_ds = next(r for r in rendered_live if r["kind"] == "DaemonSet")
        old_ds = next(r for r in docs if r["kind"] == "DaemonSet")
        assert live_ds["spec"]["template"]["spec"]["containers"][0]["resources"] == old_ds["spec"]["template"]["spec"]["containers"][0]["resources"], "live mapping changed the container limit"
    for name, bounds in live_bounds.items():
        for invalid in (bounds[0] - 1, bounds[1] + 1):
            bad = copy.deepcopy(enabled_live)
            bad["collector"]["live"][name] = invalid
            render(bad, ok=False)
        missing = copy.deepcopy(enabled_live)
        del missing["collector"]["live"][name]
        render(missing, ok=False)
    for invalid in ({}, {**requested, "enabled": True}, {**requested, "subscriptions": "1"}):
        bad = copy.deepcopy(base)
        bad["collector"]["live"] = invalid
        render(bad, ok=False)
    zero = json.loads(json.dumps(base))
    zero["collector"]["ceilings"] = {"maxActiveSources": 0, "inputBytesPerSecond": 0, "inputBurstBytes": 0}
    zero_docs = render(zero)
    zero_node = json.loads(next(r for r in zero_docs if r["kind"] == "ConfigMap")["data"]["node.json"])
    assert all(name not in zero_node["ceilings"] for name in ("maxActiveSources", "inputBytesPerSecond", "inputBurstBytes")), "zero source caps must preserve the canonical old absent-field representation"
    assert data["metadata"]["name"] == "asservat-node-input." + hashlib.sha256(data["data"]["node.json"].encode()).hexdigest()[:32]
    ds = next(r for r in collector if r["kind"] == "DaemonSet")
    pod = ds["spec"]["template"]["spec"]
    assert pod["hostPID"] is True and pod["hostNetwork"] is False and pod["hostIPC"] is False
    assert pod["automountServiceAccountToken"] is False and pod["enableServiceLinks"] is False and "imagePullSecrets" not in pod
    container, = pod["containers"]
    assert container["command"] == ["/asservat", "node"] and container["image"] == base["collector"]["image"]
    assert container["securityContext"] == {"privileged": False, "runAsUser": 0, "runAsNonRoot": False, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"], "add": ["BPF", "NET_ADMIN", "SYS_RESOURCE", "PERFMON", "SYS_ADMIN", "SYS_PTRACE"]},
                                             "seccompProfile": {"type": "RuntimeDefault"}}
    assert container["resources"]["requests"]["cpu"] == "20m" and container["resources"]["limits"]["cpu"] == "500m"
    assert container["resources"]["limits"]["memory"] == str(268435456 * 2 + 134217728)
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["disposable-host"]["hostPath"] == {"path": "/etc/asservat-disposable-host", "type": "File"}, "disposable-host guard missing"
    host_paths = {v["hostPath"]["path"] for v in pod["volumes"] if "hostPath" in v}
    assert host_paths == {"/etc/asservat-disposable-host", "/sys/kernel/debug", "/sys/kernel/tracing", "/sys/fs/bpf"}, host_paths
    assert all(m["readOnly"] is True for m in container["volumeMounts"])
    token = volumes["token"]["projected"]["sources"][0]["serviceAccountToken"]
    assert token == {"path": "token", "audience": "asservat-node:10000000-0000-4000-8000-000000000001", "expirationSeconds": 600}
    assert pod["serviceAccountName"] == account["metadata"]["name"] == ds["metadata"]["name"] == "asservat-node"
    # ADR-278: the optional ring volume is a size-limited emptyDir and the
    # only writable collector mount; it is absent unless enabled.
    assert "ring-disk" not in volumes
    disk = json.loads(json.dumps(base))
    disk["collector"]["ringDisk"] = {"enabled": True, "bytes": 2147483648}
    disk_docs = render(disk)
    disk_pod = next(r for r in disk_docs if r["kind"] == "DaemonSet")["spec"]["template"]["spec"]
    disk_volumes = {v["name"]: v for v in disk_pod["volumes"]}
    assert disk_volumes["ring-disk"] == {"name": "ring-disk", "emptyDir": {"sizeLimit": "2147483648"}}, disk_volumes.get("ring-disk")
    disk_node = json.loads(next(r for r in disk_docs if r["kind"] == "ConfigMap")["data"]["node.json"])
    assert disk_node["ceilings"]["ringDiskBytes"] == 2147483648, disk_node["ceilings"]
    assert "ringDiskBytes" not in json.loads(data["data"]["node.json"])["ceilings"]
    writable = [m for m in disk_pod["containers"][0]["volumeMounts"] if not m.get("readOnly")]
    assert writable == [{"name": "ring-disk", "mountPath": "/var/lib/asservat-ring"}], writable
    # Default: nothing of the collector renders.
    default = render({"mode": "cluster"})
    assert not any(r["kind"] in ("DaemonSet", "Namespace") for r in default)
    combined = {**hub_values(), **json.loads(json.dumps(base))}
    combined["mode"] = "combined"
    assert any(r["kind"] == "DaemonSet" for r in render(combined))
    for change in [{"mode": "hub"}, {"collector": {"namespace": "kube-system"}}, {"collector": {"namespace": "default"}}, {"collector": {"namespace": "asservat-connector"}}, {"region": {"namespace": "asservat-collector"}},
                   {"collector": {"image": "registry.example/asservat:latest"}}, {"collector": {"installationID": "not-a-uuid"}}, {"collector": {"clusterID": ""}},
                   {"collector": {"connector": {"endpoint": "http://connector:8444", "serverName": "x", "rootsPEM": roots}}},
                   {"collector": {"connector": {"endpoint": "https://connector:8444", "serverName": "x", "rootsPEM": ""}}},
                   {"collector": {"ceilings": {"ringBytes": 8589934592, "frozenBytes": 1, "uploadBytesPerSecond": 1, "uploadBurstBytes": 1}}},
                   {"collector": {"ceilings": {"maxActiveSources": 0, "inputBytesPerSecond": 1, "inputBurstBytes": 1}}},
                   {"collector": {"ceilings": {"maxActiveSources": 1, "inputBytesPerSecond": 0, "inputBurstBytes": 1}}},
                   {"collector": {"privileged": True}}]:
        v = json.loads(json.dumps(base))
        for key, value in change.items():
            if isinstance(value, dict):
                v.setdefault(key, {}).update(value)
            else:
                v[key] = value
        render(v, ok=False)
    render(base, ok=False, namespace="asservat-collector")

def main():
    schema = json.loads((CHART / "values.schema.json").read_text())
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(yaml.safe_load((CHART / "values.yaml").read_text()))
    metadata = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert not metadata.get("dependencies"), "the chart must not install dependency charts"
    expected = {p.name: yaml.safe_load(p.read_text()) for p in (CHART / "crds").glob("*.yaml")}
    # ADR-228 adds the hub-held DebugPolicy CRD (structural accepted subset).
    # S-04 increment 11 adds the CaptureProfile catalog CRD (REQ-CPR-001).
    assert len(expected) == 8, "review newly added installation resources"
    cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="helm-check-", dir=cache) as directory:
        render = Renderer(directory)
        values = Path(directory) / "lint.yaml"
        for mode in ["hub", "cluster", "combined"]:
            values.write_text(yaml.safe_dump({**hub_values(), "mode": mode}))
            run(["lint", "--strict", str(CHART), "-f", str(values)])
            output = run(["template", "asservat", str(CHART), "--namespace", "asservat-system", "--include-crds", "--kube-version", "1.35.0", "-f", str(values)])
            resources = list(yaml.safe_load_all(output))
            crds = [r for r in resources if r["kind"] == "CustomResourceDefinition"]
            assert sorted(crds, key=lambda r: r["metadata"]["name"]) == sorted(expected.values(), key=lambda r: r["metadata"]["name"])
            for r in resources:
                assert r["kind"] != "Pod", "hooks must be Jobs, not bare Pods"
        for value in ["mode=cluser", "password=must-not-be-accepted", "runtime.enabled=true", "image.digest=latest", "installation.name=Bad_Name"]:
            run(["template", "asservat", str(CHART), "-f", str(values), "--set", value], ok=False)
        run(["template", "asservat", str(CHART), "-f", str(values), "--kube-version", "1.34.9"], ok=False)
        check_secrets(render)
        check_setup(render)
        check_exposure(render)
        check_examples(render, directory)
        check_collector(directory)
        run(["package", str(CHART), "--destination", directory])
        archive, = Path(directory).glob("*.tgz")
        with tarfile.open(archive) as bundle:
            members = set(bundle.getnames())
            assert {"asservat/Chart.yaml", "asservat/values.schema.json", "asservat/README.md"} <= members
            for name, content in expected.items():
                assert yaml.safe_load(bundle.extractfile("asservat/crds/" + name).read()) == content
        run(["lint", "--strict", str(archive), "-f", str(values)])
        assert run(["template", "asservat", str(archive), "--include-crds", "-f", str(values)]) == run(["template", "asservat", str(CHART), "--include-crds", "-f", str(values)])
    print("Helm schema/render/package checks passed: 3 modes, 8 canonical CRDs, secrets hook Job and Role, setup Job, Ingress/HTTPRoute exposure, examples, the guarded collector DaemonSet and invalid values rejected.")
    print(run(["version", "--short"]).strip())


if __name__ == "__main__":
    main()
