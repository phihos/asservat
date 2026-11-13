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


PROFILE = yaml.safe_load((ROOT / "examples/helm/context-trial-profile.yaml").read_text())


def hub_values():
    """Minimal hub values with external providers (render fixtures only)."""
    return {
        "image": {"repository": "registry.example/asservat", "digest": DIGEST, "pullPolicy": "IfNotPresent", "pullSecrets": []},
        "origin": "https://asservat.example.org",
        "identity": {"issuer": "https://id.example.org/realms/org", "clientID": "asservat-console", "eligibleGroups": ["00000000-0000-4000-8000-000000000001"], "clientSecret": {"existingSecret": "operator-oidc"}, "providerRootsPEM": "PUBLIC-CA"},
        "exposure": {"tlsSecret": "console-tls"},
        # The regional offer's connector and backup limits (mode=combined).
        "federation": {"connector": PROFILE["federation"]["connector"]},
        "capacity": PROFILE["capacity"],
        "services": {
            "postgres": {"external": {"host": "postgres.example", "port": 5432, "database": "asservat", "rootsPEM": "PUBLIC-CA", "adminSecret": "operator-postgres-admin"}},
            "objectStore": {"external": {"endpoint": "https://s3.example", "region": "r", "bucket": "audit", "rootsPEM": "PUBLIC-CA"}},
            "keyService": {"external": {"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"}},
        },
    }


def bundled_values(mode="combined"):
    v = hub_values()
    v["mode"] = mode
    # Bundled Keycloak derives the issuer and holds the console client secret.
    v["identity"] = {"clientID": "asservat-console"}
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


def named(docs, kind, name, namespace="asservat-system"):
    found = [r for r in docs if r["kind"] == kind and r["metadata"]["name"] == name and r["metadata"].get("namespace", namespace) == namespace]
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
        assert "asservat-s3-download-read" in names
        assert {"asservat-s3-regional-write", "asservat-s3-regional-history"} <= names if mode == "combined" else "asservat-s3-regional-write" not in names
        for hooked in [named(docs, k, "asservat-secrets") for k in ("ServiceAccount", "Role", "RoleBinding", "ConfigMap")]:
            assert hooked["metadata"]["annotations"]["helm.sh/hook"] == "pre-install,pre-upgrade"
        plan = json.loads(named(docs, "ConfigMap", "asservat-secrets")["data"]["secrets.json"])
        assert plan["format"] == "asservat-secrets/v1" and plan["ids"] == {"secret": "asservat-ids", "generate": True}
        # download-read is copied into the workers' namespace with its own Role.
        assert plan["downloadStore"] == {"source": "asservat-s3-download-read", "namespace": "asservat-downloads", "secret": "asservat-s3-download-read"}
        assert named(docs, "Role", "asservat-secrets", "asservat-downloads")["rules"][1]["resourceNames"] == ["asservat-s3-download-read"]
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
    volumes = {v["name"]: v for v in pod["volumes"]}
    # The exact files `asservat setup` opens (contracts.Setup*Root).
    mounts = {m["mountPath"]: m for m in pod["containers"][0]["volumeMounts"]}
    assert {"/run/asservat/ids", "/run/asservat/setup/config.json", "/run/asservat/setup/postgres", "/run/asservat/setup/openbao", "/run/asservat/setup/objectstore"} | {f"/run/asservat/setup/sql/{c}" for c in COMPONENTS} <= set(mounts)
    assert mounts["/run/asservat/setup/config.json"]["subPath"] == "config.json"
    files = lambda name: {i["path"] for s in volumes[name]["projected"]["sources"] for i in s.get("secret", s.get("configMap", {})).get("items", [])} | {s["serviceAccountToken"]["path"] for s in volumes[name]["projected"]["sources"] if "serviceAccountToken" in s}
    assert files("postgres") == {"administrator.json", "ddl.json", "ca.crt"}
    assert files("openbao") == {"ca.crt", "token"} and files("objectstore") == {"ca.crt", "credentials.json", "bucket-policies.json"}
    token, = [s["serviceAccountToken"] for s in volumes["openbao"]["projected"]["sources"] if "serviceAccountToken" in s]
    assert token["audience"] == "https://asservat.io/openbao/setup"
    assert named(docs, "Role", "asservat-setup")["rules"] == [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["asservat-fleet"], "verbs": ["get"]}]
    cluster = named(docs, "ClusterRole", "asservat-system-asservat-setup")["rules"]
    assert cluster == [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["asservat-system"], "verbs": ["get"]}]
    # The name follows chart version, image and values.
    changed = bundled_values("combined")
    changed["identity"] = {"maxSessions": 9}
    other = [r for r in render(changed) if r["kind"] == "Job" and r["metadata"]["name"].startswith("asservat-setup-")][0]
    assert other["metadata"]["name"] != job["metadata"]["name"]
    config = json.loads(named(docs, "ConfigMap", "asservat-setup-config")["data"]["config.json"])
    assert config == {"format": "asservat-setup/v1", "name": "asservat", "namespace": "asservat-system", "fleetSource": "asservat-fleet",
                      "postgres": {"host": "asservat-postgres.asservat-system.svc", "port": 5432, "database": "asservat"},
                      "openBao": {"endpoint": "https://asservat-openbao.asservat-system.svc:8200", "bundled": True, "accounts": {c: f"asservat-{c}" for c in ["hub-api", "hub-worker", "federation", "publisher"]}},
                      "objectStore": {"endpoint": "https://asservat-objectstore.asservat-system.svc:8333", "region": "us-east-1", "bundled": True, "auditBucket": "asservat-audit", "evidenceBucket": "asservat-evidence"}}, config
    # SeaweedFS restarts when the hook recompiles its IAM Secret.
    store = named(docs, "StatefulSet", "asservat-objectstore")
    assert "checksum/iam" in store["spec"]["template"]["metadata"]["annotations"]
    # External providers: the operator's administrator Secret and PEM roots.
    docs = render(hub_values())
    roots = named(docs, "ConfigMap", "asservat-provider-roots")["data"]
    assert roots == {"postgres.crt": "PUBLIC-CA", "objectStore.crt": "PUBLIC-CA", "openBao.crt": "PUBLIC-CA"}
    job = [r for r in docs if r["kind"] == "Job" and r["metadata"]["name"].startswith("asservat-setup-")][0]
    sources = {v["name"]: v for v in job["spec"]["template"]["spec"]["volumes"]}["postgres"]["projected"]["sources"]
    assert {"secret": {"name": "operator-postgres-admin", "items": [{"key": "credentials.json", "path": "administrator.json"}]}} in sources
    assert {"configMap": {"name": "asservat-provider-roots", "items": [{"key": "postgres.crt", "path": "ca.crt"}]}} in sources
    external = hub_values()
    external["services"]["postgres"]["external"]["adminSecret"] = ""
    assert "services.postgres.external.adminSecret is required" in render(external, ok=False)


def check_exposure(render):
    v = hub_values()
    assert not any(r["kind"] in ("Ingress", "HTTPRoute") for r in render(v))
    v["exposure"] = {"tlsSecret": "console-tls", "ingress": {"enabled": True, "className": "example", "annotations": {"a": "b"}, "tls": [{"hosts": ["asservat.example.org"], "secretName": "t"}]},
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
        bad["exposure"] = {"tlsSecret": "console-tls", key: v["exposure"][key]}
        assert "must not carry a port" in render(bad, ok=False)
    bad = copy.deepcopy(v)
    bad["exposure"] = {"tlsSecret": "console-tls", "httpRoute": {"enabled": True, "parentRefs": []}}
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
    # ADR-246: the node collector DaemonSet. Off by default; the only
    # privileged Pod Security exception is its namespace. It needs the
    # regional connector (mode=cluster or combined).
    path = Path(directory) / "collector-values.yaml"
    offer = {"format": "asservat-regional-offer/v1", "installationID": "10000000-0000-4000-8000-000000000001"}
    base = {**hub_values(), "mode": "cluster", "collector": {"enabled": True},
            "region": {"enabled": True, "clusterID": "50000000-0000-4000-8000-000000000001", "peerID": "50000000-0000-4000-8000-000000000002",
                       "bootstrapSecret": "operator-bootstrap", "offer": json.dumps(offer)}}
    del base["services"]

    def render(v, ok=True, namespace="asservat-region"):
        path.write_text(yaml.safe_dump(v))
        result = run(["template", "asservat", str(CHART), "--namespace", namespace, "--kube-version", "1.35.0", "-f", str(path)], ok=ok)
        return result if not ok else [r for r in yaml.safe_load_all(result) if r]

    docs = render(base)
    collector = [r for r in docs if r["metadata"].get("namespace") == "asservat-collector" or r["kind"] == "Namespace" and r["metadata"]["name"] == "asservat-collector"]
    assert sorted(r["kind"] for r in collector) == ["ConfigMap", "ConfigMap", "DaemonSet", "Namespace", "Role", "RoleBinding", "ServiceAccount"], [r["kind"] for r in collector]
    namespace = next(r for r in collector if r["kind"] == "Namespace")
    assert {k: v for k, v in namespace["metadata"]["labels"].items() if k.startswith("pod-security")} == {f"pod-security.kubernetes.io/{m}": "privileged" for m in ("enforce", "audit", "warn")}
    # The collector account has no API permission; the Role is the connector's.
    binding = next(r for r in collector if r["kind"] == "RoleBinding")
    assert binding["subjects"] == [{"kind": "ServiceAccount", "namespace": "asservat-region", "name": "asservat-connector"}]
    account = next(r for r in collector if r["kind"] == "ServiceAccount")
    assert account["automountServiceAccountToken"] is False
    data = next(r for r in collector if r["kind"] == "ConfigMap" and r["metadata"]["name"] == "asservat-node-config")
    node = json.loads(data["data"]["node.json"])
    assert node == {"format": "asservat-node-deployment/v1", "connector": {"endpoint": "https://asservat-connector-nodes.asservat-region.svc:8444", "serverName": "asservat-connector-nodes.asservat-region.svc", "rootsPEM": ""},
                    "ceilings": {"maxActiveSources": 16, "inputBytesPerSecond": 16777216, "inputBurstBytes": 16777216, "ringBytes": 268435456, "frozenBytes": 268435456, "uploadBytesPerSecond": 33554432, "uploadBurstBytes": 67108864}}, node
    live = {"subscriptions": 1, "memoryBytes": 1048576, "eventsPerSecond": 1, "bytesPerSecond": 1, "processingNanosPerSecond": 1}
    v = copy.deepcopy(base)
    v["collector"]["live"] = live
    live_node = json.loads(next(r for r in render(v) if r["kind"] == "ConfigMap" and r["metadata"]["name"] == "asservat-node-config")["data"]["node.json"])
    assert live_node == {**node, "live": live}
    ds = next(r for r in collector if r["kind"] == "DaemonSet")
    pod = ds["spec"]["template"]["spec"]
    assert pod["hostPID"] is True and pod["hostNetwork"] is False and pod["hostIPC"] is False
    assert pod["automountServiceAccountToken"] is False and pod["enableServiceLinks"] is False
    container, = pod["containers"]
    assert container["command"] == ["/asservat", "node"] and container["image"] == "registry.example/asservat@" + DIGEST
    assert container["securityContext"] == {"privileged": False, "runAsUser": 0, "runAsNonRoot": False, "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                             "capabilities": {"drop": ["ALL"], "add": ["BPF", "NET_ADMIN", "SYS_RESOURCE", "PERFMON", "SYS_ADMIN", "SYS_PTRACE"]},
                                             "seccompProfile": {"type": "RuntimeDefault"}}
    assert container["resources"]["limits"]["memory"] == str(268435456 * 2 + 134217728)
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["disposable-host"]["hostPath"] == {"path": "/etc/asservat-disposable-host", "type": "File"}, "disposable-host guard missing"
    assert {v["hostPath"]["path"] for v in pod["volumes"] if "hostPath" in v} == {"/etc/asservat-disposable-host", "/sys/kernel/debug", "/sys/kernel/tracing", "/sys/fs/bpf"}
    assert all(m["readOnly"] is True for m in container["volumeMounts"])
    assert volumes["token"]["projected"]["sources"][0]["serviceAccountToken"] == {"path": "token", "audience": "asservat-node", "expirationSeconds": 600}
    assert pod["serviceAccountName"] == account["metadata"]["name"] == ds["metadata"]["name"] == "asservat-node"
    # ADR-278: the optional ring volume is the only writable collector mount.
    assert "ring-disk" not in volumes
    disk = copy.deepcopy(base)
    disk["collector"]["ringDisk"] = {"enabled": True, "bytes": 2147483648}
    disk_docs = render(disk)
    disk_pod = next(r for r in disk_docs if r["kind"] == "DaemonSet")["spec"]["template"]["spec"]
    assert {v["name"]: v for v in disk_pod["volumes"]}["ring-disk"] == {"name": "ring-disk", "emptyDir": {"sizeLimit": "2147483648"}}
    assert [m for m in disk_pod["containers"][0]["volumeMounts"] if not m.get("readOnly")] == [{"name": "ring-disk", "mountPath": "/var/lib/asservat-ring"}]
    # Default: nothing of the collector renders.
    assert not any(r["kind"] == "DaemonSet" for r in render({**base, "collector": {"enabled": False}}))
    for change in [{"region": {"enabled": False}}, {"collector": {"namespace": "kube-system"}}, {"collector": {"namespace": "default"}}, {"collector": {"privileged": True}},
                   {"collector": {"ceilings": {"ringBytes": 8589934592}}}]:
        v = copy.deepcopy(base)
        for key, value in change.items():
            v[key].update(value)
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
