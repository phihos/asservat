#!/usr/bin/env python3
"""Offline render checks for the federation, key service and publisher
templates; no Kubernetes API calls. CHART overrides the chart directory."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = Path(os.environ.get("CHART", ROOT / "charts/asservat"))
HELM = os.environ.get("HELM", "helm")
DIGEST = "sha256:" + "0" * 63 + "1"
IMAGE = "registry.example/dependency@sha256:" + "1" * 64
# All bundled providers, combined mode: the default small install.
BASE = {
    "mode": "combined",
    "image": {"repository": "registry.example/asservat", "digest": DIGEST},
    "origin": "https://asservat.example",
    "exposure": {"tlsSecret": "console-tls"},
    "identity": {"processingOperators": [{"clientID": "asservat-console", "issuer": "https://login.example.org/realms/asservat", "kind": "User", "id": "0f03f92a-6920-47cd-85d5-26080d3571d5"}]},
    # The regional offer's connector limits (mode=combined).
    "federation": {"connector": yaml.safe_load((CHART.parents[1] / "examples/helm/context-trial-profile.yaml").read_text())["federation"]["connector"]},
    "capacity": yaml.safe_load((CHART.parents[1] / "examples/helm/context-trial-profile.yaml").read_text())["capacity"],
    "services": {
        "postgres": {"provider": "bundled", "bundled": {"image": IMAGE}},
        "objectStore": {"provider": "seaweedfs", "seaweedfs": {"image": IMAGE}},
        "keyService": {"provider": "openbao"},
        "identity": {"provider": "keycloak", "keycloak": {"image": IMAGE, "hostname": "https://id.example", "tlsSecretName": "id-tls"}},
    },
}
COMPONENTS = {"federation": "FederationConfig", "key-service": "KeyServiceConfig", "publisher": "PublisherConfig"}
TEMPLATES = [f"templates/{c}-workload.yaml" for c in COMPONENTS]


def render(values, ok=True):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
        yaml.safe_dump(values, f)
        f.flush()
        args = [HELM, "template", "t", str(CHART), "-n", "hub", "-f", f.name]
        for t in TEMPLATES:
            args += ["--show-only", t]
        r = subprocess.run(args, text=True, capture_output=True, timeout=60)
    if (r.returncode == 0) != ok:
        raise AssertionError(f"unexpected Helm result: {r.stderr}")
    return [d for d in yaml.safe_load_all(r.stdout) if d] if ok else r.stderr


def merge(base, extra):
    out = json.loads(json.dumps(base))
    for k, v in extra.items():
        out[k] = merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def go_fields(struct):
    """JSON tags of one Go struct in internal/contracts/service_config.go."""
    src = (ROOT / "internal/contracts/service_config.go").read_text()
    body = re.search(r"type " + struct + r" struct \{(.*?)\n\}", src, re.S).group(1)
    return set(re.findall(r'json:"([A-Za-z]+)', body))


def sources(pod):
    return pod["spec"]["volumes"][0]["projected"]["sources"]


def files(pod):
    """Projected path -> (kind, object name, key) of the inputs volume."""
    out = {}
    for s in sources(pod):
        kind = next(iter(s))
        if kind == "serviceAccountToken":
            out[s[kind]["path"]] = (kind, s[kind]["audience"], None)
            continue
        for i in s[kind]["items"]:
            out[i["path"]] = (kind, s[kind]["name"], i["key"])
    return out


def main():
    docs = render(BASE)
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    for component, struct in COMPONENTS.items():
        config = json.loads(by[("ConfigMap", f"asservat-{component}-config")]["data"]["config.json"])
        expected = go_fields(struct)
        assert set(config) == expected, (component, set(config) ^ expected)
        assert config["name"] == "asservat" and config["namespace"] == "hub" and set(config["postgres"]) == {"host", "port", "database"}
        pod = by[("Deployment", f"asservat-{component}")]["spec"]["template"]
        assert pod["metadata"]["annotations"]["checksum/config"], component
        assert pod["spec"]["securityContext"]["runAsNonRoot"] is True
        assert pod["spec"]["serviceAccountName"] == f"asservat-{component}"
        f = files(pod)
        # wait-schema reads the component's own config, SQL file and CA.
        wait = pod["spec"]["initContainers"][0]
        assert wait["name"] == "wait-schema" and wait["command"][1:3] == ["setup", "--wait-schema"], wait
        root = f"/run/asservat/{component}/"
        for flag in ("--config", "--credential", "--ca"):
            path = wait["command"][wait["command"].index(flag) + 1]
            assert path.startswith(root) and path[len(root):] in f, (component, flag, path)
        # SQL files carry the Secret key names unchanged.
        sql = {p: v for p, v in f.items() if v[1] == f"asservat-sql-{component}"}
        assert sql and all(p == k for p, (_, _, k) in sql.items()), sql
        # The artifact root key is mounted into the key service only.
        assert (f.get("artifact-key.json") == ("secret", "asservat-artifact-key", "keys.json")) == (component == "key-service"), component
        assert f["postgres-ca.crt"] == ("secret", "asservat-postgres-state", "ca.crt")
        ids = [v for v in pod["spec"]["volumes"] if v["name"] == "ids"][0]["secret"]
        assert ids["secretName"] == "asservat-ids" and "items" not in ids
    fed = files(by[("Deployment", "asservat-federation")]["spec"]["template"])
    assert fed["audit-storage.json"] == ("secret", "asservat-s3-federation-audit", "credentials.json")
    assert {fed[k] for k in ("inputVersion", "inputKey", "accountVersion", "accountKey")} == {("secret", "asservat-audit-mac", k) for k in ("inputVersion", "inputKey", "accountVersion", "accountKey")}
    assert fed["provider-auth.token"] == ("serviceAccountToken", "asservat-federation-provider", None)
    assert fed["tls.key"] == ("secret", "asservat-federation-tls", "tls.key")
    pub = files(by[("Deployment", "asservat-publisher")]["spec"]["template"])
    assert pub["audit-storage.json"][1] == "asservat-s3-publisher-audit" and pub["evidence-read.json"][1] == "asservat-s3-publisher-read"
    assert pub["provider-auth.token"] == ("serviceAccountToken", "asservat-publisher-provider", None)
    # Only the key service's CA, never its key, reaches the publisher.
    assert pub["key-service-ca.crt"] == ("secret", "asservat-key-service-tls", "ca.crt") and "tls.key" not in pub
    # Without cert-manager or an existing Secret the secrets hook creates the
    # CA and certificate once; Helm renders no key material.
    assert not any(d["kind"] == "Secret" for d in docs)
    assert by[("Service", "asservat-federation")]["spec"]["ports"][0]["port"] == 9446
    assert by[("Service", "asservat-key-service")]["spec"]["ports"][0]["port"] == 9447
    assert ("Service", "asservat-publisher") not in by
    # Downloads are on by default (the hub-local download workers).
    assert ("Role", "asservat-key-service") in by
    off = {(d["kind"], d["metadata"]["name"]): d for d in render(merge(BASE, {"hub": {"key-service": {"downloads": {"enabled": False}}}}))}
    assert ("Role", "asservat-key-service") not in off and "downloads" not in json.loads(off[("ConfigMap", "asservat-key-service-config")]["data"]["config.json"])
    # Downloads add the acquisition login and the configured topology.
    docs = render(merge(BASE, {"hub": {"key-service": {"downloads": {"enabled": True, "retentionTopologies": [{"targetClusterID": "10000000-0000-4000-8000-000000000002", "name": "topology"}]}}}}))
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    config = json.loads(by[("ConfigMap", "asservat-key-service-config")]["data"]["config.json"])
    assert "retentionTopologies" in config["downloads"] and set(config["downloads"]) <= go_fields("KeyServiceDownloadsConfig") and config["downloads"]["retentionTopologies"][0]["name"] == "topology"
    assert "sql-key-acquisition.json" in files(by[("Deployment", "asservat-key-service")]["spec"]["template"])
    assert ("Role", "asservat-key-service") in by
    # cert-manager issues the serving certificate; an existing Secret wins.
    docs = render(merge(BASE, {"hub": {"federation": {"tls": {"issuerRef": {"name": "ca"}}}, "key-service": {"tls": {"existingSecret": "keys-tls"}}}}))
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    assert by[("Certificate", "asservat-federation")]["spec"]["secretName"] == "asservat-federation-tls"
    assert not any(d["kind"] == "Secret" for d in docs) and ("Certificate", "asservat-key-service") not in by
    assert files(by[("Deployment", "asservat-publisher")]["spec"]["template"])["key-service-ca.crt"][1] == "keys-tls"
    # Remote regions: NodePort and LoadBalancer listeners.
    docs = render(merge(BASE, {"hub": {"federation": {"service": {"type": "NodePort", "nodePort": 31446}}, "key-service": {"service": {"type": "LoadBalancer"}}}}))
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    assert by[("Service", "asservat-federation")]["spec"]["ports"][0]["nodePort"] == 31446
    assert by[("Service", "asservat-key-service")]["spec"]["type"] == "LoadBalancer"
    # Refusals: no image digest, unknown Service type.
    render(merge(BASE, {"image": {"digest": "latest"}}), ok=False)
    render(merge(BASE, {"hub": {"federation": {"service": {"type": "ExternalName"}}}}), ok=False)
    print("helm services render checks passed")


if __name__ == "__main__":
    main()
