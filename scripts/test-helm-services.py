#!/usr/bin/env python3
"""Offline render checks for the Helm-native federation, key service and
publisher templates; no Kubernetes API calls."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/asservat"
HELM = os.environ.get("HELM", "helm")
DIGEST = "sha256:" + "0" * 63 + "1"
BASE = {
    "mode": "combined",
    "image": {"repository": "registry.example/asservat", "digest": DIGEST},
    "services": {"postgres": {"provider": "external", "external": {"host": "pg.example", "caSecret": "pg-ca"}},
                 "objectStore": {"provider": "external", "external": {"endpoint": "https://s3.example", "caSecret": "s3-ca"}},
                 "keyService": {"provider": "external", "external": {"endpoint": "https://bao.example:8200", "caSecret": "bao-ca"}}},
    "federation": {"tls": {"issuerRef": {"name": "asservat-ca"}}},
    "hub": {"federation": {"enabled": True}, "keyService": {"enabled": True}, "publisher": {"enabled": True}},
}


def render(values, ok=True):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
        yaml.safe_dump(values, f)
        f.flush()
        r = subprocess.run([HELM, "template", "t", str(CHART), "-n", "asservat", "-f", f.name], text=True, capture_output=True, timeout=60)
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


def main():
    docs = render(BASE)
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    assert not any(d["kind"] == "Secret" for d in docs), "templates must not render Secrets"
    for component, struct in [("federation", "FederationConfig"), ("key-service", "KeyServiceConfig"), ("publisher", "PublisherConfig")]:
        config = json.loads(by[("ConfigMap", f"asservat-{component}-config")]["data"]["config.json"])
        expected = go_fields(struct) - ({"downloads"} if component == "key-service" else set())
        assert set(config) == expected, (component, set(config) ^ expected)
        pod = by[("Deployment", f"asservat-{component}")]["spec"]["template"]
        assert pod["metadata"]["annotations"]["checksum/config"], component
        assert pod["spec"]["securityContext"]["runAsNonRoot"] is True
        assert [c["name"] for c in pod["spec"]["initContainers"]] == ["schema-wait"]
        sources = pod["spec"]["volumes"][0]["projected"]["sources"]
        secrets = {s["secret"]["name"]: [i["path"] for i in s["secret"]["items"]] for s in sources if "secret" in s}
        # The artifact root key is mounted into the key service only.
        assert ("asservat-artifact-key" in secrets) == (component == "key-service"), component
        assert any(i == "postgres-ca.crt" for v in secrets.values() for i in v)
        ids = [v for v in pod["spec"]["volumes"] if v["name"] == "ids"][0]["secret"]
        assert ids["secretName"] == "asservat-ids"
    # Only the key service's CA, never its key, reaches the publisher.
    pub = by[("Deployment", "asservat-publisher")]["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"]
    assert {"secret": {"name": "asservat-key-service-tls", "optional": False, "items": [{"key": "ca.crt", "path": "key-service-ca.crt"}]}} in pub
    assert ("Certificate", "asservat-federation") in by and ("Certificate", "asservat-key-service") in by
    assert by[("Service", "asservat-federation")]["spec"]["type"] == "ClusterIP"
    assert ("Service", "asservat-publisher") not in by
    # Downloads add the acquisition login and the configured topology.
    docs = render(merge(BASE, {"hub": {"keyService": {"downloads": {"enabled": True, "retentionTopologies": [{"targetClusterID": "10000000-0000-4000-8000-000000000002", "name": "topology"}]}}}}))
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    config = json.loads(by[("ConfigMap", "asservat-key-service-config")]["data"]["config.json"])
    assert set(config["downloads"]) == go_fields("KeyServiceDownloadsConfig") and config["downloads"]["retentionTopologies"][0]["name"] == "topology"
    items = [s["secret"]["items"] for s in by[("Deployment", "asservat-key-service")]["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"] if s.get("secret", {}).get("name") == "asservat-sql-key-service"][0]
    assert {"key": "sql-key-acquisition.json", "path": "sql-key-acquisition.json"} in items
    # Remote regions: NodePort and an existing serving Secret without cert-manager.
    remote = merge(BASE, {"federation": {"tls": {"issuerRef": {"name": ""}}}, "hub": {"federation": {"service": {"type": "NodePort", "nodePort": 31446}, "tls": {"existingSecret": "fed-tls"}}, "keyService": {"service": {"type": "LoadBalancer"}, "tls": {"existingSecret": "keys-tls"}}}})
    docs = render(remote)
    by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
    assert not any(d["kind"] == "Certificate" for d in docs)
    assert by[("Service", "asservat-federation")]["spec"]["ports"][0]["nodePort"] == 31446
    assert by[("Service", "asservat-key-service")]["spec"]["type"] == "LoadBalancer"
    # Refusals: no TLS source, no image digest, unknown Service type.
    assert "tls.existingSecret or federation.tls.issuerRef" in render(merge(BASE, {"federation": {"tls": {"issuerRef": {"name": ""}}}}), ok=False)
    render(merge(BASE, {"image": {"digest": "latest"}}), ok=False)
    render(merge(BASE, {"hub": {"federation": {"service": {"type": "ExternalName"}}}}), ok=False)
    # Disabled by default: no service objects.
    assert not any(d["kind"] == "Deployment" for d in render({"mode": "combined"}))
    print("helm services render checks passed")


if __name__ == "__main__":
    main()
