#!/usr/bin/env python3
"""Offline render checks of the connector, collector and download-worker
templates in mode=cluster and mode=combined; no Kubernetes API calls. The
rendered connector config.json is decoded by the Go loader test."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/asservat"
HELM = os.environ.get("HELM", "helm")
DIGEST = "sha256:" + "a" * 64
CLUSTER, PEER = "50000000-0000-4000-8000-000000000001", "50000000-0000-4000-8000-000000000002"
OFFER = {"format": "asservat-regional-offer/v1", "installationID": "10000000-0000-4000-8000-000000000001", "hubClusterID": "10000000-0000-4000-8000-000000000030",
         "permissionRootID": "10000000-0000-4000-8000-000000000003", "issuerEpoch": "10000000-0000-4000-8000-000000000004",
         "federation": {"endpoint": "https://hub.example.invalid:31446", "serverName": "federation.example.invalid", "roots": ["AQ=="]},
         "connectorServerSuffix": "connectors.example.invalid", "connectorIssuerRoots": ["AQ=="],
         "roles": {"source": "a", "journal": "b", "acknowledgement": "c", "cleanup": "d", "verifier": "e", "finalizer": "f"}, "connectorBacking": {},
         "image": "registry.example/asservat@" + DIGEST, "owners": {"address": "hub.example.invalid:31447", "configuration": {}},
         "keyService": {"endpoint": "https://keys.example.invalid:31448", "roots": ["AQ=="], "keyID": "k"},
         "workKey": {"id": "w", "publicKey": "x", "notBefore": "a", "notAfter": "b"},
         "evidenceStore": {"endpoint": "https://s3.example.invalid", "roots": ["AQ=="], "region": "r", "bucket": "b", "storeID": "10000000-0000-4000-8000-000000000014"}}


def render(values, namespace, ok=True):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
        yaml.safe_dump(values, f)
        f.flush()
        r = subprocess.run([HELM, "template", "t", str(CHART), "-n", namespace, "-f", f.name], text=True, capture_output=True, timeout=60)
    if (r.returncode == 0) != ok:
        raise AssertionError(f"unexpected render result: {r.stderr[-800:]}")
    return [d for d in yaml.safe_load_all(r.stdout) if d] if ok else r.stderr


def base(mode, **region):
    v = {"mode": mode, "image": {"repository": "registry.example/asservat", "digest": DIGEST},
         "region": {"enabled": True, "clusterID": CLUSTER, "peerID": PEER, "bootstrapSecret": "operator-bootstrap", **region},
         "collector": {"enabled": True}}
    return v


def find(docs, kind, name=None):
    out = [d for d in docs if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]
    assert out, f"missing {kind} {name}"
    return out[0] if name else out


def rules(role):
    return {(g, r, v) for rule in role["rules"] for g in rule.get("apiGroups", []) for r in rule["resources"] for v in rule["verbs"]}


def check_common(docs, ns, executor=True):
    d = find(docs, "Deployment", "asservat-connector")
    pod = d["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False and pod["securityContext"]["runAsNonRoot"] is True
    c = pod["containers"][0]
    assert c["command"] == ["/asservat", "connector"] and c["image"] == "registry.example/asservat@" + DIGEST
    assert c["securityContext"]["allowPrivilegeEscalation"] is False and c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    sources = pod["volumes"][0]["projected"]["sources"]
    tokens = {s["serviceAccountToken"]["path"]: s["serviceAccountToken"].get("audience") for s in sources if "serviceAccountToken" in s}
    assert tokens == {"kube.token": None, "connector-pod.token": f"https://asservat.{CLUSTER}/connector-process-enrollment"}, tokens
    boot = [s["secret"] for s in sources if "secret" in s and s["secret"]["name"] == "operator-bootstrap"]
    assert boot and boot[0]["optional"] is True
    # No installer machinery: no admission policies, hooks or token minting rights except the capacity account.
    assert not [x for x in docs if x["kind"].startswith("ValidatingAdmissionPolicy") or "helm.sh/hook" in x["metadata"].get("annotations", {})]
    cred = find(docs, "Secret", "asservat-cluster-credential")
    assert "data" not in cred and cred["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    role = find(docs, "Role", "asservat-connector")
    secrets = [r for r in role["rules"] if r["resources"] == ["secrets"]][0]
    assert secrets["verbs"] == ["get", "update"] and set(secrets["resourceNames"]) == {"asservat-cluster-credential", "asservat-connector-nodes"}
    assert (("", "serviceaccounts/token", "create") in rules(role)) == executor
    cluster = rules(find(docs, "ClusterRole")[0])
    for need in [("authentication.k8s.io", "tokenreviews", "create"), ("", "nodes", "get")] + ([("", "pods", "list"), ("", "namespaces", "watch"), ("discovery.k8s.io", "endpointslices", "list")] if executor else []):
        assert need in cluster, need
    if not executor:
        assert ("", "pods", "list") not in cluster
    for forbidden in [("", "secrets", "get"), ("rbac.authorization.k8s.io", "roles", "create"), ("admissionregistration.k8s.io", "validatingadmissionpolicies", "get"), ("authorization.k8s.io", "subjectaccessreviews", "create")]:
        assert forbidden not in cluster, forbidden
    # Collector: privileged namespace only there, node.json without roots, root ConfigMap published by the connector.
    nsobj = find(docs, "Namespace", "asservat-collector")
    assert nsobj["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "privileged"
    node = json.loads(find(docs, "ConfigMap", "asservat-node-config")["data"]["node.json"])
    assert node["clusterID"] == CLUSTER and node["connector"] == {"endpoint": f"https://asservat-connector-nodes.{ns}.svc:8444", "serverName": f"asservat-connector-nodes.{ns}.svc", "rootsPEM": ""}
    ds = find(docs, "DaemonSet", "asservat-node")["spec"]["template"]["spec"]
    vols = {v["name"]: v for v in ds["volumes"]}
    assert vols["token"]["projected"]["sources"][0]["serviceAccountToken"]["audience"] == "asservat-node:" + CLUSTER
    assert vols["input"]["projected"]["sources"][1]["configMap"] == {"name": "asservat-node-connector-ca", "optional": True, "items": [{"key": "connector-ca.crt", "path": "connector-ca.crt"}]}
    croles = rules(find(docs, "Role", "asservat-node-connector"))
    assert croles == {("", "pods", "get"), ("apps", "daemonsets", "get"), ("", "configmaps", "get"), ("", "configmaps", "update")}
    return json.loads(find(docs, "ConfigMap", "asservat-connector-config")["data"]["config.json"])


def main():
    configs = []
    # mode=cluster with an executor offer.
    docs = render(base("cluster", offer=json.dumps(OFFER), executor={"evidenceSecret": "operator-evidence"}), "asservat-region")
    c = check_common(docs, "asservat-region")
    assert c["mode"] == "cluster" and c["offer"] == OFFER and "hub" not in c and c["executor"]["capacityAccount"] == "asservat-connector-capacity"
    assert not [d for d in docs if d["kind"] == "PriorityClass"], "download workers rendered in a regional release"
    configs.append(c)
    # A plain offer installs no executor objects.
    plain = {k: v for k, v in OFFER.items() if k not in ("owners", "keyService", "workKey", "evidenceStore")}
    docs = render(base("cluster", offer=json.dumps(plain)), "asservat-region")
    c = check_common(docs, "asservat-region", executor=False)
    assert "executor" not in c and not [d for d in docs if d["metadata"]["name"] == "asservat-connector-capacity"]
    configs.append(c)
    # mode=combined: in-cluster addresses, the hub's offer ConfigMap, generated S3 principals, download workers.
    v = base("combined")
    v["hub"] = {"downloadWorker": {"enabled": True}}
    docs = render(v, "asservat")
    c = check_common(docs, "asservat")
    assert c["hub"] == {"federation": "https://asservat-federation.asservat.svc:9446", "owners": "asservat-hub-api-native.asservat.svc:9444", "keyService": "https://asservat-key-service.asservat.svc:9447"}
    assert c["offerConfigMap"] == "asservat-regional-offer" and "offer" not in c
    role = find(docs, "Role", "asservat-connector")
    assert [r for r in role["rules"] if r["resources"] == ["configmaps"]][0] == {"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["asservat-regional-offer"], "verbs": ["get"]}
    sources = find(docs, "Deployment", "asservat-connector")["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"]
    assert {s["secret"]["name"] for s in sources if "secret" in s} == {"operator-bootstrap", "asservat-s3-regional-write", "asservat-s3-regional-history"}
    pc = find(docs, "PriorityClass", "asservat-download-worker")
    assert pc["value"] == 0 and pc["preemptionPolicy"] == "Never"
    profile = json.loads(find(docs, "ConfigMap", "asservat-worker-profile")["data"]["worker-profile.json"])
    assert profile["namespace"] == "asservat-downloads" and profile["controlConfig"] == "asservat-download-worker-control" and "uid" not in json.dumps(profile).lower()
    hub = rules(find(docs, "Role", "asservat-downloads-hub-api"))
    assert ("batch", "jobs", "create") in hub and ("", "configmaps", "update") in hub
    assert find(docs, "RoleBinding", "asservat-downloads-hub-api")["subjects"][0] == {"kind": "ServiceAccount", "namespace": "asservat", "name": "asservat-hub-api"}
    configs.append(c)
    # Refusals.
    for bad, ns in [(base("hub"), "asservat"), (base("cluster"), "asservat-region"), ({**base("combined"), "region": {**base("combined")["region"], "offer": json.dumps(OFFER)}}, "asservat"),
                    ({**base("cluster", offer=json.dumps(OFFER))}, "asservat-region"), ({**base("combined"), "region": {**base("combined")["region"], "clusterID": "x"}}, "asservat"),
                    ({**base("combined"), "region": {**base("combined")["region"], "bootstrapSecret": ""}}, "asservat"), ({**base("combined"), "image": {"repository": "r", "digest": ""}}, "asservat")]:
        render(bad, ns, ok=False)
    # The Go loader decodes and validates every rendered config.
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for i, c in enumerate(configs):
            p = Path(d) / f"config-{i}.json"
            p.write_text(json.dumps(c))
            paths.append(str(p))
        env = dict(os.environ, ASSERVAT_RENDERED_CONNECTOR_CONFIG=os.pathsep.join(paths))
        env.setdefault("TMPDIR", str(Path.home() / ".cache/go-tmp"))
        r = subprocess.run(["go", "test", "-count=1", "-run", "TestRenderedConnectorConfigDecodes", "./internal/bootstrap/"], cwd=ROOT, env=env, text=True, capture_output=True, timeout=600)
        assert r.returncode == 0 and "no tests to run" not in r.stdout, r.stdout + r.stderr
    print("helm region templates OK: cluster (executor, plain), combined, refusals, Go loader decode")


if __name__ == "__main__":
    main()
