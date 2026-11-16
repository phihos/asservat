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
CHART = Path(os.environ.get("ASSERVAT_CHART", ROOT / "charts/asservat"))
HELM = os.environ.get("HELM", "helm")
DIGEST = "sha256:" + "a" * 64
# Extra helm template arguments, for example --skip-schema-validation.
HELM_ARGS = os.environ.get("ASSERVAT_HELM_ARGS", "").split()
BUNDLED = {"keyService": {"provider": "openbao"}, "objectStore": {"provider": "seaweedfs"},
           "postgres": {"provider": "bundled", "bundled": {"image": "registry.example/postgres@sha256:" + "b" * 64}},
           "identity": {"provider": "keycloak", "keycloak": {"hostname": "https://login.example.invalid", "tlsSecretName": "login-tls"}}}
HUB = "https://hub.example.invalid"


def render(values, namespace, ok=True):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml") as f:
        yaml.safe_dump(values, f)
        f.flush()
        r = subprocess.run([HELM, "template", "t", str(CHART), "-n", namespace, "-f", f.name, *HELM_ARGS], text=True, capture_output=True, timeout=60)
    if (r.returncode == 0) != ok:
        raise AssertionError(f"unexpected render result: {r.stderr[-800:]}")
    return [d for d in yaml.safe_load_all(r.stdout) if d] if ok else r.stderr


def base(mode, **region):
    """mode=cluster dials hub.url, its token audience (ADR-334); its IDs and
    settings arrive from the hub on connect."""
    v = {"mode": mode, "image": {"repository": "registry.example/asservat", "digest": DIGEST},
         "region": {"enabled": True, **region}, "collector": {"enabled": True}}
    if mode == "cluster":
        v["hub"] = {"url": HUB}
    if mode == "combined":
        v["origin"], v["services"] = "https://asservat.example.invalid", BUNDLED
        v["exposure"] = {"tlsSecret": "console-tls"}
        v["identity"] = {"processingOperators": [{"clientID": "asservat-console", "issuer": "https://login.example.org/realms/asservat", "kind": "User", "id": "0f03f92a-6920-47cd-85d5-26080d3571d5"}]}
        profile = yaml.safe_load((Path(__file__).resolve().parents[1] / "examples/helm/context-trial-profile.yaml").read_text())
        v["capacity"] = profile["capacity"]
    return v


def find(docs, kind, name=None):
    out = [d for d in docs if d["kind"] == kind and (name is None or d["metadata"]["name"] == name)]
    assert out, f"missing {kind} {name}"
    return out[0] if name else out


def rules(role):
    return {(g, r, v) for rule in role["rules"] for g in rule.get("apiGroups", []) for r in rule["resources"] for v in rule["verbs"]}


def check_common(docs, ns, executor=True, audience=HUB):
    d = find(docs, "Deployment", "asservat-connector")
    pod = d["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False and pod["securityContext"]["runAsNonRoot"] is True
    c = pod["containers"][0]
    assert c["command"] == ["/asservat", "connector"] and c["image"] == "registry.example/asservat@" + DIGEST
    assert c["securityContext"]["allowPrivilegeEscalation"] is False and c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    sources = next(v for v in pod["volumes"] if v["name"] == "inputs")["projected"]["sources"]
    tokens = {s["serviceAccountToken"]["path"]: s["serviceAccountToken"].get("audience") for s in sources if "serviceAccountToken" in s}
    assert tokens == {"kube.token": None, "hub.token": audience}, tokens
    assert not [s for s in sources if "secret" in s and any(i["key"] == "bootstrap.json" for i in s["secret"]["items"])]
    # No installer machinery: no admission policies, and no hook among these
    # templates except the download-worker namespace the secrets hook fills.
    mine = [x for x in docs if x["metadata"].get("labels", {}).get("app.kubernetes.io/component") in ("connector", "node", "download-worker")]
    # The only policy is the ADR-329 AccessBinding bind check of a hub release.
    assert [x["metadata"]["name"] for x in docs if x["kind"].startswith("ValidatingAdmissionPolicy")] in ([], [ns + "-asservat-accessbindings"] * 2)
    hooks = [(x["kind"], x["metadata"]["name"]) for x in mine if "helm.sh/hook" in x["metadata"].get("annotations", {})]
    assert hooks in ([], [("Namespace", "asservat-downloads")]), hooks
    assert not [d for d in docs if d["kind"] == "Secret" and d["metadata"]["name"] == "asservat-cluster-credential"]
    role = find(docs, "Role", "asservat-connector")
    secrets = [r for r in role["rules"] if r["resources"] == ["secrets"]][0]
    assert secrets["verbs"] == ["get", "update"] and secrets["resourceNames"] == ["asservat-connector-nodes"]
    assert ("", "serviceaccounts/token", "create") not in rules(role)
    cluster = rules(find(docs, "ClusterRole", ns + "-asservat-connector"))
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
    assert "clusterID" not in node and node["connector"] == {"endpoint": f"https://asservat-connector-nodes.{ns}.svc:8444", "serverName": f"asservat-connector-nodes.{ns}.svc", "rootsPEM": ""}
    ds = find(docs, "DaemonSet", "asservat-node")["spec"]["template"]["spec"]
    vols = {v["name"]: v for v in ds["volumes"]}
    assert vols["token"]["projected"]["sources"][0]["serviceAccountToken"]["audience"] == "asservat-node"
    assert vols["input"]["projected"]["sources"][1]["configMap"] == {"name": "asservat-node-connector-ca", "optional": True, "items": [{"key": "connector-ca.crt", "path": "connector-ca.crt"}]}
    croles = rules(find(docs, "Role", "asservat-node-connector"))
    assert croles == {("", "configmaps", "get"), ("", "configmaps", "update")}
    return json.loads(find(docs, "ConfigMap", "asservat-connector-config")["data"]["config.json"])


def main():
    configs = []
    # mode=cluster: hub.url and its optional CA bundle; nothing copied.
    v = base("cluster", executor={"enabled": True, "profileAuthorization": "operator-profiles"})
    v["hub"]["caBundle"] = "-----BEGIN CERTIFICATE-----\n"
    docs = render(v, "asservat-region")
    c = check_common(docs, "asservat-region")
    assert c["mode"] == "cluster" and c["hub"] == HUB and not {"offer", "clusterID", "peerID"} & set(c) and c["executor"]["concurrency"] == 4, c
    assert find(docs, "ConfigMap", "asservat-connector-config")["data"]["hub-ca.crt"] == v["hub"]["caBundle"]
    pod = find(docs, "Deployment", "asservat-connector")["spec"]["template"]["spec"]
    sources = next(x for x in pod["volumes"] if x["name"] == "inputs")["projected"]["sources"]
    assert [x["secret"]["name"] for x in sources if "secret" in x] == ["operator-profiles"], sources
    assert not [d for d in docs if d["kind"] == "PriorityClass"], "download workers rendered in a regional release"
    configs.append(c)
    docs = render(base("cluster", executor={"enabled": False}), "asservat-region")
    c = check_common(docs, "asservat-region", executor=False)
    assert "executor" not in c
    configs.append(c)
    # mode=combined: the in-cluster federation and its CA; no IDs mount.
    docs = render(base("combined"), "asservat")
    c = check_common(docs, "asservat", audience="https://asservat-federation.asservat.svc:9446")
    assert c["hub"] == "https://asservat-federation.asservat.svc:9446" and "clusterID" not in c, c
    pod = find(docs, "Deployment", "asservat-connector")["spec"]["template"]["spec"]
    assert not [x for x in pod["volumes"] if x["name"] == "ids"]
    sources = next(x for x in pod["volumes"] if x["name"] == "inputs")["projected"]["sources"]
    assert [x["secret"] for x in sources if "secret" in x] == [{"name": "asservat-federation-tls", "items": [{"key": "ca.crt", "path": "hub-ca.crt"}]}], sources
    role = find(docs, "Role", "asservat-connector")
    assert not [r for r in role["rules"] if r["resources"] == ["configmaps"]]
    federation = rules(find(docs, "Role", "asservat-federation"))
    assert ("", "secrets", "get") in federation
    pc = find(docs, "PriorityClass", "asservat-download-worker")
    assert pc["value"] == 0 and pc["preemptionPolicy"] == "Never"
    profile = json.loads(find(docs, "ConfigMap", "asservat-worker-profile")["data"]["worker-profile.json"])
    assert profile["namespace"] == "asservat-downloads" and profile["controlConfig"] == "asservat-download-worker-control" and "uid" not in json.dumps(profile).lower()
    assert profile["storeCredentials"] == "asservat-s3-download-read"
    assert find(docs, "Namespace", "asservat-downloads")["metadata"]["annotations"]["helm.sh/hook"] == "pre-install"
    store = [r for r in find(docs, "Role", "asservat-downloads-hub-worker")["rules"] if r["resources"] == ["secrets"]][0]
    assert store["resourceNames"] == ["asservat-s3-download-read"] and store["verbs"] == ["get"]
    hub = rules(find(docs, "Role", "asservat-downloads-hub-api"))
    assert ("batch", "jobs", "create") in hub and ("", "configmaps", "update") in hub
    assert find(docs, "RoleBinding", "asservat-downloads-hub-api")["subjects"][0] == {"kind": "ServiceAccount", "namespace": "asservat", "name": "asservat-hub-api"}
    configs.append(c)
    # Refusals.
    for bad, ns in [(base("hub"), "asservat"), ({**base("cluster"), "hub": {}}, "asservat-region"),
                    ({**base("cluster"), "region": {"enabled": True, "joinSecret": "asservat-join-work"}}, "asservat-region"),
                    ({**base("combined"), "region": {**base("combined")["region"], "hub": {"federation": HUB}}}, "asservat"),
                    ({**base("combined"), "image": {"repository": "r", "digest": ""}}, "asservat")]:
        render(bad, ns, ok=False)
    # The Go loader decodes and validates every rendered config.
    with tempfile.TemporaryDirectory() as d:
        paths = []
        for i, c in enumerate(configs):
            p = Path(d) / f"config-{i}.json"
            p.write_text(json.dumps(c))
            paths.append(str(p))
        env = dict(os.environ, ASSERVAT_RENDERED_CONNECTOR_CONFIG=os.pathsep.join(paths))
        tmp = Path(env.get("TMPDIR") or Path.home() / ".cache/go-tmp")
        tmp.mkdir(parents=True, exist_ok=True)
        env["TMPDIR"] = str(tmp)
        r = subprocess.run(["go", "test", "-count=1", "-run", "TestRenderedConnectorConfigDecodes", "./internal/bootstrap/"], cwd=ROOT, env=env, text=True, capture_output=True, timeout=600)
        assert r.returncode == 0 and "no tests to run" not in r.stdout, r.stdout + r.stderr
    print("helm region templates OK: cluster (executor, plain), combined, refusals, Go loader decode")


if __name__ == "__main__":
    main()
