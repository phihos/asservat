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


def run(args, ok=True):
    result = subprocess.run([HELM, *args], text=True, capture_output=True, timeout=45)
    if (result.returncode == 0) != ok:
        raise RuntimeError(f"unexpected Helm result for {args}: {result.stdout}\n{result.stderr}")
    return result.stdout + result.stderr if not ok else result.stdout


def check_bootstrap(directory):
    # Static render evidence only. PEM/provider and actual authority validation
    # are performed by the compiled product and native chain separately.
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    b = values["bootstrap"]
    b.update(enabled=True, image="registry.example/asservat@sha256:" + "a" * 64,
             registrySecret="operator-pull", targetNamespace="asservat-runtime")
    b["secrets"] = {"producer": "operator-producer", "schema": "operator-schema", "retirement": "operator-retirement"}
    b["postgres"].update(host="postgres.example", rootsPEM="PUBLIC-CA")
    b["auditStore"].update(endpoint="https://store.example", region="region-a", bucket="audit", rootsPEM="PUBLIC-CA")
    b["keyService"].update(endpoint="https://bao.example", rootsPEM="PUBLIC-CA")
    b["fleet"].update(issuer="https://id.example/realms/org", clients=["console"], subjects=[{"id": "installer", "kind": "human"}])
    path = Path(directory) / "bootstrap-values.yaml"

    def render(v, *, ok=True, namespace="trusted-bootstrap", extra=()):
        path.write_text(yaml.safe_dump(v))
        args = ["template", "asservat", str(CHART), "--namespace", namespace,
                "--kube-version", "1.37.0", "-f", str(path), *extra]
        result = run(args, ok=ok)
        if not ok:
            return result
        assert result == run(args), "bootstrap render gained ambient/random state"
        return [r for r in yaml.safe_load_all(result) if r]

    docs = render(values)
    assert sorted(r["kind"] for r in docs) == ["ClusterRole", "ClusterRoleBinding", "ConfigMap", "ConfigMap", "Pod", "ServiceAccount"]
    pod, = [r for r in docs if r["kind"] == "Pod"]
    public, = [r for r in docs if "bootstrap.json" in r.get("data", {})]
    data = public["data"]
    digest = hashlib.sha256((data["bootstrap.json"] + "\n" + data["runner.json"]).encode()).hexdigest()
    input_name = b["name"] + "-bootstrap-input." + digest[:32] + "." + digest[32:]
    assert public["metadata"]["name"] == input_name
    assert public["immutable"] is True and public["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"
    assert pod["metadata"]["name"] == b["name"] + "-bootstrap"
    annotations = pod["metadata"]["annotations"]
    assert annotations["asservat.io/bootstrap-input"] == digest
    assert annotations["helm.sh/hook"] == "post-install,post-upgrade"
    assert annotations["helm.sh/hook-delete-policy"] == "hook-succeeded"
    spec = pod["spec"]
    assert spec["restartPolicy"] == "Never" and spec["activeDeadlineSeconds"] == 1800
    assert spec["automountServiceAccountToken"] is False and spec["enableServiceLinks"] is False
    assert spec["imagePullSecrets"] == [{"name": "operator-pull"}]
    assert spec["securityContext"]["runAsUser"] == 65532 and spec["securityContext"]["fsGroup"] == 65532
    phases = spec["initContainers"] + spec["containers"]
    assert [p["name"] for p in phases] == ["produce", "schema", "prepare", "retire"]
    assert [p["command"] for p in phases] == [["/asservat", c] for c in ["initial-bootstrap", "initial-bootstrap-schema", "initial-bootstrap-prepare", "initial-bootstrap-retire"]]
    for phase in phases:
        assert phase["image"] == b["image"] and phase["imagePullPolicy"] == "IfNotPresent"
        assert phase["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    mounts = {p["name"]: p["volumeMounts"] for p in phases}
    assert {m["name"] for m in mounts["schema"]} == {"scratch", "ddl-input"}
    assert {m["name"] for m in mounts["prepare"]} == {"scratch"}
    volumes = {v["name"]: v for v in spec["volumes"]}
    assert volumes["scratch"]["emptyDir"] == {"medium": "Memory", "sizeLimit": "8Mi"}
    assert volumes["ddl-input"]["secret"]["optional"] is True
    assert volumes["ddl-input"]["secret"]["items"] == [{"key": "postgres-ddl.json", "path": "postgres-ddl.json"}]
    for name in ["producer-input", "retirement-input"]:
        sources = volumes[name]["projected"]["sources"]
        assert sources[0]["configMap"]["name"] == input_name
        assert sources[0]["configMap"]["optional"] is False
        assert sources[1]["serviceAccountToken"]["expirationSeconds"] == 600
        assert "audience" not in sources[1]["serviceAccountToken"]
        for source in sources:
            if "secret" in source:
                assert source["secret"]["optional"] is True
    assert [s["secret"]["name"] for s in volumes["producer-input"]["projected"]["sources"] if "secret" in s] == ["operator-producer", "operator-pull"]
    assert [s["secret"]["name"] for s in volumes["retirement-input"]["projected"]["sources"] if "secret" in s] == ["operator-retirement"]
    public_input = json.loads(data["bootstrap.json"])
    assert public_input["registryAuthentication"] == "dockerconfigjson/v1"
    assert "probeAudience" not in public_input and "rootsPEM" not in public_input["kubernetes"]
    assert not any(r["kind"] in ["Secret", "Namespace", "Deployment", "Job"] for r in docs)
    role, = [r for r in docs if r["kind"] == "ClusterRole"]
    assert len(role["rules"]) == 5 and all("*" not in json.dumps(rule) for rule in role["rules"])
    patch, = [rule for rule in role["rules"] if "patch" in rule["verbs"]]
    assert patch["resources"] == ["secrets"] and patch["resourceNames"] == [b["name"]+suffix for suffix in ["-bootstrap-state", "-sql-material", "-provider-material"]]

    changed = copy.deepcopy(values)
    changed["bootstrap"]["postgres"]["host"] = "corrected.example"
    changed_docs = render(changed)
    new_input, = [r for r in changed_docs if "bootstrap.json" in r.get("data", {})]
    assert new_input["metadata"]["name"] != input_name, "correction would mutate immutable original public input"
    new_pod, = [r for r in changed_docs if r["kind"] == "Pod"]
    assert new_pod["metadata"]["name"] == pod["metadata"]["name"], "new values bypass retained fixed runner"
    assert new_input["metadata"]["annotations"]["helm.sh/resource-policy"] == "keep"

    groups_only = copy.deepcopy(values)
    groups_only["bootstrap"]["fleet"]["subjects"] = []
    groups_only["bootstrap"]["fleet"]["groups"] = ["stable-group-id"]
    render(groups_only)

    without_registry = copy.deepcopy(values)
    without_registry["bootstrap"]["registrySecret"] = ""
    without_registry["bootstrap"]["probeAudience"] = "https://explicit-api.example"
    plain = render(without_registry)
    plain_pod, = [r for r in plain if r["kind"] == "Pod"]
    plain_input, = [r for r in plain if "bootstrap.json" in r.get("data", {})]
    assert "imagePullSecrets" not in plain_pod["spec"]
    assert "registryAuthentication" not in json.loads(plain_input["data"]["bootstrap.json"])
    assert plain_pod["spec"]["volumes"][1]["projected"]["sources"][1]["serviceAccountToken"]["audience"] == "https://explicit-api.example"

    # One fixed installer Pod owns both stages. Retirement refreshes the
    # shared preparer projection before continuation; no second producer runs.
    continued = copy.deepcopy(values)
    c = continued["bootstrap"]["continuation"]
    c.update(enabled=True, ownerIssuerRootsPEM="-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n")
    c["workerProvider"] = {"authMount": "worker-k8s", "authMountAccessor": "auth_kubernetes_1"}
    c["ownerProvider"] = {"authMount": "owner-k8s", "authMountAccessor": "auth_kubernetes_2"}
    cdocs = render(continued)
    cpod, = [r for r in cdocs if r["kind"] == "Pod"]
    assert cpod["metadata"]["name"] == b["name"] + "-bootstrap"
    cinput, = [r for r in cdocs if "continuation.json" in r.get("data", {})]
    assert cinput["immutable"] is True
    assert json.loads(cinput["data"]["continuation.json"])["namespace"] == "trusted-bootstrap"
    assert cpod["metadata"]["annotations"]["asservat.io/bootstrap-runner"] == "five-command/v1"
    assert "helm.sh/hook-weight" not in cpod["metadata"]["annotations"]
    assert cpod["spec"]["serviceAccountName"] == b["name"] + "-bootstrap-runner" and cpod["spec"]["activeDeadlineSeconds"] == 1800
    cphases = cpod["spec"]["initContainers"] + cpod["spec"]["containers"]
    assert [p["name"] for p in cphases] == ["produce", "schema", "prepare", "retire", "continue"]
    assert [p["command"] for p in cphases] == [["/asservat", c] for c in ["initial-bootstrap", "initial-bootstrap-schema", "initial-bootstrap-prepare", "initial-bootstrap-retire", "installer-continue"]]
    assert len(cpod["spec"]["initContainers"]) == 4 and len(cpod["spec"]["containers"]) == 1
    cmounts = {p["name"]: p["volumeMounts"] for p in cphases}
    for phase in ["produce", "schema", "prepare", "retire"]:
        assert cmounts[phase] == mounts[phase], "joining continuation broadened an earlier credential compartment"
    assert cmounts["continue"] == [{"name": "scratch", "mountPath": "/run/asservat/initial-preparer", "subPath": "projection/preparer", "readOnly": True}, {"name": "continuation-input", "mountPath": "/run/asservat/installer-continue", "readOnly": True}]
    cvolumes = {v["name"]: v for v in cpod["spec"]["volumes"]}
    assert sum("emptyDir" in v for v in cvolumes.values()) == 1 and cvolumes["scratch"] == volumes["scratch"]
    continuation_sources = cvolumes["continuation-input"]["projected"]["sources"]
    assert continuation_sources[0]["configMap"]["name"] == cinput["metadata"]["name"]
    assert continuation_sources[1] == {"serviceAccountToken": {"path": "administrator-token", "expirationSeconds": 600}}
    assert continuation_sources[2] == {"secret": {"name": "operator-producer", "optional": False, "items": [{"key": "postgres-administrator.json", "path": "postgres-administrator.json"}]}}
    cpublic, = [r for r in cdocs if "runner.json" in r.get("data", {})]
    cref = json.loads(cpublic["data"]["runner.json"])
    assert cref["continuationDigest"] == hashlib.sha256(cinput["data"]["continuation.json"].encode()).hexdigest()
    assert cinput["metadata"]["name"] == b["name"] + "-continuation." + cref["continuationDigest"][:32]
    cdigest = hashlib.sha256((cpublic["data"]["bootstrap.json"] + "\n" + cpublic["data"]["runner.json"]).encode()).hexdigest()
    assert cpod["metadata"]["annotations"]["asservat.io/bootstrap-input"] == cdigest and cdigest != digest
    assert "token" not in cinput["data"]["continuation.json"].lower()
    crole, = [r for r in cdocs if r["kind"] == "ClusterRole" and r["metadata"]["name"].endswith("-bootstrap-continuation")]
    # ADR-204 worker dispatch and ADR-196 operator maintenance retain exact
    # resource/verb additions, never a blanket administrative wildcard.
    jobs, = [rule for rule in crole["rules"] if "jobs" in rule["resources"]]
    assert jobs == {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get", "create", "delete"]}
    binding_delete, = [rule for rule in crole["rules"] if "accessbindings" in rule["resources"] and "delete" in rule["verbs"]]
    assert binding_delete == {"apiGroups": ["asservat.io"], "resources": ["accessbindings"], "verbs": ["delete"]}
    pool_update, = [rule for rule in crole["rules"] if "evidencestoragepools" in rule["resources"] and "update" in rule["verbs"]]
    assert pool_update == {"apiGroups": ["asservat.io"], "resources": ["evidencestoragepools"], "verbs": ["update"]}
    cverbs = {v for rule in crole["rules"] if rule is not jobs and rule is not binding_delete for v in rule["verbs"]}
    assert "*" not in json.dumps(crole["rules"]) and not cverbs & {"escalate", "bind", "impersonate", "delete", "patch"}
    cbinding, = [r for r in cdocs if r["kind"] == "ClusterRoleBinding" and r["roleRef"]["name"] == crole["metadata"]["name"]]
    assert cbinding["subjects"] == [{"kind": "ServiceAccount", "namespace": "trusted-bootstrap", "name": b["name"] + "-bootstrap-runner"}]
    assert "public" not in json.loads(cinput["data"]["continuation.json"])
    public = copy.deepcopy(continued)
    public["bootstrap"]["continuation"]["public"].update(origin="https://asservat.example", issuer="https://id.example/realms/org", clientID="console",
                                                         clients=[{"id": "console", "kind": "human"}], eligibleGroups=["stable-group-id"])
    pdocs = render(public)
    pinput, = [r for r in pdocs if "continuation.json" in r.get("data", {})]
    settings = json.loads(pinput["data"]["continuation.json"])["public"]
    assert settings["clients"] == [{"id": "console", "kind": "human", "classQualified": True}] and settings["eligibleGroups"] == ["stable-group-id"]
    assert settings["origin"] == "https://asservat.example" and settings["groupMaxAgeSeconds"] == 300
    for field in ["workerProvider", "ownerProvider"]:
        bad = copy.deepcopy(continued)
        bad["bootstrap"]["continuation"][field]["authMount"] = ""
        render(bad, ok=False)

    for chain, replacement in [(["mode"], "cluster"), (["runtime", "enabled"], True),
                                (["bootstrap", "image"], "registry.example/asservat:latest"),
                                (["bootstrap", "secrets", "schema"], ""),
                                (["bootstrap", "providerToken"], "must-not-enter-release")]:
        bad = copy.deepcopy(values)
        at = bad
        for key in chain[:-1]:
            at = at[key]
        at[chain[-1]] = replacement
        render(bad, ok=False)
    render(values, ok=False, namespace="asservat-runtime")
    render(values, ok=False, namespace="default")
    bad = copy.deepcopy(values)
    bad["bootstrap"]["image"] = "registry.example/asservat:latest"
    render(bad, ok=False, extra=["--skip-schema-validation"])


def check_cluster(directory):
    # ADR-193 step 6: the regional installer hook, rendered statically.
    path = Path(directory) / "cluster-values.yaml"
    offer = json.dumps({"format": "asservat-regional-offer/v1", "installationID": "10000000-0000-4000-8000-000000000001"})
    base = {"mode": "cluster", "cluster": {"enabled": True, "namespace": "asservat-connector", "image": "registry.example/asservat@sha256:" + "a" * 64,
                                           "registrySecret": "operator-pull", "offer": offer, "bootstrapSecret": "operator-bootstrap"}}

    def render(v, ok=True, namespace="asservat-region"):
        path.write_text(yaml.safe_dump(v))
        args = ["template", "asservat", str(CHART), "--namespace", namespace, "--kube-version", "1.37.0", "-f", str(path)]
        result = run(args, ok=ok)
        return result if not ok else [r for r in yaml.safe_load_all(result) if r]

    docs = render(base)
    kinds = sorted(r["kind"] for r in docs)
    assert kinds == ["ClusterRole", "ClusterRoleBinding", "ConfigMap", "ConfigMap", "Job", "ServiceAccount"], kinds
    job = next(r for r in docs if r["kind"] == "Job")
    assert job["metadata"]["annotations"]["helm.sh/hook"] == "post-install,post-upgrade"
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    assert container["command"][:3] == ["/asservat", "installer-cluster", "--in-cluster"] and container["command"][-1] == "asservat-connector"
    assert container["securityContext"] == {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
    assert pod["securityContext"]["runAsNonRoot"] is True and pod["securityContext"]["fsGroup"] == 65532 and pod["imagePullSecrets"] == [{"name": "operator-pull"}]
    sources = pod["volumes"][0]["projected"]["sources"]
    assert sources[1]["secret"] == {"name": "operator-bootstrap", "items": [{"key": "bootstrap.json", "path": "bootstrap.json"}]}
    offer_map = next(r for r in docs if r["kind"] == "ConfigMap" and "regional-offer.json" in r.get("data", {}))
    assert offer_map["immutable"] is True and json.loads(offer_map["data"]["regional-offer.json"])["format"] == "asservat-regional-offer/v1"
    assert not any(r["kind"] == "Secret" for r in docs), "the bootstrap record must stay an operator Secret"
    role = next(r for r in docs if r["kind"] == "ClusterRole")
    verbs = {v for rule in role["rules"] for v in rule["verbs"]}
    assert "*" not in json.dumps(role["rules"]) and not verbs & {"delete", "patch", "escalate", "bind", "impersonate", "deletecollection"}
    for change in [{"mode": "hub"}, {"cluster": {"image": "registry.example/asservat:latest"}}, {"cluster": {"bootstrapSecret": ""}},
                   {"cluster": {"offer": json.dumps({"format": "other"})}}, {"cluster": {"namespace": "kube-system"}}]:
        v = json.loads(json.dumps(base))
        for key, value in change.items():
            if isinstance(value, dict):
                v[key].update(value)
            else:
                v[key] = value
        render(v, ok=False)
    render(base, ok=False, namespace="asservat-connector")
    # ADR-196 decision 7: an executor offer requires the evidence Secret,
    # which the hook projects and passes; a stray evidence Secret is refused.
    executor = json.loads(json.dumps(base))
    executor["cluster"]["offer"] = json.dumps({"format": "asservat-regional-offer/v1", "installationID": "10000000-0000-4000-8000-000000000001",
                                               "owners": {}, "keyService": {}, "workKey": {}, "evidenceStore": {}})
    render(executor, ok=False)
    executor["cluster"]["evidenceSecret"] = "operator-evidence"
    pod = next(r for r in render(executor) if r["kind"] == "Job")["spec"]["template"]["spec"]
    assert pod["containers"][0]["command"][-2:] == ["--evidence-credential", "/run/asservat/cluster/evidence-storage.json"]
    assert pod["volumes"][0]["projected"]["sources"][2]["secret"] == {"name": "operator-evidence", "items": [{"key": "evidence-storage.json", "path": "evidence-storage.json"}]}
    stray = json.loads(json.dumps(base))
    stray["cluster"]["evidenceSecret"] = "operator-evidence"
    render(stray, ok=False)


def main():
    schema = json.loads((CHART / "values.schema.json").read_text())
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(yaml.safe_load((CHART / "values.yaml").read_text()))
    metadata = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert not metadata.get("dependencies"), "foundation must not install dependency charts"
    expected = {p.name: yaml.safe_load(p.read_text()) for p in (CHART / "crds").glob("*.yaml")}
    # ADR-228 adds the hub-held DebugPolicy CRD (structural accepted subset).
    assert len(expected) == 7, "review newly added installation resources"
    for mode in ["hub", "cluster", "combined"]:
        run(["lint", "--strict", str(CHART), "--set", "mode=" + mode])
        args = ["template", "asservat", str(CHART), "--namespace", "asservat-system", "--include-crds", "--kube-version", "1.35.0", "--set", "mode=" + mode]
        output = run(args)
        assert output == run(args), "render depends on ambient state or randomness"
        resources = list(yaml.safe_load_all(output))
        crds = [r for r in resources if r["kind"] == "CustomResourceDefinition"]
        assert sorted(crds, key=lambda r: r["metadata"]["name"]) == sorted(expected.values(), key=lambda r: r["metadata"]["name"])
        ordinary = [r for r in resources if r["kind"] != "CustomResourceDefinition"]
        assert len(ordinary) == 1 and ordinary[0]["kind"] == "ConfigMap", "unexpected runtime/authority installation"
        assert ordinary[0]["data"]["runtimeAvailable"] == "false"
        assert ordinary[0]["data"]["mode"] == mode
        assert ordinary[0]["metadata"]["namespace"] == "asservat-system"
    for value in ["runtime.enabled=true", "mode=cluser", "password=must-not-be-accepted", "runtime.image=placeholder", "runtime.enabled=1"]:
        run(["template", "asservat", str(CHART), "--set", value], ok=False)
    msg = run(["template", "asservat", str(CHART), "--skip-schema-validation", "--set", "runtime.enabled=true"], ok=False)
    assert "configuration foundations only" in msg, "schema bypass enabled unavailable runtime"
    run(["template", "asservat", str(CHART), "--kube-version", "1.34.9"], ok=False)
    long_name = "a" * 53
    doc = yaml.safe_load(run(["template", long_name, str(CHART)]))
    assert len(doc["metadata"]["name"]) <= 63
    cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="helm-check-", dir=cache) as directory:
        check_bootstrap(directory)
        check_cluster(directory)
        run(["package", str(CHART), "--destination", directory])
        archive, = Path(directory).glob("*.tgz")
        with tarfile.open(archive) as bundle:
            members = set(bundle.getnames())
            assert {"asservat/Chart.yaml", "asservat/values.schema.json", "asservat/README.md"} <= members
            for name, content in expected.items():
                assert yaml.safe_load(bundle.extractfile("asservat/crds/" + name).read()) == content
        run(["lint", "--strict", str(archive)])
        assert run(["template", "asservat", str(archive), "--include-crds"]) == run(["template", "asservat", str(CHART), "--include-crds"])
    print("Helm schema/render/package checks passed: 3 foundation modes, 7 canonical CRDs, fixed bootstrap hook/compartments/revisions, the regional installer hook, invalid values and unavailable runtime rejected.")
    print(run(["version", "--short"]).strip())


if __name__ == "__main__":
    main()
