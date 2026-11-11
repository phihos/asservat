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


def check_context_public(public, render):
    # Explicit synthetic shape exercises packaging only. These values are not
    # a usable backend qualification or an operator capacity recommendation.
    additions = json.loads((ROOT / "internal/bootstrap/testdata/helm_context_public.json").read_text())
    capacity = additions["capacity"]
    configured = copy.deepcopy(public)
    configured["bootstrap"]["continuation"]["public"].update(additions)
    docs = render(configured)
    projection, = [r for r in docs if "continuation.json" in r.get("data", {})]
    actual = json.loads(projection["data"]["continuation.json"])["public"]
    expected = copy.deepcopy(additions)
    expected["capacity"]["policySpec"]["scope"].setdefault("clusterID", "")
    for key, value in expected.items():
        assert actual[key] == value, "public context installer field was lost or rewritten: " + key
    assert not any(r["kind"] in ["Deployment", "DaemonSet", "Secret"] for r in docs), "forwarding configuration added another runtime or private Helm payload"
    for field in additions:
        bad = copy.deepcopy(public)
        bad["bootstrap"]["continuation"]["public"] = {"origin": "", field: additions[field]}
        render(bad, ok=False)
    oversized = copy.deepcopy(configured)
    oversized_public = oversized["bootstrap"]["continuation"]["public"]
    oversized_public["promotion"]["providerRootsPEM"] = "P" * 32768
    oversized_public["federation"]["connectorIssuerRootsPEM"] = "P" * 32768
    assert "complete continuation public input exceeds 64 KiB" in render(oversized, ok=False)
    for field, value in [("capacity", {**capacity, "password": "forbidden"}),
                         ("promotion", {**additions["promotion"], "clientSecret": "forbidden"}),
                         ("federation", {**additions["federation"], "token": "forbidden"}),
                         ("retentionBaseline", {**additions["retentionBaseline"], "unknown": True})]:
        bad = copy.deepcopy(configured)
        bad["bootstrap"]["continuation"]["public"][field] = value
        render(bad, ok=False)
    # The ticket's original purge must still back its entire promised ordinary
    # admission period. This is checked during Helm rendering, before mutation.
    boundary = copy.deepcopy(configured)
    trial_public = boundary["bootstrap"]["continuation"]["public"]
    connector, backup = trial_public["federation"]["connector"], trial_public["capacity"]["backup"]
    connector["retainedSeconds"] = (connector["validSeconds"] + 2 * backup["horizonSeconds"]
                                    + 3 * backup["cleanupBudgetSeconds"] + backup["proofWindowSeconds"] + 60)
    render(boundary)
    connector["retainedSeconds"] -= 1
    assert "federation.connector.retainedSeconds must cover" in render(boundary, ok=False)
    connector["retainedSeconds"] += 1
    connector["validSeconds"] += 1
    assert "federation.connector.retainedSeconds must cover" in render(boundary, ok=False)
    preprovided = copy.deepcopy(configured)
    preprovided_capacity = preprovided["bootstrap"]["continuation"]["public"]["capacity"]
    preprovided_capacity.pop("poolSpec", None)
    preprovided_capacity.pop("policySpec", None)
    preprovided_docs = render(preprovided)
    preprovided_input, = [r for r in preprovided_docs if "continuation.json" in r.get("data", {})]
    assert "poolSpec" not in json.loads(preprovided_input["data"]["continuation.json"])["public"]["capacity"]
    for missing in ["poolSpec", "policySpec"]:
        bad = copy.deepcopy(configured)
        del bad["bootstrap"]["continuation"]["public"]["capacity"][missing]
        render(bad, ok=False)
    for section in ["poolSpec", "policySpec"]:
        bad = copy.deepcopy(configured)
        bad["bootstrap"]["continuation"]["public"]["capacity"][section]["metadata"] = {"uid": "forbidden"}
        render(bad, ok=False)
    bad = copy.deepcopy(configured)
    del bad["bootstrap"]["continuation"]["public"]["capacity"]
    render(bad, ok=False)
    return configured, projection


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
    assert "administrators" not in public_input, "omission changed existing runner-only input"
    admin_values = copy.deepcopy(values)
    actors = [{"kind": "User", "name": "operator@example.org"}, {"kind": "Group", "name": "platform-admins"}]
    admin_values["bootstrap"]["administrators"] = actors
    admin_docs = render(admin_values)
    admin_input, = [r for r in admin_docs if "bootstrap.json" in r.get("data", {})]
    assert json.loads(admin_input["data"]["bootstrap.json"])["administrators"] == actors
    assert admin_input["metadata"]["name"] != public["metadata"]["name"], "administrator scope is not bound to immutable input"
    for invalid in [[], [actors[0], actors[0]], [{"kind": "ServiceAccount", "name": "unsupported"}], [{"kind": "User", "name": ""}], [{"kind": "User", "name": "x" * 257}], [{"kind": "User", "name": str(i)} for i in range(32)]]:
        bad = copy.deepcopy(values)
        bad["bootstrap"]["administrators"] = invalid
        render(bad, ok=False)

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
    # ADR-247: the owner workload role it creates watches workloads, so the
    # continuation must hold exactly that watch (RBAC escalation prevention).
    workload_watch, = [rule for rule in crole["rules"] if "statefulsets" in rule["resources"] and "watch" in rule["verbs"]]
    assert workload_watch == {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets"], "verbs": ["watch"]}
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
    assert "permissionDelegations" not in settings, "empty delegations changed existing installer identities"
    assert "approvals" not in settings, "absent approval settings changed existing installer identities"
    assert "captureHistory" not in settings, "absent history limits changed existing installer identities"
    assert "processors" not in settings, "absent organization declarations changed existing installer identities"
    check_context_public(public, render)
    organization = {"id": "org-1", "name": "Declared organization", "activities": ["Evidence storage"], "regions": []}
    for declarations in ([], [organization]):
        declared = copy.deepcopy(public)
        declared["bootstrap"]["continuation"]["public"]["processors"] = declarations
        declared_docs = render(declared)
        declared_input, = [r for r in declared_docs if "continuation.json" in r.get("data", {})]
        assert json.loads(declared_input["data"]["continuation.json"])["public"]["processors"] == declarations
    for declarations in (None, [organization, organization], [dict(organization, activities=[])],
                         [dict(organization, regions=None)], [dict(organization, endpoint="https://outside.invalid")],
                         [dict(organization, name="n" * 161)], [dict(organization, activities=["a" * 129])],
                         [dict(organization, regions=["r" * 129])], [dict(organization, id=str(n)) for n in range(17)]):
        bad = copy.deepcopy(public)
        bad["bootstrap"]["continuation"]["public"]["processors"] = declarations
        render(bad, ok=False)
    no_public = copy.deepcopy(continued)
    no_public["bootstrap"]["continuation"]["public"]["processors"] = []
    render(no_public, ok=False)
    bounded = copy.deepcopy(public)
    bounded["bootstrap"]["continuation"]["public"]["captureHistory"] = {"perSelector": 200, "perInstallation": 10000}
    bdocs = render(bounded)
    binput, = [r for r in bdocs if "continuation.json" in r.get("data", {})]
    assert json.loads(binput["data"]["continuation.json"])["public"]["captureHistory"] == {"perSelector": 200, "perInstallation": 10000}
    for limits in ({"perSelector": 0,"perInstallation":1000},{"perSelector":1001,"perInstallation":1000},{"perSelector":1,"perInstallation":100001},{"perSelector":1}):
        bad=copy.deepcopy(public);bad["bootstrap"]["continuation"]["public"]["captureHistory"]=limits;render(bad,ok=False)
    approved = copy.deepcopy(public)
    approvals = {"requireRecordingApproval": True, "stepUp": {"acrValues": ["2"], "maxAgeSeconds": 300}}
    approved["bootstrap"]["continuation"]["public"]["approvals"] = approvals
    adocs = render(approved)
    ainput, = [r for r in adocs if "continuation.json" in r.get("data", {})]
    assert json.loads(ainput["data"]["continuation.json"])["public"]["approvals"] == approvals
    assert ainput["data"]["continuation.json"] != pinput["data"]["continuation.json"], "approval policy is not bound to installer input"
    delegated = copy.deepcopy(public)
    envelope = {"writers": [{"kind": "Group", "name": "payments-admins"}],
                "clusterID": "10000000-0000-4000-8000-000000000001",
                "namespace": {"name": "payments", "uid": "namespace-uid"},
                "workloads": [{"kind": "Deployment", "name": "api", "uid": "workload-uid"}],
                "roles": ["evidence-reader"], "issuers": ["https://id.example/realms/org"],
                "previewers": [{"issuer": "https://id.example/realms/org", "kind": "Group", "id": "payments-leads"}]}
    delegated["bootstrap"]["continuation"]["public"]["permissionDelegations"] = [envelope]
    ddocs = render(delegated)
    dinput, = [r for r in ddocs if "continuation.json" in r.get("data", {})]
    assert json.loads(dinput["data"]["continuation.json"])["public"]["permissionDelegations"] == [envelope]
    # Delegation is protected installer input, so changing it must change
    # both immutable continuation identity and the original runner digest.
    assert dinput["metadata"]["name"] != pinput["metadata"]["name"]
    dpod, = [r for r in ddocs if r["kind"] == "Pod"]
    ppod, = [r for r in pdocs if r["kind"] == "Pod"]
    assert dpod["metadata"]["annotations"]["asservat.io/bootstrap-input"] != ppod["metadata"]["annotations"]["asservat.io/bootstrap-input"]
    assert [r for r in ddocs if r["kind"] in ("ClusterRole", "ClusterRoleBinding")] == [r for r in pdocs if r["kind"] in ("ClusterRole", "ClusterRoleBinding")], "delegations broadened installer RBAC"
    namespace_wide = copy.deepcopy(delegated)
    namespace_wide["bootstrap"]["continuation"]["public"]["permissionDelegations"][0]["workloads"] = []
    ndocs = render(namespace_wide)
    ninput, = [r for r in ndocs if "continuation.json" in r.get("data", {})]
    assert json.loads(ninput["data"]["continuation.json"])["public"]["permissionDelegations"][0]["workloads"] == []
    for field, value in [("writers", []), ("writers", [{"kind": "ServiceAccount", "name": "controller"}]),
                         ("clusterID", "not-a-uuid"), ("clusterID", "00000000-0000-0000-0000-000000000000"),
                         ("namespace", {"name": "payments", "uid": ""}),
                         ("roles", ["permission-administrator"]), ("roles", ["evidence-reader", "evidence-reader"]),
                         ("issuers", []), ("previewers", []),
                         ("previewers", [{"issuer": "https://id.example", "kind": "Workload", "id": "lead"}]),
                         ("workloads", [{"kind": "Pod", "name": "api", "uid": "pod-uid"}]),
                         ("extraAuthority", True)]:
        bad = copy.deepcopy(delegated)
        bad["bootstrap"]["continuation"]["public"]["permissionDelegations"][0][field] = value
        render(bad, ok=False)
    no_public = copy.deepcopy(delegated)
    no_public["bootstrap"]["continuation"]["public"]["origin"] = ""
    assert "permissionDelegations requires public.origin" in render(no_public, ok=False)
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
    # ADR-241: the installer holds the log and metrics reads it grants the
    # connector (RBAC escalation check), read-only.
    assert {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]} in role["rules"]
    assert {"apiGroups": ["metrics.k8s.io"], "resources": ["pods"], "verbs": ["list"]} in role["rules"]
    assert {"apiGroups": ["asservat.io"], "resources": ["captureprofiles"], "verbs": ["get", "list"]} in role["rules"]
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
    assert pod["containers"][0]["command"][-2:] == ["--history-credential", "/run/asservat/cluster/history-storage.json"]
    assert pod["volumes"][0]["projected"]["sources"][2]["secret"] == {"name": "operator-evidence", "items": [{"key": "evidence-storage.json", "path": "evidence-storage.json"}, {"key": "history-storage.json", "path": "history-storage.json"}]}
    # ADR-231: the optional Alertmanager URL is passed to an executor's
    # installer only; without an executor offer it is refused.
    executor["cluster"]["alertmanager"] = "http://alertmanager-operated.monitoring.svc:9093"
    pod = next(r for r in render(executor) if r["kind"] == "Job")["spec"]["template"]["spec"]
    assert pod["containers"][0]["command"][-2:] == ["--alertmanager", "http://alertmanager-operated.monitoring.svc:9093"]
    executor["cluster"]["alertmanager"] = "http://user:secret@alertmanager:9093"
    render(executor, ok=False)
    # ADR-245: identity mappings reach an executor's installer as JSON and
    # let the installer grant SubjectAccessReview create; elsewhere refused.
    executor["cluster"]["alertmanager"] = ""
    mappings = [{"name": "company", "issuer": "https://id.example.invalid", "usernamePrefix": "oidc:", "groupsPrefix": "oidc:"}]
    executor["cluster"]["identityMappings"] = mappings
    rendered = render(executor)
    pod = next(r for r in rendered if r["kind"] == "Job")["spec"]["template"]["spec"]
    assert pod["containers"][0]["command"][-2] == "--identity-mappings" and json.loads(pod["containers"][0]["command"][-1]) == mappings
    role = next(r for r in rendered if r["kind"] == "ClusterRole")
    assert {"apiGroups": ["authorization.k8s.io"], "resources": ["subjectaccessreviews"], "verbs": ["create"]} in role["rules"]
    executor["cluster"]["identityMappings"] = [{"name": "Company", "issuer": "https://id.example.invalid", "usernamePrefix": ""}]
    render(executor, ok=False)
    executor["cluster"]["identityMappings"] = []
    role = next(r for r in render(executor) if r["kind"] == "ClusterRole")
    assert not any("subjectaccessreviews" in r["resources"] for r in role["rules"])
    stray = json.loads(json.dumps(base))
    stray["cluster"]["identityMappings"] = mappings
    render(stray, ok=False)
    # ADR-285: profile endpoint templates reach an executor's installer as
    # JSON and add no RBAC; a free URL or a non-executor is refused.
    endpoints = [{"name": "go-pprof-loopback", "kind": "template", "addressModes": ["targetLoopback"], "loopbackFamily": "ipv4", "minPort": 6060, "maxPort": 6060},
                 {"name": "payments-pprof", "kind": "profile", "addressMode": "podIP", "port": 6060, "namespaces": ["payments"]}]
    executor["cluster"]["profileEndpoints"] = endpoints
    rendered = render(executor)
    pod = next(r for r in rendered if r["kind"] == "Job")["spec"]["template"]["spec"]
    assert pod["containers"][0]["command"][-2] == "--profile-endpoints" and json.loads(pod["containers"][0]["command"][-1]) == endpoints
    role = next(r for r in rendered if r["kind"] == "ClusterRole")
    assert not any("secrets" in r["resources"] and "list" in r["verbs"] for r in role["rules"])
    # ADR-299: public TLS configuration uses the same flag and no new RBAC.
    # Rendering is not certificate validation or installed TLS qualification.
    tls = {"serverName": "localhost", "rootsPEM": "PUBLIC-CERTIFICATE-FIXTURE"}
    tls_endpoints = [{**endpoints[0], "tls": tls}]
    executor["cluster"]["profileEndpoints"] = tls_endpoints
    docs = render(executor)
    pod = next(r for r in docs if r["kind"] == "Job")["spec"]["template"]["spec"]
    assert pod["containers"][0]["command"][-2] == "--profile-endpoints"
    assert json.loads(pod["containers"][0]["command"][-1]) == tls_endpoints
    assert next(r for r in docs if r["kind"] == "ClusterRole")["rules"] == role["rules"]
    # ADR-302 public audiences use the existing private evidence input bundle.
    credential = {"audiences": [{"clusterID": "00000000-0000-4000-8000-000000000001",
                                "namespaceUID": "00000000-0000-4000-8000-000000000002",
                                "workloadKind": "Deployment", "workloadUID": "00000000-0000-4000-8000-000000000003"}]}
    auth_endpoints = [{**tls_endpoints[0], "credential": credential}]
    executor["cluster"]["profileEndpoints"] = auth_endpoints
    auth_docs = render(executor)
    auth_pod = next(r for r in auth_docs if r["kind"] == "Job")["spec"]["template"]["spec"]
    assert "--profile-authorization" in auth_pod["containers"][0]["command"]
    assert json.loads(auth_pod["containers"][0]["command"][-1]) == auth_endpoints
    auth_secret = [p["secret"] for p in auth_pod["volumes"][0]["projected"]["sources"] if "secret" in p]
    assert len(auth_secret) == 2
    assert auth_secret[-1]["name"] == executor["cluster"]["evidenceSecret"]
    assert {"key": "profile-authorization.json", "path": "profile-authorization.json"} in auth_secret[-1]["items"]
    assert next(r for r in auth_docs if r["kind"] == "ClusterRole")["rules"] == role["rules"]
    for bad in [{"audiences": []}, {**credential, "authorization": "must-not-be-values"},
                {"audiences": [{**credential["audiences"][0], "workloadKind": "ReplicaSet"}]}]:
        executor["cluster"]["profileEndpoints"] = [{**tls_endpoints[0], "credential": bad}]
        render(executor, ok=False)
    executor["cluster"]["profileEndpoints"] = [{**endpoints[0], "credential": credential}]
    render(executor, ok=False)
    for invalid in [{"serverName": "localhost"}, {"rootsPEM": "PUBLIC"},
                    {**tls, "insecureSkipVerify": True}, {**tls, "credential": "not-accepted"},
                    {**tls, "rootsPEM": "x" * 8193}, {**tls, "serverName": ""}]:
        executor["cluster"]["profileEndpoints"] = [{**endpoints[0], "tls": invalid}]
        render(executor, ok=False)
    executor["cluster"]["profileEndpoints"] = [{**endpoints[0], "url": "http://unapproved.invalid"}]
    render(executor, ok=False)
    executor["cluster"]["profileEndpoints"] = [{**endpoints[1], "minPort": 1}]
    render(executor, ok=False)
    executor["cluster"]["profileEndpoints"] = []
    stray = json.loads(json.dumps(base))
    stray["cluster"]["profileEndpoints"] = endpoints
    render(stray, ok=False)
    stray = json.loads(json.dumps(base))
    stray["cluster"]["evidenceSecret"] = "operator-evidence"
    render(stray, ok=False)
    stray = json.loads(json.dumps(base))
    stray["cluster"]["alertmanager"] = "http://alertmanager-operated.monitoring.svc:9093"
    render(stray, ok=False)


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
    combined = json.loads(json.dumps(base))
    combined["mode"] = "combined"
    render(combined)
    for change in [{"mode": "hub"}, {"collector": {"namespace": "kube-system"}}, {"collector": {"namespace": "default"}}, {"collector": {"namespace": "asservat-connector"}},
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
                v[key].update(value)
            else:
                v[key] = value
        render(v, ok=False)
    render(base, ok=False, namespace="asservat-collector")
    # ADR-246 decision 9: with this release's cluster installer and an empty
    # collector.connector, the installer provisions the connector's node
    # listener and publishes the values in the connector-nodes ConfigMap.
    # helm template cannot look it up, so only the namespace and account
    # render (the installer needs the namespace); a later upgrade renders the
    # DaemonSet. The installer gets the collector names and the reads it grants.
    offer = json.dumps({"format": "asservat-regional-offer/v1", "installationID": "10000000-0000-4000-8000-000000000001"})
    joint = json.loads(json.dumps(base))
    joint["cluster"] = {"enabled": True, "namespace": "asservat-connector", "image": "registry.example/asservat@sha256:" + "a" * 64, "offer": offer, "bootstrapSecret": "operator-bootstrap"}
    joint["collector"]["connector"] = {"endpoint": "", "serverName": "", "rootsPEM": ""}
    docs = render(joint)
    collector = [r for r in docs if r["metadata"].get("namespace") == "asservat-collector" or r["kind"] == "Namespace"]
    assert sorted(r["kind"] for r in collector) == ["Namespace", "ServiceAccount"], [r["kind"] for r in collector]
    command = next(r for r in docs if r["kind"] == "Job")["spec"]["template"]["spec"]["containers"][0]["command"]
    assert command[-4:] == ["--collector-namespace", "asservat-collector", "--collector-name", "asservat-node"], command
    rules = next(r for r in docs if r["kind"] == "ClusterRole")["rules"]
    for rule in [{"apiGroups": [""], "resources": ["services"], "verbs": ["get", "create"]}, {"apiGroups": [""], "resources": ["nodes"], "verbs": ["get"]},
                 {"apiGroups": ["apps"], "resources": ["daemonsets"], "verbs": ["get"]}]:
        assert rule in rules, rule
    without = json.loads(json.dumps(joint))
    without["collector"]["enabled"] = False
    rules = next(r for r in render(without) if r["kind"] == "ClusterRole")["rules"]
    # Without the collector there is no node read and no Service create; the
    # unconditional Service get is ADR-283's Kubernetes peer read.
    assert not any("nodes" in r["resources"] or "services" in r["resources"] and r["verbs"] != ["get"] for r in rules)
    assert {"apiGroups": [""], "resources": ["services"], "verbs": ["get"]} in rules
    # Explicit values still render the DaemonSet; partial values are refused.
    joint["collector"]["connector"] = base["collector"]["connector"]
    assert any(r["kind"] == "DaemonSet" for r in render(joint))
    joint["collector"]["connector"] = {"endpoint": "https://connector:8444", "serverName": "", "rootsPEM": ""}
    render(joint, ok=False)


def main():
    schema = json.loads((CHART / "values.schema.json").read_text())
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(yaml.safe_load((CHART / "values.yaml").read_text()))
    metadata = yaml.safe_load((CHART / "Chart.yaml").read_text())
    assert not metadata.get("dependencies"), "foundation must not install dependency charts"
    expected = {p.name: yaml.safe_load(p.read_text()) for p in (CHART / "crds").glob("*.yaml")}
    # ADR-228 adds the hub-held DebugPolicy CRD (structural accepted subset).
    # S-04 increment 11 adds the CaptureProfile catalog CRD (REQ-CPR-001).
    assert len(expected) == 8, "review newly added installation resources"
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
        check_collector(directory)
        run(["package", str(CHART), "--destination", directory])
        archive, = Path(directory).glob("*.tgz")
        with tarfile.open(archive) as bundle:
            members = set(bundle.getnames())
            assert {"asservat/Chart.yaml", "asservat/values.schema.json", "asservat/README.md"} <= members
            for name, content in expected.items():
                assert yaml.safe_load(bundle.extractfile("asservat/crds/" + name).read()) == content
        run(["lint", "--strict", str(archive)])
        assert run(["template", "asservat", str(archive), "--include-crds"]) == run(["template", "asservat", str(CHART), "--include-crds"])
    print("Helm schema/render/package checks passed: 3 foundation modes, 8 canonical CRDs, public context continuation/administrator inputs, fixed bootstrap hook/compartments/revisions, the regional installer hook, the guarded collector DaemonSet, invalid values and unavailable runtime rejected.")
    print(run(["version", "--short"]).strip())


if __name__ == "__main__":
    main()
