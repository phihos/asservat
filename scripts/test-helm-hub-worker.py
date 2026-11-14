#!/usr/bin/env python3
"""Offline render checks of the Helm-native hub-worker templates.

By default the hub-worker templates render from a scratch copy of the chart
that keeps only the helpers and the hub-worker, capacity, retention,
provider-roots and download-worker templates, so a component that is mid-edit
elsewhere in the chart does not mask these checks. ASSERVAT_HELM_FULL=1 renders
the whole chart with schema validation instead.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

spec = importlib.util.spec_from_file_location("helm_checks", Path(__file__).with_name("check-helm.py"))
helm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helm)

CONFIG_KEYS = {"format", "namespace", "serviceAccount", "fleetSource", "ownerSource", "leaderLease", "postgres", "auditStore", "keyService", "provider", "permission"}
KEEP = ("_", "hub-worker-", "hub-retention-baseline.yaml", "provider-roots.yaml", "download-worker.yaml")
FULL = os.environ.get("ASSERVAT_HELM_FULL") == "1"


def context_public():
    return json.loads((helm.ROOT / "internal/bootstrap/testdata/helm_context_public.json").read_text())


def sources(docs):
    """The hub-worker inputs volume: {path: source name}, tokens, whole Secrets."""
    pod = docs["Deployment"]["spec"]["template"]["spec"]
    inputs, = [v for v in pod["volumes"] if v["name"] == "inputs"]
    files, tokens, whole = {}, {}, []
    for s in inputs["projected"]["sources"]:
        kind, = s
        if kind == "serviceAccountToken":
            tokens[s[kind]["path"]] = s[kind].get("audience")
        elif "items" in s[kind]:
            for item in s[kind]["items"]:
                files[item["path"]] = (s[kind]["name"], item["key"])
        else:
            whole.append(s[kind]["name"])
    return files, tokens, whole


class HubWorkerChart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
        cache.mkdir(parents=True, exist_ok=True)
        cls.directory = tempfile.TemporaryDirectory(prefix="helm-hub-worker-", dir=cache)
        cls.chart = helm.CHART
        if not FULL:
            cls.chart = Path(cls.directory.name) / "asservat"
            shutil.copytree(helm.CHART, cls.chart)
            for f in (cls.chart / "templates").iterdir():
                if not f.name.startswith(KEEP):
                    f.unlink()

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.bundled = helm.bundled_values("combined")
        self.external = helm.hub_values()
        self.external["mode"] = "hub"
        for s in ("postgres", "objectStore", "keyService"):
            self.external["services"][s]["provider"] = "external"
        self.external["services"]["identity"] = {"provider": "external"}
        self.external["identity"] = {"issuer": "https://id.example/realms/org", "clientID": "console"}
        # The shared fixtures carry capacity for the hub-api's combined-mode
        # offer; these checks start without it.
        for v in (self.bundled, self.external):
            v.pop("capacity", None)

    def render(self, values, *, ok=True, namespace="asservat-system"):
        path = Path(self.directory.name) / "values.yaml"
        path.write_text(yaml.safe_dump(values))
        args = ["template", "asservat", str(self.chart), "--namespace", namespace, "--kube-version", "1.35.0", "-f", str(path)]
        if not FULL:
            args.append("--skip-schema-validation")
        out = helm.run(args, ok=ok)
        return [d for d in yaml.safe_load_all(out) if d] if ok else out

    def worker(self, docs):
        out = {}
        for d in docs:
            if d["metadata"].get("labels", {}).get("app.kubernetes.io/component") == "hub-worker" and d["kind"] not in ("RoleBinding", "ClusterRoleBinding"):
                out[d["kind"] if d["kind"] != "ConfigMap" else d["metadata"]["name"]] = d
        return out

    def config(self, w):
        return json.loads(w["asservat-hub-worker-config"]["data"]["config.json"])

    def test_bundled_combined_first_install(self):
        docs = self.render(self.bundled)
        w = self.worker(docs)
        self.assertEqual(set(w), {"ServiceAccount", "Role", "ClusterRole", "Deployment", "asservat-hub-worker-config", "asservat-fleet", "asservat-owner-source"})
        self.assertFalse(w["ServiceAccount"]["automountServiceAccountToken"])
        c = self.config(w)
        self.assertEqual(set(c), CONFIG_KEYS)
        self.assertEqual(c["postgres"], {"host": "asservat-postgres.asservat-system.svc", "port": 5432, "database": "asservat"})
        self.assertEqual(c["auditStore"], {"endpoint": "https://asservat-objectstore.asservat-system.svc:8333", "region": "us-east-1", "bucket": "asservat-audit"})
        # Mounts, audience and key names derive in Go; none is rendered.
        self.assertEqual(c["keyService"], {"endpoint": "https://asservat-openbao.asservat-system.svc:8200"})
        self.assertEqual(c["provider"], {"roles": {"auditWrap": "asservat-hub-worker-audit-wrap", "auditUnwrap": "asservat-hub-worker-audit-unwrap"}})
        p = c["permission"]
        self.assertEqual(p["statusUsers"], ["system:serviceaccount:asservat-system:asservat-hub-worker"])
        self.assertEqual(p["browser"], {"settings": "asservat-browser-settings"})
        self.assertEqual(p["identity"], {"settings": "asservat-identity-settings", "issuer": "https://login.example.org/realms/asservat"})
        self.assertEqual(p["workerConfiguration"], {"namespace": "asservat-downloads", "source": "asservat-worker-profile"})
        self.assertNotIn("contextDeletion", p)
        self.assertNotIn("retention", p)
        pod = w["Deployment"]["spec"]["template"]["spec"]
        self.assertEqual(pod["containers"][0]["command"], ["/asservat", "hub-worker"])
        wait, = pod["initContainers"]
        self.assertEqual(wait["command"], ["/asservat", "setup", "--wait-schema", "--config", "/run/asservat/hub-worker/config.json",
                                           "--credential", "/run/asservat/hub-worker/sql-configuration-fleet.json", "--ca", "/run/asservat/hub-worker/roots/postgres.crt"])
        files, tokens, whole = sources(w)
        self.assertEqual(files, {"config.json": ("asservat-hub-worker-config", "config.json"), "kube-ca.crt": ("kube-root-ca.crt", "ca.crt"),
                                 "audit-storage.json": ("asservat-s3-configuration-audit", "credentials.json"),
                                 "roots/postgres.crt": ("asservat-postgres-state", "ca.crt"), "roots/audit-store.crt": ("asservat-objectstore-state", "ca.crt"),
                                 "roots/key-service.crt": ("asservat-openbao-state", "ca.crt")})
        self.assertEqual(tokens, {"kube.token": None, "provider.token": "asservat-configuration-provider"})
        self.assertEqual(whole, ["asservat-sql-hub-worker"])
        self.assertEqual({v["name"] for v in pod["volumes"]}, {"inputs", "ids"})
        fleet = json.loads(w["asservat-fleet"]["data"]["fleet.json"])
        self.assertNotIn("installationID", fleet)
        self.assertNotIn("issuerEpoch", fleet)
        self.assertEqual((fleet["issuer"], fleet["clients"]), ("https://login.example.org/realms/asservat", ["asservat-console"]))
        owner = json.loads(w["asservat-owner-source"]["data"]["owner-pool.json"])
        self.assertEqual(owner, {"format": "asservat-hub-owner-source/v1", "revision": 1, "suspended": False, "service": "asservat-hub-api-owner",
                                 "deployment": "asservat-hub-api", "serviceAccount": "asservat-hub-api", "port": 9443, "nativePort": 9444,
                                 "nativeBootstrap": "owner-bootstrap/v1", "nativeCandidateLimit": 1024, "operationPort": 9448})
        self.assertFalse(any(d["kind"] in ("EvidenceStoragePool", "EvidenceBudgetPolicy", "EvidenceRetentionPolicy") for d in docs))
        self.decode(c)

    def decode(self, config):
        """The loader's own decode, completion and section checks."""
        path = Path(self.directory.name) / "rendered" / "config.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(config))
        tmp = Path(os.environ.get("TMPDIR") or Path.home() / ".cache/go-tmp")
        tmp.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, ASSERVAT_HUB_WORKER_CONFIG=str(path), TMPDIR=str(tmp))
        go = subprocess.run(["go", "test", "-count=1", "-run", "^TestHubWorkerConfigRendered$", "-v", "./internal/bootstrap"], cwd=helm.ROOT, env=env, text=True, capture_output=True, timeout=600)
        self.assertEqual(go.returncode, 0, go.stdout + go.stderr)
        self.assertIn("--- PASS: TestHubWorkerConfigRendered", go.stdout)

    def test_rbac_reads_only(self):
        w = self.worker(self.render(self.bundled))
        for rule in w["Role"]["rules"] + w["ClusterRole"]["rules"]:
            if {"create", "update"} & set(rule["verbs"]):
                self.assertEqual(rule["apiGroups"], ["coordination.k8s.io"], rule)
            self.assertNotIn("secrets", rule["resources"])
        named = {(tuple(r["resources"]), tuple(r.get("resourceNames", ()))) for r in w["Role"]["rules"]}
        self.assertIn((("services", "serviceaccounts"), ("asservat-hub-api-owner", "asservat-hub-api")), named)
        self.assertIn((("deployments",), ("asservat-hub-api",)), named)
        # ADR-329: the hub cluster's AccessBindings in every namespace.
        self.assertEqual(w["ClusterRole"]["rules"], [{"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get", "list", "watch"]},
                                                     {"apiGroups": ["asservat.io"], "resources": ["accessbindings"], "verbs": ["get", "list", "watch"]}])
        self.assertNotIn("accessbindings", [x for r in w["Role"]["rules"] for x in r["resources"]])

    def test_external_providers(self):
        w = self.worker(self.render(self.external))
        c = self.config(w)
        self.assertEqual(c["postgres"], {"host": "postgres.example", "port": 5432, "database": "asservat"})
        self.assertEqual(c["auditStore"], {"endpoint": "https://s3.example", "region": "r", "bucket": "audit"})
        self.assertEqual(c["permission"]["identity"]["issuer"], "https://id.example/realms/org")
        files, _, _ = sources(w)
        for path, key in (("roots/postgres.crt", "postgres.crt"), ("roots/audit-store.crt", "objectStore.crt"), ("roots/key-service.crt", "openBao.crt")):
            self.assertEqual(files[path], ("asservat-provider-roots", key))
        self.assertEqual(json.loads(w["asservat-fleet"]["data"]["fleet.json"])["clients"], ["console"])

    def test_capacity_cleanup_deletion_and_retention(self):
        values = copy.deepcopy(self.bundled)
        values["capacity"] = {"evidenceStorage": "8Gi", "workload": {"share": "256Mi"}}
        values["retention"] = context_public()["retentionBaseline"]
        docs = self.render(values)
        w = self.worker(docs)
        c = self.config(w)
        self.assertEqual(set(c), CONFIG_KEYS | {"capacity", "cleanup"})
        self.assertEqual(c["cleanup"], {})
        self.assertEqual(c["capacity"]["processingSource"], "asservat-processing-source")
        self.assertEqual((c["capacity"]["paths"], c["capacity"]["sharedQueries"]), ([], True))
        self.assertTrue(c["permission"]["retention"])
        self.assertEqual(c["permission"]["contextDeletion"]["evidenceStore"], dict(c["auditStore"], bucket="asservat-evidence"))
        self.assertEqual(set(c["provider"]["roles"]), {"auditWrap", "auditUnwrap", "cleanupWrap", "cleanupOpen", "cleanupVerify", "cleanupSign"})
        files, tokens, _ = sources(w)
        self.assertEqual(files["capture-account.key"], ("asservat-audit-mac", "accountKey"))
        self.assertEqual(files["cleanup-storage.json"], ("asservat-s3-operation-cleanup", "credentials.json"))
        self.assertEqual(files["verify-storage.json"], ("asservat-s3-operation-verify", "credentials.json"))
        self.assertEqual(files["evidence-delete-storage.json"], ("asservat-s3-evidence-delete", "credentials.json"))
        self.assertEqual(tokens["cluster-observation.token"], "asservat-cluster-observation")
        self.assertEqual((c["capacity"]["evidenceStorage"], c["capacity"]["revision"]), (values["capacity"]["evidenceStorage"], 1))
        self.assertFalse([d for d in docs if d["kind"] in ("EvidenceStoragePool", "EvidenceBudgetPolicy")])
        retention, = [d for d in docs if d["kind"] == "EvidenceRetentionPolicy"]
        self.assertEqual((retention["metadata"]["name"], retention["spec"]["legalExceptions"]), ("asservat-baseline", "disabled"))
        self.assertIn({"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}, w["ClusterRole"]["rules"])
        self.decode(c)

    def test_not_rendered_for_cluster_mode(self):
        values = copy.deepcopy(self.external)
        values["mode"] = "cluster"
        self.assertFalse(self.worker(self.render(values)))


if __name__ == "__main__":
    unittest.main()
