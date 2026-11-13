#!/usr/bin/env python3
"""Offline render checks of the Helm-native hub-worker templates."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

import yaml

spec = importlib.util.spec_from_file_location("helm_checks", Path(__file__).with_name("check-helm.py"))
helm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helm)

IMAGE = {"repository": "registry.example/asservat", "digest": "sha256:" + "a" * 64}
CONFIG_KEYS = {"format", "namespace", "serviceAccount", "fleetSource", "ownerSource", "leaderLease", "postgres", "auditStore", "keyService", "provider"}
CLUSTER_ID = "10000000-0000-4000-8000-000000000001"


def context_public():
    return json.loads((helm.ROOT / "internal/bootstrap/testdata/helm_context_public.json").read_text())


class HubWorkerChart(unittest.TestCase):
    def setUp(self):
        cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
        cache.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="helm-hub-worker-", dir=cache)
        self.addCleanup(self.directory.cleanup)
        self.external = {"image": IMAGE, "hub": {"hub-worker": {"enabled": True}}, "services": {
            "postgres": {"provider": "external", "external": {"host": "pg.example", "port": 5433, "database": "evidence", "rootsPEM": "PG-CA"}},
            "objectStore": {"provider": "external", "external": {"endpoint": "https://s3.example", "region": "eu-1", "bucket": "audit", "rootsPEM": "S3-CA"}},
            "keyService": {"provider": "external", "external": {"endpoint": "https://bao.example", "rootsPEM": "BAO-CA"}}}}
        # Bundled providers are still coupled to bootstrap.enabled in this chart.
        self.bundled = {"image": IMAGE, "hub": {"hub-worker": {"enabled": True}},
                        "bootstrap": {"enabled": True, "targetNamespace": "asservat-runtime", "image": "registry.example/asservat@sha256:" + "a" * 64,
                                      "fleet": {"issuer": "https://id.example/realms/org", "clients": ["console"], "subjects": [{"id": "installer", "kind": "human"}]}},
                        "services": {"postgres": {"provider": "bundled", "bundled": {"image": "registry.example/postgres@sha256:" + "b" * 64}},
                                     "objectStore": {"provider": "seaweedfs"}, "keyService": {"provider": "openbao"}},
                        "retention": context_public()["retentionBaseline"]}

    def render(self, values, *, ok=True, namespace="asservat-system"):
        path = Path(self.directory.name) / "values.yaml"
        path.write_text(yaml.safe_dump(values))
        out = helm.run(["template", "asservat", str(helm.CHART), "--namespace", namespace, "--kube-version", "1.37.0", "-f", str(path)], ok=ok)
        return [d for d in yaml.safe_load_all(out) if d] if ok else out

    def worker(self, docs):
        return {d["kind"]: d for d in docs if d["metadata"].get("labels", {}).get("app.kubernetes.io/component") == "hub-worker" and d["kind"] != "RoleBinding" and d["kind"] != "ClusterRoleBinding"}

    def test_bundled_renders_worker_projection_and_retention(self):
        docs = self.render(self.bundled)
        w = self.worker(docs)
        self.assertEqual(set(w), {"ServiceAccount", "Role", "ClusterRole", "ConfigMap", "Deployment"})
        self.assertEqual(sum(d["kind"] in ("RoleBinding", "ClusterRoleBinding") and d["metadata"]["name"].endswith("asservat-hub-worker") for d in docs), 2)
        self.assertFalse(w["ServiceAccount"]["automountServiceAccountToken"])
        config = json.loads(w["ConfigMap"]["data"]["config.json"])
        self.assertEqual(set(config), CONFIG_KEYS)
        self.assertEqual(config["format"], "asservat-hub-worker-config/v1")
        self.assertEqual(config["postgres"], {"host": "asservat-postgres.asservat-system.svc", "port": 5432, "database": "asservat"})
        self.assertEqual(config["auditStore"], {"endpoint": "https://asservat-objectstore.asservat-system.svc:8333", "region": "us-east-1", "bucket": "asservat-audit"})
        self.assertEqual(config["keyService"], {"endpoint": "https://asservat-openbao.asservat-system.svc:8200", "auditMount": "asservat-audit", "auditKey": "audit"})
        self.assertEqual(config["provider"], {"authMount": "asservat-configuration", "audience": "asservat-hub-worker",
                                              "roles": {"auditWrap": "asservat-hub-worker-audit-wrap", "auditUnwrap": "asservat-hub-worker-audit-unwrap"}})
        self.assertEqual((config["fleetSource"], config["ownerSource"], config["leaderLease"]), ("asservat-fleet", "asservat-owner-source", "asservat-hub-worker-leader"))
        pod = w["Deployment"]["spec"]["template"]["spec"]
        self.assertIn("checksum/config", w["Deployment"]["spec"]["template"]["metadata"]["annotations"])
        self.assertEqual(pod["containers"][0]["command"], ["/asservat", "hub-worker"])
        self.assertEqual([c["name"] for c in pod["initContainers"]], ["wait-schema"])
        self.assertFalse(pod["automountServiceAccountToken"])
        inputs, ids = pod["volumes"]
        self.assertEqual(ids["secret"]["secretName"], "asservat-ids")
        self.assertEqual(inputs["projected"]["defaultMode"], 0o440)
        paths, tokens, secrets = set(), {}, {}
        for s in inputs["projected"]["sources"]:
            kind, = s
            for item in s[kind].get("items", []):
                paths.add(item["path"])
            if kind == "serviceAccountToken":
                tokens[s[kind]["path"]] = s[kind].get("audience")
            if kind == "secret":
                secrets[s[kind]["name"]] = s[kind].get("items")
        self.assertEqual(paths, {"config.json", "kube-ca.crt", "audit-storage.json", "roots/postgres.crt", "roots/audit-store.crt", "roots/key-service.crt"})
        self.assertEqual(tokens, {"kube.token": None, "provider.token": "asservat-hub-worker"})
        self.assertIsNone(secrets["asservat-sql-hub-worker"])
        self.assertEqual(set(secrets), {"asservat-sql-hub-worker", "asservat-s3-hub-worker-audit", "asservat-postgres-state", "asservat-objectstore-state", "asservat-openbao-state"})
        retention, = [d for d in docs if d["kind"] == "EvidenceRetentionPolicy"]
        self.assertEqual(retention["metadata"]["name"], "asservat-baseline")
        self.assertEqual(retention["spec"]["legalExceptions"], "disabled")
        self.assertEqual(retention["spec"]["purposeRef"], self.bundled["retention"]["purposeRef"])
        self.assertFalse(any(d["kind"] in ("EvidenceStoragePool", "EvidenceBudgetPolicy") for d in docs))
        base = copy.deepcopy(self.bundled)
        base["hub"]["hub-worker"]["enabled"] = False
        added = {(d["kind"], d["metadata"]["name"]) for d in docs} - {(d["kind"], d["metadata"]["name"]) for d in self.render(base)}
        self.assertFalse(any(k.startswith("ValidatingAdmissionPolicy") for k, _ in added), added)
        self.assertEqual(len(added), 7, added)

    def test_rbac_reads_only(self):
        w = self.worker(self.render(self.external))
        verbs = {v for r in w["Role"]["rules"] + w["ClusterRole"]["rules"] for v in r["verbs"]}
        self.assertEqual(verbs, {"get", "list", "watch", "create", "update"})
        for rule in w["Role"]["rules"] + w["ClusterRole"]["rules"]:
            if {"create", "update"} & set(rule["verbs"]):
                self.assertEqual(rule["apiGroups"], ["coordination.k8s.io"], rule)
            self.assertNotIn("secrets", rule["resources"])
        self.assertEqual(w["ClusterRole"]["rules"], [{"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get", "list", "watch"]}])

    def test_external_providers_and_roots(self):
        w = self.worker(self.render(self.external))
        config = json.loads(w["ConfigMap"]["data"]["config.json"])
        self.assertEqual(config["postgres"], {"host": "pg.example", "port": 5433, "database": "evidence"})
        self.assertEqual(config["auditStore"], {"endpoint": "https://s3.example", "region": "eu-1", "bucket": "audit"})
        self.assertEqual(config["keyService"]["endpoint"], "https://bao.example")
        self.assertEqual(w["ConfigMap"]["data"]["roots-postgres.crt"], "PG-CA")
        items = w["Deployment"]["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"][0]["configMap"]["items"]
        self.assertEqual({i["path"] for i in items}, {"config.json", "roots/postgres.crt", "roots/audit-store.crt", "roots/key-service.crt"})
        missing = copy.deepcopy(self.external)
        missing["services"]["postgres"]["external"]["rootsPEM"] = ""
        self.assertIn("rootsPEM is required", self.render(missing, ok=False))

    def test_capacity_objects_only_when_configured(self):
        values = copy.deepcopy(self.bundled)
        capacity = context_public()["capacity"]
        capacity["policySpec"]["scope"]["clusterID"] = CLUSTER_ID
        values["capacity"] = capacity
        docs = self.render(values)
        pool, = [d for d in docs if d["kind"] == "EvidenceStoragePool"]
        policy, = [d for d in docs if d["kind"] == "EvidenceBudgetPolicy"]
        self.assertEqual((pool["metadata"]["name"], policy["metadata"]["name"]), (capacity["pool"], capacity["policy"]))
        self.assertEqual(pool["spec"], capacity["poolSpec"])
        self.assertEqual(policy["spec"], capacity["policySpec"])
        self.assertNotIn("annotations", pool["metadata"])
        tokens = {s["serviceAccountToken"]["path"]: s["serviceAccountToken"].get("audience") for s in self.worker(docs)["Deployment"]["spec"]["template"]["spec"]["volumes"][0]["projected"]["sources"] if "serviceAccountToken" in s}
        self.assertEqual(tokens["cluster-observation.token"], "asservat-cluster-observation")
        # An absent clusterID scopes the policy to the hub's own cluster.
        del capacity["policySpec"]["scope"]["clusterID"]
        policy, = [d for d in self.render(values) if d["kind"] == "EvidenceBudgetPolicy"]
        self.assertNotIn("clusterID", policy["spec"]["scope"])

    def test_not_rendered_by_default_or_for_cluster_mode(self):
        values = copy.deepcopy(self.external)
        values["hub"]["hub-worker"]["enabled"] = False
        self.assertFalse(self.worker(self.render(values)))
        values = copy.deepcopy(self.external)
        values["mode"] = "cluster"
        self.assertFalse(self.worker(self.render(values)))


if __name__ == "__main__":
    unittest.main()
