#!/usr/bin/env python3
"""Offline regional chart boundary; no Kubernetes, provider or runtime effects."""
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


class BundledRegionalChart(unittest.TestCase):
    def setUp(self):
        cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
        cache.mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix="helm-bundled-region-", dir=cache)
        self.addCleanup(self.directory.cleanup)
        self.base = {"mode": "cluster", "cluster": {"enabled": True, "namespace": "asservat-connector", "image": "registry.example/asservat@sha256:" + "a" * 64,
                      "bundledHub": "install", "bootstrapID": "10000000-0000-4000-8000-000000000001"}}

    def render(self, values, *, ok=True, extra=()):
        path = Path(self.directory.name) / "values.yaml"
        path.write_text(yaml.safe_dump(values))
        output = helm.run(["template", "region", str(helm.CHART), "--namespace", "trusted-bootstrap", "--kube-version", "1.37.0", "-f", str(path), *extra], ok=ok)
        return list(yaml.safe_load_all(output)) if ok else output

    def test_selected_uses_original_account_and_public_projection(self):
        docs = self.render(self.base)
        self.assertFalse(any(d["kind"] in ("ServiceAccount", "Secret", "Deployment", "StatefulSet", "Service") for d in docs))
        self.assertFalse(any("regional-offer.json" in d.get("data", {}) for d in docs))
        job, = [d for d in docs if d["kind"] == "Job"]
        pod = job["spec"]["template"]["spec"]
        self.assertEqual(pod["serviceAccountName"], "install-bootstrap-runner")
        self.assertEqual(pod["containers"][0]["volumeMounts"], [{"name": "inputs", "mountPath": "/run/asservat/cluster/bundled", "readOnly": True}])
        command = pod["containers"][0]["command"]
        self.assertEqual(command, ["/asservat", "installer-cluster", "--in-cluster", "--bundled-hub", "install", "--bootstrap-id", self.base["cluster"]["bootstrapID"], "--join-hub", "--namespace", "asservat-connector"])
        binding, = [d for d in docs if d["kind"] == "ClusterRoleBinding"]
        self.assertEqual(binding["subjects"], [{"kind": "ServiceAccount", "namespace": "trusted-bootstrap", "name": "install-bootstrap-runner"}])
        external = copy.deepcopy(self.base)
        external["cluster"].update(bundledHub="", bootstrapID="", bootstrapSecret="manual-bootstrap", offer=json.dumps({"format": "asservat-regional-offer/v1"}))
        external_role, = [d for d in self.render(external) if d["kind"] == "ClusterRole"]
        selected_role, = [d for d in docs if d["kind"] == "ClusterRole"]
        self.assertEqual(selected_role["rules"], external_role["rules"])
        self.assertEqual(pod["volumes"], [{"name": "inputs", "projected": {"defaultMode": 288, "sources": [
            {"configMap": {"name": "install-preparer", "items": [{"key": "deployment.json", "path": "hub-preparer.json"}]}},
            {"secret": {"name": "install-openbao-state", "items": [{"key": "plan.json", "path": "openbao-plan.json"}, {"key": "ca.crt", "path": "openbao-ca.crt"}, {"key": "backend-id", "path": "openbao-backend-id"}]}},
            {"secret": {"name": "install-objectstore-state", "items": [{"key": "plan.json", "path": "objectstore-plan.json"}, {"key": "ca.crt", "path": "objectstore-ca.crt"}]}},
            {"serviceAccountToken": {"path": "keyprovider-setup-token", "audience": "https://asservat.io/openbao/setup", "expirationSeconds": 600}},
        ]}}])

    def test_invalid_mixed_or_incomplete_selection_is_refused_without_schema_bypass(self):
        changes = [{"bundledHub": ""}, {"bootstrapID": ""}, {"bootstrapID": "chosen"}, {"bundledHub": "../hub"},
                   {"bundledHub": "a" * 31}, {"offer": "{}"}, {"bootstrapSecret": "manual"}, {"evidenceSecret": "manual"}]
        for change in changes:
            for extra in ((), ("--skip-schema-validation",)):
                with self.subTest(change=change, extra=extra):
                    values = copy.deepcopy(self.base)
                    values["cluster"].update(change)
                    self.render(values, ok=False, extra=extra)
        values = copy.deepcopy(self.base)
        values["mode"] = "combined"
        self.render(values, ok=False)
        values = copy.deepcopy(self.base)
        values["cluster"]["unrecognized"] = "forbidden"
        self.render(values, ok=False)

    def test_existing_external_matrix(self):
        helm.check_cluster(self.directory.name)

    def test_selected_rejects_unavailable_private_profile_carrier(self):
        values = copy.deepcopy(self.base)
        values["cluster"]["profileEndpoints"] = [{"name": "go-pprof-loopback", "kind": "template", "addressModes": ["targetLoopback"], "loopbackFamily": "ipv4", "minPort": 6060, "maxPort": 6060,
            "tls": {"serverName": "localhost", "rootsPEM": "PUBLIC-CERTIFICATE-FIXTURE"},
            "credential": {"audiences": [{"clusterID": "00000000-0000-4000-8000-000000000001", "namespaceUID": "00000000-0000-4000-8000-000000000002", "workloadKind": "Deployment", "workloadUID": "00000000-0000-4000-8000-000000000003"}]}}]
        for extra in ((), ("--skip-schema-validation",)):
            self.assertIn("does not supply private profile authorization", self.render(values, ok=False, extra=extra))


if __name__ == "__main__":
    unittest.main()
