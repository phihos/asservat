#!/usr/bin/env python3
"""Pure owned-registry handoff tests; never runs Docker or Kubernetes."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error

import helm_registry as registry


class RuntimeNodeAccess(unittest.TestCase):
    def setUp(self):
        cache = Path(os.environ.get("ASSERVAT_BUILD_TMP", Path.home() / ".cache/asservat-build/tmp"))
        cache.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="context-", dir=cache)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.network = "asservat-" + self.work.name.replace("_", "-")
        self.nodes = [self.network + "-0-control-plane", self.network + "-0-worker"]
        self.authority = "10.200.1.2:5000"
        self.image = self.authority + "/asservat@sha256:" + "a" * 64
        self.auth = base64.b64encode(b"synthetic-pull:allmine").decode()
        self.ca = "public-owned-ca\n"
        (self.work / "registry").mkdir()
        (self.work / "registry/ca.pem").write_text(self.ca)
        self.base = registry.node_registry_hosts("https://" + self.authority)
        self.hosts = {node: self.base for node in self.nodes}
        self.labels_valid = True
        self.logs = "\n".join(json.dumps({"http.request.remoteaddr": ip+":1234", "http.request.method": "GET", "http.request.uri": "/v2/asservat/manifests/sha256:"+"a"*64, "http.response.status": 200}) for ip in ("10.200.1.3", "10.200.1.4"))
        self.proof = {"originalHook": {"uid": "10000000-0000-4000-8000-000000000001", "namespace": "bootstrap-test", "name": "install-bootstrap", "image": self.image, "commands": [{"name": name, "exitCode": 0, "restartCount": 0, "imageID": self.image} for name in ("produce", "schema", "prepare", "retire")]}, "nodeUIDs": {node: "10000000-0000-4000-8000-00000000000"+str(i+2) for i,node in enumerate(self.nodes)}}
        self.mutations = []
        self.fixture = self.work / "fixtures.json"
        self.fixture.write_text(json.dumps({"workerImage": self.image, "helmBootstrap": {"nodeA": self.nodes[0], "nodeB": self.nodes[1], "registryConfig": {"auths": {self.authority: {"auth": self.auth}}}}}))

    def command(self, args, *, data=None):
        self.assertNotIn(self.auth, " ".join(args))
        if args[:2] == ["docker", "inspect"]:
            name = args[2]
            is_node = name in self.nodes
            labels = {"io.x-k8s.kind.cluster": self.network+"-0"} if is_node else {"asservat.test": self.work.name.replace("_", "-")}
            if not self.labels_valid and is_node:
                labels = {"io.x-k8s.kind.cluster": "foreign"}
            ip = "10.200.1.3" if name == self.nodes[0] else "10.200.1.4" if is_node else "10.200.1.2"
            return json.dumps([{"Config": {"Labels": labels}, "State": {"Running": True}, "NetworkSettings": {"Networks": {self.network: {"IPAddress": ip}}}}])
        if args[:2] == ["docker", "logs"]:
            return self.logs
        if args[:2] == ["docker", "exec"]:
            node = args[2] if args[2] != "-i" else args[3]
            if "cat" in args and data is None:
                return self.ca if args[-1].endswith("ca.crt") else self.hosts[node]
            if data is not None:
                receipt = json.loads((self.work / "runtime-node-access.json").read_text())
                self.assertFalse(receipt["initialColdPulls"]["nodeCredentialsInstalled"])
                self.assertTrue(all(receipt["initialColdPulls"]["authenticatedManifestGetsByOwnedNode"].values()))
                self.mutations.append((list(args), data))
                self.hosts[node] = data
                return ""
        self.fail("unexpected fixture command: " + str(args))

    def execute(self):
        def anonymous(*args, **kwargs):
            raise urllib.error.HTTPError("https://owned/v2/", 401, "denied", {}, None)
        with patch.object(registry, "runtime_registry_command", self.command), patch.object(registry.ssl, "create_default_context", return_value=None), patch.object(registry.subprocess, "run", return_value=SimpleNamespace(stdout=self.logs, stderr="", returncode=0)), patch.object(registry.HelmRegistry, "request", side_effect=anonymous):
            return registry.enable_runtime_node_access(self.fixture, self.proof)

    def test_cold_receipt_precedes_private_stdin_auth_and_preserves_registry(self):
        result = self.execute()
        self.assertEqual(len(self.mutations), 2)
        self.assertTrue(result["runtimeNodeCredentialsInstalled"])
        self.assertFalse(result["initialColdPulls"]["nodeCredentialsInstalled"])
        self.assertEqual(result["productImage"], self.image)
        text = json.dumps(result)
        self.assertNotIn(self.auth, text)
        self.assertNotIn("allmine", text)
        for args, payload in self.mutations:
            self.assertIn("-i", args)
            self.assertIn('authorization = ["Basic '+self.auth+'"]', payload)
            self.assertTrue(payload.startswith(self.base))

    def test_foreign_node_existing_auth_or_missing_cold_proof_never_writes(self):
        self.labels_valid = False
        with self.assertRaises(RuntimeError): self.execute()
        self.assertEqual(self.mutations, [])
        self.labels_valid = True
        self.hosts[self.nodes[0]] += "foreign-auth"
        with self.assertRaises(RuntimeError): self.execute()
        self.assertEqual(self.mutations, [])
        self.hosts[self.nodes[0]] = self.base
        self.logs = ""
        with self.assertRaises(RuntimeError): self.execute()
        self.assertEqual(self.mutations, [])


if __name__ == "__main__":
    unittest.main()
