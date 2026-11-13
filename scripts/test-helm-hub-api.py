#!/usr/bin/env python3
"""Offline render checks of the Helm-native hub-api templates."""
import json
import os
from pathlib import Path
import subprocess
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/asservat"
HELM = os.environ.get("HELM", "helm")
BASE = ["hub.hubApi.enabled=true", "image.repository=registry.example/asservat", "image.digest=sha256:" + "a" * 64]
PUBLIC = ["origin=https://asservat.example", "identity.clientSecret.name=oidc", "identity.providerRootsSecret.name=identity-ca", "exposure.tlsSecret=public-tls"]


def render(values, ok=True):
    args = [HELM, "template", "rel", str(CHART), "--namespace", "asservat-system", "--kube-version", "1.35.0"]
    for v in values:
        args += ["--set", v]
    r = subprocess.run(args, text=True, capture_output=True, timeout=45)
    if (r.returncode == 0) != ok:
        raise AssertionError(r.stdout + r.stderr)
    return [d for d in yaml.safe_load_all(r.stdout) if d] if ok else r.stderr


def objects(docs):
    return {(d["kind"], d["metadata"].get("namespace", ""), d["metadata"]["name"]): d for d in docs}


class HubAPI(unittest.TestCase):
    def test_defaults_render_no_hub_api(self):
        self.assertFalse([d for d in render([]) if "hub-api" in d["metadata"]["name"]])

    def test_requires_pinned_image(self):
        self.assertIn("image.digest", render(["hub.hubApi.enabled=true"], ok=False))

    def test_public_pod_tls(self):
        o = objects(render(BASE + PUBLIC))
        ns = "asservat-system"
        for key in [("ServiceAccount", ns, "asservat-hub-api"), ("Role", ns, "asservat-hub-api"), ("RoleBinding", ns, "asservat-hub-api"),
                    ("ClusterRole", "", "asservat.asservat-system.asservat-hub-api"), ("ClusterRoleBinding", "", "asservat.asservat-system.asservat-hub-api"),
                    ("Role", "asservat-downloads", "asservat-hub-api"), ("RoleBinding", "asservat-downloads", "asservat-hub-api"),
                    ("ConfigMap", ns, "asservat-hub-api-config"), ("Deployment", ns, "asservat-hub-api"),
                    ("Service", ns, "asservat-hub-api"), ("Service", ns, "asservat-hub-api-owner"), ("Service", ns, "asservat-hub-api-native")]:
            self.assertIn(key, o)
        config = json.loads(o[("ConfigMap", ns, "asservat-hub-api-config")]["data"]["config.json"])
        self.assertEqual(config["format"], "asservat-hub-api-config/v1")
        self.assertEqual(config["namespace"], ns)
        self.assertEqual(config["native"]["workerAPIs"], [{"namespace": "asservat-downloads"}])
        public = config["public"]
        self.assertEqual((public["origin"], public["port"], public["standby"], public["previewSeconds"]), ("https://asservat.example", 9445, 2, 120))
        self.assertNotIn("proxyTLS", public)
        self.assertNotIn("localCapacity", config["observation"])
        text = json.dumps(config).lower()
        for forbidden in ["uid", "guard", "activation", "installationid"]:
            self.assertNotIn(forbidden, text)
        d = o[("Deployment", ns, "asservat-hub-api")]
        pod = d["spec"]["template"]
        self.assertEqual(len(pod["metadata"]["annotations"]["checksum/config"]), 64)
        spec = pod["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["initContainers"][0]["command"], ["/asservat", "schema-wait"])
        c = spec["containers"][0]
        self.assertEqual(c["command"], ["/asservat", "hub-api"])
        self.assertEqual(sorted(p["containerPort"] for p in c["ports"]), [9443, 9444, 9445, 9448])
        self.assertEqual({m["mountPath"] for m in c["volumeMounts"]}, {"/run/asservat/hub-api", "/run/asservat/ids", "/run/asservat/hub", "/run/asservat/owner-observation", "/run/asservat/public"})
        vols = {v["name"]: v for v in spec["volumes"]}
        paths = lambda v: {i["path"] for s in v["projected"]["sources"] for k in ("secret", "configMap") if k in s for i in s[k].get("items", [])} | {s["serviceAccountToken"]["path"] for s in v["projected"]["sources"] if "serviceAccountToken" in s}
        self.assertEqual(paths(vols["inputs"]), {"sql-owner-runtime.json", "owner-pod.token", "kube-observer.token", "provider-auth.token", "provider-audit-storage.json", "kube-ca.crt", "postgres-ca.crt", "audit-store-ca.crt", "key-service-ca.crt", "identity-ca.crt"})
        self.assertIn("native-kube-asservat-downloads.token", paths(vols["observation"]))
        self.assertTrue({"public-tls.crt", "public-tls.key", "oidc-client-secret", "sql-public-hub-runtime.json"} <= paths(vols["public"]))
        rules = o[("Role", ns, "asservat-hub-api")]["rules"]
        self.assertFalse([r for r in rules if "update" in r["verbs"] or "admissionregistration.k8s.io" in r["apiGroups"]])
        self.assertEqual(o[("Service", ns, "asservat-hub-api")]["spec"]["ports"][0]["port"], 9445)
        self.assertEqual(o[("Service", ns, "asservat-hub-api-owner")]["spec"]["clusterIP"], "None")
        native = o[("Service", ns, "asservat-hub-api-native")]["spec"]
        self.assertEqual((native["type"], [p["port"] for p in native["ports"]]), ("ClusterIP", [9444, 9448]))

    def test_proxy_tls_nodeport(self):
        o = objects(render(BASE + PUBLIC[:3] + ["exposure.tls=proxy", "hub.hubApi.nativeService.type=NodePort", "hub.hubApi.nativeService.nodePorts.native=31447", "capacity.keys={b,a}"]))
        ns = "asservat-system"
        config = json.loads(o[("ConfigMap", ns, "asservat-hub-api-config")]["data"]["config.json"])
        self.assertTrue(config["public"]["proxyTLS"])
        self.assertEqual(config["observation"]["localCapacity"]["keys"], ["a", "b"])
        self.assertEqual(config["observation"]["localCapacity"]["callerAccount"], "asservat-hub-worker")
        spec = o[("Deployment", ns, "asservat-hub-api")]["spec"]["template"]["spec"]
        public = [v for v in spec["volumes"] if v["name"] == "public"][0]
        self.assertNotIn("public-tls.crt", json.dumps(public))
        native = o[("Service", ns, "asservat-hub-api-native")]["spec"]
        self.assertEqual(native["type"], "NodePort")
        self.assertEqual(native["ports"][0]["nodePort"], 31447)
        self.assertNotIn("nodePort", native["ports"][1])

    def test_without_origin_no_public(self):
        o = objects(render(BASE))
        config = json.loads(o[("ConfigMap", "asservat-system", "asservat-hub-api-config")]["data"]["config.json"])
        self.assertNotIn("public", config)
        spec = o[("Deployment", "asservat-system", "asservat-hub-api")]["spec"]["template"]["spec"]
        self.assertNotIn("public", {v["name"] for v in spec["volumes"]})

    def test_pod_tls_needs_secret(self):
        self.assertIn("exposure.tlsSecret", render(BASE + PUBLIC[:2], ok=False))

    def test_lint(self):
        for values in ([], BASE + PUBLIC):
            args = [HELM, "lint", "--strict", str(CHART)]
            for v in values:
                args += ["--set", v]
            r = subprocess.run(args, text=True, capture_output=True, timeout=45)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
