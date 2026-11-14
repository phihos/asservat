#!/usr/bin/env python3
"""Offline render checks of the Helm-native hub-api templates.

The representative values are an all-bundled combined install. The config
keys checked here are the JSON tags of contracts.HubAPIConfig, and the
mounted file names are the ones internal/bootstrap's hub-api loader opens.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "charts/asservat"
HELM = os.environ.get("HELM", "helm")
NS = "asservat-system"

CONNECTOR = {"accounts": 1, "recordsPerAccount": 96, "retainedSeconds": 4000, "profiles": 1, "sourceTransitions": 8, "purgeLeases": 2, "validSeconds": 3600,
             "footprint": {"rowBytes": 1048576, "transitionWALBytes": 1048576}}
BACKUP = {"horizonSeconds": 1, "cleanupBudgetSeconds": 60, "proofWindowSeconds": 60, "backupCopies": 1, "walCopies": 1}
BUNDLED = {
    "mode": "combined",
    "image": {"repository": "registry.example/asservat", "digest": "sha256:" + "a" * 64},
    "origin": "https://asservat.example.test",
    "identity": {"eligibleGroups": ["00000000-0000-4000-8000-000000000001"], "processingOperators": [{"clientID": "asservat-console", "issuer": "https://login.example.org/realms/asservat", "kind": "User", "id": "0f03f92a-6920-47cd-85d5-26080d3571d5"}]},
    "exposure": {"tlsSecret": "asservat-public-tls"},
    "fleet": {"issuer": "https://id.example.test/realms/asservat", "clients": ["asservat-console"], "deliveryProfiles": ["regional-installer"]},
    "capacity": {"namespaceKeys": ["asservat-trial"], "backup": BACKUP},
    "federation": {"connector": CONNECTOR},
    "retention": {"purposeRef": "context-trial"},
    "region": {"enabled": True},
    "services": {
        "postgres": {"provider": "bundled", "bundled": {"image": "registry.example/postgres@sha256:" + "b" * 64}},
        "objectStore": {"provider": "seaweedfs"},
        "keyService": {"provider": "openbao"},
        "identity": {"provider": "keycloak", "keycloak": {"hostname": "https://id.example.test", "tlsSecretName": "keycloak-tls"}},
    },
}

# contracts.HubAPIConfig / HubAPIPublic JSON tags.
CONFIG_KEYS = {"format", "name", "namespace", "postgres", "objectStore", "openBao", "connections", "concurrency", "observation", "native", "public"}
PUBLIC_KEYS = {"origin", "browserAudience", "processing", "captureHistory", "standby", "captures", "previewSeconds", "downloadPlan", "proxyTLS", "version",
               "operationConcurrency", "mcpPerIdentity", "downloadConcurrency", "downloadsPerIdentity", "downloadMaxSeconds", "operationAudit", "fleet",
               "permissionDelegations", "regionalOffer"}
# Files the loader and runtime open under each mount.
INPUT_FILES = {"sql-owner-runtime.json", "owner-pod.token", "kube-observer.token", "provider-auth.token", "provider-audit-storage.json",
               "kube-ca.crt", "postgres-ca.crt", "audit-store-ca.crt", "key-service-ca.crt", "identity-ca.crt", "federation-ca.crt", "download-key-service-ca.crt"}
PUBLIC_SQL = ["hub-runtime", "capture-intent-read", "worker-config-read", "capacity-profile-read", "capture-admit", "capture-journal", "capture-ack"]


def merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in extra.items():
        out[k] = merge(out.get(k, {}), v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def helm(cmd, values, ok=True, schema=False):
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        yaml.safe_dump(values, f)
    try:
        args = [HELM, cmd, "rel", str(CHART), "--namespace", NS, "-f", f.name] if cmd == "template" else [HELM, cmd, str(CHART), "-f", f.name]
        if cmd == "template":
            args += ["--kube-version", "1.35.0"]
        if not schema:
            # Other components' value subtrees are validated by their own tests.
            args += ["--skip-schema-validation"]
        r = subprocess.run(args, text=True, capture_output=True, timeout=60)
    finally:
        os.unlink(f.name)
    if ok and r.returncode != 0:
        raise AssertionError(r.stdout + r.stderr)
    if not ok and r.returncode == 0:
        raise AssertionError("render unexpectedly succeeded")
    return r


def render(values):
    docs = [d for d in yaml.safe_load_all(helm("template", values).stdout) if d]
    return {(d["kind"], d["metadata"].get("namespace", ""), d["metadata"]["name"]): d for d in docs}


def files(volume):
    out = set()
    for s in volume["projected"]["sources"]:
        for k in ("secret", "configMap"):
            out |= {i["path"] for i in s.get(k, {}).get("items", [])}
        if "serviceAccountToken" in s:
            out.add(s["serviceAccountToken"]["path"])
    return out


class HubAPI(unittest.TestCase):
    def test_all_bundled_combined(self):
        o = render(BUNDLED)
        for key in [("ServiceAccount", NS, "asservat-hub-api"), ("Role", NS, "asservat-hub-api"), ("RoleBinding", NS, "asservat-hub-api"),
                    ("ClusterRole", "", NS + "-asservat-hub-api"), ("ClusterRoleBinding", "", NS + "-asservat-hub-api"),
                    ("ConfigMap", NS, "asservat-hub-api-config"), ("Deployment", NS, "asservat-hub-api"),
                    ("Service", NS, "asservat-hub-api"), ("Service", NS, "asservat-hub-api-owner"), ("Service", NS, "asservat-hub-api-native"),
                    ("ConfigMap", NS, "asservat-browser-settings"), ("ConfigMap", NS, "asservat-identity-settings"), ("ConfigMap", NS, "asservat-cluster-catalog"),
                    ("ConfigMap", NS, "asservat-download-environment"), ("ConfigMap", NS, "asservat-processing-source"), ("ConfigMap", NS, "asservat-regional-offer")]:
            self.assertIn(key, o)
        cm = o[("ConfigMap", NS, "asservat-hub-api-config")]["data"]
        config = json.loads(cm["config.json"])
        self.assertLessEqual(set(config), CONFIG_KEYS)
        self.assertLessEqual(set(config["public"]), PUBLIC_KEYS)
        self.assertEqual((config["format"], config["name"], config["namespace"]), ("asservat-hub-api-config/v1", "asservat", NS))
        self.assertEqual(config["postgres"], {"host": f"asservat-postgres.{NS}.svc", "port": 5432, "database": "asservat"})
        self.assertEqual(config["objectStore"]["auditBucket"], "asservat-audit")
        self.assertEqual(config["native"], {"workerNamespaces": ["asservat-downloads"], "retentionTopologies": []})
        self.assertEqual(config["observation"], {"localCapacity": {"keys": ["asservat-trial"]}})
        public = config["public"]
        self.assertEqual((public["origin"], public["browserAudience"], public["fleet"]), ("https://asservat.example.test", "asservat-console", {"deliveryProfile": "regional-installer"}))
        self.assertTrue(public["processing"])
        self.assertEqual(public["regionalOffer"]["federation"], f"https://asservat-federation.{NS}.svc:9446")
        self.assertEqual(public["regionalOffer"]["connector"], CONNECTOR)
        text = cm["config.json"].lower()
        for forbidden in ["uid", "guard", "activation", "installationid", "auditkey", "role\"", "mount"]:
            self.assertNotIn(forbidden, text)
        self.assertEqual(json.loads(cm["worker-controls.json"]), {"format": "asservat-owner-worker-trust/v1", "controls": []})

        browser = json.loads(o[("ConfigMap", NS, "asservat-browser-settings")]["data"]["browser.json"])
        self.assertEqual((browser["issuer"], browser["clientID"]), ("https://id.example.test/realms/asservat", "asservat-console"))
        self.assertNotIn("rootID", browser)
        self.assertNotIn("sessionEpoch", browser)
        identity = json.loads(o[("ConfigMap", NS, "asservat-identity-settings")]["data"]["identity.json"])
        self.assertEqual(identity["clients"], [{"id": "asservat-console", "kind": "human", "classQualified": True}])
        env = json.loads(o[("ConfigMap", NS, "asservat-download-environment")]["data"]["download-environment.json"])
        self.assertEqual((env["permittedRegions"], env["clients"][0]["purposes"]), (["us-east-1"], ["context-trial"]))
        self.assertFalse({"rootID", "installationID", "recoveryEpoch"} & set(env))
        # The installed (derived) paths are named by marker, never rendered.
        self.assertEqual((env["paths"], env["installedPaths"]), ([], True))
        self.assertEqual((env["clients"][0]["pathIDs"], env["clients"][0]["installedPaths"]), ([], True))
        self.assertEqual(o[("ConfigMap", NS, "asservat-processing-source")]["data"], o[("ConfigMap", NS, "asservat-download-environment")]["data"])
        offer = o[("ConfigMap", NS, "asservat-regional-offer")]
        self.assertNotIn("data", offer)
        self.assertEqual(offer["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")

        pod = o[("Deployment", NS, "asservat-hub-api")]["spec"]["template"]
        self.assertEqual(len(pod["metadata"]["annotations"]["checksum/config"]), 64)
        spec = pod["spec"]
        self.assertFalse(spec["automountServiceAccountToken"])
        self.assertEqual(spec["initContainers"][0]["command"], ["/asservat", "setup", "--wait-schema", "--config", "/run/asservat/hub-api/config.json",
                                                                 "--credential", "/run/asservat/hub/sql-owner-runtime.json", "--ca", "/run/asservat/hub/postgres-ca.crt"])
        c = spec["containers"][0]
        self.assertEqual(c["command"], ["/asservat", "hub-api"])
        # Readiness: the hub-api's /readyz on its readiness port (the Go
        # constant HubAPIReadinessPort), passing only after startup.
        self.assertIn({"name": "readiness", "containerPort": 9449, "protocol": "TCP"}, c["ports"])
        self.assertEqual(c["readinessProbe"]["httpGet"], {"path": "/readyz", "port": "readiness", "scheme": "HTTP"})
        self.assertNotIn("livenessProbe", c)
        self.assertEqual({m["mountPath"] for m in c["volumeMounts"]}, {"/run/asservat/hub-api", "/run/asservat/ids", "/run/asservat/hub", "/run/asservat/owner-observation", "/run/asservat/public"})
        vols = {v["name"]: v for v in spec["volumes"]}
        self.assertEqual(vols["ids"]["secret"]["secretName"], "asservat-ids")
        self.assertEqual(files(vols["inputs"]), INPUT_FILES)
        sources = json.dumps(vols["inputs"])
        for secret in ["asservat-key-service-tls", "asservat-sql-hub-api", "asservat-s3-owner-audit", "asservat-postgres-state", "asservat-objectstore-state", "asservat-openbao-state", "keycloak-tls", "asservat-federation-tls"]:
            self.assertIn(f'"{secret}"', sources)
        self.assertIn('"asservat-owner-provider"', sources)
        self.assertEqual(files(vols["observation"]), {"worker-controls.json", "native-kube-asservat-downloads.token"})
        self.assertEqual(files(vols["public"]), {f"sql-public-{p}.json" for p in PUBLIC_SQL} | {"public-audit-keys.json", "oidc-client-secret", "public-tls.crt", "public-tls.key"})
        public_sources = json.dumps(vols["public"])
        self.assertIn('"asservat-keycloak-state"', public_sources)
        self.assertIn('"console-client-secret"', public_sources)

        # The local connector's bootstrap record Secret: rendered empty and
        # kept; the hub-api writes bootstrap.json into it by name.
        record = o[("Secret", NS, "asservat-region-bootstrap")]
        self.assertNotIn("data", record)
        self.assertEqual(record["metadata"]["annotations"]["helm.sh/resource-policy"], "keep")
        rules = o[("Role", NS, "asservat-hub-api")]["rules"]
        self.assertFalse([r for r in rules if "update" in r["verbs"] and r.get("resourceNames") not in (["asservat-regional-offer"], ["asservat-region-bootstrap"])])
        self.assertIn({"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["asservat-region-bootstrap"], "verbs": ["get", "update"]}, rules)
        self.assertFalse([r for r in rules if "secrets" in r["resources"] and r.get("resourceNames") != ["asservat-region-bootstrap"]])
        names = {n for r in rules for n in r.get("resourceNames", [])}
        self.assertLessEqual({"asservat-owner-source", "asservat-browser-settings", "asservat-identity-settings", "asservat-cluster-catalog", "asservat-download-environment", "asservat-processing-source", "asservat-fleet"}, names)
        self.assertEqual(o[("ClusterRole", "", NS + "-asservat-hub-api")]["rules"][0]["resourceNames"], [NS, "asservat-downloads"])
        owner = o[("Service", NS, "asservat-hub-api-owner")]["spec"]
        self.assertEqual((owner["clusterIP"], {(p["name"], p["port"], p["targetPort"]) for p in owner["ports"]}), ("None", {("owner", 9443, 9443), ("observation", 9444, 9444), ("public", 9445, 9445)}))
        native = o[("Service", NS, "asservat-hub-api-native")]["spec"]
        self.assertEqual((native["type"], [p["port"] for p in native["ports"]]), ("ClusterIP", [9444, 9448]))
        self.assertEqual(o[("Service", NS, "asservat-hub-api")]["spec"]["ports"][0]["port"], 9445)

    def test_proxy_tls_external_identity_nodeport(self):
        values = merge(BUNDLED, {"mode": "hub", "region": {"enabled": False}, "exposure": {"tls": {"mode": "proxy"}, "tlsSecret": ""},
                                 "identity": {"issuer": "https://sso.example.test/realms/org", "clientID": "console", "providerRootsPEM": "-----BEGIN CERTIFICATE-----\n", "clientSecret": {"existingSecret": "oidc"}},
                                 "services": {"identity": {"provider": "external"}},
                                 "hub": {"hub-api": {"nativeService": {"type": "NodePort", "nodePorts": {"native": 31447}}}}})
        o = render(values)
        cm = o[("ConfigMap", NS, "asservat-hub-api-config")]["data"]
        config = json.loads(cm["config.json"])
        self.assertTrue(config["public"]["proxyTLS"])
        self.assertNotIn("regionalOffer", config["public"])
        self.assertIn("identity-ca.crt", cm)
        spec = o[("Deployment", NS, "asservat-hub-api")]["spec"]["template"]["spec"]
        vols = {v["name"]: v for v in spec["volumes"]}
        self.assertNotIn("public-tls.crt", files(vols["public"]))
        self.assertNotIn("federation-ca.crt", files(vols["inputs"]))
        self.assertIn('"oidc"', json.dumps(vols["public"]))
        self.assertNotIn(("ConfigMap", NS, "asservat-regional-offer"), o)
        native = o[("Service", NS, "asservat-hub-api-native")]["spec"]
        self.assertEqual((native["type"], native["ports"][0]["nodePort"]), ("NodePort", 31447))
        self.assertNotIn("nodePort", native["ports"][1])

    def test_combined_local_bootstrap_without_fleet_issuer(self):
        # The hub-api issues the local connector's bootstrap through the fleet
        # issuance; without fleet values the profile defaults to "local" in
        # both the hub-api config and the protected fleet source.
        values = merge(BUNDLED, {"fleet": {"issuer": "", "deliveryProfiles": []}})
        o = render(values)
        config = json.loads(o[("ConfigMap", NS, "asservat-hub-api-config")]["data"]["config.json"])
        self.assertEqual(config["public"]["fleet"], {"deliveryProfile": "local"})
        fleet = json.loads(o[("ConfigMap", NS, "asservat-fleet")]["data"]["fleet.json"])
        self.assertEqual(fleet["deliveryProfiles"], ["local"])
        # No connector, no record Secret and no Secret access.
        o = render(merge(values, {"region": {"enabled": False}}))
        self.assertNotIn(("Secret", NS, "asservat-region-bootstrap"), o)
        self.assertFalse([r for r in o[("Role", NS, "asservat-hub-api")]["rules"] if "secrets" in r["resources"]])

    def test_without_origin_no_public(self):
        values = merge(BUNDLED, {"mode": "hub", "region": {"enabled": False}, "origin": "", "identity": {"issuer": "https://sso.example.test/realms/org", "clientID": "console"}, "services": {"identity": {"provider": "external"}}})
        o = render(values)
        config = json.loads(o[("ConfigMap", NS, "asservat-hub-api-config")]["data"]["config.json"])
        self.assertNotIn("public", config)
        spec = o[("Deployment", NS, "asservat-hub-api")]["spec"]["template"]["spec"]
        self.assertNotIn("public", {v["name"] for v in spec["volumes"]})
        self.assertNotIn(("ConfigMap", NS, "asservat-browser-settings"), o)

    def test_refusals(self):
        for extra, message in [({"exposure": {"tlsSecret": ""}}, "exposure.tlsSecret"),
                               ({"mode": "hub", "region": {"enabled": False}, "services": {"identity": {"provider": "external"}}, "identity": {"issuer": "https://sso.example.test", "clientID": "c", "providerRootsPEM": "x", "clientSecret": {"existingSecret": "oidc"}, "eligibleGroups": [], "eligibleSubjects": []}}, "identity.eligibleSubjects or identity.eligibleGroups"),
                               ({"mode": "hub", "region": {"enabled": False}, "services": {"identity": {"provider": "external"}}, "identity": {"issuer": "https://sso.example.test", "clientID": "c", "providerRootsPEM": "x"}}, "identity.clientSecret.existingSecret"),
                               ({"mode": "hub", "region": {"enabled": False}, "services": {"identity": {"provider": "external"}}, "identity": {"issuer": "https://sso.example.test", "clientID": "c", "clientSecret": {"existingSecret": "oidc"}}}, "identity.providerRootsPEM"),
                               ({"federation": None}, "federation.connector")]:
            r = helm("template", merge(BUNDLED, extra), ok=False)
            self.assertIn(message, r.stderr)

    def test_schema_of_hub_api_values(self):
        # Invalid hub-api, identity and exposure values are refused.
        r = helm("template", merge(BUNDLED, {"hub": {"hub-api": {"connections": 0}}, "exposure": {"tls": {"mode": "edge"}}, "identity": {"clientSecret": {"name": "old"}}}), ok=False, schema=True)
        for path in ["/hub/hub-api/connections", "/exposure/tls/mode", "/identity/clientSecret"]:
            self.assertIn(path, r.stderr)
        # The representative values pass this component's subtrees; other
        # subtrees are checked by their own tests.
        r = subprocess.run([HELM, "template", "rel", str(CHART), "--namespace", NS, "-f", "-"], input=yaml.safe_dump(BUNDLED), text=True, capture_output=True, timeout=60)
        for path in ["/hub/hub-api", "/identity", "/exposure"]:
            self.assertNotIn(f"at '{path}", r.stderr)


if __name__ == "__main__":
    unittest.main()
