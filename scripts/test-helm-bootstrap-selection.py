#!/usr/bin/env python3
"""Pure Helm fixture selection/evidence regressions; no external services."""
import importlib.util
import gzip
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
import tempfile
from unittest.mock import patch

from helm_registry import HelmRegistry, exported_image_identity, exported_layer_media, verify_registry_cleanup

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class HelmSelection(unittest.TestCase):
    def test_exported_layer_retains_exact_bytes_and_original_rootfs(self):
        plain = b"synthetic tar payload"
        digest = "sha256:"+hashlib.sha256(plain).hexdigest()
        packed = gzip.compress(plain)
        self.assertEqual(exported_layer_media(plain, digest), "application/vnd.oci.image.layer.v1.tar")
        self.assertEqual(exported_layer_media(packed, digest), "application/vnd.oci.image.layer.v1.tar+gzip")
        for data in (plain, packed):
            with self.assertRaisesRegex(RuntimeError, "rootfs identity"):
                exported_layer_media(data, "sha256:"+"0"*64)
        with self.assertRaisesRegex(RuntimeError, "uncompressed bound"):
            exported_layer_media(packed, digest, maximum=len(plain)-1)
        with self.assertRaisesRegex(RuntimeError, "gzip layer"):
            exported_layer_media(packed[:-4], digest)

    def test_exact_docker_config_or_containerd_descriptor_identity(self):
        blobs = {}
        def blob(value):
            raw = json.dumps(value, separators=(",", ":")).encode()
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            blobs["blobs/sha256/"+digest[7:]] = raw
            return {"digest": digest, "size": len(raw), "mediaType": value.get("mediaType")}
        config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"diff_ids": []}}).encode()
        digest = "sha256:" + hashlib.sha256(config).hexdigest()
        manifest = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": digest, "size": len(config)}, "layers": []})
        descriptor = dict(manifest, platform={"os": "linux", "architecture": "amd64"})
        index = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [descriptor]})
        def read(path, maximum):
            raw = blobs[path]
            self.assertLessEqual(len(raw), maximum)
            return raw
        self.assertEqual(exported_image_identity(read, digest, config)["identityKind"], "config")
        self.assertEqual(exported_image_identity(read, index["digest"], config)["selectedManifestDigest"], manifest["digest"])
        self.assertEqual(exported_image_identity(read, manifest["digest"], config)["configDigest"], digest)
        wrong = config.replace(b"amd64", b"arm64")
        with self.assertRaisesRegex(RuntimeError, "missing or ambiguous"):
            exported_image_identity(read, index["digest"], wrong)
        ambiguous = blob({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [descriptor, descriptor]})
        with self.assertRaisesRegex(RuntimeError, "missing or ambiguous"):
            exported_image_identity(read, ambiguous["digest"], config)
        with self.assertRaisesRegex(RuntimeError, "differs from compiled"):
            exported_image_identity(read, manifest["digest"], config+b" ")
        blobs["blobs/sha256/"+manifest["digest"][7:]] += b" "
        with self.assertRaisesRegex(RuntimeError, "digest differs"):
            exported_image_identity(read, manifest["digest"], config)

    def test_exact_empty_database_and_no_stale_native_flags(self):
        self.assertEqual(fixture.qualification_selection(None, False, False, False, True), ("^TestHelmBootstrapWithRealServices$", 1))
        for args in [("TestOther", False, False, False, True), (None, True, False, False, True), (None, False, True, False, True), (None, False, False, True, True)]:
            with self.assertRaises(ValueError):
                fixture.qualification_selection(*args)
        flags = {key: "1" for key in ["ASSERVAT_INITIAL_HANDOVER_NATIVE", "ASSERVAT_INITIAL_SCHEMA_HANDOVER_NATIVE", "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE", "ASSERVAT_HELM_BOOTSTRAP_NATIVE"]}
        selected = fixture.qualification_environment(flags, Path("fixture"), Path("work"), False, False, False, True)
        self.assertEqual({k: selected[k] for k in flags if k in selected}, {"ASSERVAT_HELM_BOOTSTRAP_NATIVE": "1"})
        ordinary = fixture.qualification_environment(flags, Path("fixture"), Path("work"), False, False)
        self.assertFalse(any(k in ordinary for k in flags))
        with patch.object(fixture.subprocess, "run", side_effect=AssertionError("fixture migration attempted")), patch.object(fixture, "run", side_effect=AssertionError("fixture grants attempted")):
            fixture.prepare_fixture_database(Path("unused"), Path("unused"), "unused", "unused", True)

    def test_registry_cleanup_requires_positive_container_and_network_absence(self):
        with tempfile.TemporaryDirectory() as root:
            private = Path(root) / "registry"
            private.mkdir()
            (private / "key.pem").write_text("synthetic-only")
            with self.assertRaisesRegex(RuntimeError, "container remains"):
                verify_registry_cleanup(lambda _: "owned-registry", root, "owned")
            self.assertTrue(private.exists())
            with self.assertRaisesRegex(RuntimeError, "network remains"):
                verify_registry_cleanup(lambda args: "owned" if args[1] == "network" else "", root, "owned")
            self.assertTrue(private.exists())
            result = verify_registry_cleanup(lambda _: "", root, "owned")
            self.assertFalse(private.exists())
            self.assertTrue(result["fixtureTLSAndAuthFilesAbsent"])
            self.assertFalse(result["upstreamImageCacheRemoved"])

    def test_registry_report_requires_each_owned_node_exact_manifest(self):
        registry = object.__new__(HelmRegistry)
        registry.name, registry.auth, registry.digest, registry.image = "owned", "sensitive-auth-test", "sha256:exact", "owned/image@sha256:exact"
        event = {"http.request.remoteaddr": "10.0.0.1:123", "http.request.method": "GET", "http.request.uri": "/v2/asservat/manifests/sha256:exact", "http.response.status": 200}
        one = json.dumps(event)
        with patch("helm_registry.subprocess.run", return_value=SimpleNamespace(stdout=one, stderr="")):
            with self.assertRaisesRegex(RuntimeError, "evidence missing"):
                registry.report(["10.0.0.1", "10.0.0.2"])
        event["http.request.remoteaddr"] = "10.0.0.2:456"
        with patch("helm_registry.subprocess.run", return_value=SimpleNamespace(stdout=one, stderr="\n"+json.dumps(event))):
            report = registry.report(["10.0.0.1", "10.0.0.2"])
            self.assertEqual(report["authenticatedManifestGetsByOwnedNode"], {"10.0.0.1": 1, "10.0.0.2": 1})
        with patch("helm_registry.subprocess.run", return_value=SimpleNamespace(stdout=one+registry.auth, stderr="")):
            with self.assertRaisesRegex(RuntimeError, "credential material"):
                registry.report(["10.0.0.1"])

if __name__ == "__main__":
    unittest.main()
