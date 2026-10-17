#!/usr/bin/env python3
"""Self-test: --cleanup-kept removes only one kept run's own resources."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("harness", Path(__file__).with_name("test-context-storage.py"))
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)

RUN = "ab12cd34"


class KeptCleanup(unittest.TestCase):
    def cleanup(self, kept, labels):
        removed = []

        def fake_run(args, *, data=None):
            if args[:2] == ["docker", "inspect"]:
                name = args[2].removesuffix("-control-plane")
                return json.dumps([{"Config": {"Labels": {"io.x-k8s.kind.cluster": labels.get(name, name)}}}])
            if args[0] == "docker" and args[2] == "inspect":
                label = {"asservat.test": labels.get(args[3], RUN)}
                return json.dumps([{"Config": {"Labels": label}, "Labels": label}])
            removed.append(args[-1] if args[0] == "kind" or args[2] != "rm" else args[-1])
            return ""

        harness.run = fake_run
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory, RUN + ".json")
            manifest.write_text(json.dumps(kept))
            results = harness.ROOT / "test/results"
            results.mkdir(parents=True, exist_ok=True)
            code = harness.cleanup_kept(manifest)
            report = json.loads((results / ("kept-cleanup-" + RUN + ".json")).read_text())
            (results / ("kept-cleanup-" + RUN + ".json")).unlink()
            return code, removed, report, manifest.exists()

    def test_removes_own_resources_and_manifest(self):
        kept = {"runId": RUN, "clusters": ["asservat-context-" + RUN + "-0"], "containers": ["asservat-" + RUN + "-postgres"], "volumes": [], "image": None, "networks": ["asservat-" + RUN]}
        code, removed, report, left = self.cleanup(kept, {})
        self.assertEqual(code, 0)
        self.assertEqual(report["cleanupFailures"], [])
        self.assertIn("asservat-context-" + RUN + "-0", removed)
        self.assertFalse(left)

    def test_refuses_foreign_cluster_and_label(self):
        kept = {"runId": RUN, "clusters": ["haptic-cluster"], "containers": ["other"], "volumes": [], "image": None, "networks": []}
        code, removed, report, left = self.cleanup(kept, {"other": "someone-else"})
        self.assertEqual(code, 1)
        self.assertEqual(sorted(report["cleanupFailures"]), ["haptic-cluster", "other"])
        self.assertEqual(removed, [])
        self.assertTrue(left)


if __name__ == "__main__":
    unittest.main()
