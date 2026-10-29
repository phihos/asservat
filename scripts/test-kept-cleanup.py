#!/usr/bin/env python3
"""Self-test: --cleanup-kept removes only one kept run's own resources."""
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
from unittest.mock import patch
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


class CollectorPacketCleanup(unittest.TestCase):
    def test_packet_deletes_owned_cluster_with_or_without_artifacts(self):
        spec = importlib.util.spec_from_file_location("collector_harness", Path(__file__).with_name("test-collector.py"))
        collector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(collector)
        owned = "asservat-collector-" + RUN
        for artifacts in (False, True):
            with self.subTest(artifacts=artifacts), tempfile.TemporaryDirectory() as directory:
                root, work = Path(directory, "root"), Path(directory, "work")
                (root / "test/results").mkdir(parents=True)
                work.mkdir()
                clusters, deleted, commands = {"encrypted", "unrelated"}, [], []

                def fake_subprocess(args, **kwargs):
                    commands.append(list(args))
                    output, code = "", 0
                    if args[:2] == ["go", "build"]:
                        Path(args[args.index("-o") + 1]).write_bytes(b"synthetic non-executable fixture")
                    elif args[:2] == ["go", "test"]:
                        if artifacts:
                            for artifact in ("filtered", "unfiltered", "encrypted"):
                                (work / (artifact + ".pcapng")).write_bytes(artifact.encode())
                    elif args[:3] == ["kind", "create", "cluster"]:
                        clusters.add(args[args.index("--name") + 1])
                    elif args[:3] == ["kind", "delete", "cluster"]:
                        selected = args[args.index("--name") + 1]
                        deleted.append(selected)
                        clusters.discard(selected)
                    elif args == ["kind", "get", "clusters"]:
                        output = "\n".join(sorted(clusters))
                    elif args[0] == "kubectl" and "version" in args:
                        output = json.dumps({"serverVersion": {"gitVersion": "synthetic"}})
                    elif args[:3] == ["docker", "network", "inspect"]:
                        output = json.dumps([{"IPAM": {"Config": [{"Gateway": "192.0.2.1"}]}}])
                    elif args[:3] == ["docker", "image", "inspect"]:
                        code = 1
                    elif (args[:2] in (["make", "libpcap"], ["docker", "build"], ["kind", "load"], ["helm", "template"], ["docker", "rm"])
                          or args[:3] == ["docker", "image", "rm"]
                          or (args[0] == "kubectl" and ("create" in args or "apply" in args))
                          or args[0] == str(root / "scripts/fetch-gadget.sh")):
                        pass
                    else:
                        self.fail("unexpected mocked command: " + repr(args))
                    return subprocess.CompletedProcess(args, code, stdout=output, stderr="")

                with patch.object(collector, "ROOT", root), \
                     patch.object(collector.secrets, "token_hex", return_value=RUN), \
                     patch.object(collector, "seaweed", return_value=("synthetic-s3", "http://192.0.2.2")), \
                     patch.object(collector, "certificates", return_value=("synthetic-root", work / "cert", work / "key")), \
                     patch.object(collector, "loaded_digest", return_value="synthetic@sha256:" + "0" * 64), \
                     patch.object(collector.subprocess, "run", side_effect=fake_subprocess), \
                     patch.object(collector.subprocess, "Popen", side_effect=AssertionError("unmocked process")), \
                     patch.object(collector.urllib.request, "urlopen", side_effect=AssertionError("unmocked network")):
                    report = {"runner": {"synthetic": True}}
                    collector.packet(work, report)
                self.assertEqual(report["cleanup"]["cluster"], owned not in clusters,
                                 {"deleted": deleted, "remaining": sorted(clusters), "cleanup": report["cleanup"]})
                self.assertEqual(deleted, [owned], commands)
                self.assertEqual(clusters, {"encrypted", "unrelated"})
                self.assertTrue(report["cleanup"]["cluster"])
                self.assertEqual(report["testExit"], 0)
                for artifact in ("filtered", "unfiltered", "encrypted"):
                    output = root / "test/results" / ("collector-packet-" + artifact + ".pcapng")
                    if artifacts:
                        self.assertEqual(output.read_bytes(), artifact.encode())
                    else:
                        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
