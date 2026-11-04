#!/usr/bin/env python3
"""Pure collector provenance tests. No services, builds or privileged operations."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("collector_fixture", Path(__file__).with_name("test-collector.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class CollectorProvenance(unittest.TestCase):
    def test_inventory_includes_build_inputs_and_detects_new_changed_or_removed_source(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(fixture, "ROOT", Path(directory)):
            root = Path(directory)
            names = ["go.mod", "go.sum", "Makefile", "scripts/test-collector.py", "scripts/build-libpcap.sh",
                     "scripts/package-argument-gadget.py", ".github/workflows/native.yml", ".github/actions/setup/action.yml",
                     "cmd/asservat/main.go", "internal/bootstrap/node.go", "internal/contracts/schema.json",
                     "migrations/00135.sql", "migrations/embed.go", "test/integration/native_test.go",
                     "test/fixtures/profile-native/main.go", "experiments/syscall-argument-budget/program.patch",
                     "charts/asservat/templates/collector.yaml"]
            for name in names + ["test/results/old-report.json", "web/node_modules/unused.js"]:
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"synthetic source\n")
            before = fixture.source_hashes()
            self.assertEqual(set(before), set(names))
            self.assertTrue(all(value == hashlib.sha256(b"synthetic source\n").hexdigest() for value in before.values()))
            (root / "internal/bootstrap/new.go").write_bytes(b"added")
            (root / "go.mod").write_bytes(b"changed")
            (root / "go.sum").unlink()
            self.assertNotEqual(before, fixture.source_hashes())

    def test_binary_bytes_and_hash_are_measured_and_image_id_is_a_config_id(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "asservat"
            binary.write_bytes(b"synthetic compiled bytes\x00")
            self.assertEqual(fixture.binary_inventory(binary), {"bytes": binary.stat().st_size, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()})
        config_id = "sha256:" + "a" * 64
        with patch.object(fixture, "run", return_value=config_id) as command:
            self.assertEqual(fixture.docker_config_id("fixture:run"), config_id)
            command.assert_called_once_with(["docker", "image", "inspect", "--format", "{{.Id}}", "fixture:run"])
        for invalid in ["fixture@" + config_id, "sha256:short", ""]:
            with patch.object(fixture, "run", return_value=invalid), self.assertRaises(RuntimeError):
                fixture.docker_config_id("fixture:run")

    def test_changed_sources_fail_without_replacing_original_test_exit_or_cleanup(self):
        for test_exit, mode in [(0, "same"), (0, "changed"), (7, "same"), (7, "changed"), (0, "unreadable"), (7, "unreadable")]:
            with self.subTest(test_exit=test_exit, mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "go.mod").write_text("before")
                guard = root / "disposable"
                guard.touch()

                def execute(_work, report, *_arguments, **_options):
                    report["testExit"] = test_exit
                    report["cleanup"] = {"cluster": test_exit == 0, "image": True}
                    if mode == "changed":
                        (root / "go.mod").write_text("after")
                    if test_exit:
                        raise SystemExit(test_exit)

                real_inventory = fixture.source_hashes
                inventory_calls = 0
                def inventory():
                    nonlocal inventory_calls
                    inventory_calls += 1
                    if mode == "unreadable" and inventory_calls == 2:
                        raise PermissionError("synthetic unreadable source")
                    return real_inventory()

                with patch.object(fixture, "ROOT", root), patch.object(fixture, "GUARD", guard), patch.object(fixture, "runner_facts", return_value={}), patch.object(fixture, "packet", side_effect=execute), patch.object(fixture, "source_hashes", side_effect=inventory), patch.object(fixture.sys, "argv", ["test-collector.py", "profile"]), patch.dict(os.environ, {"ASSERVAT_BUILD_TMP": str(root / "scratch")}), contextlib.redirect_stdout(io.StringIO()):
                    if test_exit:
                        with self.assertRaises(SystemExit) as raised:
                            fixture.main()
                        self.assertEqual(raised.exception.code, test_exit)
                    elif mode != "same":
                        with self.assertRaisesRegex(RuntimeError, "source inventory changed"):
                            fixture.main()
                    else:
                        fixture.main()
                report = json.loads((root / "test/results/collector-profile-report.json").read_text())
                self.assertEqual(report["testExit"], test_exit)
                self.assertEqual(report["cleanup"], {"cluster": test_exit == 0, "image": True})
                self.assertEqual(report["sourceUnchanged"], mode == "same")
                if mode == "unreadable":
                    self.assertEqual(report["sourceInventoryError"], "PermissionError")
                    self.assertNotIn("sourceHashesAfter", report)
                else:
                    self.assertEqual(report["sourceHashes"] == report["sourceHashesAfter"], mode == "same")
                self.assertEqual(report["result"], "passed" if not test_exit and mode == "same" else "failed")


if __name__ == "__main__":
    unittest.main()
