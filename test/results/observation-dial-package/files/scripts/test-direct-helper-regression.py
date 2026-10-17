#!/usr/bin/env python3
"""Selected direct-helper regression gate; mocks Go and starts no services."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class DirectHelperRegression(unittest.TestCase):
    def run_gate(self, *, omit=None, action="pass", code=0, extra=None):
        report, calls = {}, []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {"TMPDIR": directory, "CGO_ENABLED": "0", "GOMAXPROCS": "2", "GOFLAGS": "-p=2"}

            def go(command, **kwargs):
                calls.append(command)
                self.assertEqual(kwargs["cwd"], root)
                self.assertEqual(kwargs["env"], env)
                self.assertEqual(kwargs["timeout"], 600)
                for name in sorted(fixture.DIRECT_OBSERVATION_ISSUER_TESTS):
                    if name != omit:
                        kwargs["stdout"].write(json.dumps({"Action": action, "Test": name}) + "\n")
                if extra is not None:
                    kwargs["stdout"].write(json.dumps(extra) + "\n")
                return subprocess.CompletedProcess(command, code)

            with patch.object(fixture, "ROOT", root), patch.object(fixture.subprocess, "run", go):
                try:
                    fixture.qualify_direct_helper_issuer(env, report)
                finally:
                    self.last_report = report
            self.assertTrue((root / "test/results/context-storage-helper-issuer.log").is_file())
        return report, calls

    def test_actual_build_ignore_sources_and_both_usages_are_required(self):
        report, calls = self.run_gate()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:7], ["go", "test", "-count=1", "-timeout=60s", "-vet=off", "-json", "-run=^TestNativeFixtureConnectorIssuer"])
        self.assertEqual([Path(p).name for p in calls[0][7:]], [
            "data.go", "enrollment.go", "inputs.go", "main.go", "metrics.go", "runtime.go", "enrollment_test.go",
        ])
        result = report["directObservationHelperIssuer"]
        self.assertEqual(result["testExit"], 0)
        self.assertEqual(set(result["passedTests"]), fixture.DIRECT_OBSERVATION_ISSUER_TESTS)
        self.assertEqual(len(result["logSHA256"]), 64)

    def test_each_missing_test_rejects_even_zero_go_exit(self):
        for name in fixture.DIRECT_OBSERVATION_ISSUER_TESTS:
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                self.run_gate(omit=name)

    def test_skipped_or_failed_test_rejects(self):
        for action in ("skip", "fail"):
            with self.subTest(action=action), self.assertRaises(RuntimeError):
                self.run_gate(action=action)

    def test_nonzero_exit_cannot_be_hidden_by_pass_lines(self):
        with self.assertRaises(RuntimeError):
            self.run_gate(code=1)
        self.assertEqual(self.last_report["directObservationHelperIssuer"]["testExit"], 1)

    def test_unreviewed_named_pass_rejects(self):
        with self.assertRaises(RuntimeError):
            self.run_gate(extra={"Action": "pass", "Test": "TestNativeFixtureConnectorIssuerUnreviewed"})

    def test_package_failure_cannot_be_hidden_by_named_passes(self):
        with self.assertRaises(RuntimeError):
            self.run_gate(extra={"Action": "fail", "Package": "command-line-arguments"})


if __name__ == "__main__":
    unittest.main()
