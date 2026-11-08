#!/usr/bin/env python3
"""Pure selection checks for scripts/test-affected-go.py; no Go or git."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("affected", Path(__file__).with_name("test-affected-go.py"))
affected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(affected)


class AffectedSelection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        affected.ROOT = root

        def package(path, imports=(), test_imports=(), tests=True, source=""):
            directory = root / path
            directory.mkdir(parents=True)
            if tests:
                (directory / "a_test.go").write_text(source)
            return {"ImportPath": "m/" + path, "Dir": str(directory), "Imports": ["m/" + i for i in imports],
                    "XTestImports": ["m/" + i for i in test_imports], "TestGoFiles": ["a_test.go"] if tests else []}

        self.packages = {p["ImportPath"]: p for p in (
            package("domain"),
            package("app", imports=["domain"]),
            package("adapter", imports=["app"]),
            package("transport", test_imports=["adapter"]),
            package("plain", tests=False, imports=["domain"]),
            package("unrelated"),
            package("test/integration", source='os.ReadFile("../../examples/a.yaml"); filepath.Join("..", "..", "web", "x")'),
        )}

    def tearDown(self):
        self.tmp.cleanup()

    def test_changed_package_selects_transitive_and_test_only_reverse_dependencies(self):
        direct, reverse = affected.affected(["domain/x.go"], self.packages)
        self.assertEqual(direct, {"m/domain"})
        # plain has no tests; unrelated and integration do not reach domain.
        self.assertEqual(reverse, {"m/app", "m/adapter", "m/transport"})

    def test_testdata_and_test_files_map_to_their_package(self):
        self.assertEqual(affected.affected(["adapter/testdata/deep/f.json"], self.packages), ({"m/adapter"}, {"m/transport"}))
        self.assertEqual(affected.affected(["transport/a_test.go"], self.packages), ({"m/transport"}, set()))

    def test_relative_repository_reads_select_the_reading_package(self):
        for name in ("examples/a.yaml", "web/x/y.ts"):
            with self.subTest(name=name):
                self.assertEqual(affected.affected([name], self.packages), ({"m/test/integration"}, set()))
        self.assertEqual(affected.affected(["docs/readme.md", "examplesX/a"], self.packages), (set(), set()))

    def test_module_files_select_everything(self):
        direct, reverse = affected.affected(["go.sum"], self.packages)
        self.assertEqual(direct | reverse, set(self.packages) - {"m/plain"})

    def test_failed_tests_and_failure_output(self):
        events = [{"Action": "run", "Test": "TestA"}, {"Action": "output", "Test": "TestA/sub", "Output": "boom\n"},
                  {"Action": "output", "Test": "TestB", "Output": "quiet\n"}, {"Action": "fail", "Test": "TestA/sub"},
                  {"Action": "fail", "Test": "TestA"}, {"Action": "output", "Output": "FAIL p\n"}, {"Action": "fail"}]
        stream = "\n".join(json.dumps(e) for e in events) + "\nbuild diagnostic"
        self.assertEqual(affected.results(stream), (["TestA"], "boom\nFAIL p\nbuild diagnostic\n"))


if __name__ == "__main__":
    unittest.main()
