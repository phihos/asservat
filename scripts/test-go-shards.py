#!/usr/bin/env python3
"""Pure selection checks; no Go build, test binary or external fixture."""
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("go_tests", Path(__file__).with_name("check-go-tests.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GoShards(unittest.TestCase):
    def test_discovery_covers_test_example_and_fuzz(self):
        self.assertEqual(gate.discovered_names("TestB\nFuzzA\nExample_example\nTestA\nok p 0.1s\n", "p"), ["Example_example", "FuzzA", "TestA", "TestB"])

    def test_bad_or_empty_inventory_fails(self):
        for output in ("ok p 0.1s\n", "TestA\nTestA\nok p 0.1s\n", "TestA\nok other 0.1s\n", "BenchmarkA\nok p 0.1s\n", "TestA/Sub\nok p 0.1s\n", "TestA\n"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                gate.discovered_names(output, "p")

    def test_partition_is_deterministic_complete_and_bounded(self):
        names = [f"Test{index:03}" for index in range(241)]
        a, b = gate.shards(names), gate.shards(list(reversed(names)))
        self.assertEqual(a, b)
        self.assertEqual([len(group) for group in a], [40] * 6 + [1])
        self.assertEqual([name for group in a for name in group], names)
        with self.assertRaises(ValueError):
            gate.shards(["TestA", "TestA"])

    def test_actual_runs_and_terminal_results_must_match(self):
        def encode(events):
            return "\n".join(json.dumps({"Package": "p", "Action": action, **({"Test": name} if name else {})}) for action, name in events)
        good = [("run", "TestA"), ("run", "TestA/child"), ("pass", "TestA/child"), ("pass", "TestA"), ("pass", None)]
        self.assertEqual(gate.checked_shard_events(encode(good), "p", ["TestA"]), [])
        build = json.dumps({"ImportPath": "dependency", "Action": "build-output", "Output": "compiler diagnostic"})
        self.assertEqual(gate.checked_shard_events(build + "\n" + encode(good), "p", ["TestA"]), [])
        with self.assertRaises(ValueError):
            gate.checked_shard_events(json.dumps({"ImportPath": "dependency", "Action": "build-fail"}) + "\n" + encode(good), "p", ["TestA"])
        for events in (good[:-1], good[1:], good[:3] + good[4:], good + [("run", "TestA")], good + [("run", "TestUnexpected")], good + [("fail", "TestA/child")]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                gate.checked_shard_events(encode(events), "p", ["TestA"])
        skip = [("run", "TestA"), ("skip", "TestA"), ("pass", None)]
        self.assertEqual(gate.checked_shard_events(encode(skip), "p", ["TestA"]), ["TestA"])


if __name__ == "__main__":
    unittest.main()
