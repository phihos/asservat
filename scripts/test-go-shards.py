#!/usr/bin/env python3
"""Pure selection checks; no Go build, test binary or external fixture."""
import importlib.util
import json
from pathlib import Path
import re
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

    def test_ci_partition_is_balanced_complete_and_disjoint(self):
        names = [f"Test{index:03}" for index in range(30)]
        weights = {"Test007": 100, "Test020": 60}
        parts = gate.balanced(names, weights, 3)
        self.assertEqual(parts, gate.balanced(list(reversed(names)), weights, 3))
        self.assertEqual(sorted(n for part in parts for n in part), names)
        self.assertIn(["Test007"], [[n for n in part if n in weights] for part in parts])
        for bad in ((names, 0), (names[:2], 3), (names + names[:1], 2)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                gate.balanced(bad[0], weights, bad[1])
        self.assertEqual(gate.selected_shard([]), None)
        self.assertEqual(gate.selected_shard(["--shard", "3/8"]), (3, 8))
        for argv in (["--shard", "8/8"], ["--shard", "0/1"], ["--run", "TestA"], ["--shard", "-1/4"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                gate.selected_shard(argv)

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

    def test_multi_package_discovery_keeps_each_package_inventory(self):
        output = "TestB\nTestA\nok  \tp\t0.1s\nFuzzC\nok  \tq\t0.2s\n"
        self.assertEqual(gate.discovered_inventory(output, ["p", "q"]), {"p": ["TestA", "TestB"], "q": ["FuzzC"]})
        for bad in ("TestA\nok  \tp\t0.1s\n", "TestA\nok  \tp\t0.1s\nTestB\nok  \tq\t0.1s\nTestC\n",
                    "TestA\nok  \tp\t0.1s\nTestB\nok  \tp\t0.1s\nTestC\nok  \tq\t0.1s\n"):
            with self.subTest(output=bad), self.assertRaises(ValueError):
                gate.discovered_inventory(bad, ["p", "q"])

    def test_units_split_only_discovered_packages_and_weigh_unknowns(self):
        durations = {"packages": {"small": 3.0}, "tests": {"big": {"TestA": 50.0}}}
        packages = [gate.MODULE + p for p in ("small", "new", "big")]
        weights = gate.units(packages, {gate.MODULE + "big": ["TestA", "TestB"]}, durations)
        self.assertEqual(weights, {(gate.MODULE + "small", ""): 3.0, (gate.MODULE + "new", ""): gate.DEFAULT_WEIGHT,
                                   (gate.MODULE + "big", "TestA"): 50.0, (gate.MODULE + "big", "TestB"): gate.DEFAULT_WEIGHT})
        with self.assertRaises(ValueError):
            gate.units(packages[:1], {gate.MODULE + "big": ["TestA"]}, durations)

    def test_unit_plan_spreads_a_large_package_and_covers_every_unit_once(self):
        tests = {f"Test{i:03}": 30.0 for i in range(40)}
        durations = {"packages": {f"p{i}": 10.0 for i in range(20)}, "tests": {"big": tests}}
        packages = [gate.MODULE + "big"] + [gate.MODULE + f"p{i}" for i in range(20)]
        weights = gate.units(packages, {gate.MODULE + "big": sorted(tests)}, durations)
        parts = gate.balanced(list(weights), weights, 8)
        self.assertEqual(sorted(u for part in parts for u in part), sorted(weights))
        loads = [sum(weights[u] for u in part) for part in parts]
        self.assertLessEqual(max(loads) - min(loads), 30.0)
        self.assertTrue(all(any(p == gate.MODULE + "big" for p, _ in part) for part in parts))
        self.assertEqual(gate.plan_digest(parts), gate.plan_digest(gate.balanced(list(reversed(list(weights))), weights, 8)))

    def test_whole_package_results_must_be_exactly_one_per_package(self):
        def encode(events):
            return "\n".join(json.dumps({"Package": p, "Action": a, **({"Test": t} if t else {})}) for p, a, t in events)
        good = [("p", "run", "TestA"), ("p", "pass", "TestA"), ("p", "pass", None), ("q", "skip", None)]
        gate.checked_package_events(encode(good), ["p", "q"])
        for events in (good[:-1], good + [("q", "pass", None)], good + [("r", "pass", None)], good + [("p", "fail", "TestA")]):
            with self.subTest(events=events), self.assertRaises(ValueError):
                gate.checked_package_events(encode(events), ["p", "q"])

    def test_union_of_shard_records_must_execute_the_one_plan_exactly_once(self):
        planned = [["p", ""], ["q", "TestA"], ["q", "TestB"]]

        def record(index, executed, plan="d", units=planned):
            return {"shard": [index, 2], "plan": plan, "units": units, "executed": executed}
        good = [record(0, [["p", ""], ["q", "TestB"]]), record(1, [["q", "TestA"]])]
        self.assertEqual(gate.verified_union(good, 2), 3)
        bad = (
            good[:1],
            [good[0], record(0, [["q", "TestA"]])],
            [good[0], record(1, [])],
            [good[0], record(1, [["q", "TestA"], ["q", "TestB"]])],
            [good[0], record(1, [["q", "TestA"]], plan="other")],
            [good[0], record(1, [["q", "TestA"]], units=planned[:2])],
        )
        for records in bad:
            with self.subTest(records=records), self.assertRaises(ValueError):
                gate.verified_union(records, 2)

    def test_measured_timings_replace_weights_and_sum_split_packages(self):
        old = {"packages": {"small": 9.0, "gone": 1.0}, "tests": {"internal/adapters/kubernetes": {"TestOld": 4.0}}}
        records = [{"packages": {"small": 2.04}, "tests": {"small": {"TestX": 2.0}}},
                   {"packages": {}, "tests": {"internal/adapters/kubernetes": {"TestNew": 7.26}}}]
        self.assertEqual(gate.updated_weights(records, old), {
            "packages": {"gone": 1.0, "internal/adapters/kubernetes": 11.3, "small": 2.0},
            "tests": {"internal/adapters/kubernetes": {"TestNew": 7.3, "TestOld": 4.0}}})

    def test_ci_union_check_counts_every_matrix_shard(self):
        workflow = (gate.ROOT / ".github/workflows/ci.yml").read_text()
        matrix = re.search(r"^\s+shard: \[([0-9, ]+)\]$", workflow, re.M).group(1)
        shards = [int(n) for n in matrix.split(",")]
        self.assertEqual(shards, list(range(len(shards))))
        self.assertEqual(re.findall(r"--verify-union ([0-9]+) ", workflow), [str(len(shards))])

    def test_recorded_weights_cover_every_split_package(self):
        durations = json.loads(gate.DURATIONS.read_text())
        self.assertEqual(set(durations["tests"]), {gate.short(p) for p in gate.SPLIT})


if __name__ == "__main__":
    unittest.main()
