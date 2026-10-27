#!/usr/bin/env python3
"""The CI custody shards run every test of the complete suite exactly once.

Pure selection check; no Go build or fixture. Top-level tests come from the
test/integration sources. A test split across shards must use first-level
subtest filters anchored at the first character whose classes partition every
possible first character, so a new subtest cannot fall into no shard or two.
"""
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("custody_fixture", Path(__file__).with_name("test-custody.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

# Go rewrites spaces in subtest names; any other printable or non-ASCII first
# character is possible.
FIRST_CHARACTERS = [chr(c) for c in range(33, 127)] + ["é", "中"]


def top_level_tests(folder=ROOT / "test/integration"):
    names = set()
    for path in folder.glob("*_test.go"):
        names.update(re.findall(r"^func (Test\w*)\(t \*testing\.T\)", path.read_text(), re.MULTILINE))
    return sorted(names)


def coverage_errors(names, full, shards):
    """Go -run semantics: unanchored search per level, levels split at '/'."""
    errors = []
    selected = {name for name in names if re.search(full, name)}
    split = {shard: pattern.split("/", 1) for shard, pattern in shards.items()}
    for name in names:
        owners = sorted(shard for shard, levels in split.items() if re.search(levels[0], name))
        if name not in selected:
            if owners:
                errors.append(f"{name} is outside the complete suite but selected by shards {owners}")
            continue
        if not owners:
            errors.append(f"{name} is in no shard")
            continue
        if len(owners) == 1:
            continue
        unsplit = [shard for shard in owners if len(split[shard]) == 1]
        if unsplit:
            errors.append(f"{name} runs whole in shards {unsplit} and also in {sorted(set(owners) - set(unsplit))}")
            continue
        for shard in owners:
            if not split[shard][1].startswith("^"):
                errors.append(f"shard {shard} subtest filter {split[shard][1]!r} is not anchored")
        for first in FIRST_CHARACTERS:
            matching = [shard for shard in owners if re.search(split[shard][1], first + "subtest")]
            if len(matching) != 1:
                errors.append(f"{name} subtests starting with {first!r} run in shards {matching}")
    return errors


class CustodyShards(unittest.TestCase):
    def test_every_test_runs_in_exactly_one_shard(self):
        names = top_level_tests()
        self.assertIn("TestContextAdmissionWithRealServices", names)
        self.assertIn("TestCustodyWithRealServices", names)
        self.assertEqual(coverage_errors(names, fixture.CUSTODY_PATTERN, fixture.CUSTODY_SHARDS), [])

    def test_gaps_and_overlaps_are_reported(self):
        names = ["TestA", "TestB", "TestOther"]
        full = "Test(A|B)"
        self.assertEqual(coverage_errors(names, full, {"1": "^TestA$/^[a-m]", "2": "^TestA$/^[^a-m]", "3": "TestB"}), [])
        for shards in (
            {"1": "^TestA$"},                                       # TestB in no shard
            {"1": "Test(A|B)", "2": "TestB"},                       # TestB twice
            {"1": "^TestA$/^[a-m]", "2": "^TestA$/^[n-z]", "3": "TestB"},  # digits/uppercase uncovered
            {"1": "^TestA$/^[a-m]", "2": "^TestA$/^[^a-n]", "3": "TestB"},  # gap at n
            {"1": "^TestA$/^[a-m]", "2": "^TestA$/^[^a-l]", "3": "TestB"},  # overlap at m
            {"1": "^TestA$/^[a-m]", "2": "^TestA$", "3": "TestB"},  # whole and split
            {"1": "^TestA$/[a-m]", "2": "^TestA$/^[^a-m]", "3": "TestB"},  # unanchored
            {"1": "Test", },                                        # TestOther outside the suite
        ):
            with self.subTest(shards=shards):
                self.assertTrue(coverage_errors(names, full, shards))


if __name__ == "__main__":
    unittest.main()
