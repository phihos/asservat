#!/usr/bin/env python3
"""Self-test of multi-focus installed runs: the harness focus list, the
per-focus results and the grouped suites of ci-native.sh. No cluster."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixture", ROOT/"scripts/test-context-storage.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
NATIVE = str(ROOT/"scripts/ci-native.sh")


def native(*args):
    return json.loads(subprocess.check_output([NATIVE, *args], text=True))


class MultiFocusSelection(unittest.TestCase):
    def test_focus_list(self):
        self.assertEqual(fixture.journey_foci({}), [])
        self.assertEqual(fixture.journey_foci({"ASSERVAT_JOURNEY_FOCUS": "manual-logs"}), ["manual-logs"])
        self.assertEqual(fixture.journey_foci({"ASSERVAT_JOURNEY_FOCUS": "journey,policy"}), ["journey", "policy"])
        for bad in ("journey,journey", "journey,chain", "clusters,journey", "journey,", "journey,typo"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                fixture.journey_foci({"ASSERVAT_JOURNEY_FOCUS": bad})

    def test_selection_follows_every_focus(self):
        with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": "ongoing-save,live-observation"}):
            self.assertEqual(fixture.qualification_cluster_count(3, installer_continuation=True), 2)
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "18m")
        with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": "journey,policy"}):
            self.assertEqual(fixture.qualification_cluster_count(3, installer_continuation=True), 2)
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "60m")
        self.assertTrue(fixture.qualification_collector(["ongoing-save", "live-observation"]))
        self.assertFalse(fixture.qualification_collector(["journey", "policy"]))
        self.assertFalse(fixture.qualification_collector([]))
        with self.assertRaises(ValueError):
            fixture.qualification_collector(["journey", "ongoing-save"])
        # A profile fixture variant belongs to exactly one manual-profile run.
        with self.assertRaises(ValueError):
            fixture.qualification_profile_variant({"ASSERVAT_JOURNEY_FOCUS": "manual-profile,manual-http", "ASSERVAT_PROFILE_VARIANT": "heap"})

    def test_focus_results(self):
        output = "\n".join([
            "        --- PASS: TestInitialBootstrapChainWithRealServices/installer-continuation/journey (171.20s)",
            "            --- PASS: TestInitialBootstrapChainWithRealServices/installer-continuation/policy/policy (3.00s)",
            "        --- FAIL: TestInitialBootstrapChainWithRealServices/installer-continuation/policy (90.50s)",
        ])
        self.assertEqual(fixture.focus_results(output, ["journey", "policy", "share"]), {
            "journey": {"result": "pass", "seconds": 171.2}, "policy": {"result": "fail", "seconds": 90.5}, "share": {"result": "notRun", "seconds": None}})

    def test_groups_replace_their_members_in_all(self):
        everything, names = native("--list"), native("--names")
        groups = [n for n in names if "+" in n]
        self.assertGreaterEqual(len(groups), 8)
        for group in groups:
            self.assertIn(group, everything)
            for member in group.removeprefix("continuation-").split("+"):
                self.assertIn("continuation-" + member, names)
                self.assertNotIn("continuation-" + member, everything)
        self.assertTrue(set(everything) <= set(names))
        # A member's suite still dispatches alone for targeted reruns.
        self.assertIn("continuation-journey", names)

    def test_group_command_joins_focuses_and_environments(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory)/"python3"
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({"args":sys.argv[1:],"focus":os.environ.get("ASSERVAT_JOURNEY_FOCUS"),"episodes":os.environ.get("ASSERVAT_LIVE_EPISODES")}))\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=directory+os.pathsep+os.environ["PATH"])
            result = subprocess.run([NATIVE, "continuation-ongoing-mixed+ongoing-live"], env=env, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout), {"args": ["scripts/test-context-storage.py", "--initial-bootstrap-chain", "--runtime-provider-pair", "--installer-continuation"], "focus": "ongoing-mixed,live-observation", "episodes": "policy"})
            result = subprocess.run([NATIVE, "continuation-journey+policy"], env=env, capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout)["focus"], "journey,policy")
            self.assertIsNone(json.loads(result.stdout)["episodes"])

    def test_group_setup_is_the_union_of_its_members(self):
        names = native("--names")
        groups = [n for n in names if "+" in n]
        for group in groups:
            members = ["continuation-" + m for m in group.removeprefix("continuation-").split("+")]
            combined = native("--matrix", json.dumps([group]))["include"][0]
            singles = native("--matrix", json.dumps(members))["include"]
            for key, value in combined.items():
                if key == "suite":
                    continue
                if isinstance(value, bool):
                    self.assertEqual(value, any(s[key] for s in singles), (group, key))
                else:
                    self.assertEqual({value}, {s[key] for s in singles}, (group, key))

    def test_workflow_uses_the_matrix(self):
        workflow = (ROOT/".github/workflows/native.yml").read_text()
        self.assertIn("matrix: ${{ fromJSON(needs.select.outputs.matrix) }}", workflow)
        self.assertIn('scripts/ci-native.sh --matrix "$suites"', workflow)
        self.assertNotIn("matrix.suite ==", workflow)
        self.assertNotIn("matrix.suite !=", workflow)


if __name__ == "__main__":
    unittest.main()
