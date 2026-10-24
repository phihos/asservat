#!/usr/bin/env python3
"""Execute CI's change detector with canned GitHub responses; no network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
DETECT = next(step["run"] for step in WORKFLOW["jobs"]["changes"]["steps"] if step.get("id") == "diff")
GH_STUB = r'''
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
with open(os.environ["GH_CALLS"], "a") as output:
    output.write(json.dumps(args) + "\n")
fixture = json.loads(Path(os.environ["GH_FIXTURE"]).read_text())
if fixture.get("fail"):
    print("docs/partial-response.md")
    print("gh: HTTP 503", file=sys.stderr)
    sys.exit(1)
files = fixture["files"]
if args[:2] == ["pr", "diff"]:
    if len(files) > 300:
        print("gh: Sorry, the diff exceeded the maximum number of files (300). (HTTP 406)", file=sys.stderr)
        sys.exit(1)
    print("\n".join(item["filename"] for item in files))
    sys.exit(0)
if args[0] != "api" or len(args) != 4 or args[2] != "--jq":
    sys.exit("unexpected gh invocation")
if "/pulls/" in args[1]:
    if not args[1].endswith("/files?per_page=100"):
        sys.exit("expected one bounded file-list page")
    response = files[:100]
elif "/compare/" in args[1]:
    response = {"files": files[:300]}
else:
    sys.exit("unexpected API endpoint")
body = "invalid JSON" if fixture.get("malformed") else json.dumps(response)
sys.exit(subprocess.run(["jq", "-r", args[3]], input=body, text=True).returncode)
'''


class CIChanges(unittest.TestCase):
    def detect(self, paths, *, event="pull_request", before="a" * 40, **fixture):
        files = [{"filename": path} if isinstance(path, str) else path for path in paths]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "gh"
            stub.write_text(f"#!{sys.executable}\n" + GH_STUB)
            stub.chmod(0o755)
            (root / "fixture.json").write_text(json.dumps({"files": files, **fixture}))
            env = {
                **os.environ,
                "PATH": f"{root}:{os.environ['PATH']}",
                "GH_FIXTURE": str(root / "fixture.json"),
                "GH_CALLS": str(root / "calls.jsonl"),
                "GITHUB_OUTPUT": str(root / "output"),
                "GITHUB_REPOSITORY": "example/repository",
                "GITHUB_SHA": "b" * 40,
                "EVENT": event,
                "BEFORE": before,
                "PR": "40",
            }
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", DETECT],
                env=env, text=True, capture_output=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = root / "calls.jsonl"
            self.last_calls = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
            return (root / "output").read_text()

    def test_small_documentation_change_skips_code(self):
        paths = ["README.md", "docs/guide.md", "test/results/result.json", "design/ui.html"]
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                self.assertEqual(self.detect(paths, event=event), "code=false\n")

    def test_code_and_generated_contract_inputs_run_code(self):
        for path in ("internal/example.go", "web/src/app.ts", ".github/workflows/ci.yml", "docs/interfaces/api.yaml"):
            for event in ("pull_request", "push"):
                with self.subTest(path=path, event=event):
                    self.assertEqual(self.detect(["docs/guide.md", path], event=event), "code=true\n")

    def test_oversized_pr_runs_code_without_diff_endpoint(self):
        paths = [f"docs/{i}.md" for i in range(350)] + ["internal/hidden.go"]
        self.assertEqual(self.detect(paths), "code=true\n")
        self.assertEqual(len(self.last_calls), 1)
        self.assertEqual(self.last_calls[0][:2], ["api", "repos/example/repository/pulls/40/files?per_page=100"])

    def test_full_page_is_not_trusted_as_documentation_only(self):
        for event, limit in (("pull_request", 100), ("push", 300)):
            with self.subTest(event=event):
                paths = [f"docs/{i}.md" for i in range(limit)]
                self.assertEqual(self.detect(paths[:-1], event=event), "code=false\n")
                self.assertEqual(self.detect(paths, event=event), "code=true\n")
                self.assertEqual(self.detect(paths + ["internal/hidden.go"], event=event), "code=true\n")

    def test_failed_or_malformed_lookup_runs_code(self):
        for event in ("pull_request", "push"):
            for fixture in ({"fail": True}, {"malformed": True}):
                with self.subTest(event=event, fixture=fixture):
                    self.assertEqual(self.detect(["docs/guide.md"], event=event, **fixture), "code=true\n")

    def test_rename_checks_old_and_new_paths(self):
        for event in ("pull_request", "push"):
            for previous in ("internal/example.go", "docs/interfaces/api.yaml"):
                with self.subTest(event=event, previous=previous):
                    self.assertEqual(self.detect(
                        [{"filename": "docs/archived.md", "previous_filename": previous}], event=event,
                    ), "code=true\n")
            self.assertEqual(self.detect(
                [{"filename": "docs/new.md", "previous_filename": "docs/old.md"}], event=event,
            ), "code=false\n")

    def test_empty_unknown_and_initial_push_run_code(self):
        for event in ("pull_request", "push", "workflow_dispatch", "unknown"):
            with self.subTest(event=event):
                self.assertEqual(self.detect([], event=event), "code=true\n")
        for before in ("", "0" * 40):
            self.assertEqual(self.detect(["docs/guide.md"], event="push", before=before), "code=true\n")
            self.assertEqual(self.last_calls, [])


if __name__ == "__main__":
    unittest.main()
