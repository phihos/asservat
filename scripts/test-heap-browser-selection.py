#!/usr/bin/env python3
"""Pure installed-fixture wiring checks; no browser, cluster or collection."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]

class HeapBrowserSelection(unittest.TestCase):
    def test_heap_keeps_existing_alias_and_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'python3'
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps([sys.argv[1:],os.environ.get("ASSERVAT_JOURNEY_FOCUS"),os.environ.get("ASSERVAT_PROFILE_VARIANT")]))\n')
            fake.chmod(0o755)
            import json
            result = subprocess.run([str(ROOT/'scripts/ci-native.sh'), 'continuation-manual-heap'], env=dict(os.environ, PATH=directory+os.pathsep+os.environ['PATH']), capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(result.stdout), [['scripts/test-context-storage.py','--initial-bootstrap-chain','--runtime-provider-pair','--installer-continuation'], 'manual-profile','heap'])

    def test_existing_browser_setup_and_frozen_inventory_cover_heap(self):
        workflow = yaml.safe_load((ROOT/'.github/workflows/native.yml').read_text())
        steps = workflow['jobs']['native']['steps']
        browser_steps = [step for step in steps if step.get('id') == 'playwright' or step.get('name') == 'Installed React browser' or step.get('uses') == 'actions/cache@v6' and step.get('with', {}).get('path') == '~/.cache/ms-playwright']
        self.assertEqual(len(browser_steps), 3)
        for step in browser_steps:
            self.assertIn("matrix.suite == 'continuation-manual-heap'", step['if'])
            self.assertIn("matrix.suite == 'continuation-profile-comparison'", step['if'])
            self.assertIn("matrix.suite == 'continuation-profile-comparison-heavy'", step['if'])
        self.assertIn('timeout-minutes: 20', (ROOT/'.github/workflows/native.yml').read_text())
        source=(ROOT/'scripts/test-context-storage.py').read_text()
        self.assertIn('ROOT/"web/scripts/installed-profile-comparison-browser.mjs"',source)
        self.assertIn('report["installedHeapBrowserQualification"] = collector_qualification and focus == "manual-profile" and profile_variant == "heap"',source)
        self.assertIn('HeapProfile)WithBuiltPackage', (ROOT/'Makefile').read_text())

if __name__ == '__main__':
    unittest.main()
