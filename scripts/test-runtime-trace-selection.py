#!/usr/bin/env python3
"""Closed trace selection checks; never starts an external fixture."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('test-context-storage.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class RuntimeTraceSelection(unittest.TestCase):
    def test_closed_variant(self):
        for variant, focus in (('cpu','manual-profile'), ('heap','manual-profile'), ('trace','manual-profile'), ('accepted-heavy','profile-comparison')):
            self.assertEqual(fixture.qualification_profile_variant({'ASSERVAT_PROFILE_VARIANT':variant,'ASSERVAT_JOURNEY_FOCUS':focus}), variant)
        for base in ({'ASSERVAT_PROFILE_VARIANT':'trace','ASSERVAT_JOURNEY_FOCUS':'profile-comparison'}, {'ASSERVAT_PROFILE_VARIANT':'typo'}):
            with self.assertRaises(ValueError):
                fixture.qualification_profile_variant(base)
        with patch.dict(os.environ, {'ASSERVAT_JOURNEY_FOCUS':'manual-profile','ASSERVAT_PROFILE_VARIANT':'trace'}):
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), '18m')
            self.assertEqual(fixture.qualification_cluster_count(3, installer_continuation=True), 2)
    def test_alias(self):
        with tempfile.TemporaryDirectory() as d:
            fake=Path(d)/'python3'
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps([sys.argv[1:],os.environ.get("ASSERVAT_JOURNEY_FOCUS"),os.environ.get("ASSERVAT_PROFILE_VARIANT")]))\n')
            fake.chmod(0o755)
            result=subprocess.run([str(Path(__file__).with_name('ci-native.sh')),'continuation-manual-trace'], env=dict(os.environ, PATH=d+os.pathsep+os.environ['PATH']), capture_output=True,text=True,check=True)
            self.assertEqual(json.loads(result.stdout), [['scripts/test-context-storage.py','--initial-bootstrap-chain','--runtime-provider-pair','--installer-continuation'],'manual-profile','trace'])
    def test_trace_branch_preserves_cpu_and_heap(self):
        root=Path(__file__).resolve().parents[1]
        source=(root/'test/integration/installed_approved_recording_native_test.go').read_text()
        self.assertLess(source.index('qualifyRuntimeTraceSummaryDenied('),source.index('\n\tprepareDownload()'))
        self.assertLess(source.index('qualifyManualRuntimeTraceNative('),source.index('qualifyManualProfileNative('))
        self.assertIn("matrix.suite != 'continuation-manual-trace'",(root/'.github/workflows/native.yml').read_text())
        self.assertIn('timeout-minutes: 20',(root/'.github/workflows/native.yml').read_text())

if __name__ == '__main__': unittest.main()
