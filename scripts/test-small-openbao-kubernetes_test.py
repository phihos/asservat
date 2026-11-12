#!/usr/bin/env python3
"""Offline exact-owner cleanup validation; never starts a fixture."""
import copy
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('bao_kubernetes', Path(__file__).with_name('test-small-openbao-kubernetes.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class KeptOwnerTest(unittest.TestCase):
    def setUp(self):
        self.manifest = runner.CACHE / 'small-installation/openbao-kubernetes/unit/kept-resources.json'
        self.data = {'format': 'asservat-openbao-kept/v1', 'owner': 'asv-bao-k8s-0123456789',
                     'nodeID': 'a' * 64, 'volumes': [{'Name': 'b' * 64, 'CreatedAt': '2026-11-12T12:00:00Z', 'Driver': 'local', 'Labels': None}],
                     'image': 'asv-bao-k8s-0123456789:probe', 'imageID': 'sha256:' + 'c' * 64,
                     'workDirectory': str(runner.CACHE / 'openbao-kubernetes-private-abc_123')}

    def test_exact_original_inventory(self):
        owner, work = runner.validate_kept(self.manifest, self.data)
        self.assertEqual(owner, self.data['owner'])
        self.assertEqual(work.parent, runner.CACHE)

    def test_foreign_or_broad_cleanup_refused(self):
        for field, value in [('owner', 'haptic-e2e'), ('workDirectory', str(Path.home())),
                             ('image', 'ghcr.io/openbao/openbao:latest'), ('nodeID', 'replacement'),
                             ('volumes', [{'Name': 'shared-volume', 'CreatedAt': 'now', 'Driver': 'local', 'Labels': None}]),
                             ('extra', True)]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.data)
                changed[field] = value
                with self.assertRaises(ValueError):
                    runner.validate_kept(self.manifest, changed)
        with self.assertRaises(ValueError):
            runner.validate_kept(Path('/tmp/foreign.json'), self.data)


if __name__ == '__main__':
    unittest.main()
