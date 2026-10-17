#!/usr/bin/env python3
"""Closed selector checks; these never create containers or run Go."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

script=Path(__file__).resolve().parent/'test-custody.py'
spec=importlib.util.spec_from_file_location('owner_inventory_fixture',script)
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)

class OwnerInventorySelection(unittest.TestCase):
    def test_closed_cli_selection(self):
        for arguments in [['--fleet'],['--run','TestAnything'],['--database-recovery'],['--initial-installation'],['--connector-retirement'],['--scoped-audit']]:
            with self.subTest(arguments=arguments):
                result=subprocess.run([sys.executable,str(script),'--owner-audit-inventory',*arguments],capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,2)
                self.assertIn('owns its exact',result.stderr)
    def test_closed_programmatic_selection(self):
        for option in ['fleet','test_pattern','database_recovery','initial_installation','connector_retirement','scoped_audit']:
            with self.subTest(option=option):
                with self.assertRaisesRegex(ValueError,'Owner audit inventory owns its exact'):
                    fixture.main(owner_audit_inventory=True,**{option:'TestAnything' if option=='test_pattern' else True})
    def test_inspection_credentials_have_only_list(self):
        identities={item['name']:item for item in fixture.owner_audit_inventory_configuration()['identities']}
        self.assertEqual(set(identities),{'administrator','configuration','inventory'})
        self.assertEqual(identities['inventory']['actions'],['List:'+fixture.OWNER_AUDIT_INVENTORY_BUCKET])
        self.assertFalse(any('inventory'==item['name'] for item in fixture.scoped_audit_configuration()['identities']))
    def test_zero_or_other_pass_cannot_supply_expected_name(self):
        name=fixture.OWNER_AUDIT_INVENTORY_TEST
        self.assertNotIn(name,fixture.passed_test_names('--- SKIP: '+name+' (0.00s)','^'+name+'$'))
        self.assertNotIn(name,fixture.passed_test_names('--- PASS: TestOther (0.01s)','^'+name+'$'))
        self.assertIn(name,fixture.passed_test_names('--- PASS: '+name+' (0.01s)','^'+name+'$'))

if __name__=='__main__':unittest.main()
