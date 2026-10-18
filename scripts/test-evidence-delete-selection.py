#!/usr/bin/env python3
"""Closed fixture selection checks; never create containers or run Go."""
import importlib.util
from pathlib import Path
import unittest

script = Path(__file__).resolve().parent / "test-custody.py"
spec = importlib.util.spec_from_file_location("evidence_delete_fixture", script)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class EvidenceDeleteSelection(unittest.TestCase):
    def test_only_exact_test_gets_credential_profile(self):
        name = fixture.INSTALLED_EVIDENCE_DELETE_TEST
        self.assertTrue(fixture.installed_evidence_delete_selection("^" + name + "$"))
        for pattern in [None, "", name, "^TestInstalled", "^" + name, name + "$", "^" + name + "$/subtest"]:
            with self.subTest(pattern=pattern):
                self.assertFalse(fixture.installed_evidence_delete_selection(pattern))

    def test_other_profiles_cannot_be_combined(self):
        for option in ["fleet", "database_recovery", "initial_installation", "connector_retirement", "scoped_audit", "owner_audit_inventory"]:
            with self.subTest(option=option):
                with self.assertRaisesRegex(ValueError, "Installed evidence deletion owns its exact"):
                    fixture.main(test_pattern="^" + fixture.INSTALLED_EVIDENCE_DELETE_TEST + "$", **{option: True})

    def test_cleaner_has_no_coarse_read_write_or_admin(self):
        identities = {item["name"]: item for item in fixture.installed_evidence_delete_configuration()["identities"]}
        self.assertEqual(set(identities), {"administrator", "evidence-delete"})
        self.assertEqual(identities["evidence-delete"]["actions"], ["List:" + fixture.INSTALLED_EVIDENCE_DELETE_BUCKET])
        self.assertNotEqual(identities["administrator"]["credentials"], identities["evidence-delete"]["credentials"])

    def test_skip_or_other_pass_cannot_supply_exact_name(self):
        name = fixture.INSTALLED_EVIDENCE_DELETE_TEST
        pattern = "^" + name + "$"
        self.assertNotIn(name, fixture.passed_test_names("--- SKIP: " + name + " (0.00s)", pattern))
        self.assertNotIn(name, fixture.passed_test_names("--- PASS: TestOther (0.01s)", pattern))
        self.assertIn(name, fixture.passed_test_names("--- PASS: " + name + " (0.01s)", pattern))


if __name__ == "__main__":
    unittest.main()
