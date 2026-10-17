#!/usr/bin/env python3
"""Closed provider fixture selection; this test starts no services."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class OwnerProviderSelection(unittest.TestCase):
    def test_exact_single_cluster_selection(self):
        self.assertEqual(
            fixture.qualification_selection(None, False, False, owner_provider_auth=True),
            ("^TestOwnerProviderAuthenticationWithRealKubernetesAndOpenBao$", 1),
        )

    def test_rejects_every_conflicting_mode(self):
        for options in (
            ("TestOther", False, False, False, False, None, False),
            (None, True, False, False, False, None, False),
            (None, False, True, False, False, None, False),
            (None, False, False, True, False, None, False),
            (None, False, False, False, True, None, False),
            (None, False, False, False, False, "first", False),
            (None, False, False, False, False, "continuation", False),
            (None, False, False, False, False, None, True),
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                fixture.qualification_selection(*options, owner_provider_auth=True)

    def test_environment_cannot_inherit_provider_opt_in(self):
        key = "ASSERVAT_OWNER_PROVIDER_AUTH_NATIVE"
        original = {key: "1", "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE": "1"}
        ordinary = fixture.qualification_environment(original, Path("fixture"), Path("work"), False, False)
        self.assertNotIn(key, ordinary)
        selected = fixture.qualification_environment(original, Path("fixture"), Path("work"), False, False, owner_provider_auth=True)
        self.assertEqual(selected[key], "1")
        self.assertNotIn("ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE", selected)
        self.assertEqual(original, {key: "1", "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE": "1"})

    def test_existing_selection_unchanged(self):
        self.assertEqual(fixture.qualification_selection("TestOther", False, False), ("TestOther", 2))
        self.assertEqual(fixture.qualification_selection(None, False, False, runtime_object_roundtrip=True), ("^TestInitialRuntimeObjectRoundTripWithRealKubernetes$", 1))


if __name__ == "__main__":
    unittest.main()
