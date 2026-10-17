#!/usr/bin/env python3
"""Pure closed native resource qualification selection; starts no services."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class RuntimeObjectSelection(unittest.TestCase):
    def test_exact_single_cluster_selection(self):
        self.assertEqual(
            fixture.qualification_selection(None, False, False, runtime_object_roundtrip=True),
            ("^TestInitialRuntimeObjectRoundTripWithRealKubernetes$", 1),
        )

    def test_conflicting_modes_are_rejected(self):
        for options in (
            ("TestOther", False, False, False, False, None),
            (None, True, False, False, False, None),
            (None, False, True, False, False, None),
            (None, False, False, True, False, None),
            (None, False, False, False, True, None),
            (None, False, False, False, False, "first"),
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                fixture.qualification_selection(*options, runtime_object_roundtrip=True)

    def test_original_ordinary_and_regional_selection(self):
        self.assertEqual(fixture.qualification_selection("TestOther", False, False), ("TestOther", 2))
        self.assertEqual(
            fixture.qualification_selection(None, False, False, regional_context_start="first"),
            ("^TestContextAdmissionWithRealServices$/^native-regional-api-first$", 2),
        )

    def test_inherited_opt_in_does_not_enable_another_run(self):
        original = {"ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE": "1"}
        ordinary = fixture.qualification_environment(original, Path("fixture"), Path("work"), False, False)
        self.assertNotIn("ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE", ordinary)
        selected = fixture.qualification_environment({}, Path("fixture"), Path("work"), False, False, runtime_object_roundtrip=True)
        self.assertEqual(selected["ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE"], "1")
        self.assertEqual(original, {"ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE": "1"})


if __name__ == "__main__":
    unittest.main()
