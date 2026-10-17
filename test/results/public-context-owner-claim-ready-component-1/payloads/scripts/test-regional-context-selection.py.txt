#!/usr/bin/env python3
"""Pure qualification selection tests; no services or native fixtures."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class RegionalContextSelection(unittest.TestCase):
    def test_exact_first_continuation_and_journey_selection(self):
        for mode in ("first", "continuation", "journey"):
            self.assertEqual(
                fixture.qualification_selection(None, False, False, regional_context_start=mode),
                ("^TestContextAdmissionWithRealServices$/^native-regional-api-" + mode + "$", 2),
            )

    def test_conflicting_or_unknown_selection_is_refused(self):
        for arguments in (
            ("TestOther", False, False, False, False, "first"),
            (None, True, False, False, False, "first"),
            (None, False, True, False, False, "first"),
            (None, False, False, True, False, "first"),
            (None, False, False, False, True, "first"),
            (None, False, False, False, False, "native-api-runner"),
        ):
            with self.assertRaises(ValueError):
                fixture.qualification_selection(*arguments)

    def test_inherited_flags_cannot_change_ordinary_or_selected_run(self):
        flags = {
            "ASSERVAT_CONTEXT_REGIONAL_START_NATIVE": "first",
            "ASSERVAT_INITIAL_HANDOVER_NATIVE": "1",
            "ASSERVAT_INITIAL_SCHEMA_HANDOVER_NATIVE": "1",
            "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE": "1",
            "ASSERVAT_HELM_BOOTSTRAP_NATIVE": "1",
        }
        ordinary = fixture.qualification_environment(flags, Path("fixture"), Path("work"), False, False)
        self.assertFalse(any(key in ordinary for key in flags))
        selected = fixture.qualification_environment(
            flags, Path("fixture"), Path("work"), False, False, regional_context_start="continuation"
        )
        self.assertEqual(
            {key: selected[key] for key in flags if key in selected},
            {"ASSERVAT_CONTEXT_REGIONAL_START_NATIVE": "continuation"},
        )
        self.assertEqual(flags["ASSERVAT_CONTEXT_REGIONAL_START_NATIVE"], "first")

    def test_ordinary_runner_selection_is_unchanged(self):
        pattern = "^TestContextAdmissionWithRealServices$/^native-api-runner$"
        self.assertEqual(fixture.qualification_selection(pattern, False, False), (pattern, 2))

    def test_server_diagnostics_only_affect_journey(self):
        original = ["-c", "max_connections=48", "-c", "shared_buffers=128MB", "-c", "fsync=on", "-c", "synchronous_commit=on"]
        for mode in (None, "first", "continuation"):
            self.assertEqual(fixture.postgres_fixture_options(mode), original)
        journey = fixture.postgres_fixture_options("journey")
        self.assertEqual(journey, original + [
            "-c", "log_line_prefix=%m [%p] role=%u sqlstate=%e ",
            "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
            "-c", "log_error_verbosity=terse",
            "-c", "log_parameter_max_length=0", "-c", "log_parameter_max_length_on_error=0",
        ])
        journey.append("must-not-retain-mutable-options")
        self.assertNotIn("must-not-retain-mutable-options", fixture.postgres_fixture_options("journey"))
        with self.assertRaises(ValueError):
            fixture.postgres_fixture_options("unexpected")


if __name__ == "__main__":
    unittest.main()
