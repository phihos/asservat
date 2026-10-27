#!/usr/bin/env python3
"""Pure qualification selection tests; no services or native fixtures."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import os
import copy
import io
import json
import tempfile

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class RegionalContextSelection(unittest.TestCase):
    def test_numeric_statistics_are_an_explicit_fixture_option(self):
        ordinary = fixture.postgres_fixture_options()
        measured = fixture.postgres_fixture_options(native_statistics=True)
        self.assertEqual(measured[:len(ordinary)], ordinary)
        self.assertNotIn("shared_preload_libraries=pg_stat_statements", ordinary)
        self.assertIn("shared_preload_libraries=pg_stat_statements", measured)
        self.assertIn("pg_stat_statements.save=off", measured)
        self.assertIn("fsync=on", measured)
        self.assertIn("synchronous_commit=on", measured)
        self.assertEqual(measured.count("max_connections=48"), 1)

    def test_approved_recording_refuses_missing_disposable_guard_before_setup(self):
        for focus in ("approved-recording", "native-paced"):
            with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}), patch.object(fixture.Path, "is_file", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "disposable-host guard"):
                    fixture.main(installer_continuation=True)

    def test_history_driver_and_locked_browser_dependencies_are_source_pinned(self):
        hashes = fixture.source_hashes()
        for name in ("web/scripts/installed-history-browser.mjs", "web/package.json", "web/package-lock.json"):
            self.assertIn(name, hashes)
            self.assertEqual(len(hashes[name]), 64)

    def test_approved_recording_has_finite_go_envelope(self):
        for focus in ("approved-recording", "native-paced"):
            with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}):
                self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "18m")

    def test_installed_focus_topology_and_flags_reach_the_go_consumer(self):
        for focus, expected in (("approved-recording", 2), ("native-paced", 2), ("journey", 2), ("browser", 2),
                                ("policy", 2), ("alert", 2), ("logresource", 2),
                                ("restart", 2), ("upgrade", 2), ("share", 2),
                                ("chain", 2), ("clusters", 3), ("", 3), ("unknown", 3)):
            with self.subTest(focus=focus), patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}):
                pattern, base_count = fixture.qualification_selection(
                    None, False, False, initial_bootstrap_chain=True,
                    runtime_provider_pair=True, installer_continuation=True)
                self.assertEqual(pattern, "^TestInitialBootstrapChainWithRealServices$")
                self.assertEqual(fixture.qualification_cluster_count(base_count, True), expected)
                self.assertEqual(fixture.qualification_cluster_count(2, False), 2)
                env = fixture.qualification_environment(
                    {"ASSERVAT_JOURNEY_FOCUS": focus}, Path("fixture"), Path("work"), False, False,
                    initial_bootstrap_chain=True, runtime_provider_pair=True, installer_continuation=True)
                self.assertEqual(env["ASSERVAT_JOURNEY_FOCUS"], focus)
                for flag in ("ASSERVAT_INSTALLER_CONTINUATION", "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE",
                             "ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR", "ASSERVAT_INITIAL_RUNTIME_BRIDGE"):
                    self.assertEqual(env[flag], "1")

    def test_exact_first_continuation_and_journey_selection(self):
        for mode in ("first", "continuation", "journey"):
            self.assertEqual(
                fixture.qualification_selection(None, False, False, regional_context_start=mode),
                ("^TestContextAdmissionWithRealServices$/^native-regional-api-" + mode + "$", 2),
            )

    def test_native_audit_configuration_keeps_original_mounts_and_no_bodies(self):
        audit = fixture.native_kube_audit
        original = {"nodes": [{"role": "control-plane", "extraMounts": [{"hostPath": "/owned-volume", "containerPath": "/var/lib/etcd"}]}]}
        config = copy.deepcopy(original)
        with tempfile.TemporaryDirectory() as directory:
            audit.configure(config, Path(directory), 0)
            self.assertEqual(config["nodes"][0]["extraMounts"][:-1], original["nodes"][0]["extraMounts"])
            policy = json.loads((Path(directory)/"native-audit-policy-0.json").read_text())
            self.assertEqual([rule["level"] for rule in policy["rules"]], ["Metadata", "Metadata", "Metadata", "None"])
            self.assertNotIn("RequestResponse", json.dumps(policy))
            patch_data = json.loads(config["nodes"][0]["kubeadmConfigPatches"][0])
            args = {arg["name"]: arg["value"] for arg in patch_data["apiServer"]["extraArgs"]}
            self.assertEqual((args["audit-log-maxsize"], args["audit-log-maxbackup"]), ("32", "3"))
            self.assertEqual(args["audit-log-mode"], "blocking-strict")
            self.assertEqual(patch_data["apiVersion"], "kubeadm.k8s.io/v1beta4")

    def test_native_audit_counts_background_inclusive_phases_without_private_fields(self):
        audit = fixture.native_kube_audit
        phases = [{"name": "paced", "startedAt": "2026-10-27T12:00:01Z", "finishedAt": "2026-10-27T12:00:03Z"}]
        def event(second, resource="serviceaccounts", verb="get", number=1):
            return {"apiVersion": "audit.k8s.io/v1", "kind": "Event", "level": "Metadata", "stage": "RequestReceived", "auditID": "00000000-0000-4000-8000-"+str(number).zfill(12),
                    "requestReceivedTimestamp": f"2026-10-27T12:00:0{second}Z", "stageTimestamp": f"2026-10-27T12:00:0{second}.000001Z",
                    "objectRef": {"resource": resource, "apiGroup": "authentication.k8s.io" if resource == "tokenreviews" else ""}, "verb": verb,
                    "user": {"username": "PRIVATE-IDENTITY"}, "requestURI": "/PRIVATE-PATH"}
        def framed(events):
            data = b"".join(json.dumps(e).encode()+b"\n" for e in events)
            return io.BytesIO(str(len(data)).encode()+b" audit.log\n"+data+b"\n")
        events = [event(0, number=1), event(1, number=2), event(2, "tokenreviews", "create", 3), event(4, number=4)]
        events[0]["requestURI"] = "/readyz"
        events[-1]["requestURI"] = "/readyz"
        marker = event(2, number=5)
        marker["requestURI"] = "/readyz"
        events.append(marker)
        result = audit.aggregate(framed(events), phases)
        self.assertEqual(result["phases"][0]["serviceAccountGet"], 1)
        self.assertEqual(result["phases"][0]["tokenReviewCreate"], 1)
        self.assertEqual(result["coverageMarkers"], 3)
        self.assertNotIn("PRIVATE", json.dumps(result))
        for mode in ("lost beginning", "lost end", "duplicate", "request body", "truncated", "wrong category"):
            with self.subTest(mode=mode):
                bad = copy.deepcopy(events)
                if mode == "lost beginning": bad = bad[2:]
                if mode == "lost end": bad = bad[:3]
                if mode == "duplicate": bad.append(bad[0])
                if mode == "request body": bad[1]["requestObject"] = {"token": "MUST-NOT-EXPORT"}
                if mode == "wrong category": bad[1]["objectRef"]["resource"] = "secrets"
                data = framed(bad)
                if mode == "truncated": data = io.BytesIO(data.getvalue()[:-2])
                with self.assertRaises(ValueError): audit.aggregate(data, phases)

    def test_native_audit_phase_names_and_original_intervals_are_closed(self):
        audit = fixture.native_kube_audit
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"phases.json"
            phase = {"name": "paced", "startedAt": "2026-10-27T12:00:01.123456789Z", "finishedAt": "2026-10-27T12:00:03Z"}
            path.write_text(json.dumps({"phases": [phase]}))
            self.assertEqual(audit.phases_from_report(path), [phase])
            for changed in ({**phase, "name": "arbitrary-role-name"}, {**phase, "finishedAt": "2026-10-27T12:00:00Z"}, {**phase, "startedAt": "2026-10-27T12:00:01+03:00"}):
                path.write_text(json.dumps({"phases": [changed]}))
                with self.assertRaises(ValueError): audit.phases_from_report(path)
            for second_start in ("2026-10-27T12:00:02Z", "2026-10-27T12:00:00Z"):
                second = {"name": "unpaced", "startedAt": second_start, "finishedAt": "2026-10-27T12:00:04Z"}
                path.write_text(json.dumps({"phases": [phase, second]}))
                with self.assertRaises(ValueError): audit.phases_from_report(path)
            second["startedAt"] = phase["finishedAt"]
            path.write_text(json.dumps({"phases": [phase, second]}))
            self.assertEqual(len(audit.phases_from_report(path)), 2)

    def test_native_audit_never_substitutes_another_control_plane(self):
        audit = fixture.native_kube_audit
        cluster = "asservat-context-owned-0"
        identity = "a" * 64
        observed = {"Id": identity, "Name": "/"+cluster+"-control-plane", "Config": {"Labels": {"io.x-k8s.kind.cluster": cluster, "io.x-k8s.kind.role": "control-plane"}}}
        with patch.object(audit.subprocess, "check_output", return_value=json.dumps([observed])) as invoke:
            self.assertEqual(audit.owned_node(cluster, identity)["id"], identity)
            self.assertEqual(invoke.call_args.args[0], ["docker", "inspect", identity])
            for changed in ({**observed, "Id": "b"*64}, {**observed, "Name": "/unrelated-control-plane"}, {**observed, "Config": {"Labels": {}}}):
                invoke.return_value = json.dumps([changed])
                with self.assertRaises(ValueError): audit.owned_node(cluster, identity)
        with patch.object(audit.subprocess, "check_output") as invoke:
            with self.assertRaises(ValueError): audit.owned_node(cluster, "--all")
            invoke.assert_not_called()

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
        locks = fixture.postgres_fixture_options(None, lock_waits=True)
        self.assertEqual(locks[:len(original)], original)
        self.assertIn("log_lock_waits=on", locks)
        self.assertNotIn("log_statement=all", locks)
        self.assertEqual(fixture.postgres_fixture_options(None), original)
        journey.append("must-not-retain-mutable-options")
        self.assertNotIn("must-not-retain-mutable-options", fixture.postgres_fixture_options("journey"))
        with self.assertRaises(ValueError):
            fixture.postgres_fixture_options("unexpected")

    def test_installed_budget_is_explicit_and_does_not_change_components(self):
        # The runner receives this from the Go plan helper, not a Python copy
        # of the growing product purpose inventory.
        budget = {"requiredOrdinary": 112, "superuserReserved": 3,
                  "reserved": 0, "fixtureAdminConnections": 1,
                  "maxConnections": 116}
        options = fixture.postgres_fixture_options(installed_budget=budget, lock_waits=True)
        self.assertIn("max_connections=116", options)
        self.assertIn("superuser_reserved_connections=3", options)
        self.assertIn("reserved_connections=0", options)
        self.assertIn("log_disconnections=on", options)
        self.assertIn("max_connections=48", fixture.postgres_fixture_options())
        # The observer is independent of reserve eligibility or connection order.
        no_reserve = dict(budget, superuserReserved=0, maxConnections=113)
        self.assertIn("max_connections=113", fixture.postgres_fixture_options(installed_budget=no_reserve))
        extra_reserve = dict(budget, reserved=5, maxConnections=121)
        self.assertIn("reserved_connections=5", fixture.postgres_fixture_options(installed_budget=extra_reserve))
        for field, value in (("maxConnections", 115), ("requiredOrdinary", 0),
                             ("fixtureAdminConnections", 4), ("reserved", -1), ("superuserReserved", -1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.postgres_fixture_options(installed_budget=dict(budget, **{field: value}))


if __name__ == "__main__":
    unittest.main()
