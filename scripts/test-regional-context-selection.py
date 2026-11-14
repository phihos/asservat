#!/usr/bin/env python3
"""Pure qualification selection tests; no services or native fixtures."""
import ast
import inspect
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import os
import copy
import io
import json
import tempfile
import hashlib
import subprocess
import signal
import sys
import time
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("context_fixture", Path(__file__).with_name("test-context-storage.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)



def native_needs(suite):
    """The runner setup native.yml gives suite (ci-native.sh --matrix)."""
    out = subprocess.check_output([str(Path(__file__).with_name("ci-native.sh")), "--matrix", json.dumps([suite])], text=True)
    return json.loads(out)["include"][0]


class RegionalContextSelection(unittest.TestCase):
    def test_bundled_identity_owns_same_api_automatic_helm_workflow(self):
        selected = dict(helm_bootstrap=True, installer_continuation=True, bundled_identity=True)
        self.assertEqual(fixture.qualification_selection(None, False, False, **selected), ("^TestHelmBootstrapWithRealServices$", 1))
        self.assertEqual(fixture.qualification_go_timeout(helm_bootstrap=True, installer_continuation=True, bundled_identity=True), "22m")
        with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": "journey"}, clear=True):
            self.assertEqual(fixture.qualification_cluster_count(3, True, bundled_identity=True), 1)
        for invalid in (dict(selected, helm_bootstrap=False), dict(selected, installer_continuation=False), dict(selected, runtime_provider_pair=True), dict(selected, initial_bootstrap_chain=True)):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "Bundled identity"):
                fixture.qualification_selection(None, False, False, **invalid)
        options = dict(selected, bundled_postgres=True, bundled_keyservice=True, bundled_objectstore=True)
        with tempfile.TemporaryDirectory() as directory:
            env = fixture.qualification_environment({"ASSERVAT_HELM_CONTEXT_NATIVE": "1", "ASSERVAT_HELM_CONTEXT_TOPOLOGY": "same-api"}, "fixture.json", Path(directory), False, False, **options)
            self.assertEqual(env["ASSERVAT_HELM_BUNDLED_IDENTITY"], "1")
            self.assertEqual(env["ASSERVAT_INSTALLER_CONTINUATION"], "1")
            self.assertNotIn("ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR", env)
            # This is the existing all-service Helm driver, not a competing
            # bootstrap-chain/impersonation path or an external identity realm.
            self.assertNotIn("ASSERVAT_HELM_CONTEXT_NATIVE", env)
            clean = fixture.qualification_environment({"ASSERVAT_HELM_BUNDLED_IDENTITY": "1"}, "fixture.json", Path(directory), False, False)
            self.assertNotIn("ASSERVAT_HELM_BUNDLED_IDENTITY", clean)
        for missing in ("bundled_postgres", "bundled_keyservice", "bundled_objectstore", "helm_bootstrap", "installer_continuation"):
            invalid = dict(options, **{missing: False})
            with self.subTest(missing=missing), patch.object(fixture, "run", side_effect=AssertionError("external setup")) as external:
                with self.assertRaisesRegex(ValueError, "Bundled identity"):
                    fixture.main(**invalid)
                external.assert_not_called()

    def test_bundled_public_requires_both_exact_positive_stage_receipts(self):
        prefix = "TestHelmBootstrapWithRealServices/"
        login, context = prefix + "bundled-public-login", prefix + "bundled-context-journey"
        expected = ["bundled-public-login", "bundled-context-journey"]
        self.assertEqual(fixture.missing_bundled_public_stages(set()), expected)
        self.assertEqual(fixture.missing_bundled_public_stages({"TestHelmBootstrapWithRealServices"}), expected)
        self.assertEqual(fixture.missing_bundled_public_stages({login}), ["bundled-context-journey"])
        self.assertEqual(fixture.missing_bundled_public_stages({context}), ["bundled-public-login"])
        self.assertEqual(fixture.missing_bundled_public_stages({login, context + "/child"}), ["bundled-context-journey"])
        self.assertEqual(fixture.missing_bundled_public_stages({login, context}), [])

    def test_bundled_restart_requires_its_own_exact_receipt(self):
        prefix = "TestHelmBootstrapWithRealServices/"
        base = {prefix + stage for stage in fixture.BUNDLED_PUBLIC_REQUIRED_STAGES}
        restart = "bundled-context-journey/postgres-restart"
        self.assertEqual(fixture.missing_bundled_public_stages(base, "restart"), [restart])
        self.assertEqual(fixture.missing_bundled_public_stages(base | {prefix + restart + "/child"}, "restart"), [restart])
        self.assertEqual(fixture.missing_bundled_public_stages(base | {prefix + restart}, "restart"), [])
        self.assertEqual(fixture.bundled_public_focus({}), "journey")
        self.assertEqual(fixture.bundled_public_focus({"ASSERVAT_JOURNEY_FOCUS": "restart"}), "restart")
        options = dict(helm_bootstrap=True, installer_continuation=True, bundled_identity=True,
                       bundled_postgres=True, bundled_keyservice=True, bundled_objectstore=True)
        env = fixture.qualification_environment({"ASSERVAT_JOURNEY_FOCUS": "restart"}, "fixture", Path("work"), False, False, **options)
        self.assertEqual(env["ASSERVAT_JOURNEY_FOCUS"], "restart")
        for focus in ("manual-profile", "journey,restart", "restart,restart"):
            with self.subTest(focus=focus), patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}, clear=True):
                with patch.object(fixture, "run", side_effect=AssertionError("external setup")) as external:
                    with self.assertRaises(ValueError):
                        fixture.main(**options)
                    external.assert_not_called()

    def test_manual_logs_api_only_focus_and_resource_selector(self):
        with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS":"manual-logs"}):
            self.assertEqual(fixture.qualification_cluster_count(3, installer_continuation=True),2)
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True),"18m")
        source=Path(fixture.__file__).read_text()
        collector=next(line for line in source.splitlines() if line.strip().startswith("collector_qualification ="))
        self.assertNotIn('"manual-logs"',collector)
        self.assertIn('report["installedLogsQueryQualification"] = installer_continuation and "manual-logs" in foci',source)
        selected=json.loads(subprocess.check_output([str(Path(__file__).with_name("ci-native.sh")),"--list"],text=True))
        self.assertIn("continuation-manual-logs",selected)
        self.assertIn("logs-resource",selected)

    def test_cancelled_go_capture_retains_partial_output_and_source_checkpoint(self):
        # Real subprocesses, no cluster/services: terminate the harness while a
        # tiny flushed child is still alive. A partial checkpoint is not a pass.
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            marker = results/"child-started"
            source = Path(fixture.__file__).resolve()
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            child = "import pathlib,time;print('=== RUN   SyntheticPartial',flush=True);print('synthetic stage reached',flush=True);pathlib.Path(" + repr(str(marker)) + ").write_text('started');time.sleep(30)"
            code = "\n".join([
                "import importlib.util, json, os, sys",
                "from pathlib import Path",
                "sys.path.insert(0, " + repr(str(source.parent)) + ")",
                "spec=importlib.util.spec_from_file_location('context_fixture', " + repr(str(source)) + ")",
                "h=importlib.util.module_from_spec(spec); spec.loader.exec_module(h)",
                "results=Path(" + repr(str(results)) + ")",
                "report={'harnessState':'setup','goTestExit':None,'testExit':None,'cleanupComplete':False,'sourceHashes':{'scripts/test-context-storage.py':" + repr(digest) + "}}",
                "child=" + repr(child),
                "h.record_go_output([sys.executable,'-u','-c',child],os.environ.copy(),results,report)",
            ])
            process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                until = time.monotonic() + 5
                while not marker.exists() and process.poll() is None and time.monotonic() < until:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), "synthetic child did not start")
                # Allow the harness to consume the flushed line before killing
                # both test-owned processes; buffered files still lose it.
                until = time.monotonic() + 1
                while time.monotonic() < until:
                    log, timing = results/"context-storage.log", results/"context-storage-timing.log"
                    if log.exists() and timing.exists():
                        timed = timing.read_bytes().splitlines()
                        if log.read_bytes() == b"=== RUN   SyntheticPartial\nsynthetic stage reached\n" and len(timed) == 2 and timed[0].endswith(b"=== RUN   SyntheticPartial") and timed[1].endswith(b"synthetic stage reached"):
                            break
                    time.sleep(.01)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate(timeout=5)
            self.assertNotEqual(process.returncode, 0, (stdout, stderr))
            self.assertEqual((results/"context-storage.log").read_bytes(), b"=== RUN   SyntheticPartial\nsynthetic stage reached\n")
            timing = (results/"context-storage-timing.log").read_text().splitlines()
            self.assertEqual([line.split(maxsplit=1)[1] for line in timing], ["=== RUN   SyntheticPartial", "synthetic stage reached"])
            report = json.loads((results/"context-storage-environment.json").read_text())
            self.assertEqual(report, {'harnessState':'running','goTestExit':None,'testExit':None,'cleanupComplete':False,'sourceHashes':{'scripts/test-context-storage.py':digest}})

    def test_go_capture_preserves_child_exit_and_exact_output(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            report = {"sourceHashes": {}, "testExit": None, "goTestExit": None, "cleanupComplete": False}
            status = fixture.record_go_output([sys.executable, "-c", "import sys;print('synthetic failure',flush=True);sys.exit(7)"], os.environ.copy(), results, report)
            self.assertEqual(status, 7)
            self.assertEqual((results/"context-storage.log").read_bytes(), b"synthetic failure\n")
            self.assertEqual(json.loads((results/"context-storage-environment.json").read_text()), dict(report, harnessState="running"))
            self.assertIsNone(report["goTestExit"])
            self.assertFalse(report["cleanupComplete"])

    def test_profile_auth_alias_is_closed_and_preserves_existing_defaults(self):
        with tempfile.TemporaryDirectory() as directory:
            fake=Path(directory)/"python3"
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({"args":sys.argv[1:],"focus":os.environ.get("ASSERVAT_JOURNEY_FOCUS"),"variant":os.environ.get("ASSERVAT_PROFILE_VARIANT"),"transport":os.environ.get("ASSERVAT_PROFILE_TRANSPORT"),"auth":os.environ.get("ASSERVAT_PROFILE_AUTH")}))\n')
            fake.chmod(0o755)
            env=dict(os.environ,PATH=directory+os.pathsep+os.environ["PATH"],ASSERVAT_PROFILE_VARIANT="heap",ASSERVAT_PROFILE_TRANSPORT="http",ASSERVAT_PROFILE_AUTH="typo")
            result=subprocess.run([str(Path(__file__).with_name("ci-native.sh")),"continuation-manual-profile-auth"],env=env,capture_output=True,text=True,check=True)
            selected=json.loads(result.stdout)
            self.assertEqual(selected,{"args":["scripts/test-context-storage.py","--initial-bootstrap-chain","--runtime-provider-pair","--installer-continuation"],"focus":"manual-profile","variant":"cpu","transport":"tls","auth":"required"})
            for suite in ("continuation-manual-profile","continuation-manual-profile-tls","continuation-manual-heap","continuation-manual-trace","continuation-profile-comparison","continuation-profile-comparison-heavy"):
                with self.subTest(suite=suite):
                    current=subprocess.run([str(Path(__file__).with_name("ci-native.sh")),suite],env=env,capture_output=True,text=True,check=True)
                    self.assertEqual(json.loads(current.stdout)["auth"],"none")
        for base in ({},{"ASSERVAT_PROFILE_AUTH":""},{"ASSERVAT_PROFILE_AUTH":"none"}):
            self.assertEqual(fixture.qualification_profile_auth(base),"none")
        accepted={"ASSERVAT_JOURNEY_FOCUS":"manual-profile","ASSERVAT_PROFILE_VARIANT":"cpu","ASSERVAT_PROFILE_TRANSPORT":"tls","ASSERVAT_PROFILE_AUTH":"required"}
        self.assertEqual(fixture.qualification_profile_auth(accepted),"required")
        invalid=[dict(accepted,ASSERVAT_PROFILE_AUTH="typo"),dict(accepted,ASSERVAT_PROFILE_TRANSPORT="http"),dict(accepted,ASSERVAT_PROFILE_VARIANT="heap"),dict(accepted,ASSERVAT_PROFILE_VARIANT="trace"),dict(accepted,ASSERVAT_JOURNEY_FOCUS="profile-comparison"),{"ASSERVAT_PROFILE_AUTH":"required"}]
        for base in invalid:
            with self.subTest(base=base):
                with self.assertRaisesRegex(ValueError,"auth"):
                    fixture.qualification_profile_auth(base)
        for base in (dict(accepted,ASSERVAT_PROFILE_AUTH="typo"),dict(accepted,ASSERVAT_PROFILE_TRANSPORT="http")):
            with self.subTest(base=base),patch.dict(os.environ,base,clear=True),patch.object(fixture,"run",side_effect=AssertionError("external setup")) as external:
                with self.assertRaisesRegex(ValueError,"auth"):
                    fixture.main(installer_continuation=True)
                external.assert_not_called()
        with patch.dict(os.environ,accepted,clear=True):
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True),"18m")
            self.assertEqual(fixture.qualification_cluster_count(3,installer_continuation=True),2)
        self.assertFalse(native_needs("continuation-manual-profile-auth")["tshark"])

    def test_tls_transport_alias_is_closed_and_keeps_cpu_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            fake=Path(directory)/"python3"
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({"args":sys.argv[1:],"focus":os.environ.get("ASSERVAT_JOURNEY_FOCUS"),"variant":os.environ.get("ASSERVAT_PROFILE_VARIANT"),"transport":os.environ.get("ASSERVAT_PROFILE_TRANSPORT")}))\n')
            fake.chmod(0o755)
            env=dict(os.environ,PATH=directory+os.pathsep+os.environ["PATH"],ASSERVAT_PROFILE_VARIANT="heap",ASSERVAT_PROFILE_TRANSPORT="typo")
            result=subprocess.run([str(Path(__file__).with_name("ci-native.sh")),"continuation-manual-profile-tls"],env=env,capture_output=True,text=True,check=True)
            selected=json.loads(result.stdout)
            self.assertEqual(selected,{"args":["scripts/test-context-storage.py","--initial-bootstrap-chain","--runtime-provider-pair","--installer-continuation"],"focus":"manual-profile","variant":"cpu","transport":"tls"})
        for base in ({"ASSERVAT_PROFILE_TRANSPORT":"typo"},{"ASSERVAT_PROFILE_TRANSPORT":"tls","ASSERVAT_JOURNEY_FOCUS":"profile-comparison"},{"ASSERVAT_PROFILE_TRANSPORT":"tls","ASSERVAT_JOURNEY_FOCUS":"manual-profile","ASSERVAT_PROFILE_VARIANT":"heap"}):
            with self.subTest(base=base),patch.dict(os.environ,base,clear=True),patch.object(fixture,"run",side_effect=AssertionError("external setup")) as external:
                with self.assertRaisesRegex(ValueError,"transport"):
                    fixture.main(installer_continuation=True)
                external.assert_not_called()
        with patch.dict(os.environ,{"ASSERVAT_PROFILE_TRANSPORT":"tls","ASSERVAT_JOURNEY_FOCUS":"manual-profile","ASSERVAT_PROFILE_VARIANT":"cpu"},clear=True),patch.object(fixture,"run",side_effect=AssertionError("external setup")) as external:
            with self.assertRaisesRegex(ValueError,"transport"):
                fixture.main(installer_continuation=False)
            external.assert_not_called()
        self.assertEqual(fixture.qualification_profile_transport({}),"http")
        with patch.dict(os.environ,{"ASSERVAT_JOURNEY_FOCUS":"manual-profile","ASSERVAT_PROFILE_VARIANT":"cpu","ASSERVAT_PROFILE_TRANSPORT":"tls"},clear=True):
            self.assertEqual(fixture.qualification_profile_transport(os.environ),"tls")
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True),"18m")
            self.assertEqual(fixture.qualification_cluster_count(3,installer_continuation=True),2)
        self.assertFalse(native_needs("continuation-manual-profile-tls")["tshark"])

    def test_accepted_heavy_alias_keeps_existing_focus_limits_and_pins_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            fake=Path(directory)/"python3"
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({"args":sys.argv[1:],"focus":os.environ.get("ASSERVAT_JOURNEY_FOCUS"),"variant":os.environ.get("ASSERVAT_PROFILE_VARIANT")}))\n')
            fake.chmod(0o755)
            env=dict(os.environ,PATH=directory+os.pathsep+os.environ["PATH"],ASSERVAT_PROFILE_VARIANT="heap")
            result=subprocess.run([str(Path(__file__).with_name("ci-native.sh")),"continuation-profile-comparison-heavy"],env=env,capture_output=True,text=True,check=True)
            selected=json.loads(result.stdout)
            self.assertEqual(selected,{"args":["scripts/test-context-storage.py","--initial-bootstrap-chain","--runtime-provider-pair","--installer-continuation"],"focus":"profile-comparison","variant":"accepted-heavy"})
        with patch.dict(os.environ,{"ASSERVAT_JOURNEY_FOCUS":"profile-comparison","ASSERVAT_PROFILE_VARIANT":"accepted-heavy"}):
            self.assertEqual(fixture.qualification_profile_variant(os.environ),"accepted-heavy")
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True),"18m")
            self.assertEqual(fixture.qualification_cluster_count(3,installer_continuation=True),2)
        with self.assertRaises(ValueError):
            fixture.qualification_profile_variant({"ASSERVAT_JOURNEY_FOCUS":"manual-profile","ASSERVAT_PROFILE_VARIANT":"accepted-heavy"})
        workflow=(Path(__file__).resolve().parents[1]/".github/workflows/native.yml").read_text()
        heavy=native_needs("continuation-profile-comparison-heavy")
        self.assertTrue(heavy["guard"])
        self.assertFalse(heavy["tshark"])
        self.assertTrue(heavy["builder"])
        self.assertIn("timeout-minutes: 20",workflow)
        source=(Path(__file__).resolve().parents[1]/"test/integration/installed_profile_comparison_native_test.go").read_text()
        self.assertLess(source.index("resources[0](index, handle, operation, pair, true)"),source.index("\n\tproofs.flush(t)"))

    def test_accepted_heavy_generator_image_provenance_and_nonroot_readability(self):
        # This checks provenance plumbing with synthetic bytes; the separate
        # real generator component proves that its native pprof is accepted.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"test/results").mkdir(parents=True)
            image=root/"image";image.mkdir()
            generator=root/"profile-heavy-generator.test"
            def compile_fake(command,**kwargs):
                output=Path(command[command.index("-o")+1])
                output.write_bytes(b"synthetic trusted build output")
                self.assertEqual(kwargs["env"]["CGO_ENABLED"],"0")
            def generate_fake(command,**kwargs):
                generator_sha=hashlib.sha256(generator.read_bytes()).hexdigest()
                manifest={"format":"accepted-heavy-pprof-fixture/v1","generator_binary_sha256":generator_sha,"profile_type":"cpu","sample_type":"cpu","unit":"nanoseconds","duration_ns":10000000000,"inputs":[]}
                for side in ("baseline","incident"):
                    p=image/("profile-heavy-"+side+".pb.gz")
                    with p.open("wb") as out:out.truncate(8*1024**2+1)
                    with p.open("rb") as source:digest=hashlib.file_digest(source,"sha256").hexdigest()
                    manifest["inputs"].append({"filename":p.name,"side":side,"native_bytes":p.stat().st_size,"native_sha256":digest,"protobuf_bytes":16*1024**2-56,"functions":100000,"locations":100000,"samples":100000,"frame_visits":1048576,"sample_location_references":1048576,"inline_lines":100000,"values_per_sample":16,"sample_types":16,"numeric_label_records_with_units":32768,"shared_object_units":662144})
                (image/"profile-heavy-manifest.json").write_text(json.dumps(manifest))
                self.assertNotIn("GOMEMLIMIT",kwargs["env"])
                self.assertEqual(kwargs["env"]["GOMAXPROCS"],"2")
                return SimpleNamespace(pid=12345,returncode=None)
            report={}
            with patch.object(fixture,"ROOT",root),patch.object(fixture.subprocess,"run",side_effect=compile_fake),patch.object(fixture.subprocess,"Popen",side_effect=generate_fake),patch.object(fixture.os,"wait4",return_value=(12345,0,SimpleNamespace(ru_maxrss=487412,ru_utime=2.0,ru_stime=0.2))):
                metadata=fixture.prepare_profile_containment_fixture({"CGO_ENABLED":"0","GOMEMLIMIT":"must-not-leak"},root,image,report)
            self.assertFalse(any((root/"test/results").iterdir()), "producer wrote generated artifacts before explicit terminal collection")
            self.assertEqual(metadata["OutputDirectory"],str(root/"profile-containment"))
            self.assertTrue((root/"profile-containment/profile-heavy-generation.log").is_file())
            self.assertTrue((root/"profile-containment/profile-heavy-manifest.json").is_file())
            self.assertEqual(report["profileHeavyGeneration"]["peakRSSKiB"],487412)
            self.assertEqual(report["profileHeavyGeneration"]["exitCode"],0)
            self.assertFalse(report["profileHeavyGeneration"]["timedOut"])
            self.assertEqual(report["profileHeavyImageNativeBytes"],2*(8*1024**2+1))
            self.assertEqual(metadata["ResourceProbeSHA256"],hashlib.sha256((image/"worker-resource-probe").read_bytes()).hexdigest())
            for item in metadata["Manifest"]["inputs"]:
                self.assertEqual((image/item["filename"]).stat().st_mode&0o777,0o444)
            p=image/metadata["Manifest"]["inputs"][0]["filename"]
            p.chmod(0o600)
            with p.open("r+b") as f:f.write(b"changed")
            with self.assertRaisesRegex(RuntimeError,"hash/bound"):
                fixture.validate_profile_heavy_manifest(image,metadata["Manifest"]["generator_binary_sha256"])

    def test_failed_heavy_producer_retains_original_artifacts_for_terminal_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            results=root/"test/results"; results.mkdir(parents=True)
            work=root/"private-run"; work.mkdir(mode=0o700)
            image=work/"image"; image.mkdir()
            def compile_fake(command,**kwargs):
                Path(command[command.index("-o")+1]).write_bytes(b"synthetic generator binary")
            def fail_fake(command,**kwargs):
                kwargs["stdout"].write(b"synthetic producer terminal failure")
                (image/"profile-heavy-manifest.json").write_bytes(b"partial producer manifest")
                return SimpleNamespace(pid=12345,returncode=None)
            report={}
            with patch.object(fixture,"ROOT",root),patch.object(fixture.subprocess,"run",side_effect=compile_fake),patch.object(fixture.subprocess,"Popen",side_effect=fail_fake),patch.object(fixture.os,"wait4",return_value=(12345,256,SimpleNamespace(ru_maxrss=1,ru_utime=0.0,ru_stime=0.0))):
                with self.assertRaisesRegex(RuntimeError,"separate producer failed"):
                    fixture.prepare_profile_containment_fixture({"CGO_ENABLED":"0"},work,image,report)
            self.assertEqual(report["profileHeavyGeneration"]["exitCode"],1)
            self.assertFalse(any(results.iterdir()))
            collected=fixture.collect_profile_containment_artifacts(work,results)
            destination=Path(collected["directory"])
            self.assertEqual((destination/"profile-heavy-generation.log").read_bytes(),b"synthetic producer terminal failure")
            self.assertEqual((destination/"profile-heavy-manifest.json").read_bytes(),b"partial producer manifest")

    def test_containment_terminal_collection_preserves_success_and_failure_before_cleanup(self):
        for complete in (False, True):
            with self.subTest(complete=complete), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                work=root/"private-run"; work.mkdir(mode=0o700)
                artifacts=work/"profile-containment"; artifacts.mkdir(mode=0o700)
                results=root/"results"; results.mkdir()
                (artifacts/"profile-heavy-generation.log").write_bytes(b"trusted generator output")
                (artifacts/"profile-heavy-manifest.json").write_text('{"synthetic":true}')
                kind="complete" if complete else "failure"
                name=f"profile-worker-containment-0-{kind}.json"
                (artifacts/name).write_text(json.dumps({"resourceQualified":complete}))
                (artifacts/"unrelated-private-file").write_text("must not be collected")
                self.assertFalse(any(results.iterdir()))
                report=fixture.collect_profile_containment_artifacts(work,results)
                expected=["profile-heavy-generation.log","profile-heavy-manifest.json",name]
                self.assertEqual(report["files"],expected)
                destination=Path(report["directory"])
                self.assertEqual(destination.parent,results)
                for name in expected:
                    self.assertEqual((destination/name).read_bytes(),(artifacts/name).read_bytes())
                self.assertFalse((destination/"unrelated-private-file").exists())
                # Collection survives the actual following private-work cleanup.
                import shutil
                shutil.rmtree(work)
                self.assertEqual(json.loads((destination/f"profile-worker-containment-0-{kind}.json").read_text()),{"resourceQualified":complete})
        source=inspect.getsource(fixture.main)
        terminal=source.index('finally:\n            report["testExit"]')
        collect=source.index("collect_profile_containment_artifacts(work",terminal)
        cleanup=source.index('keep = (keep_on_failure',terminal)
        self.assertLess(terminal,collect)
        self.assertLess(collect,cleanup)
        self.assertIsNone(fixture.collect_profile_containment_artifacts(root/"absent",results))

    def test_heap_alias_uses_existing_focus_and_closed_variant(self):
        # Execute only the dispatcher against a fake Python executable: no
        # harness, provider, image build or Kubernetes operation is started.
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "python3"
            fake.write_text('#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({"args":sys.argv[1:],"focus":os.environ.get("ASSERVAT_JOURNEY_FOCUS"),"variant":os.environ.get("ASSERVAT_PROFILE_VARIANT")}))\n')
            fake.chmod(0o755)
            env = dict(os.environ, PATH=directory+os.pathsep+os.environ["PATH"], ASSERVAT_PROFILE_VARIANT="heap")
            for suite, variant in (("continuation-manual-profile", "cpu"), ("continuation-manual-heap", "heap")):
                result = subprocess.run([str(Path(__file__).with_name("ci-native.sh")), suite], env=env, capture_output=True, text=True, check=True)
                selected = json.loads(result.stdout)
                self.assertEqual(selected, {"args": ["scripts/test-context-storage.py", "--initial-bootstrap-chain", "--runtime-provider-pair", "--installer-continuation"], "focus": "manual-profile", "variant": variant})
                with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": "manual-profile", "ASSERVAT_PROFILE_VARIANT": variant}):
                    self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "18m")
                    self.assertEqual(fixture.qualification_cluster_count(3, installer_continuation=True), 2)
                    self.assertEqual(fixture.qualification_profile_variant(os.environ), variant)

    def test_heap_variant_is_reported_and_unknown_values_refuse_before_setup(self):
        for base in ({"ASSERVAT_PROFILE_VARIANT": "typo"}, {"ASSERVAT_PROFILE_VARIANT": "heap", "ASSERVAT_JOURNEY_FOCUS": "profile-comparison"}):
            with self.subTest(base=base), patch.dict(os.environ, base, clear=True), patch.object(fixture, "run", side_effect=AssertionError("external setup")) as external:
                with self.assertRaisesRegex(ValueError, "fixture variant"):
                    fixture.main(installer_continuation=True)
                external.assert_not_called()
        base = {"ASSERVAT_PROFILE_VARIANT": "heap", "ASSERVAT_JOURNEY_FOCUS": "manual-profile"}
        selected = fixture.qualification_environment(base, Path("fixture"), Path("work"), False, False, initial_bootstrap_chain=True, runtime_provider_pair=True, installer_continuation=True)
        self.assertEqual(selected["ASSERVAT_PROFILE_VARIANT"], "heap")
        self.assertEqual(fixture.qualification_profile_variant({}), "cpu")
        self.assertIn('report["installedProfileVariant"] = profile_variant', inspect.getsource(fixture.main))
        workflow = (Path(__file__).resolve().parents[1]/".github/workflows/native.yml").read_text()
        self.assertFalse(native_needs("continuation-manual-heap")["tshark"])
        self.assertIn("timeout-minutes: 20", workflow)

    def test_heap_summary_precedes_authorized_native_preparation(self):
        source = (Path(__file__).resolve().parents[1]/"test/integration/installed_approved_recording_native_test.go").read_text()
        check = source.index('verify := summaryCheck(row.ID)')
        browser = source.index('call, downloadNative, finishBrowser := installedProfileBrowser(', check)
        summary = source.index('heapSummary := queryInstalledProfileSummary(', browser)
        joined = source.index('heap phase: installed React summary completed with joined SQL worker/key proof', summary)
        preparing = source.index('heap phase: separately authorized browser native preparation begins', joined)
        native = source.index('native, _ := downloadNative()', preparing)
        self.assertLess(check, browser)
        self.assertLess(browser, summary)
        self.assertLess(summary, joined)
        self.assertLess(joined, preparing)
        self.assertLess(preparing, native)
        self.assertLess(native, source.index('installedProfileSummaryMatchesNative(heapSummary, native', native))

    def test_policy_recording_guard_precedes_all_external_setup(self):
        with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": "policy-recording"}), patch.object(fixture.Path, "is_file", return_value=False), patch.object(fixture, "run", side_effect=AssertionError("external setup before guard")) as external:
            with self.assertRaisesRegex(RuntimeError, "disposable-host guard"):
                fixture.main(installer_continuation=True)
            external.assert_not_called()
        with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": "policy-recording"}):
            self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "18m")

    def test_policy_recording_workflow_installs_guard_and_offline_reader(self):
        source = (Path(__file__).resolve().parents[1]/".github/workflows/native.yml").read_text()
        self.assertIn("timeout-minutes: 20", source)
        for name, need in (("Disposable-host guard", "guard"), ("tshark", "tshark")):
            step = source.index("name: " + name)
            self.assertIn("      - if: matrix." + need + "\n", source[source.rfind("      - if:", 0, step):step])
            self.assertTrue(native_needs("continuation-policy-recording")[need])
        suites = (Path(__file__).with_name("ci-native.sh")).read_text()
        self.assertIn("[continuation-policy-recording]", suites)
        self.assertIn("ASSERVAT_JOURNEY_FOCUS=policy-recording", suites)

    def test_finite_raw_policies_use_guarded_focus_without_packet_tools(self):
        source = (Path(__file__).resolve().parents[1]/".github/workflows/native.yml").read_text()
        guard = source.index("name: Disposable-host guard")
        reader = source.index("name: tshark")
        self.assertIn("      - if: matrix.guard\n", source[source.rfind("      - if:", 0, guard):guard])
        self.assertIn("      - if: matrix.tshark\n", source[source.rfind("      - if:", 0, reader):reader])
        suites = Path(__file__).with_name("ci-native.sh").read_text()
        for focus in ("policy-arguments", "policy-profile"):
            with self.subTest(focus=focus):
                needs = native_needs("continuation-" + focus)
                self.assertTrue(needs["guard"])
                self.assertFalse(needs["tshark"])
                self.assertIn("[continuation-" + focus + "]", suites)
                self.assertIn("ASSERVAT_JOURNEY_FOCUS=" + focus, suites)
                with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}):
                    self.assertEqual(fixture.qualification_cluster_count(3, installer_continuation=True), 2)
                    self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "18m")
                    with patch.object(fixture.Path, "is_file", return_value=False), patch.object(fixture, "run", side_effect=AssertionError("external setup before guard")) as external:
                        with self.assertRaisesRegex(RuntimeError, "disposable-host guard"):
                            fixture.main(installer_continuation=True)
                        external.assert_not_called()

    def test_history_browser_report_uses_actual_current_guard_expression(self):
        tree = ast.parse(inspect.getsource(fixture.main))
        expressions = [node.value for node in ast.walk(tree)
                       if isinstance(node, ast.Assign) and any(
                           isinstance(target, ast.Subscript)
                           and isinstance(target.value, ast.Name) and target.value.id == "report"
                           and isinstance(target.slice, ast.Constant)
                           and target.slice.value == "installedHistoryBrowserQualification"
                           for target in node.targets)]
        self.assertEqual(len(expressions), 1)
        expression = compile(ast.Expression(expressions[0]), "actual-main-report", "eval")
        for focus, collector, expected in (("approved-recording", True, True),
                                           ("native-paced", True, False),
                                           ("policy-recording", True, False),
                                           ("policy-arguments", True, False),
                                           (None, False, False)):
            with self.subTest(focus=focus):
                self.assertEqual(eval(expression, {}, {"foci": [focus] if focus else [], "collector_qualification": collector}), expected)

    def test_traffic_probe_prelude_reaches_selection_without_external_effects(self):
        # Stop at selection, before cache/build/container work. This catches
        # a probe flag used by artifact cleanup before it is initialized.
        with patch.object(Path, "unlink"), patch.object(fixture, "qualification_selection", side_effect=RuntimeError("selection boundary")), patch.object(fixture, "run", side_effect=AssertionError("external effect")) as external:
            with self.assertRaisesRegex(RuntimeError, "selection boundary"):
                fixture.main(fixture.NATIVE_TRAFFIC_PROBE)
            external.assert_not_called()

    def test_cpu_limited_traffic_probe_has_one_short_recorded_go_bound(self):
        self.assertEqual(fixture.qualification_go_timeout(native_traffic_probe=True), "2m")

    def test_native_traffic_helper_setup_is_not_gated_by_helm_registry(self):
        main = ast.parse(inspect.getsource(fixture.main))
        guards = []

        def walk(node, conditions):
            if isinstance(node, ast.If):
                conditions = conditions + [ast.unparse(node.test)]
            if isinstance(node, ast.Call):
                installs = isinstance(node.func, ast.Name) and node.func.id == "install_native_traffic_helper"
                old_inline = (isinstance(node.func, ast.Attribute) and node.func.attr == "setdefault"
                              and node.args and isinstance(node.args[0], ast.Constant)
                              and node.args[0].value == "nativeTrafficHelper")
                if installs or old_inline:
                    guards.append(conditions)
            for child in ast.iter_child_nodes(node):
                walk(child, conditions)

        walk(main, [])
        self.assertEqual(len(guards), 1, "one common traffic-helper setup site is required")
        self.assertTrue(any("native_paced" in condition for condition in guards[0]))
        self.assertFalse(any("helm_bootstrap" in condition for condition in guards[0]),
                         "actual native-paced setup has no Helm registry; its helper must still install")

    def test_fast_native_traffic_helper_installs_and_serializes_exact_owned_nodes(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"provider-proxy"
            binary.write_bytes(b"static fixture binary")
            digest = fixture.hashlib.sha256(binary.read_bytes()).hexdigest()
            cluster, node = "owned-fast-region", "owned-fast-region-control-plane"
            calls = []
            def command(args):
                calls.append(args)
                if args[:3] == ["kind", "get", "nodes"]:
                    return node
                if args[:2] == ["docker", "inspect"]:
                    return cluster
                if args[:2] == ["docker", "cp"]:
                    return ""
                if args[:2] == ["docker", "exec"]:
                    return digest+"  /asservat-fixture-traffic"
                self.fail("unexpected setup command: "+str(args))
            values, report = {}, {}
            with patch.object(fixture, "run", command):
                fixture.install_native_traffic_helper(binary, cluster, values, report)
            serialized = json.loads(json.dumps(values))
            expected = {"cluster": cluster, "nodes": [node], "sha256": digest}
            self.assertEqual(fixture.require_native_traffic_helper(serialized, cluster), expected)
            self.assertEqual(report["nativeTrafficHelper"], expected)
            self.assertEqual(report["nativeTrafficHelperSetup"]["copiedBytes"], binary.stat().st_size)
            self.assertEqual(len([c for c in calls if c[:2] == ["docker", "cp"]]), 1)
            self.assertEqual(fixture.qualification_selection(fixture.NATIVE_TRAFFIC_PROBE, False, False), (fixture.NATIVE_TRAFFIC_PROBE, 1))

    def test_traffic_helper_refuses_missing_foreign_or_mismatched_bytes(self):
        with self.assertRaisesRegex(RuntimeError, "before Go bootstrap"):
            fixture.require_native_traffic_helper({}, "owned")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory)/"provider-proxy"
            binary.write_bytes(b"static fixture binary")
            for wrong in ("owner", "digest"):
                def command(args):
                    if args[0] == "kind": return "owned-control-plane"
                    if args[1] == "inspect": return "foreign" if wrong == "owner" else "owned"
                    if args[1] == "cp": return ""
                    if args[1] == "exec": return "0"*64+"  /asservat-fixture-traffic"
                    self.fail(str(args))
                with patch.object(fixture, "run", command), self.assertRaisesRegex(RuntimeError, "ownership differs|bytes differ"):
                    fixture.install_native_traffic_helper(binary, "owned", {}, {})
        source = inspect.getsource(fixture.main)
        self.assertLess(source.index("require_native_traffic_helper(fixture, clusters"), source.index("path.write_text(json.dumps(fixture))"))

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
        for focus in ("approved-recording", "manual-syscall", "manual-arguments", "manual-mixed", "manual-raw", "manual-http", "manual-peers", "manual-profile", "native-paced", "policy-recording", "policy-arguments", "ongoing-save", "ongoing-save-disk", "ongoing-incident", "ongoing-syscall", "ongoing-mixed", "live-observation", "ongoing-mixed", "live-observation"):
            with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}), patch.object(fixture.Path, "is_file", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "disposable-host guard"):
                    fixture.main(installer_continuation=True)

    def test_argument_engine_build_inputs_are_frozen(self):
        hashes = fixture.source_hashes()
        for name in ("scripts/package-argument-gadget.py", "experiments/syscall-argument-budget/prepare.py",
                     "experiments/syscall-argument-budget/pins.json", "experiments/syscall-argument-budget/program.patch",
                     "experiments/syscall-argument-budget/budget.h"):
            self.assertIn(name, hashes)
            self.assertEqual(len(hashes[name]), 64)

    def test_argument_inventory_refuses_object_or_source_pin_substitution(self):
        # Synthetic bytes exercise reporting/refusal only; this never builds or loads BPF.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "experiments/syscall-argument-budget"
            source.mkdir(parents=True)
            package = root / "package"
            package.mkdir()
            pins = {"compiled_object_sha256": hashlib.sha256(b"synthetic ELF").hexdigest(), "upstream_commit": "synthetic"}
            (source / "pins.json").write_text(json.dumps(pins))
            (package / "source-pins.json").write_text(json.dumps(pins))
            (package / "program.bpf.o").write_bytes(b"synthetic ELF")
            with patch.object(fixture, "ROOT", root):
                report = fixture.argument_engine_build_inventory(package)
                self.assertEqual(report["objectSHA256"], pins["compiled_object_sha256"])
                self.assertEqual(report["sourcePins"], pins)
                self.assertEqual(report["objectBytes"], 13)
                (package / "program.bpf.o").write_bytes(b"replacement")
                with self.assertRaisesRegex(RuntimeError, "pins"):
                    fixture.argument_engine_build_inventory(package)
                (package / "program.bpf.o").write_bytes(b"synthetic ELF")
                (package / "source-pins.json").write_text(json.dumps(dict(pins, upstream_commit="replacement")))
                with self.assertRaisesRegex(RuntimeError, "pins"):
                    fixture.argument_engine_build_inventory(package)

    def test_history_driver_and_locked_browser_dependencies_are_source_pinned(self):
        hashes = fixture.source_hashes()
        for name in ("web/scripts/installed-history-browser.mjs", "web/scripts/installed-history-response.mjs", "web/package.json", "web/package-lock.json"):
            self.assertIn(name, hashes)
            self.assertEqual(len(hashes[name]), 64)

    def test_approved_recording_has_finite_go_envelope(self):
        for focus in ("approved-recording", "manual-syscall", "manual-arguments", "manual-mixed", "manual-raw", "manual-http", "manual-peers", "manual-profile", "native-paced", "policy-recording", "policy-arguments", "ongoing-save", "ongoing-save-disk", "ongoing-incident", "ongoing-syscall", "ongoing-mixed", "live-observation", "ongoing-mixed", "live-observation"):
            with patch.dict(os.environ, {"ASSERVAT_JOURNEY_FOCUS": focus}):
                self.assertEqual(fixture.qualification_go_timeout(installer_continuation=True), "18m")

    def test_installed_focus_topology_and_flags_reach_the_go_consumer(self):
        for focus, expected in (("approved-recording", 2), ("manual-syscall", 2), ("manual-arguments", 2), ("manual-mixed", 2), ("manual-raw", 2), ("manual-http", 2), ("manual-peers", 2), ("manual-profile", 2), ("policy-recording", 2), ("policy-arguments", 2), ("ongoing-save", 2), ("ongoing-save-disk", 2), ("ongoing-incident", 2), ("ongoing-syscall", 2), ("ongoing-mixed", 2), ("live-observation", 2), ("native-paced", 2), ("journey", 2), ("browser", 2),
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

    def test_fast_kubelet_sync_only_for_installed_feature_focuses(self):
        self.assertEqual(fixture.kubelet_sync_frequency(True, "manual-logs"), "5s")
        self.assertIsNone(fixture.kubelet_sync_frequency(True, "chain"))
        self.assertIsNone(fixture.kubelet_sync_frequency(False, "manual-logs"))
        mount = {"hostPath": "/owned", "containerPath": "/var"}
        config = fixture.kind_cluster_config(mounts=[mount], sync_frequency="5s")
        self.assertEqual(config["nodes"], [{"role": "control-plane", "extraMounts": [mount]}])
        self.assertEqual(json.loads(config["kubeadmConfigPatches"][0]),
                         {"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration", "syncFrequency": "5s"})
        default = fixture.kind_cluster_config(helm=True)
        self.assertEqual([n["role"] for n in default["nodes"]], ["control-plane", "worker"])
        self.assertNotIn("kubeadmConfigPatches", default)
        # The native audit patch extends the node, never the kubelet patch.
        with tempfile.TemporaryDirectory() as directory:
            fixture.native_kube_audit.configure(config, Path(directory), 0)
        self.assertEqual(len(config["kubeadmConfigPatches"]), 1)
        self.assertEqual(config["nodes"][0]["extraMounts"][0], mount)

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
