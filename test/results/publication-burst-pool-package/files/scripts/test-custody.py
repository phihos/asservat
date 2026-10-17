#!/usr/bin/env python3
"""Disposable PostgreSQL/S3 fixtures for the product custody facet, synthetic only."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
POSTGRES = "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
BAO = "quay.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
SEAWEED = "chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d"
CONNECTOR_RETIREMENT_TEST = "TestContextAdmissionWithRealServices/connector-identity-real-time-retirement"
CONNECTOR_RETIREMENT_ENV = "ASSERVAT_CONNECTOR_RETIREMENT_REALTIME"
SCOPED_AUDIT_ENV = "ASSERVAT_SCOPED_AUDIT_STORAGE"
SCOPED_AUDIT_ID = "a9a9b231-0d4c-4d72-89aa-1a4516be9e9c"
SCOPED_AUDIT_BUCKET = "synthetic-scoped-audit"

def scoped_audit_configuration():
    """Fixture-only fixed credentials, never installer or runtime provisioning."""
    configuration = "hub-owner-configuration/v1/" + "/".join([SCOPED_AUDIT_ID] * 3) + "/"
    enrollment = "hub-owner-enrollment/v1/" + SCOPED_AUDIT_ID + "/"
    certificate = "hub-owner-certificate/v1/" + SCOPED_AUDIT_ID + "/"
    prefixes = [configuration, enrollment, certificate]
    def access(actions, values):
        return [action + ":" + SCOPED_AUDIT_BUCKET + "/" + prefix + "*" for prefix in values for action in actions]
    roles = [
        ("administrator", "synthetic-only", "synthetic-only-secret", ["Admin", "Read", "Write", "List"]),
        ("configuration", "configuration-synthetic", "configuration-synthetic-secret", access(["Read", "Write"], [configuration])),
        ("owner", "owner-synthetic", "owner-synthetic-secret", access(["Read", "Write"], [enrollment, certificate])),
        ("retirement", "retirement-synthetic", "retirement-synthetic-secret", ["List:" + SCOPED_AUDIT_BUCKET] + access(["Read"], prefixes)),
    ]
    return {"identities": [{"name": role, "credentials": [{"accessKey": key, "secretKey": secret}], "actions": actions} for role, key, secret, actions in roles]}


def run(args, **kw):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=120, **kw).strip()

def hashes():
    files = [ROOT/"go.mod", ROOT/"go.sum", ROOT/"sqlc.yaml", Path(__file__)]
    for folder, pattern in [("cmd", "*.go"), ("internal", "*.go"), ("internal", "*.json"), ("migrations", "*.sql"), ("migrations", "*.go"), ("test/fixtures", "*.sql"), ("test/integration", "*.go")]:
        files += list((ROOT/folder).rglob(pattern))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}

def passed_test_names(output, pattern):
    """A zero Go exit with no matching tests is not integration evidence."""
    names = [line.strip().split()[2] for line in output.splitlines()
             if line.strip().startswith("--- PASS: Test")]
    if pattern and "/" in pattern:
        names = [name for name in names if "/" in name]
    return names

def passed_test_elapsed(output, name):
    """Require the selected Go test's duration, excluding compilation/startup."""
    matches = re.findall(r"^\s*--- PASS: " + re.escape(name) + r" \(([0-9]+(?:\.[0-9]+)?)s\)$", output, re.MULTILINE)
    return float(matches[0]) if len(matches) == 1 else None

def main(fleet=False, test_pattern=None, database_recovery=False, initial_installation=False, connector_retirement=False, scoped_audit=False):
    if scoped_audit and (fleet or test_pattern or database_recovery or initial_installation or connector_retirement):
        raise ValueError("Scoped audit qualification owns its exact fixture/test selection")
    if connector_retirement and (fleet or test_pattern or database_recovery or initial_installation):
        raise ValueError("Connector retirement owns its exact fixture/test selection")
    cache = Path.home()/".cache/asservat-build"
    cache.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="custody-", dir=cache) as temp:
        work = Path(temp)
        label = "asservat.test="+work.name
        network = "asservat-"+work.name
        containers = []
        created_network = False
        pgname = None
        result_name="scoped-audit-storage" if scoped_audit else "initial-installation" if initial_installation else ("database-recovery" if database_recovery else ("fleet" if fleet else "custody"))
        log_path = ROOT/("test/results/"+result_name+".log")
        log_path.write_text("")
        report = {"scope": "storage custody, permission acceptance and bounded context admission components; synthetic control provenance only; no public acquisition or disclosure", "images": {}, "sourceHashes": hashes(), "passedTestNames": []}
        exit_code = 1
        try:
            run(["docker", "network", "create", "--internal", "--label", label, network])
            created_network = True
            def service(name, image, extra, command):
                name = network+"-"+name
                run(["docker", "create", "--name", name, "--network", network, "--label", label,
                     "--memory", "768m", "--cpus", "2", "--pids-limit", "256", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", *extra, image, *command])
                containers.append(name)
                run(["docker", "start", name])
                info = json.loads(run(["docker", "inspect", name]))[0]
                report["images"][name] = {"requested": image, "imageID": info["Image"], "containerID": info["Id"]}
                return info["NetworkSettings"]["Networks"][network]["IPAddress"], name
            pgip, pgname = service("postgres", POSTGRES, ["--user", "postgres", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777", "-v", "/var/lib/postgresql", "-e", "POSTGRES_PASSWORD=synthetic-only", "-e", "POSTGRES_DB=custody_test"], ["-c", "max_connections=48", "-c", "shared_buffers=128MB", "-c", "fsync=on", "-c", "synchronous_commit=on"])
            s3_extra, s3_command = [], []
            if scoped_audit:
                # Exact read-only bind; these public synthetic test credentials
                # are deliberately not copied into the retained result report.
                s3_configuration = work/"s3.json"
                s3_configuration.write_text(json.dumps(scoped_audit_configuration()))
                s3_configuration.chmod(0o444)
                s3_extra = ["-v", str(s3_configuration) + ":/config/s3.json:ro"]
                s3_command = ["-s3.config=/config/s3.json"]
            s3ip, _ = service("s3", SEAWEED, ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-v", "/data", "-e", "AWS_ACCESS_KEY_ID=synthetic-only", "-e", "AWS_SECRET_ACCESS_KEY=synthetic-only-secret", *s3_extra, "--entrypoint", "/usr/bin/weed"], ["mini", "-dir=/data", "-ip.bind=0.0.0.0", "-admin.ui=false", "-s3.port=8333", *s3_command])
            bao_endpoint = ""
            if fleet:
                baoip, _ = service("kms", BAO, ["--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-e", "SKIP_SETCAP=true", "-e", "BAO_DISABLE_MLOCK=true", "--entrypoint", "/usr/bin/bao"], ["server", "-dev", "-dev-no-store-token", "-dev-root-token-id=synthetic-root", "-dev-listen-address=0.0.0.0:8200"])
                bao_endpoint="http://"+baoip+":8200"
                for _ in range(80):
                    try:
                        urllib.request.urlopen(bao_endpoint+"/v1/sys/health",timeout=1).close()
                        break
                    except OSError: pass
                    time.sleep(.25)
                else: raise RuntimeError("OpenBao fixture not ready")
                report["scope"]="connector enrollment, custody of credentials/audit and current TLS registration; synthetic bootstrap/trust; no public ingress or workload collection"
            for _ in range(100):
                if subprocess.run(["docker", "exec", pgname, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "custody_test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
                time.sleep(.1)
            else: raise RuntimeError("PostgreSQL fixture not ready")
            for _ in range(80):
                try:
                    urllib.request.urlopen("http://"+s3ip+":8333", timeout=1).close()
                    break
                except urllib.error.HTTPError as exc:
                    if exc.code in (403, 404): break
                except OSError: pass
                time.sleep(.25)
            else: raise RuntimeError("S3 fixture not ready")
            dsn = "postgres://postgres:synthetic-only@"+pgip+":5432/custody_test?sslmode=disable"
            goose = str(cache/"bin/goose")
            env = os.environ.copy()
            # An inherited opt-in must never lengthen an ordinary suite or a
            # caller-selected test into a 31-minute qualification unexpectedly.
            env.pop(CONNECTOR_RETIREMENT_ENV, None)
            env.pop(SCOPED_AUDIT_ENV, None)
            if scoped_audit:
                env[SCOPED_AUDIT_ENV] = "1"
            if connector_retirement:
                env[CONNECTOR_RETIREMENT_ENV] = "1"
            env.update({"GOOSE_DRIVER": "postgres", "GOOSE_DBSTRING": dsn, "TMPDIR": str(work)})
            report["gooseVersion"] = run([goose, "-version"])
            if database_recovery:
                report["legacyMigration"] = run([goose, "-dir", str(ROOT/"migrations"), "up-to", "30"], env=env)
                run(["docker", "exec", pgname, "psql", "-U", "postgres", "-d", "custody_test", "-v", "ON_ERROR_STOP=1", "-c",
                     "INSERT INTO fleet_trust(installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES('4a748d72-85e9-4305-a737-3abfb22cf788','e7924388-979c-4620-944d-c4067c80c875','synthetic-recovery',1,decode('01'||repeat('00',31),'hex'),false,false,statement_timestamp(),statement_timestamp()+interval '30 seconds')"])
                report["legacyEnabledRootSeeded"] = True
            report["migration"] = run([goose, "-dir", str(ROOT/"migrations"), "up"], env=env)
            # A second invocation must not change schema or repeat data changes.
            run([goose, "-dir", str(ROOT/"migrations"), "up"], env=env)
            run(["docker", "exec", pgname, "psql", "-U", "postgres", "-d", "custody_test", "-v", "ON_ERROR_STOP=1", "-c", (ROOT/"test/fixtures/sql/runtime-roles.sql").read_text()])
            path = work/"fixtures.json"
            path.touch(mode=0o600)
            path.write_text(json.dumps({"postgres": dsn, "s3": "http://"+s3ip+":8333", "kms":bao_endpoint}))
            env["ASSERVAT_CUSTODY_FIXTURES"] = str(path)
            if fleet: env["ASSERVAT_FLEET_FIXTURES"] = str(path)
            if initial_installation:
                env["ASSERVAT_INITIAL_INSTALLATION"] = "1"
                report["scope"] = "first-installation SQL eligibility, witness composition and encrypted S3/OpenBao audit; synthetic protected Kubernetes inputs; no restore or installer deployment qualification"
            report["goVersion"] = run(["go", "version"])
            pattern = "^TestInitialInstallationWithRealServices$" if initial_installation else ("^TestDatabaseRecoveryAfterRestartAndRestore$" if database_recovery else (test_pattern or ("Test(Enrollment|PeerRegistry|ConnectorPKI|BootstrapChannel|InitialProviderIssuer)" if fleet else "Test(Custody|PermissionAuthority|ContextAdmission|PeerRegistry|Enrollment)")))
            if scoped_audit:
                pattern = "^TestScopedVersionedAuditStorageWithRealServices$"
                report["scope"] = "real prefix-scoped versioned audit SDK/TLS writes and version reads, runtime deletion/configuration denial and separate exact-version retirement; synthetic storage administration and wrapping keys, no installed accounting, recovery or production key qualification"
            if connector_retirement:
                pattern = "^TestContextAdmissionWithRealServices$/^connector-identity-real-time-retirement$"
                report["scope"] = "connector identity retirement with configured 30-second ordinary admission, original 30-minute process/certificate lifetime and 2100-second retention; synthetic protected source/proof setup, no maximum admission-window, installed connector or provider migration qualification"
            report["testPattern"] = pattern
            # The full growing component matrix exceeded its original aggregate
            # two-minute limit while individual bounded cases were still passing.
            # Keep their authority/provider deadlines unchanged and give the
            # entire race-enabled process a separately recorded finite budget.
            # The expanded full suite reached the 600-second aggregate alarm
            # after context completed in 589.63 seconds and the next custody
            # case had run for only seven seconds (native-3, 2026-10-13).
            # Actual retirement/backup waits remain unchanged. Give only this
            # aggregate process 900 seconds (960 including harness cleanup).
            # Selected, fleet, initial and recovery runs keep their 300-second
            # limit. No individual authority/provider/retention deadline changes.
            full_custody = not (test_pattern or fleet or initial_installation or database_recovery or connector_retirement or scoped_audit)
            test_timeout = 2400 if connector_retirement else (900 if full_custody else 300)
            report["connectorRetirementRealtime"] = connector_retirement
            report["goTestTimeoutSeconds"] = test_timeout
            report["harnessTestTimeoutSeconds"] = test_timeout + 60
            report["phases"] = []
            phases = ["initial", "restarted", "restored"] if database_recovery else ["suite"]
            for phase in phases:
                exit_code = 1  # a later phase setup failure cannot inherit success
                if database_recovery:
                    env["ASSERVAT_DATABASE_RECOVERY_PHASE"] = phase
                    report["scope"] = "real PostgreSQL restart and logical restore incarnation denial; synthetic independent activation; no failover, checkpoint replay or production restoration qualification"
                    if phase == "restarted":
                        # Only the container created and tracked by this invocation.
                        run(["docker", "restart", "--time", "10", pgname])
                        for _ in range(100):
                            if subprocess.run(["docker", "exec", pgname, "pg_isready", "-U", "postgres", "-d", "custody_test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
                            time.sleep(.1)
                        else: raise RuntimeError("Restarted PostgreSQL fixture not ready")
                    if phase == "restored":
                        dump = run(["docker", "exec", pgname, "pg_dump", "-U", "postgres", "--no-owner", "custody_test"])
                        report["syntheticDumpSHA256"] = hashlib.sha256(dump.encode()).hexdigest()
                        run(["docker", "exec", pgname, "createdb", "-U", "postgres", "custody_restore"])
                        subprocess.run(["docker", "exec", "-i", pgname, "psql", "-U", "postgres", "-d", "custody_restore", "-v", "ON_ERROR_STOP=1"], input=dump, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=120)
                        descriptor = json.loads(path.read_text())
                        descriptor["postgres"] = dsn.replace("/custody_test?", "/custody_restore?")
                        path.write_text(json.dumps(descriptor))
                database = "custody_restore" if phase == "restored" else "custody_test"
                incarnation = json.loads(run(["docker", "exec", pgname, "psql", "-U", "postgres", "-d", database, "-At", "-c", "SELECT json_build_object('serverStart',pg_postmaster_start_time(),'databaseOID',oid) FROM pg_database WHERE datname=current_database()"] ))
                with log_path.open("a") as log:
                    test_started = time.monotonic()
                    result = subprocess.run(["go", "test", "-race", "-count=1", "-timeout="+str(test_timeout)+"s", "-v", "-run", pattern, "./test/integration"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=test_timeout+60)
                    test_elapsed = time.monotonic() - test_started
                exit_code = result.returncode
                all_passed = passed_test_names(log_path.read_text(), pattern)
                passed = all_passed[len(report["passedTestNames"]):]
                phase_report = {"phase": phase, "testExit": exit_code, "incarnation": incarnation, "passedTestNames": passed, "testElapsedSeconds": test_elapsed}
                report["phases"].append(phase_report)
                report["passedTestNames"] = all_passed
                if exit_code == 0 and not passed:
                    print("No selected tests passed; refusing empty integration evidence", flush=True)
                    exit_code = 1
                if connector_retirement:
                    selected_elapsed = passed_test_elapsed(log_path.read_text(), CONNECTOR_RETIREMENT_TEST)
                    phase_report["selectedTestElapsedSeconds"] = selected_elapsed
                    if exit_code == 0 and (CONNECTOR_RETIREMENT_TEST not in passed or test_elapsed < 1860 or selected_elapsed is None or selected_elapsed < 1860):
                        print("Missing exact real-time retirement pass or actual 31-minute test interval", flush=True)
                        exit_code = 1
                phase_report["qualificationExit"] = exit_code
                if exit_code: break
            report["sourceUnchangedDuringTest"] = report["sourceHashes"] == hashes()
            if not report["sourceUnchangedDuringTest"]: exit_code = 1
            print(result_name.capitalize()+" integration exit:", exit_code, flush=True)
        except subprocess.CalledProcessError as exc:
            exit_code = 1
            print("Fixture command failed:", exc.stderr[-2000:] if exc.stderr else exc.returncode, flush=True)
            raise
        except BaseException:
            exit_code = 1
            raise
        finally:
            failures = []
            # Setup/migration failures also need fresh, non-stale diagnostics
            # and a source-freeze verdict, before the owned database is removed.
            report["sourceUnchangedDuringTest"] = report["sourceHashes"] == hashes()
            if not report["sourceUnchangedDuringTest"]: exit_code = 1
            if exit_code and pgname:
                try:
                    provider = subprocess.run(["docker", "logs", pgname], text=True, capture_output=True, timeout=10)
                    (ROOT/("test/results/"+result_name+"-postgres.log")).write_text(provider.stdout+provider.stderr)
                    report["providerLogExit"] = provider.returncode
                except (OSError, subprocess.TimeoutExpired) as exc:
                    report["providerLogFailure"] = type(exc).__name__
            for name in reversed(containers):
                try:
                    info = json.loads(run(["docker", "inspect", name]))[0]
                    assert info["Config"]["Labels"]["asservat.test"] == work.name
                    run(["docker", "rm", "-f", "-v", name])
                except Exception: failures.append(name)
            if created_network:
                try: run(["docker", "network", "rm", network])
                except Exception: failures.append(network)
            report.update({"testExit": exit_code, "cleanupFailures": failures})
            (ROOT/("test/results/"+result_name+"-environment.json")).write_text(json.dumps(report, indent=2)+"\n")
            if failures: raise RuntimeError("Owned fixture cleanup failed: "+", ".join(failures))
        return exit_code

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--fleet",action="store_true")
    parser.add_argument("--database-recovery",action="store_true",help="Qualify actual owned PostgreSQL restart and logical restore")
    parser.add_argument("--initial-installation",action="store_true",help="Qualify first installation on an otherwise unused owned database")
    parser.add_argument("--connector-retirement",action="store_true",help="Opt in to actual connector retirement timing (at least 31 minutes; 40-minute Go budget)")
    parser.add_argument("--scoped-audit", action="store_true", help="Qualify prefix-scoped immutable audit versions and independent retirement")
    parser.add_argument("--run", help="Go test name regex for an owned targeted fixture; default runs the complete suite")
    args=parser.parse_args()
    if args.database_recovery and (args.fleet or args.run): parser.error("--database-recovery owns its exact phase/test selection")
    if args.initial_installation and (args.fleet or args.run or args.database_recovery): parser.error("--initial-installation owns its exact fresh-fixture selection")
    if args.connector_retirement and (args.fleet or args.run or args.database_recovery or args.initial_installation): parser.error("--connector-retirement owns its exact long-fixture selection")
    if args.scoped_audit and (args.fleet or args.run or args.database_recovery or args.initial_installation or args.connector_retirement): parser.error("--scoped-audit owns its exact fixture/test selection")
    raise SystemExit(main(args.fleet or args.initial_installation, args.run, args.database_recovery, args.initial_installation, args.connector_retirement, args.scoped_audit))
