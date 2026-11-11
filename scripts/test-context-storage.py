#!/usr/bin/env python3
"""Owned, synthetic component integration fixtures; never uses current kube context.

Creates two disposable Kind clusters plus private S3/OpenBao fixtures, runs the
Go integration test, and removes only resources it created, even on failure.
The explicit fresh-database initial-handover case uses its single installer
cluster; it contains no multi-cluster assertions. Ordinary selections retain two.
No host kernel configuration or privileged collector is installed.
"""
import argparse
import concurrent.futures
from contextlib import ExitStack
import json
import hashlib
import os
import re
import shutil
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from helm_registry import HelmRegistry, REGISTRY, verify_registry_cleanup
import native_kube_audit
from pod_log_stream import PodLogStreamer

ROOT = Path(__file__).resolve().parents[1]
SEAWEED = "chrislusf/seaweedfs@sha256:4e61d15fd35994cb1e43e1e553dff106794841fd9a99ade2fc8c8bfce4d7872d"
BAO = "quay.io/openbao/openbao@sha256:6d2b93856e3fcf7b18ad855a0b51eaba474dc8b79cf554379ea32034797d2acf"
NODE = "kindest/node@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
PAUSE = "registry.k8s.io/pause@sha256:ee6521f290b2168b6e0935a181d4cff9be1ac3f505666ef0e3c98fae8199917a"
POSTGRES = "postgres@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c"
# The identity suite's pinned Keycloak (scripts/test-identity.py).
KEYCLOAK = "quay.io/keycloak/keycloak@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc"
# The alert focus's official Alertmanager v0.28.1 (ADR-231). Like PAUSE, the
# owned node pulls it by digest: `kind load` of this multi-platform image fails
# with Docker's containerd image store.
ALERTMANAGER = "quay.io/prometheus/alertmanager@sha256:27c475db5fb156cab31d5c18a4251ac7ed567746a2483ff264516437a39b15ba"
# The logresource focus's official metrics-server v0.8.0 (ADR-241), pulled by
# digest by the workload cluster node like ALERTMANAGER.
METRICS_SERVER = "registry.k8s.io/metrics-server/metrics-server@sha256:89258156d0e9af60403eafd44da9676fd66f600c7934d468ccc17e42b199aee2"


def run(args, *, data=None):
    return subprocess.check_output(args, text=True, input=data, stderr=subprocess.PIPE).strip()



def postgres_fixture_options(regional_context_start=None, lock_waits=False, installed_budget=None, native_statistics=False):
    if regional_context_start not in (None, "first", "continuation", "journey"):
        raise ValueError("unknown regional context qualification")
    options = ["-c", "max_connections=48", "-c", "shared_buffers=128MB", "-c", "fsync=on", "-c", "synchronous_commit=on"]
    if installed_budget is not None:
        # Only the complete installed graph selects this allowance, generated
        # by test/fixtures/installed-sql-budget from the product's Go plan.
        fields = ("requiredOrdinary", "maxConnections", "superuserReserved", "reserved", "fixtureAdminConnections")
        if (regional_context_start is not None or
                any(type(installed_budget.get(key)) is not int for key in fields) or
                installed_budget["requiredOrdinary"] < 1 or installed_budget["reserved"] < 0 or
                installed_budget["fixtureAdminConnections"] != 1 or
                installed_budget["superuserReserved"] < 0 or
                installed_budget["maxConnections"] != installed_budget["requiredOrdinary"] + installed_budget["fixtureAdminConnections"] + installed_budget["superuserReserved"] + installed_budget["reserved"]):
            raise ValueError("invalid installed PostgreSQL connection budget")
        options[1] = "max_connections=" + str(installed_budget["maxConnections"])
        options += ["-c", "superuser_reserved_connections=" + str(installed_budget["superuserReserved"]),
                    "-c", "reserved_connections=" + str(installed_budget["reserved"])]
    if lock_waits:
        # Owned synthetic fixture only. The installer continuation's
        # reconcilers fail together on lock_timeout; log each wait longer than
        # 300 ms with its holder's PID, and each connection's role so the PID
        # names its purpose. No statements or parameters are logged.
        options += ["-c", "log_line_prefix=%m [%p] role=%u sqlstate=%e ",
                    "-c", "log_lock_waits=on", "-c", "deadlock_timeout=300ms", "-c", "log_connections=on", "-c", "log_disconnections=on",
                    "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
                    "-c", "log_parameter_max_length=0", "-c", "log_parameter_max_length_on_error=0"]
    if native_statistics:
        # Owned measurement fixture only. No product tracer or statement logging.
        # Numeric per-role counters are read by the existing fixture administrator;
        # extension text/parameters are never exported. Do not persist its state.
        options += ["-c", "shared_preload_libraries=pg_stat_statements",
                    "-c", "pg_stat_statements.save=off",
                    "-c", "pg_stat_statements.track=top"]
    if regional_context_start == "journey":
        # Owned synthetic fixture only. Diagnose the actual refused connection
        # without adding a pgx tracer (forbidden by product SQL constructors).
        # Never add statement/parameter logging or change connection capacity.
        options += ["-c", "log_line_prefix=%m [%p] role=%u sqlstate=%e ",
                    "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
                    "-c", "log_error_verbosity=terse",
                    "-c", "log_parameter_max_length=0", "-c", "log_parameter_max_length_on_error=0"]
    return options


def write_environment_report(path, report):
    """Keep the last complete report readable if this process is killed mid-write."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(path)


def record_go_output(command, env, results, report, name="context-storage"):
    """Retain the original child output and elapsed line times."""
    report["harnessState"] = "running"
    write_environment_report(results/(name+"-environment.json"), report)
    began = time.monotonic()
    # SIGTERM/hard runner cancellation may bypass finally. Persist every
    # received line now; a partial file never supplies a terminal verdict.
    with (results/(name+".log")).open("wb", buffering=0) as log, (results/(name+"-timing.log")).open("wb", buffering=0) as timing:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        with process.stdout:
            for line in process.stdout:
                log.write(line)
                timing.write(("%8.1f " % (time.monotonic() - began)).encode() + line)
        return process.wait()


def build_hub_binaries(image_dir, build_env):
    # ADR-243 decision 4: the product binary links the pinned static libpcap
    # filter compiler (cgo, tags libpcap,netgo,osusergo, fully static for the
    # FROM-scratch image), built as make pcap-check builds it. The fixture
    # helpers stay cgo-free.
    subprocess.run(["make", "--no-print-directory", "hub-binary", "HUB_BINARY="+str(image_dir/"asservat"), "ASSERVAT_BUILD_TMP="+build_env["TMPDIR"]], cwd=ROOT, env=build_env, check=True)
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(image_dir/"provider-proxy"), "./test/fixtures/provider-proxy/main.go"], cwd=ROOT, env=build_env, check=True)


def build_console(image_dir, build_env):
    """Build the image-owned console package (ADR-194); returns its digest."""
    subprocess.run(["npm", "exec", "--offline", "--", "vite", "build", "--outDir", str(image_dir/"console"), "--emptyOutDir", "--logLevel", "warn"], cwd=ROOT/"web", env=build_env, check=True)
    digest = hashlib.sha256()
    for path in sorted((image_dir/"console").rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(image_dir/"console")).encode() + b"\0" + path.read_bytes())
    return digest.hexdigest()


def source_hashes():
    files = [ROOT/"go.mod", ROOT/"go.sum", Path(__file__), ROOT/"scripts/fetch-gadget.sh", ROOT/"scripts/ci-native.sh", ROOT/".github/workflows/native.yml"]
    files += [ROOT/"scripts/package-argument-gadget.py"]
    files += [ROOT/"experiments/syscall-argument-budget"/name for name in ("prepare.py", "pins.json", "program.patch", "budget.h")]
    files += [ROOT/"web/package.json", ROOT/"web/package-lock.json", ROOT/"web/scripts/installed-history-browser.mjs", ROOT/"web/scripts/installed-history-response.mjs", ROOT/"web/scripts/installed-profile-comparison-browser.mjs", ROOT/"web/scripts/installed-packet-summary-browser.mjs", ROOT/"web/scripts/installed-packet-query-browser.mjs", ROOT/"web/scripts/installed-syscall-query-browser.mjs", ROOT/"web/scripts/installed-profile-case-proof.mjs", ROOT/"web/src/generated/validate-auth.js", ROOT/"web/src/generated/validate-evidence.js"]
    # Freeze both the image-owned React inputs and the real browser drivers,
    # including new journeys without extending a hand-maintained file list.
    files += list((ROOT/"web/src").rglob("*"))
    files += list((ROOT/"web/scripts").glob("*.mjs")) + list((ROOT/"web/tests").glob("*.mjs"))
    files += [ROOT/"web/index.html", ROOT/"web/vite.config.ts", ROOT/"web/tsconfig.json"]
    files += list((ROOT/"cmd").rglob("*.go")) + list((ROOT/"internal").rglob("*.go")) + list((ROOT/"test/integration").rglob("*.go"))
    files += [ROOT/"scripts/helm_registry.py", ROOT/"scripts/native_kube_audit.py", ROOT/"scripts/pod_log_stream.py"] + list((ROOT/"charts/asservat").rglob("*"))
    files = [p for p in files if p.is_file()]
    files += list((ROOT/"internal").rglob("*.json")) + list((ROOT/"migrations").rglob("*.sql")) + list((ROOT/"migrations").rglob("*.go")) + list((ROOT/"test/fixtures").rglob("*.sql")) + list((ROOT/"test/fixtures").rglob("*.go"))
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}


def argument_engine_build_inventory(directory):
    pins_bytes = (directory / "source-pins.json").read_bytes()
    pins = json.loads(pins_bytes)
    expected = json.loads((ROOT / "experiments/syscall-argument-budget/pins.json").read_text())
    raw = (directory / "program.bpf.o").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if pins != expected or digest != expected["compiled_object_sha256"]:
        raise RuntimeError("packaged argument engine differs from reviewed source/object pins")
    return {"objectSHA256": digest, "objectBytes": len(raw),
            "sourcePinsSHA256": hashlib.sha256(pins_bytes).hexdigest(), "sourcePins": pins}


NATIVE_TRAFFIC_PROBE = "^TestNativePacingTrafficWithRealKubernetes$"


def require_native_traffic_helper(fixture, cluster):
    helper = fixture.get("nativeTrafficHelper")
    if (not isinstance(helper, dict) or set(helper) != {"cluster", "sha256", "nodes"}
            or helper["cluster"] != cluster or not isinstance(helper["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", helper["sha256"])
            or not isinstance(helper["nodes"], list) or not 1 <= len(helper["nodes"]) <= 2
            or any(not isinstance(node, str) or not node.startswith(cluster+"-") for node in helper["nodes"])
            or len(set(helper["nodes"])) != len(helper["nodes"])):
        raise RuntimeError("native traffic helper descriptor is absent or differs before Go bootstrap")
    return helper


def install_native_traffic_helper(binary, cluster, fixture, report):
    began = time.monotonic()
    nodes = run(["kind", "get", "nodes", "--name", cluster]).splitlines()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    helper = {"cluster": cluster, "sha256": digest, "nodes": nodes}
    require_native_traffic_helper({"nativeTrafficHelper": helper}, cluster)
    for node in nodes:
        if run(["docker", "inspect", "--format", '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', node]) != cluster:
            raise RuntimeError("traffic helper node ownership differs")
        run(["docker", "cp", str(binary), node+":/asservat-fixture-traffic"])
        observed = run(["docker", "exec", node, "sha256sum", "/asservat-fixture-traffic"]).split()[0]
        if observed != digest:
            raise RuntimeError("traffic helper bytes differ")
    fixture["nativeTrafficHelper"] = helper
    report["nativeTrafficHelper"] = helper
    report["nativeTrafficHelperSetup"] = {"elapsedSeconds": time.monotonic()-began,
                                        "binaryBytes": binary.stat().st_size,
                                        "copiedBytes": binary.stat().st_size*len(nodes)}


def qualification_selection(test_pattern, initial_handover, initial_schema_handover, initial_bootstrap_chain=False, helm_bootstrap=False, regional_context_start=None, runtime_object_roundtrip=False, owner_provider_auth=False, runtime_provider_pair=False, runtime_provider_worker=False, runtime_provider_owner=False, installer_continuation=False):
    if test_pattern == NATIVE_TRAFFIC_PROBE:
        if any((initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap,
                regional_context_start, runtime_object_roundtrip, owner_provider_auth,
                runtime_provider_pair, runtime_provider_worker, runtime_provider_owner, installer_continuation)):
            raise ValueError("Traffic probe owns its single synthetic cluster selection")
        return test_pattern, 1
    if installer_continuation and (not runtime_provider_pair or runtime_provider_worker or runtime_provider_owner):
        raise ValueError("Installer continuation reuses the provider-pair network and replaces the fixture continuation")
    if runtime_provider_owner and not runtime_provider_worker:
        raise ValueError("owner runtime requires the original provider worker qualification")
    if runtime_provider_worker and (not runtime_provider_pair or not initial_bootstrap_chain):
        raise ValueError("Runtime worker requires the original provider pair and bootstrap chain")
    if runtime_provider_pair and (test_pattern is not None or not initial_bootstrap_chain or any((initial_handover, initial_schema_handover, helm_bootstrap, runtime_object_roundtrip, owner_provider_auth, regional_context_start is not None))):
        raise ValueError("Provider pair owns the fresh original bootstrap-chain qualification")
    if owner_provider_auth:
        if test_pattern is not None or regional_context_start is not None or any((initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap, runtime_object_roundtrip)):
            raise ValueError("Owner provider qualification owns its exact package/test selection")
        return "^TestOwnerProviderAuthenticationWithRealKubernetesAndOpenBao$", 1
    if runtime_object_roundtrip:
        if test_pattern is not None or regional_context_start is not None or any((initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap)):
            raise ValueError("Runtime object qualification owns its exact package/test selection")
        return "^TestInitialRuntimeObjectRoundTripWithRealKubernetes$", 1
    if regional_context_start is not None:
        if regional_context_start not in ("first", "continuation", "journey") or test_pattern is not None or any((initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap)):
            raise ValueError("Regional context qualification owns its exact test selection")
        return "^TestContextAdmissionWithRealServices$/^native-regional-api-" + regional_context_start + "$", 2
    if sum((initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap)) > 1:
        raise ValueError("Select exactly one installation qualification")
    if initial_handover or initial_schema_handover or initial_bootstrap_chain or helm_bootstrap:
        if test_pattern is not None:
            raise ValueError("Installation qualification owns its exact database selection")
        name = "TestHelmBootstrapWithRealServices" if helm_bootstrap else "TestInitialBootstrapChainWithRealServices" if initial_bootstrap_chain else ("TestInitialSchemaHandoverWithRealServices" if initial_schema_handover else "TestInitialPreparationHandoverWithRealServices")
        # ADR-193 step 5: the continuation qualification also installs a
        # regional connector into two further owned workload clusters (S-02 exit).
        return "^" + name + "$", 3 if installer_continuation else 1
    return test_pattern, 2


def qualification_environment(base, fixture_path, work, initial_handover, initial_schema_handover, initial_bootstrap_chain=False, helm_bootstrap=False, regional_context_start=None, runtime_object_roundtrip=False, owner_provider_auth=False, runtime_provider_pair=False, runtime_provider_worker=False, runtime_provider_owner=False, installer_continuation=False):
    env = base.copy()
    env["ASSERVAT_CONTEXT_FIXTURES"] = str(fixture_path)
    # Development-only keep/rerun switches never leak from the caller's shell.
    for key in DEVELOPMENT_ENVIRONMENT:
        env.pop(key, None)
    for key in ("ASSERVAT_INITIAL_HANDOVER_NATIVE", "ASSERVAT_INITIAL_SCHEMA_HANDOVER_NATIVE", "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE", "ASSERVAT_HELM_BOOTSTRAP_NATIVE", "ASSERVAT_CONTEXT_REGIONAL_START_NATIVE", "ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE", "ASSERVAT_OWNER_PROVIDER_AUTH_NATIVE"):
        env.pop(key, None)
    if initial_handover:
        env["ASSERVAT_INITIAL_HANDOVER_NATIVE"] = "1"
    if initial_schema_handover:
        env["ASSERVAT_INITIAL_SCHEMA_HANDOVER_NATIVE"] = "1"
    if initial_bootstrap_chain:
        env["ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE"] = "1"
    if helm_bootstrap:
        env["ASSERVAT_HELM_BOOTSTRAP_NATIVE"] = "1"
    if regional_context_start is not None:
        if regional_context_start not in ("first", "continuation", "journey"):
            raise ValueError("Invalid regional context qualification")
        env["ASSERVAT_CONTEXT_REGIONAL_START_NATIVE"] = regional_context_start
    if runtime_object_roundtrip:
        env["ASSERVAT_RUNTIME_OBJECT_ROUNDTRIP_NATIVE"] = "1"
    if owner_provider_auth:
        env["ASSERVAT_OWNER_PROVIDER_AUTH_NATIVE"] = "1"
    env.pop("ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR", None)
    env.pop("ASSERVAT_INITIAL_RUNTIME_PROVIDER_WORKER", None)
    env.pop("ASSERVAT_INITIAL_RUNTIME_PROVIDER_OWNER", None)
    env.pop("ASSERVAT_INSTALLER_CONTINUATION", None)
    if not initial_bootstrap_chain or runtime_provider_pair:
        for key in ("ASSERVAT_INITIAL_RUNTIME_BRIDGE", "ASSERVAT_INITIAL_RUNTIME_INSTALLED_OWNER"):
            env.pop(key, None)
    if runtime_provider_pair:
        qualification_selection(None, initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap, regional_context_start, runtime_object_roundtrip, owner_provider_auth, True, runtime_provider_worker, runtime_provider_owner, installer_continuation)
        env["ASSERVAT_INITIAL_RUNTIME_BRIDGE"] = "1"
        env["ASSERVAT_INITIAL_RUNTIME_PROVIDER_PAIR"] = "1"
    if installer_continuation:
        qualification_selection(None, initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap, regional_context_start, runtime_object_roundtrip, owner_provider_auth, runtime_provider_pair, runtime_provider_worker, runtime_provider_owner, True)
        env["ASSERVAT_INSTALLER_CONTINUATION"] = "1"
    if runtime_provider_worker:
        if not runtime_provider_pair or not initial_bootstrap_chain:
            raise ValueError("Runtime worker requires the original provider pair and bootstrap chain")
        env["ASSERVAT_INITIAL_RUNTIME_PROVIDER_WORKER"] = "1"
    if runtime_provider_owner:
        qualification_selection(None, initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap, regional_context_start, runtime_object_roundtrip, owner_provider_auth, runtime_provider_pair, runtime_provider_worker, True)
        env["ASSERVAT_INITIAL_RUNTIME_PROVIDER_OWNER"] = "1"
    env["TMPDIR"] = str(work)
    return env


def start_keycloak(work, network, run_id, containers, report):
    """An owned TLS Keycloak on the private network, reachable by IP from the
    kind nodes and the test process. Its certificate names its container IP,
    which exists only after start, so the entrypoint waits for the key file."""
    import secrets
    import ssl
    certs = work/"keycloak"
    certs.mkdir()
    certs.chmod(0o755)
    admin_password, user_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    env = work/"keycloak.env"
    env.write_text(f"KC_BOOTSTRAP_ADMIN_USERNAME=fixture-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD={admin_password}\n")
    env.chmod(0o600)
    full = network+"-keycloak"
    start = ("while [ ! -s /fixture/key.pem ]; do sleep 0.2; done; exec /opt/keycloak/bin/kc.sh start --db=dev-file --http-enabled=false "
             "--https-port=8443 --https-certificate-file=/fixture/cert.pem --https-certificate-key-file=/fixture/key.pem "
             "--hostname \"https://$(cat /fixture/ip):8443\" --cache=local --health-enabled=false --metrics-enabled=false")
    run(["docker", "create", "--name", full, "--network", network, "--label", "asservat.test="+run_id, "--memory", "1536m", "--cpus", "2",
         "--pids-limit", "512", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--env-file", str(env),
         "--mount", f"type=bind,src={certs},dst=/fixture,readonly", "--entrypoint", "/bin/bash", KEYCLOAK, "-c", start])
    containers.append(full)
    run(["docker", "start", full])
    ip = json.loads(run(["docker", "inspect", full]))[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
    # A one-day synthetic CA (installed provider roots must be CA certificates)
    # and Keycloak's leaf for its container IP.
    ca_key, ca = work/"keycloak-ca-key.pem", work/"keycloak-ca.pem"
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=synthetic-keycloak-root",
         "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca_key), "-out", str(ca)])
    run(["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN="+ip, "-keyout", str(work/"keycloak-key.pem"), "-out", str(work/"keycloak.csr")])
    (work/"keycloak.ext").write_text(f"subjectAltName=IP:{ip}\nextendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\nbasicConstraints=critical,CA:FALSE\n")
    run(["openssl", "x509", "-req", "-in", str(work/"keycloak.csr"), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1",
         "-extfile", str(work/"keycloak.ext"), "-out", str(certs/"cert.pem")])
    (certs/"ip").write_text(ip)
    (certs/"cert.pem").chmod(0o444)
    (certs/"ip").chmod(0o444)
    key = (work/"keycloak-key.pem").read_bytes()
    (certs/"key.pem").write_bytes(key)  # written last: it starts Keycloak
    (certs/"key.pem").chmod(0o444)
    tls = ssl.create_default_context(cafile=str(ca))
    started = time.monotonic()

    def wait():
        # The same readiness bound as before, counted from Keycloak's start;
        # the caller creates the owned clusters meanwhile.
        while time.monotonic() - started < 180:
            try:
                with urllib.request.urlopen(f"https://{ip}:8443/realms/master/.well-known/openid-configuration", context=tls, timeout=2) as response:
                    if response.status == 200:
                        return
            except (OSError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError("owned Keycloak not ready")
    report["keycloak"] = {"image": KEYCLOAK, "address": ip, "scope": "synthetic realm and user; private network only"}
    return {"base": f"https://{ip}:8443", "rootCA": ca.read_text(), "adminUser": "fixture-admin", "adminPassword": admin_password, "userPassword": user_password}, wait


def prepare_fixture_database(cache, work, dsn, pgname, initial_schema_handover):
    # The dedicated schema qualification must give the product an empty database.
    # In particular, even broad fixture runtime grants would hide loader defects.
    if initial_schema_handover:
        return
    migration_env = os.environ.copy()
    migration_env.update({"GOOSE_DRIVER": "postgres", "GOOSE_DBSTRING": dsn, "TMPDIR": str(work)})
    subprocess.run([str(cache/"bin/goose"), "-dir", str(ROOT/"migrations"), "up"], env=migration_env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=60)
    run(["docker", "exec", pgname, "psql", "-U", "postgres", "-d", "custody_test", "-v", "ON_ERROR_STOP=1", "-c", (ROOT/"test/fixtures/sql/runtime-roles.sql").read_text()])


def prepare_ephemeral_node(name, run_id, containers, volumes):
    """Bounded synthetic node state; never used for persistence qualification.

    Keep the seed process alive: Docker's initial tmpfs population is lost when
    create unmounts it before start. Copy the pinned image's /var after mounting.
    The seed never runs Kubernetes or receives any test/provider credentials.
    """
    available = next(int(line.split()[1])*1024 for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    if available < 8 * 1024**3:
        raise RuntimeError("Provider-pair node requires 8 GiB available memory")
    volume, seed = name+"-var", name+"-seed"
    if volume in run(["docker", "volume", "ls", "--format", "{{.Name}}"]).splitlines() or seed in run(["docker", "ps", "-a", "--format", "{{.Names}}"]).splitlines():
        raise RuntimeError("Ephemeral node fixture name collision")
    volumes.append(volume)
    run(["docker", "volume", "create", "--driver", "local", "--label", "asservat.test="+run_id, "--opt", "type=tmpfs", "--opt", "device=tmpfs", "--opt", "o=size=3g", volume])
    containers.append(seed)
    run(["docker", "run", "-d", "--name", seed, "--label", "asservat.test="+run_id, "--network", "none", "--memory", "768m", "--pids-limit", "32", "--mount", "type=volume,source="+volume+",target=/scratch", "--entrypoint", "/bin/sh", NODE, "-c", "cp -a /var/. /scratch/ && touch /scratch/.asservat-seeded && exec sleep 3600"])
    end = time.monotonic()+60
    while time.monotonic() < end:
        if subprocess.run(["docker", "exec", seed, "test", "-f", "/scratch/.asservat-seeded"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5).returncode == 0:
            break
        time.sleep(.1)
    else:
        raise RuntimeError("Ephemeral node image population deadline")
    info = json.loads(run(["docker", "volume", "inspect", volume]))[0]
    if info["Labels"].get("asservat.test") != run_id or info["Options"] != {"device":"tmpfs", "type":"tmpfs", "o":"size=3g"}:
        raise RuntimeError("Ephemeral node volume ownership or limit changed")
    return {"hostPath":info["Mountpoint"], "containerPath":"/var", "propagation":"None"}


DIRECT_OBSERVATION_HELPER_SOURCES = (
    "data.go", "enrollment.go", "inputs.go", "main.go", "metrics.go", "runtime.go",
)
DIRECT_OBSERVATION_ISSUER_TESTS = {
    "TestNativeFixtureConnectorIssuerOriginalSigningInstant",
    "TestNativeFixtureConnectorIssuerOriginalSigningInstant/client",
    "TestNativeFixtureConnectorIssuerOriginalSigningInstant/server",
    "TestNativeFixtureConnectorIssuerStillRejectsExpiredOrCancelled",
    "TestNativeFixtureConnectorIssuerStillRejectsExpiredOrCancelled/expired",
    "TestNativeFixtureConnectorIssuerStillRejectsExpiredOrCancelled/cancelled",
    "TestNativeFixtureConnectorIssuerStillRejectsExpiredOrCancelled/wrong-key",
}


def qualify_direct_helper_issuer(env, report):
    # These files deliberately have build-ignore tags. Explicit file selection
    # tests the very helper implementation compiled into this fixture image.
    files = (*DIRECT_OBSERVATION_HELPER_SOURCES, "enrollment_test.go")
    command = ["go", "test", "-count=1", "-timeout=60s", "-vet=off", "-json",
               "-run=^TestNativeFixtureConnectorIssuer",
               *[str(ROOT/"test/fixtures/observation-native"/name) for name in files]]
    log = ROOT/"test/results/context-storage-helper-issuer.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    entry = {"scope": "actual helper issuer; synthetic permit and CA, no native authority",
             "passedTests": [], "testExit": None}
    report["directObservationHelperIssuer"] = entry
    with log.open("w") as output:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=output,
                                stderr=subprocess.STDOUT, timeout=600)
    entry["testExit"] = result.returncode
    entry["logSHA256"] = hashlib.sha256(log.read_bytes()).hexdigest()
    passed, skipped, failed = set(), set(), set()
    for line in log.read_text().splitlines():
        event = json.loads(line)
        action, test = event.get("Action"), event.get("Test")
        if action == "fail":
            failed.add(test or "package")
        if test and action == "pass":
            passed.add(test)
        if test and action == "skip":
            skipped.add(test)
    entry["passedTests"] = sorted(passed)
    entry["skippedTests"] = sorted(skipped)
    entry["failedTests"] = sorted(failed)
    if result.returncode or failed or skipped or passed != DIRECT_OBSERVATION_ISSUER_TESTS:
        raise RuntimeError("Selected direct helper issuer regression failed or did not execute")


# Installed focuses that load the node collector (disposable-host guard).
COLLECTOR_FOCUSES = ("approved-recording", "manual-syscall", "manual-arguments", "manual-mixed", "manual-raw", "manual-http", "manual-peers", "manual-profile", "profile-comparison", "native-paced", "policy-recording", "policy-arguments", "policy-profile", "ongoing-save", "ongoing-save-disk", "ongoing-incident", "ongoing-syscall", "ongoing-mixed", "live-observation")
# Installed focuses with one hub and one workload cluster.
TWO_CLUSTER_FOCUSES = ("restart", "journey", "browser", "upgrade", "policy", "alert", "logresource", "chain", "share", "manual-logs", "journey-store-failure", "journey-start-failure", "retention-shortening", "early-erasure") + COLLECTOR_FOCUSES
# Focuses that may share one installation with others (ASSERVAT_JOURNEY_FOCUS=a,b):
# chain alone keeps the full installation-process checks and the default
# kubelet resync, clusters needs a third cluster, retention-shortening
# changes the retention source, and early-erasure exercises a cleaner fault.
SOLO_FOCUSES = ("chain", "clusters", "retention-shortening", "early-erasure")


def journey_foci(environ=os.environ):
    """ASSERVAT_JOURNEY_FOCUS as a list: one focus, or several compatible
    focuses run in sequence on one installation (comma-separated). The Go test
    refuses focuses whose shared bootstrap differs
    (installedFocusBootstrapSignature)."""
    value = environ.get("ASSERVAT_JOURNEY_FOCUS") or ""
    foci = value.split(",") if value else []
    if len(foci) > 1 and (len(set(foci)) != len(foci) or any(not re.fullmatch(r"[a-z-]+", f) or f in SOLO_FOCUSES or f not in TWO_CLUSTER_FOCUSES for f in foci)):
        raise ValueError("several focuses must be distinct two-cluster focuses other than " + ", ".join(SOLO_FOCUSES) + ": " + value)
    return foci


def qualification_cluster_count(default_count, installer_continuation=False):
    """Owned topology: one hub plus one workload cluster for these focuses."""
    foci = journey_foci()
    if installer_continuation and foci and all(f in TWO_CLUSTER_FOCUSES for f in foci):
        return 2
    return default_count


def focus_results(output, foci):
    """Each focus subtest's result and seconds from go test -v output; a focus
    without a result line did not run."""
    results = {f: {"result": "notRun", "seconds": None} for f in foci}
    for line in output.splitlines():
        match = re.fullmatch(r"\s*--- (PASS|FAIL|SKIP): TestInitialBootstrapChainWithRealServices/installer-continuation/([a-z-]+) \(([\d.]+)s\)", line)
        if match and match.group(2) in results:
            results[match.group(2)] = {"result": match.group(1).lower(), "seconds": float(match.group(3))}
    return results


def qualification_collector(foci):
    """Whether the focuses load the node collector; never a mix."""
    collector = [f in COLLECTOR_FOCUSES for f in foci]
    if any(collector) and not all(collector):
        raise ValueError("focuses with and without the node collector cannot share one installation: " + ",".join(foci))
    return bool(foci) and all(collector)


def qualification_go_timeout(helm_bootstrap=False, runtime_provider_owner=False, installer_continuation=False, native_traffic_probe=False):
    if native_traffic_probe:
        return "2m"
    foci = journey_foci()
    if installer_continuation and foci and all(f in COLLECTOR_FOCUSES + ("manual-logs",) for f in foci):
        return "18m"
    if installer_continuation:
        # The installed journey waits for its capture's ten-minute expiry; the
        # second workload cluster adds an enrollment and a short journey.
        return "60m"
    # Aggregate test envelope only. Product authority/root/token dates are unchanged.
    # The complete component suite no longer fits Go's 10-minute default.
    return "14m" if runtime_provider_owner else ("12m" if helm_bootstrap else "30m")


# Seconds kept free after go test for this harness's failure diagnostics and
# cleanup (measured: under 10 s after a pass, kubelet journals bounded to 2 x 10 s
# after a failure) and the job's artifact upload/post steps (measured: <= 10 s).
CI_JOB_CLEANUP_MARGIN = 60


def ci_bounded_go_timeout(static, environ=os.environ, now=None):
    """Bound go test -timeout by the CI job deadline, so Go's own timeout fires
    (printing every goroutine) and this harness still records and uploads
    results before the runner cancels the job. ASSERVAT_CI_JOB_DEADLINE is the
    job's Unix end time, set by .github/workflows/native.yml; local runs keep
    the static value."""
    deadline = environ.get("ASSERVAT_CI_JOB_DEADLINE", "")
    if not deadline:
        return static
    remaining = int(deadline) - int(time.time() if now is None else now) - CI_JOB_CLEANUP_MARGIN
    if remaining < 60:
        raise RuntimeError("CI job deadline leaves under one minute for go test")
    if static:
        match = re.fullmatch(r"(\d+)m", static)
        if not match:
            raise ValueError("static go timeout must be whole minutes")
        remaining = min(remaining, int(match.group(1)) * 60)
    return str(remaining) + "s"


def qualification_profile_auth(base):
    auth = base.get("ASSERVAT_PROFILE_AUTH", "") or "none"
    if auth not in ("none", "required") or (auth == "required" and (base.get("ASSERVAT_JOURNEY_FOCUS") != "manual-profile" or (base.get("ASSERVAT_PROFILE_TRANSPORT", "") or "http") != "tls" or (base.get("ASSERVAT_PROFILE_VARIANT", "") or "cpu") != "cpu")):
        raise ValueError("Unknown or incompatible installed profile fixture auth")
    return auth


def qualification_profile_transport(base):
    transport = base.get("ASSERVAT_PROFILE_TRANSPORT", "") or "http"
    variant = base.get("ASSERVAT_PROFILE_VARIANT", "") or "cpu"
    if transport not in ("http", "tls") or (transport == "tls" and (base.get("ASSERVAT_JOURNEY_FOCUS") != "manual-profile" or variant != "cpu")):
        raise ValueError("Unknown or incompatible installed profile fixture transport")
    return transport


def qualification_profile_variant(base):
    variant = base.get("ASSERVAT_PROFILE_VARIANT", "") or "cpu"
    if variant not in ("cpu", "heap", "accepted-heavy", "trace") or (variant in ("heap", "trace") and base.get("ASSERVAT_JOURNEY_FOCUS") != "manual-profile") or (variant == "accepted-heavy" and base.get("ASSERVAT_JOURNEY_FOCUS") != "profile-comparison"):
        raise ValueError("Invalid installed profile fixture variant/focus")
    return variant


def validate_profile_heavy_manifest(directory, generator_sha):
    path = directory / "profile-heavy-manifest.json"
    if not path.is_file() or path.stat().st_size > 16384:
        raise RuntimeError("Accepted-heavy manifest missing or oversized")
    manifest = json.loads(path.read_text())
    if (manifest.get("format") != "accepted-heavy-pprof-fixture/v1" or manifest.get("generator_binary_sha256") != generator_sha
            or manifest.get("profile_type") != "cpu" or manifest.get("sample_type") != "cpu" or manifest.get("unit") != "nanoseconds"
            or manifest.get("duration_ns") != 10000000000 or len(manifest.get("inputs", [])) != 2):
        raise RuntimeError("Accepted-heavy generator provenance mismatch")
    for index, side in enumerate(("baseline", "incident")):
        item = manifest["inputs"][index]
        name = "profile-heavy-"+side+".pb.gz"
        source = directory / name
        if item.get("filename") != name or item.get("side") != side or not source.is_file() or source.stat().st_size != item.get("native_bytes"):
            raise RuntimeError("Accepted-heavy fixed input file mismatch")
        with source.open("rb") as content:
            digest = hashlib.file_digest(content, "sha256").hexdigest()
        if digest != item.get("native_sha256") or not 8*1024**2 < source.stat().st_size <= 16*1024**2:
            raise RuntimeError("Accepted-heavy native input hash/bound mismatch")
        expected = {"functions":100000,"locations":100000,"samples":100000,"frame_visits":1048576,"sample_location_references":1048576,"inline_lines":100000,"values_per_sample":16,"sample_types":16,"numeric_label_records_with_units":32768,"shared_object_units":662144}
        if any(item.get(key) != value for key,value in expected.items()) or not 16*1024**2-128 <= item.get("protobuf_bytes",0) <= 16*1024**2:
            raise RuntimeError("Accepted-heavy structural bound mismatch")
    return manifest


def prepare_profile_containment_fixture(build_env, work, image_dir, report):
    # Separate trusted producer: its graph/encryption-free native generation
    # must not be mistaken for384MiB worker/application memory consumption.
    artifacts = work / "profile-containment"
    artifacts.mkdir(mode=0o700)
    generator = work / "profile-heavy-generator.test"
    subprocess.run(["go","test","-c","-o",str(generator),"./internal/adapters/objectstore"],cwd=ROOT,env=build_env,check=True)
    with generator.open("rb") as content:
        generator_sha = hashlib.file_digest(content, "sha256").hexdigest()
    generate_env = dict(build_env, ASSERVAT_PROFILE_ACCEPTED_HEAVY_DIR=str(image_dir), GOMAXPROCS="2", GOGC="100")
    generate_env.pop("GOMEMLIMIT",None)
    log = artifacts / "profile-heavy-generation.log"
    began = time.monotonic()
    with log.open("wb") as output:
        process = subprocess.Popen([str(generator),"-test.run","^TestProfileAcceptedHeavyNativeFixture$","-test.v"],cwd=ROOT,env=generate_env,stdout=output,stderr=subprocess.STDOUT)
        timed_out = False
        while True:
            waited, status, usage = os.wait4(process.pid,os.WNOHANG)
            if waited:
                break
            if time.monotonic()-began > 60:
                timed_out = True
                process.kill()
                _, status, usage = os.wait4(process.pid,0)
                break
            time.sleep(0.05)
        process.returncode = os.waitstatus_to_exitcode(status)
    generation = {"binarySHA256":generator_sha,"elapsedSeconds":time.monotonic()-began,"peakRSSKiB":usage.ru_maxrss,"userCPUSeconds":usage.ru_utime,"systemCPUSeconds":usage.ru_stime,"exitCode":process.returncode,"timedOut":timed_out,"scope":"separate build producer outside workload/worker cgroups"}
    report["profileHeavyGeneration"] = generation
    manifest_path = image_dir / "profile-heavy-manifest.json"
    if manifest_path.is_file() and manifest_path.stat().st_size <= 16384:
        shutil.copyfile(manifest_path, artifacts/"profile-heavy-manifest.json")
    if process.returncode != 0:
        raise RuntimeError("Accepted-heavy separate producer failed")
    manifest = validate_profile_heavy_manifest(image_dir,generator_sha)
    for item in manifest["inputs"]:
        (image_dir/item["filename"]).chmod(0o444)  # FROMscratch workload UID65532 must read fixed synthetic input files.
    probe = image_dir / "worker-resource-probe"
    subprocess.run(["go","build","-trimpath","-buildvcs=false","-o",str(probe),"./test/fixtures/worker-resource-probe/main.go"],cwd=ROOT,env=build_env,check=True)
    with probe.open("rb") as content:
        probe_sha = hashlib.file_digest(content,"sha256").hexdigest()
    metadata = {"ResourceProbeSHA256":probe_sha,"OutputDirectory":str(artifacts),"Manifest":manifest}
    report["profileContainment"] = metadata
    report["profileHeavyImageNativeBytes"] = sum(item["native_bytes"] for item in manifest["inputs"])
    report["profileResourceProbeBytes"] = probe.stat().st_size
    return metadata


# Kind's kubelet refreshes mounted Secret/ConfigMap volumes only on a Pod
# resync: syncFrequency, default 1m with up to 1.5x jitter. The installed
# bootstrap waits on such refreshes (capacity projection, ReadyAt). Feature
# focuses resync every 5 s; the chain focus keeps the default so the product's
# slow-resync path (projectionMountWait, permission mount bound) stays qualified.
FAST_KUBELET_SYNC = "5s"


def kubelet_sync_frequency(installer_continuation, focus):
    return FAST_KUBELET_SYNC if installer_continuation and focus != "chain" else None


def kind_cluster_config(*, helm=False, mounts=(), sync_frequency=None):
    """The kind Cluster config of one owned cluster (a single control plane
    unless helm adds a worker); mounts go on the control plane."""
    nodes = [{"role": "control-plane"}] + ([{"role": "worker"}] if helm else [])
    if mounts:
        nodes[0]["extraMounts"] = list(mounts)
    config = {"kind": "Cluster", "apiVersion": "kind.x-k8s.io/v1alpha4", "nodes": nodes}
    if sync_frequency:
        config["kubeadmConfigPatches"] = [json.dumps({"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration", "syncFrequency": sync_frequency})]
    return config


def collect_profile_containment_artifacts(work, results):
    """Collect only this run's fixed synthetic producer/observer files at terminal."""
    artifacts = work / "profile-containment"
    if not artifacts.is_dir():
        return None
    destination = results / ("profile-worker-containment-" + work.name)
    destination.mkdir(mode=0o700)
    names = ["profile-heavy-generation.log", "profile-heavy-manifest.json"]
    names += [f"profile-worker-containment-{index}-{kind}.json" for index in range(2) for kind in ("complete", "failure")]
    collected = []
    for name in names:
        source = artifacts / name
        if source.is_file():
            shutil.copyfile(source, destination / name)
            collected.append(name)
    return {"directory": str(destination), "files": collected, "scope": "explicit terminal collection from the private harness directory, including failed runs"}


def main(test_pattern=None, *, initial_handover=False, initial_schema_handover=False, initial_bootstrap_chain=False, helm_bootstrap=False, regional_context_start=None, runtime_object_roundtrip=False, owner_provider_auth=False, runtime_provider_pair=False, runtime_provider_worker=False, runtime_provider_owner=False, installer_continuation=False, helm_cluster=False, keep_on_failure=False, keep_installed=False):
    focus = os.environ.get("ASSERVAT_JOURNEY_FOCUS")
    foci = journey_foci()
    if keep_installed:
        refuse_development_mode_in_ci("--keep-installed")
        if not (installer_continuation and runtime_provider_pair and initial_bootstrap_chain) or focus not in RERUN_FOCUSES:
            raise ValueError("--keep-installed needs the installer continuation and a rerun focus: " + ", ".join(RERUN_FOCUSES))
    profile_auth = qualification_profile_auth(os.environ)
    profile_transport = qualification_profile_transport(os.environ)
    if profile_transport == "tls" and not installer_continuation:
        raise ValueError("TLS profile fixture transport requires the installed CPU continuation")
    profile_variant = qualification_profile_variant(os.environ)
    if profile_variant == "accepted-heavy" and not installer_continuation:
        raise ValueError("Accepted-heavy requires the installed comparison continuation")
    collector_qualification = installer_continuation and qualification_collector(foci)
    native_paced = installer_continuation and "native-paced" in foci
    native_traffic_probe = test_pattern == NATIVE_TRAFFIC_PROBE
    guard = Path("/etc/asservat-disposable-host")
    if collector_qualification and not guard.is_file():
        raise RuntimeError(f"{focus} refused: disposable-host guard is absent; never run a collector on a workstation")
    if helm_cluster and (helm_bootstrap or test_pattern is not None):
        raise ValueError("--helm-cluster owns its registry/chart infrastructure and exact test selection")
    # ADR-193 step 6: the Helm registry/chart infrastructure, another test.
    helm_bootstrap = helm_bootstrap or helm_cluster
    test_pattern, cluster_count = qualification_selection(test_pattern, initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap, regional_context_start, runtime_object_roundtrip, owner_provider_auth, runtime_provider_pair, runtime_provider_worker, runtime_provider_owner, installer_continuation)
    cluster_count = qualification_cluster_count(cluster_count, installer_continuation)
    if native_traffic_probe:
        (ROOT/"test/results/native-traffic-probe.json").unlink(missing_ok=True)
    if native_paced:
        for filename in ("native-paced-report.json", "native-paced-kubernetes-audit.json"):
            (ROOT/"test/results"/filename).unlink(missing_ok=True)
    helm_test = "TestHelmClusterInstallWithRealServices" if helm_cluster else "TestHelmBootstrapWithRealServices"
    if helm_cluster:
        test_pattern = "^" + helm_test + "$"
    direct_observation = test_pattern == "^TestDirectHolderObservationWithRealKubernetes$"
    # Product federation/connector Pods also run in every owned cluster.
    two_cluster_pods = direct_observation or test_pattern == "^TestFederationRegionalProductWithRealKubernetes$" or installer_continuation
    test_package = "./internal/adapters/kms" if owner_provider_auth else "./internal/adapters/kubernetes" if runtime_object_roundtrip else "./test/integration"
    cache = Path(os.environ.get("XDG_CACHE_HOME", Path.home()/".cache"))/"asservat-build"
    cache.mkdir(parents=True, exist_ok=True)
    with ExitStack() as cleanup:
        work = Path(tempfile.mkdtemp(prefix="context-", dir=cache)).absolute()
        work.chmod(0o700)
        keep_work = False
        cleanup.callback(lambda: None if keep_work else shutil.rmtree(work))
        run_id = work.name.replace("_", "-")
        network = "asservat-"+run_id
        containers, clusters, ephemeral_volumes = [], [], []
        created_network = False
        # Kind nodes join an owned egress network instead of the shared "kind"
        # network, whose host rules other projects' containers may depend on.
        kind_network, created_kind_network = network+"-kind", False
        worker_tag = None
        collector_tag = None
        # ADR-227 focused upgrade run: a second release image of the same
        # build, differing only by a label, so its digest differs.
        upgrade_tag = None
        upgrade = installer_continuation and "upgrade" in foci
        alert = installer_continuation and "alert" in foci
        signals = installer_continuation and "logresource" in foci
        registry = None
        registry_nodes = []
        build_scratch = None
        log_streamer = None
        audit_started = False
        audit_nodes = []
        report = {"scope": "component integration, not S-02 release acceptance", "runtimeProviderPairQualification": runtime_provider_pair, "runtimeProviderWorkerQualification": runtime_provider_worker, "runtimeProviderOwnerQualification": runtime_provider_owner, "installerContinuationQualification": installer_continuation, "aggregateGoTimeout": qualification_go_timeout(helm_bootstrap, runtime_provider_owner, installer_continuation, native_traffic_probe), "bootstrapFixtureSeconds": (2700 if installer_continuation else 720 if runtime_provider_owner else 480) if initial_bootstrap_chain else None, "images": {"s3": SEAWEED, "kms": BAO, "kubernetes": NODE, "postgres": POSTGRES}, "clusters": [], "testPattern": test_pattern, "testPackage": test_package, "runtimeObjectRoundTripQualification": runtime_object_roundtrip, "ownerProviderAuthenticationQualification": owner_provider_auth, "initialHandoverQualification": initial_handover, "initialSchemaHandoverQualification": initial_schema_handover, "initialBootstrapChainQualification": initial_bootstrap_chain, "helmBootstrapQualification": helm_bootstrap and not helm_cluster, "helmClusterQualification": helm_cluster, "regionalContextStartQualification": regional_context_start, "fixtureMigratesDatabase": not (initial_schema_handover or initial_bootstrap_chain or helm_bootstrap)}
        if keep_installed:
            report["qualification"] = False
            report["developmentMode"] = "keep-installed: the installation is left running for --rerun-installed; never a qualification"
        state_path = work/"installed-state.json"
        exit_code = 1
        # Harness phase end times in seconds since start, so slow setup is
        # measured (report "phaseSeconds"; the Go test has its own timing log).
        began = time.monotonic()
        report["phaseSeconds"] = {}

        def phase(name):
            report["phaseSeconds"][name] = round(time.monotonic()-began, 1)
        keycloak_ready = None
        compile_ahead = None
        cluster_pool, cluster_futures = None, []
        try:
            if runtime_provider_pair or direct_observation:
                if shutil.disk_usage(tempfile.gettempdir()).free < 4 * 1024**3:
                    raise RuntimeError("Selected in-Pod qualification requires 4 GiB free build scratch")
                build_scope = "direct-observation" if direct_observation else "provider-pair"
                build_scratch = Path(tempfile.mkdtemp(prefix="asservat-"+build_scope+"-build-", dir=tempfile.gettempdir()))
                report["buildScratch"] = str(build_scratch)
            report["goVersion"] = run(["go", "version"])
            report["installedHistoryBrowserQualification"] = collector_qualification and "approved-recording" in foci
            report["installedProfileComparisonBrowserQualification"] = collector_qualification and "profile-comparison" in foci
            report["installedPacketSummaryBrowserQualification"] = collector_qualification and any(f in ("manual-mixed", "manual-raw") for f in foci)
            report["installedPacketQueryQualification"] = collector_qualification and "manual-raw" in foci
            report["installedRawSyscallQueryQualification"] = collector_qualification and "manual-arguments" in foci
            report["installedLogsQueryQualification"] = installer_continuation and "manual-logs" in foci
            report["installedHeapBrowserQualification"] = collector_qualification and "manual-profile" in foci and profile_variant == "heap"
            report["installedProfileAuth"] = profile_auth if collector_qualification and "manual-profile" in foci else None
            report["installedProfileTransport"] = profile_transport if collector_qualification and "manual-profile" in foci else None
            report["installedProfileVariant"] = profile_variant if collector_qualification and any(f in ("manual-profile","profile-comparison") for f in foci) else None
            report["installedPolicyRecordingFocus"] = collector_qualification and "policy-recording" in foci
            report["installedPolicyArgumentsFocus"] = collector_qualification and "policy-arguments" in foci
            report["installedPolicyProfileFocus"] = collector_qualification and "policy-profile" in foci
            report["sourceHashes"] = source_hashes()
            report.update({"harnessState": "setup", "goTestExit": None, "testExit": None, "cleanupComplete": False})
            write_environment_report(ROOT/"test/results/context-storage-environment.json", report)
            if helm_bootstrap:
                report["helmVersion"] = run(["helm", "version", "--short"])
                report["images"]["registry"] = REGISTRY
            run(["docker", "network", "create", "--internal", "--label", "asservat.test="+run_id, network])
            created_network = True
            run(["docker", "network", "create", "--label", "asservat.test="+run_id, kind_network])
            created_kind_network = True
            os.environ["KIND_EXPERIMENTAL_DOCKER_NETWORK"] = kind_network
            # Create every owned cluster concurrently (each takes about 40 s)
            # while the images build and the services start; per-cluster setup
            # after the join below runs in order as before. The clusters need
            # neither images nor services.
            sync_frequency = kubelet_sync_frequency(installer_continuation, focus)
            report["kubeletSyncFrequency"] = sync_frequency or "kind default (1m)"
            creates = []
            existing = run(["kind", "get", "clusters"]).splitlines()
            for index in range(cluster_count):
                name = network+"-"+str(index)
                config = work/("kube-"+str(index))
                # Refuse collisions before recording ownership; never reuse a cluster.
                if name in existing: raise RuntimeError("cluster name collision")
                clusters.append(name)
                print("Creating owned synthetic cluster", index+1, flush=True)
                # Retain only until our finally cleanup so setup failures can be
                # diagnosed; Kind's default removes the evidence immediately.
                create = ["kind", "create", "cluster", "--name", name, "--image", NODE, "--kubeconfig", str(config), "--wait", "90s", "--retain"]
                mounts = []
                if runtime_provider_pair and index == 0 and not helm_bootstrap:
                    mounts.append(prepare_ephemeral_node(name, run_id, containers, ephemeral_volumes))
                    report["ephemeralNodeState"] = {"volume":ephemeral_volumes[-1], "maxBytes":3*1024**3, "storage":"tmpfs", "scope":"Synthetic API node only; original startup/product deadlines, no persistence qualification"}
                if collector_qualification and index == 1:
                    mounts.append({"hostPath": str(guard), "containerPath": str(guard), "readOnly": True})
                kind_config = kind_cluster_config(helm=helm_bootstrap, mounts=mounts, sync_frequency=sync_frequency)
                if native_paced:
                    # Extend the provider-pair/collector configuration; never
                    # replace its tmpfs or disposable-host guard mounts.
                    native_kube_audit.configure(kind_config, work, index)
                config_path = work/("kind-"+str(index)+".json")
                config_path.write_text(json.dumps(kind_config))
                creates.append(create + ["--config", str(config_path)])
            # Every create joins the owned network created above
            # (KIND_EXPERIMENTAL_DOCKER_NETWORK); none sets up a shared one, so
            # all run concurrently.
            cluster_pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(creates)))
            cluster_futures = [cluster_pool.submit(run, create) for create in creates]
            image_dir = work/"worker-image"
            image_dir.mkdir()
            build_env = os.environ.copy()
            build_env.update({"TMPDIR": str(build_scratch or work), "CGO_ENABLED": "0"})
            installed_budget = None
            if installer_continuation:
                installed_budget = json.loads(subprocess.check_output(
                    ["go", "run", "./test/fixtures/installed-sql-budget/main.go"], cwd=ROOT, env=build_env, text=True))
                report["postgresqlConnectionBudget"] = installed_budget
            build_hub_binaries(image_dir, build_env)
            helper_copy = ""
            containment_fixture = None
            if profile_variant == "accepted-heavy":
                containment_fixture = prepare_profile_containment_fixture(build_env,work,image_dir,report)
                helper_copy += "COPY profile-heavy-baseline.pb.gz /profile-heavy-baseline.pb.gz\nCOPY profile-heavy-incident.pb.gz /profile-heavy-incident.pb.gz\nCOPY worker-resource-probe /worker-resource-probe\n"
            if any(f in ("manual-profile", "profile-comparison", "policy-profile") for f in foci):
                subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(image_dir/"profile-native"), "./test/fixtures/profile-native/main.go"], cwd=ROOT, env=build_env, check=True)
                helper_copy += "COPY profile-native /profile-native\n"
                report["profileWorkloadSHA256"] = hashlib.sha256((image_dir/"profile-native").read_bytes()).hexdigest()
            if direct_observation:
                qualify_direct_helper_issuer(build_env, report)
                subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(image_dir/"observation-native"), *[str(ROOT/"test/fixtures/observation-native"/name) for name in DIRECT_OBSERVATION_HELPER_SOURCES]], cwd=ROOT, env=build_env, check=True)
                helper_copy = "COPY observation-native /observation-native\n"
                report["directObservation"] = {"helperSHA256": hashlib.sha256((image_dir/"observation-native").read_bytes()).hexdigest(), "runtimeSelection": False, "setupAuthority": "synthetic installer/issuer acceptance; actual API/SQL/S3/TLS path", "fullInstalledHWORKBackground": False}
            if installer_continuation:
                # ADR-194: the promoted hub-api serves the image-owned console
                # package; build it fresh into the image, never from web/dist.
                report["consolePackageSHA256"] = build_console(image_dir, build_env)
                helper_copy += "COPY console /usr/share/asservat/console\n"
            (image_dir/"Dockerfile").write_text("FROM scratch\nCOPY asservat /asservat\nCOPY provider-proxy /provider-proxy\n"+helper_copy+"USER 65532:65532\n")
            worker_tag = "asservat-context-worker:"+run_id
            run(["docker", "build", "--network=none", "--label", "asservat.test="+run_id, "-t", worker_tag, str(image_dir)])
            worker_info = json.loads(run(["docker", "image", "inspect", worker_tag]))[0]
            report["workerBuild"] = {"binarySHA256": hashlib.sha256((image_dir/"asservat").read_bytes()).hexdigest(), "tags": "libpcap,netgo,osusergo (static)", "dockerImageID": worker_info["Id"], "tag": worker_tag}
            if collector_qualification:
                collector_dir = work / "collector-image"
                collector_dir.mkdir()
                started = time.monotonic()
                subprocess.run(["go", "build", "-tags", "gadget,netgo,osusergo", "-trimpath", "-buildvcs=false", "-o", str(collector_dir / "asservat"), "./cmd/asservat"], cwd=ROOT, env=build_env, check=True)
                subprocess.run([str(ROOT / "scripts/fetch-gadget.sh"), str(collector_dir / "gadgets/tcpdump")], check=True)
                subprocess.run([str(ROOT / "scripts/fetch-gadget.sh"), str(collector_dir / "gadgets/traceloop"), "traceloop"], check=True)
                subprocess.run([sys.executable, str(ROOT / "scripts/package-argument-gadget.py"), str(collector_dir / "gadgets/traceloop-arguments"), "--tmpdir", str(work)], check=True)
                (collector_dir / "Dockerfile").write_text("FROM scratch\nCOPY asservat /asservat\nCOPY gadgets /usr/lib/asservat/gadgets\n")
                collector_tag = "asservat-approved-collector:" + run_id
                run(["docker", "build", "--network=none", "--label", "asservat.test="+run_id, "-t", collector_tag, str(collector_dir)])
                report["collectorBuild"] = {"seconds": round(time.monotonic()-started, 1), "binarySHA256": hashlib.sha256((collector_dir / "asservat").read_bytes()).hexdigest(), "tags": "gadget,netgo,osusergo", "kernelRelease": os.uname().release, "gadgetBlobs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((collector_dir / "gadgets/tcpdump/blobs/sha256").iterdir())}}
                report["collectorBuild"]["arguments"] = argument_engine_build_inventory(collector_dir / "gadgets/traceloop-arguments")
            if upgrade:
                upgrade_tag = "asservat-context-worker:"+run_id+"-upgrade"
                run(["docker", "build", "--network=none", "--label", "asservat.test="+run_id, "--label", "asservat.release=upgrade", "-t", upgrade_tag, str(image_dir)])
                upgrade_info = json.loads(run(["docker", "image", "inspect", upgrade_tag]))[0]
                if upgrade_info["Id"] == worker_info["Id"]:
                    raise RuntimeError("upgrade image has the original image's digest")
                report["upgradeBuild"] = {"dockerImageID": upgrade_info["Id"], "tag": upgrade_tag}
            phase("imagesBuilt")
            # Compile the Go test package while the fixtures start: same flags
            # as the run below, output discarded. It only fills the Go build
            # cache; the real `go test` still builds (and reports) everything.
            compile_ahead = subprocess.Popen(["go", "test", "-count=1"] + ([] if installer_continuation else ["-race"]) + ["-run", "^$", test_package],
                                             cwd=ROOT, env={**os.environ, "TMPDIR": str(build_scratch or work)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            if helm_bootstrap:
                registry = HelmRegistry(work, network, run_id, containers, run)
                registry.upload(worker_tag, worker_info["Id"])
                report["registryImageIdentity"] = registry.export_identity
                chart_dir = work/"chart"
                chart_dir.mkdir()
                run(["helm", "package", str(ROOT/"charts/asservat"), "--destination", str(chart_dir)])
                chart_archive, = chart_dir.glob("*.tgz")
                report["helmChartArchiveSHA256"] = hashlib.sha256(chart_archive.read_bytes()).hexdigest()
            def service(name, image, command, extra):
                full = network+"-"+name
                run(["docker", "create", "--name", full, "--network", network,
                     "--label", "asservat.test="+run_id, "--memory", "768m", "--cpus", "1",
                     "--pids-limit", "256", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                     *extra, image, *command])
                containers.append(full)
                run(["docker", "start", full])
                info = json.loads(run(["docker", "inspect", full]))[0]
                return info["NetworkSettings"]["Networks"][network]["IPAddress"]
            s3ip = service("s3", SEAWEED, ["mini", "-dir=/data", "-ip.bind=0.0.0.0", "-admin.ui=false", "-s3.port=8333"], ["--user", "1000:1000", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-v", "/data", "-e", "AWS_ACCESS_KEY_ID=synthetic-only", "-e", "AWS_SECRET_ACCESS_KEY=synthetic-only-secret", "--entrypoint", "/usr/bin/weed"])
            baoip = service("kms", BAO, ["server", "-dev", "-dev-no-store-token", "-dev-root-token-id=synthetic-root", "-dev-listen-address=0.0.0.0:8200"], ["--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m", "-e", "SKIP_SETCAP=true", "-e", "BAO_DISABLE_MLOCK=true", "--entrypoint", "/usr/bin/bao"])
            pgip = service("postgres", POSTGRES, postgres_fixture_options(regional_context_start, lock_waits=installer_continuation, installed_budget=installed_budget, native_statistics=native_paced), ["--user", "postgres", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,size=32m", "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,size=16m,mode=1777", "-v", "/var/lib/postgresql", "-e", "POSTGRES_PASSWORD=synthetic-only", "-e", "POSTGRES_DB=custody_test"])
            proxy_ip = service("tls", worker_tag, ["http://"+s3ip+":8333", "http://"+baoip+":8200", pgip+":5432"], ["--user", "65532:65532", "--read-only", "--entrypoint", "/provider-proxy"])
            for _ in range(50):
                try:
                    native_providers = json.loads(run(["docker", "logs", network+"-tls"]))
                    break
                except (json.JSONDecodeError, subprocess.CalledProcessError): time.sleep(.1)
            else: raise RuntimeError("native TLS fixture unavailable")
            report["nativeTLSProviders"] = {"address": proxy_ip, "scope": "TLS in owned private container, plaintext private backend hops"}
            pgname=network+"-postgres"
            if runtime_provider_pair:
                # This is fixture initdb readiness before any product operation,
                # not an extension of a native proof or installation deadline.
                startup = time.monotonic()
                startup_end = startup + 90
                ready = False
                try:
                    while time.monotonic() < startup_end:
                        remaining = startup_end - time.monotonic()
                        try:
                            probe = subprocess.run(["docker", "exec", pgname, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "custody_test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=max(.001, min(5, remaining)))
                            if probe.returncode == 0:
                                ready = True
                                break
                        except subprocess.TimeoutExpired:
                            pass
                        time.sleep(min(.1, max(0, startup_end-time.monotonic())))
                finally:
                    report["postgresFixtureStartup"] = {"limitSeconds": 90, "elapsedSeconds": round(time.monotonic()-startup, 3), "ready": ready}
                if not ready:
                    raise RuntimeError("PostgreSQL fixture not ready")
            else:
                for _ in range(100):
                    if subprocess.run(["docker", "exec", pgname, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "custody_test"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
                    time.sleep(.1)
                else: raise RuntimeError("PostgreSQL fixture not ready")
            dsn="postgres://postgres:synthetic-only@"+pgip+":5432/custody_test?sslmode=disable"
            if native_paced:
                report["nativeSQLStatistics"] = True
            prepare_fixture_database(cache, work, dsn, pgname, initial_schema_handover or initial_bootstrap_chain or helm_bootstrap)
            for url in ["http://"+s3ip+":8333", "http://"+baoip+":8200/v1/sys/health"]:
                for attempt in range(40):
                    try:
                        with urllib.request.urlopen(url, timeout=1): pass
                        break
                    except urllib.error.HTTPError as exc:
                        if exc.code in (403, 404): break
                    except OSError: pass
                    time.sleep(.25)
                else: raise RuntimeError("fixture did not become ready")
            fixture = {"s3": "http://"+s3ip+":8333", "kms": "http://"+baoip+":8200", "postgres":dsn, "postgresContainer": pgname, "nativeProviders":native_providers, "clusters": []}
            if profile_transport == "tls":
                tls_directory = work/"profile-tls"
                tls_directory.mkdir(mode=0o700)
                fixture["ProfileTLSDirectory"] = str(tls_directory)
            if containment_fixture is not None:
                fixture["ProfileContainment"] = containment_fixture
            if native_paced:
                fixture["nativeSQLStatistics"] = True
            if installer_continuation:
                fixture["identity"], keycloak_ready = start_keycloak(work, network, run_id, containers, report)
            if alert:
                fixture["alertmanagerImage"] = ALERTMANAGER
                report["images"]["alertmanager"] = ALERTMANAGER
            if signals:
                fixture["metricsServerImage"] = METRICS_SERVER
                report["images"]["metricsServer"] = METRICS_SERVER

            if direct_observation:
                fixture["directObservation"] = report["directObservation"]
            # Product Pods in the second cluster need the image loaded there too.
            fixture["twoClusterPods"] = two_cluster_pods
            if helm_bootstrap:
                fixture["helmBootstrap"] = {"registryConfig": registry.material(), "productBinary": str(image_dir/"asservat"), "chartArchive": str(chart_archive)}
            phase("servicesStarted")
            # Join the cluster creation started before the image build.
            for future in cluster_futures:
                future.result()
            phase("clustersCreated")
            for index in range(cluster_count):
                name = network+"-"+str(index)
                config = work/("kube-"+str(index))
                config.chmod(0o600)
                if (native_paced and index == 1) or (native_traffic_probe and index == 0):
                    # Common to fast provider-pair and private-registry setup.
                    install_native_traffic_helper(image_dir/"provider-proxy", name, fixture, report)
                run(["docker", "update", "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", name+"-control-plane"])
                if index == 0 or two_cluster_pods:
                    node_name = name+"-control-plane"
                    run(["docker", "network", "connect", network, node_name])
                    if runtime_provider_pair and index == 0:
                        # Only the owned provider joins the exact owned node's
                        # original API network. No foreign node is read or used.
                        info = json.loads(run(["docker", "inspect", node_name]))[0]
                        original_networks = [n for n in info["NetworkSettings"]["Networks"] if n != network]
                        if len(original_networks) != 1:
                            raise RuntimeError("original owned API network is ambiguous")
                        run(["docker", "network", "connect", original_networks[0], network+"-kms"])
                        report["providerReviewerNetwork"] = {"ownedProvider": network+"-kms", "ownedAPINode": node_name, "network": original_networks[0]}
                        fixture["runtimeProviderPairS3Container"] = network+"-s3"
                    if helm_bootstrap:
                        worker_node = name+"-worker"
                        run(["docker", "update", "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", worker_node])
                        run(["docker", "network", "connect", network, worker_node])
                        for owned in [node_name, worker_node]:
                            registry.configure_owned_node(owned)
                            info = json.loads(run(["docker", "inspect", owned]))[0]
                            registry_nodes.append(info["NetworkSettings"]["Networks"][network]["IPAddress"])
                        fixture["workerImage"] = registry.image
                        report["workerBuild"]["nodeImage"] = registry.image
                        report["workerBuild"]["exactImageAbsentBeforeBothPulls"] = True
                        k = ["kubectl", "--kubeconfig", str(config), "--request-timeout=15s"]
                        run(k+["taint", "node", node_name, "node-role.kubernetes.io/control-plane:NoSchedule-"])
                        run(k+["cordon", worker_node])
                        a = json.loads(run(k+["get","node",node_name,"-o","json"]))
                        b = json.loads(run(k+["get","node",worker_node,"-o","json"]))
                        fixture["helmBootstrap"].update(nodeA=node_name,nodeAUID=a["metadata"]["uid"],nodeB=worker_node,nodeBUID=b["metadata"]["uid"])
                    else:
                        run(["kind", "load", "docker-image", worker_tag, "--name", name])
                        native_tag = "docker.io/library/"+worker_tag
                        rows = run(["docker", "exec", node_name, "ctr", "-n", "k8s.io", "images", "ls"]).splitlines()
                        matches = [row.split()[2] for row in rows if row.split()[0] == native_tag]
                        if len(matches) != 1 or not matches[0].startswith("sha256:"):
                            raise RuntimeError("loaded worker image identity unavailable")
                        digest_ref = "docker.io/library/asservat-context-worker@"+matches[0]
                        run(["docker", "exec", node_name, "ctr", "-n", "k8s.io", "images", "tag", native_tag, digest_ref])
                        if direct_observation and "workerImage" in fixture and fixture["workerImage"] != digest_ref:
                            raise RuntimeError("two owned nodes loaded different exact helper image identities")
                        fixture["workerImage"] = digest_ref
                        report["workerBuild"]["nodeImage"] = digest_ref
                        if collector_tag and index == 1:
                            run(["kind", "load", "docker-image", collector_tag, "--name", name])
                            collector_native = "docker.io/library/" + collector_tag
                            rows = run(["docker", "exec", node_name, "ctr", "-n", "k8s.io", "images", "ls"]).splitlines()
                            matches = [row.split()[2] for row in rows if row.split()[0] == collector_native]
                            if len(matches) != 1 or not matches[0].startswith("sha256:"):
                                raise RuntimeError("loaded approved collector image identity unavailable")
                            collector_ref = "docker.io/library/asservat-approved-collector@" + matches[0]
                            run(["docker", "exec", node_name, "ctr", "-n", "k8s.io", "images", "tag", collector_native, collector_ref])
                            fixture["collectorImage"] = collector_ref
                            report["collectorBuild"]["nodeImage"] = collector_ref
                        if upgrade_tag and index == 0:
                            # Only the hub cluster runs the upgraded hub workloads.
                            run(["kind", "load", "docker-image", upgrade_tag, "--name", name])
                            native_upgrade = "docker.io/library/"+upgrade_tag
                            rows = run(["docker", "exec", node_name, "ctr", "-n", "k8s.io", "images", "ls"]).splitlines()
                            matches = [row.split()[2] for row in rows if row.split()[0] == native_upgrade]
                            if len(matches) != 1 or not matches[0].startswith("sha256:") or "asservat-context-worker@"+matches[0] == digest_ref.removeprefix("docker.io/library/"):
                                raise RuntimeError("loaded upgrade image identity unavailable")
                            upgrade_ref = "docker.io/library/asservat-context-worker@"+matches[0]
                            run(["docker", "exec", node_name, "ctr", "-n", "k8s.io", "images", "tag", native_upgrade, upgrade_ref])
                            fixture["upgradeImage"] = upgrade_ref
                            report["upgradeBuild"]["nodeImage"] = upgrade_ref
                pause = PAUSE
                k = ["kubectl", "--kubeconfig", str(config), "--request-timeout=15s"]
                resources = [
                    {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "synthetic", "labels": {"pod-security.kubernetes.io/enforce": "restricted"}}},
                    {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "fixture", "namespace": "synthetic"}, "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "fixture"}}, "template": {"metadata": {"labels": {"app": "fixture"}, "annotations": {"synthetic-user-data": "MUST-NOT-LEAK"}}, "spec": {"securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "fixture", "image": pause, "imagePullPolicy": "IfNotPresent", "env": [{"name": "SYNTHETIC_SECRET", "value": "MUST-NOT-LEAK"}], "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}, "resources": {"requests": {"memory": "8Mi", "cpu": "5m"}, "limits": {"memory": "32Mi", "cpu": "50m"}}}]}}}},
                    {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "context-reader", "namespace": "synthetic"}},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "context-reader", "namespace": "synthetic"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "context-reader", "namespace": "synthetic"}, "subjects": [{"kind": "ServiceAccount", "name": "context-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "context-reader"}},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "context-reader"}, "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["synthetic"], "verbs": ["get"]}]},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "context-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "context-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "context-reader"}},
                ]
                resources.extend([
                    {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "target-reader", "namespace": "synthetic"}},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "target-reader", "namespace": "synthetic"}, "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}, {"apiGroups": ["apps"], "resources": ["deployments", "statefulsets", "replicasets"], "verbs": ["get"]}]},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": "target-reader", "namespace": "synthetic"}, "subjects": [{"kind": "ServiceAccount", "name": "target-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "target-reader"}},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": "target-reader"}, "rules": [{"apiGroups": [""], "resources": ["namespaces"], "resourceNames": ["synthetic"], "verbs": ["get"]}, {"apiGroups": [""], "resources": ["nodes"], "resourceNames": [name+"-control-plane"], "verbs": ["get"]}]},
                    {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": "target-reader"}, "subjects": [{"kind": "ServiceAccount", "name": "target-reader", "namespace": "synthetic"}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "target-reader"}},
                ])
                run(k+["apply", "-f", "-"], data=json.dumps({"apiVersion": "v1", "kind": "List", "items": resources}))
                try:
                    run(k+["-n", "synthetic", "rollout", "status", "deployment/fixture", "--timeout=90s"])
                except subprocess.CalledProcessError:
                    # Fixture setup diagnosis only: the Pod and event state at the failure.
                    for extra in (["-n", "synthetic", "describe", "pods"], ["-n", "synthetic", "get", "events", "--sort-by=.lastTimestamp"], ["get", "nodes", "-o", "wide"]):
                        try:
                            print(run(k+extra), file=sys.stderr)
                        except subprocess.CalledProcessError as error:
                            print(error.stderr, file=sys.stderr)
                    raise
                pod = json.loads(run(k+["-n", "synthetic", "get", "pod", "-l", "app=fixture", "-o", "json"]))["items"][0]
                ns = json.loads(run(k+["get", "namespace", "synthetic", "-o", "json"]))
                node = json.loads(run(k+["get", "node", pod["spec"]["nodeName"], "-o", "json"]))
                deployment = json.loads(run(k+["-n", "synthetic", "get", "deployment", "fixture", "-o", "json"]))
                token = run(k+["-n", "synthetic", "create", "token", "context-reader", "--duration=1h"])
                target_token = run(k+["-n", "synthetic", "create", "token", "target-reader", "--duration=1h"])
                fixture["clusters"].append({"config": str(config), "token": token, "targetToken": target_token, "nodeUID":node["metadata"]["uid"], "nodeBootID":node["status"]["nodeInfo"]["bootID"], "workloadUID":deployment["metadata"]["uid"], "pod": {"Namespace": "synthetic", "NamespaceUID": ns["metadata"]["uid"], "Name": pod["metadata"]["name"], "UID": pod["metadata"]["uid"], "NodeName": pod["spec"]["nodeName"], "ControllerUID": pod["metadata"]["ownerReferences"][0]["uid"]}})
                report["clusters"].append({"name": name, "nodeImage": NODE, "workloadImage": pause, "podUID": pod["metadata"]["uid"]})
            if native_paced or native_traffic_probe:
                require_native_traffic_helper(fixture, clusters[1 if native_paced else 0])
            phase("clustersPrepared")
            if keycloak_ready is not None:
                keycloak_ready()
                phase("keycloakReady")
            path = work/"fixtures.json"
            path.touch(mode=0o600)
            path.write_text(json.dumps(fixture))
            env = qualification_environment(os.environ, path, work, initial_handover, initial_schema_handover, initial_bootstrap_chain, helm_bootstrap, regional_context_start, runtime_object_roundtrip, owner_provider_auth, runtime_provider_pair, runtime_provider_worker, runtime_provider_owner, installer_continuation)

            if build_scratch is not None:
                env["TMPDIR"] = str(build_scratch)
            if keep_on_failure:
                env["ASSERVAT_KEEP_ON_FAILURE"] = "1"
            if keep_installed:
                env["ASSERVAT_INSTALLED_KEEP"] = "1"
                env["ASSERVAT_INSTALLED_STATE"] = str(state_path)

            # The installed journey's test process is a client waiting on
            # Kubernetes; the product runs in Pods built without -race. Race
            # coverage stays with the component and unit suites.
            command = ["go", "test", "-count=1", "-v"] if installer_continuation else ["go", "test", "-race", "-count=1", "-v"]
            if test_pattern:
                command += ["-run", test_pattern]
            aggregate_timeout = qualification_go_timeout(helm_bootstrap, runtime_provider_owner, installer_continuation, native_traffic_probe)
            if os.environ.get("ASSERVAT_JOURNEY_HOLD") and installer_continuation:
                aggregate_timeout = "150m"  # local debugging hold only
            report["journeyFocus"] = os.environ.get("ASSERVAT_JOURNEY_FOCUS", "")
            if native_paced:
                for index, cluster in enumerate(fixture["clusters"]):
                    owned = native_kube_audit.owned_node(network+"-"+str(index))
                    audit_nodes.append((owned, cluster["config"]))
                    run(["kubectl", "--kubeconfig", cluster["config"], "--request-timeout=5s", "get", "--raw", "/readyz"])
                audit_started = True
            compile_ahead.wait()
            # Bound by the CI job deadline only now, when go test starts.
            aggregate_timeout = ci_bounded_go_timeout(aggregate_timeout)
            report["effectiveGoTimeout"] = aggregate_timeout
            if aggregate_timeout:
                command += ["-timeout", aggregate_timeout]
            command += [test_package]
            phase("goTestStart")
            # Each output line also goes, with its elapsed seconds, to a timing
            # log, so slow phases are measured rather than guessed.
            if installer_continuation or helm_bootstrap:
                # Pod logs reach test/results as they are written: Go cleanup
                # collection is lost when a timeout ends the test process.
                shutil.rmtree(ROOT/"test/results/pod-logs", ignore_errors=True)
                log_streamer = PodLogStreamer([(name, work/("kube-"+str(index))) for index, name in enumerate(clusters)], ROOT/"test/results/pod-logs").start()
            try:
                exit_code = record_go_output(command, env, ROOT/"test/results", report)
                phase("goTestEnd")
            finally:
                if log_streamer is not None:
                    report["podLogStream"] = log_streamer.stop()
                    log_streamer = None
            report["goTestExit"] = exit_code
            raw_output = (ROOT/"test/results/context-storage.log").read_bytes()
            try:
                output = raw_output.decode("utf-8")
            except UnicodeDecodeError:
                # Preserve the original log and still record source/cleanup
                # evidence if a synthetic diagnostic contains binary bytes.
                # An undecodable log never becomes a passing qualification.
                output = raw_output.decode("utf-8", errors="replace")
                report["logEncodingError"] = True
                exit_code = 1
            passed = [line.strip().split()[2] for line in output.splitlines()
                      if line.strip().startswith("--- PASS: Test")]
            if test_pattern and "/" in test_pattern:
                passed = [name for name in passed if "/" in name]
            report["passedTests"] = passed
            if not passed:
                exit_code = 1
            if installer_continuation and len(foci) > 1:
                # Each focus of a multi-focus run is its own subtest; every
                # one must pass (a later one is not run after a failure).
                report["focusResults"] = focus_results(output, foci)
                if any(r["result"] != "pass" for r in report["focusResults"].values()):
                    exit_code = 1
            if owner_provider_auth and "TestOwnerProviderAuthenticationWithRealKubernetesAndOpenBao" not in passed:
                report["missingRequiredOwnerProviderAuthentication"] = True
                exit_code = 1
            if runtime_object_roundtrip and "TestInitialRuntimeObjectRoundTripWithRealKubernetes" not in passed:
                report["missingRequiredRuntimeObjectRoundTrip"] = True
                exit_code = 1
            if regional_context_start and "TestContextAdmissionWithRealServices/native-regional-api-" + regional_context_start not in passed:
                report["missingRequiredRegionalContextStart"] = True
                exit_code = 1
            if initial_schema_handover and "TestInitialSchemaHandoverWithRealServices" not in passed:
                report["missingRequiredSchemaHandover"] = True
                exit_code = 1
            if initial_bootstrap_chain and "TestInitialBootstrapChainWithRealServices" not in passed:
                report["missingRequiredBootstrapChain"] = True
                exit_code = 1
            if direct_observation and "TestDirectHolderObservationWithRealKubernetes" not in passed:
                report["missingRequiredDirectObservation"] = True
                exit_code = 1
            if runtime_provider_pair:
                required = "installer-continuation" if installer_continuation else "runtime-provider-owner-identity" if runtime_provider_owner else ("runtime-provider-worker-source" if runtime_provider_worker else "runtime-provider-pair-worker-inputs")
                if "TestInitialBootstrapChainWithRealServices/" + required not in passed:
                    report["missingRequiredRuntimeProviderPair"] = required
                    exit_code = 1
            if helm_bootstrap:
                if helm_test not in passed:
                    report["missingRequiredHelmBootstrap"] = True
                    exit_code = 1
                if exit_code == 0:
                    # The cluster hook runs once on the schedulable node; the
                    # bootstrap test flips nodes so both pull.
                    report["registryPulls"] = registry.report(registry_nodes[:1] if helm_cluster else registry_nodes)
            report["sourceUnchangedDuringTest"] = report["sourceHashes"] == source_hashes()
            if not report["sourceUnchangedDuringTest"]: exit_code = 1
            if exit_code:
                with (ROOT/"test/results/context-storage-kubelet.log").open("w") as diagnostics:
                    for name in clusters:
                        diagnostics.write("Owned node: "+name+"-control-plane\n")
                        result = subprocess.run(["docker", "exec", name+"-control-plane", "journalctl", "--unit", "kubelet", "--since", "-5min", "--no-pager", "-n", "80"], capture_output=True, text=True, timeout=10)
                        diagnostics.write(result.stdout[-32768:])
            print("Component test exit:", exit_code, flush=True)
        except subprocess.CalledProcessError as exc:
            (ROOT/"test/results/context-storage-fixture-error.log").write_text(exc.stderr or str(exc.returncode))
            if cluster_pool is not None:
                cluster_pool.shutdown(wait=True)  # export finished clusters only
            for name in clusters:
                try:
                    info = json.loads(run(["docker", "inspect", name+"-control-plane"]))[0]
                    assert info["Config"]["Labels"]["io.x-k8s.kind.cluster"] == name
                    run(["kind", "export", "logs", str(ROOT/"test/results"/(name+"-logs")), "--name", name])
                except Exception:
                    pass  # diagnostics cannot suppress the original failure or cleanup
            print("Fixture command failed:", exc.stderr[-4000:] if exc.stderr else exc.returncode, flush=True)
            raise
        finally:
            report["testExit"] = exit_code
            failures = []
            # A setup failure can leave cluster creation running; let it end
            # before the cleanup below deletes those clusters.
            if cluster_pool is not None:
                cluster_pool.shutdown(wait=True)
            # Stop a still-running compile-ahead (setup failure) before any
            # scratch removal below.
            if compile_ahead is not None and compile_ahead.poll() is None:
                os.killpg(compile_ahead.pid, signal.SIGKILL)  # with its compiler children
                compile_ahead.wait()
            try:
                artifacts = collect_profile_containment_artifacts(work, ROOT/"test/results")
                if artifacts is not None:
                    report["profileContainmentArtifacts"] = artifacts
            except OSError as exc:
                report["profileContainmentArtifactError"] = type(exc).__name__
                exit_code = 1
                report["testExit"] = exit_code
            if native_paced:
                try:
                    if not audit_started or len(audit_nodes) != 2:
                        raise ValueError("native audit setup incomplete")
                    for _, config in audit_nodes:
                        run(["kubectl", "--kubeconfig", config, "--request-timeout=5s", "get", "--raw", "/readyz"])
                    audit = native_kube_audit.collect(ROOT/"test/results/native-paced-report.json", audit_nodes, work)
                    report["nativeKubernetesAudit"] = audit
                except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.SubprocessError):
                    report["nativeKubernetesAudit"] = {"complete": False, "reason": "bounded owned audit coverage unavailable"}
                    exit_code = 1
                try:
                    (ROOT/"test/results/native-paced-kubernetes-audit.json").write_text(json.dumps(report["nativeKubernetesAudit"], indent=2)+"\n")
                except OSError:
                    report["nativeKubernetesAudit"] = {"complete": False, "reason": "aggregate artifact unavailable"}
                    exit_code = 1
                report["testExit"] = exit_code
            # Preserve diagnostics from this owned database before removing it.
            # Without them, role/query failures collapse to the public unavailable
            # error and the original SQL cause disappears with fixture cleanup.
            pgname = network + "-postgres"
            if exit_code and pgname in containers:
                try:
                    info = json.loads(run(["docker", "inspect", pgname]))[0]
                    assert info["Config"]["Labels"]["asservat.test"] == run_id
                    provider = subprocess.run(["docker", "logs", "--tail", "4000" if installer_continuation else "200", pgname], text=True, capture_output=True, timeout=10)
                    (ROOT/"test/results/context-storage-postgres.log").write_text(provider.stdout+provider.stderr)
                    report["providerLogExit"] = provider.returncode
                except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError, KeyError, IndexError, AssertionError) as exc:
                    report["providerLogFailure"] = type(exc).__name__
            # --keep-on-failure (local debugging only): leave this run's own
            # clusters and labelled containers for inspection and record them;
            # --cleanup-kept removes exactly these later with its own evidence.
            # --keep-installed (development only) keeps every run that reached
            # its focus, passed or not: the Go test wrote the state first.
            installed_kept = keep_installed and state_path.is_file() and bool(clusters)
            keep = (keep_on_failure and exit_code != 0 or installed_kept) and bool(clusters)
            if keep:
                kept = {"runId": run_id, "clusters": clusters, "containers": containers, "volumes": ephemeral_volumes, "image": worker_tag, "upgradeImage": upgrade_tag, "collectorImage": collector_tag, "workDirectory": str(work),
                        "networks": [n for n, made in ((network, created_network), (kind_network, created_kind_network)) if made]}
                if installed_kept:
                    kept.update({"mode": KEPT_INSTALLED_MODE, "qualification": False, "focus": focus, "keptAt": time.time(),
                                 "notAfter": time.time() - (time.monotonic() - began) + KEPT_INSTALLED_SECONDS,
                                 "fixtures": str(work/"fixtures.json"), "state": str(state_path), "hubImage": fixture["workerImage"],
                                 "imageHashes": image_hashes(image_dir), "reruns": 0, "rerunImages": []})
                (cache/"kept").mkdir(exist_ok=True)
                manifest = cache/"kept"/(run_id+".json")
                write_environment_report(manifest, kept)
                keep_work = True
                report["keptResources"] = str(manifest)
                report["keptWorkDirectory"] = str(work)
                if installed_kept:
                    print("Kept installation (development only, not a qualification):", manifest, flush=True)
                    print("  rerun the focus with: python3 scripts/test-context-storage.py --rerun-installed", manifest, flush=True)
                else:
                    print("Kept failed fixture for inspection:", manifest, flush=True)
                print("  private fixture directory:", work, flush=True)
                for name in clusters:
                    print("  kubeconfig: kind get kubeconfig --name", name, flush=True)
                print("  remove with: python3 scripts/test-context-storage.py --cleanup-kept", manifest, flush=True)
            else:
                for name in reversed(clusters):
                    try: run(["kind", "delete", "cluster", "--name", name])
                    except Exception: failures.append(name)
                for name in reversed(containers):
                    try:
                        info = json.loads(run(["docker", "inspect", name]))[0]
                        assert info["Config"]["Labels"]["asservat.test"] == run_id
                        run(["docker", "rm", "-f", "-v", name])
                    except Exception: failures.append(name)
                for name in reversed(ephemeral_volumes):
                    try:
                        info = json.loads(run(["docker", "volume", "inspect", name]))[0]
                        assert info["Labels"]["asservat.test"] == run_id
                        run(["docker", "volume", "rm", name])
                    except Exception: failures.append(name)
                for tag in [t for t in (worker_tag, upgrade_tag, collector_tag) if t]:
                    try:
                        info = json.loads(run(["docker", "image", "inspect", tag]))[0]
                        assert info["Config"]["Labels"]["asservat.test"] == run_id
                        run(["docker", "image", "rm", tag])
                    except Exception: failures.append(tag)
                if created_network:
                    try: run(["docker", "network", "rm", network])
                    except Exception: failures.append(network)
                if created_kind_network:
                    try:
                        info = json.loads(run(["docker", "network", "inspect", kind_network]))[0]
                        assert info["Labels"]["asservat.test"] == run_id
                        run(["docker", "network", "rm", kind_network])
                    except Exception: failures.append(kind_network)
                    os.environ.pop("KIND_EXPERIMENTAL_DOCKER_NETWORK", None)
                if helm_bootstrap:
                    try: report["registryCleanup"] = verify_registry_cleanup(run, work, network)
                    except Exception: failures.append(network+"-registry-cleanup-verification")
            if build_scratch is not None:
                try:
                    shutil.rmtree(build_scratch)
                    report["buildScratchRemoved"] = not build_scratch.exists()
                except OSError:
                    failures.append(str(build_scratch))
            report["cleanupFailures"] = failures
            phase("cleanedUp")
            print("Harness phases (seconds since start):", report["phaseSeconds"], flush=True)
            # Setup failures still need an actual source comparison. This is
            # provenance only and never turns an unexecuted test into a pass.
            if "sourceHashes" in report:
                report["sourceUnchangedDuringTest"] = report["sourceHashes"] == source_hashes()
                if not report["sourceUnchangedDuringTest"]:
                    exit_code = 1
            report["harnessState"] = "finished"
            report["cleanupComplete"] = not keep and not failures
            write_environment_report(ROOT/"test/results/context-storage-environment.json", report)
            if failures: raise RuntimeError("Owned fixtures need cleanup: "+", ".join(failures))
        return exit_code


def kept_work_directory(kept, path):
    """The kept run's private directory, or None if the manifest names any
    other path: a manifest cannot turn cleanup into an arbitrary removal."""
    cache = (Path(os.environ.get("XDG_CACHE_HOME", Path.home()/".cache"))/"asservat-build").resolve()
    candidate = Path(kept["workDirectory"])
    manifest = Path(path)
    if (not candidate.is_absolute() or candidate.is_symlink()
            or candidate.parent.resolve() != cache
            or not candidate.name.startswith("context-")
            or candidate.name.replace("_", "-") != kept["runId"]
            or manifest.is_symlink() or manifest.name != kept["runId"]+".json"
            or manifest.parent.resolve() != cache/"kept"):
        return None
    return candidate


def kept_leftovers(run_id):
    """Every Docker object labelled with, and every kind cluster named for, this run."""
    leftovers = {}
    for kind, command in (("containers", ["docker", "ps", "-a", "--format", "{{.Names}}"]), ("volumes", ["docker", "volume", "ls", "--format", "{{.Name}}"]),
                          ("networks", ["docker", "network", "ls", "--format", "{{.Name}}"]), ("images", ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"])):
        leftovers[kind] = [n for n in run(command[:-2] + ["--filter", "label=asservat.test="+run_id] + command[-2:]).splitlines() if n]
    leftovers["clusters"] = [n for n in run(["kind", "get", "clusters"]).splitlines() if run_id in n]
    return leftovers


def cleanup_kept(path):
    """Remove one kept run's own recorded resources, checking each name or
    label against that run, verify nothing labelled for the run is left and
    write cleanup evidence."""
    kept = json.loads(Path(path).read_text())
    run_id = kept["runId"]
    if not re.fullmatch(r"[a-z0-9-]{4,64}", run_id):
        raise ValueError("invalid kept run id")
    failures = []
    work = None
    if "workDirectory" in kept:
        # Keep the original path so fixtures.json and kubeconfig references work.
        work = kept_work_directory(kept, path)
        if work is None:
            failures.append(str(kept["workDirectory"]))
    for name in reversed(kept["clusters"]):
        try:
            info = json.loads(run(["docker", "inspect", name+"-control-plane"]))[0]
            assert run_id in name and info["Config"]["Labels"]["io.x-k8s.kind.cluster"] == name
            run(["kind", "delete", "cluster", "--name", name])
        except Exception: failures.append(name)
    images = [i for i in (kept["image"], kept.get("upgradeImage"), kept.get("collectorImage"), *kept.get("rerunImages", [])) if i]
    for kind, names in (("container", reversed(kept["containers"])), ("volume", kept["volumes"]), ("image", images), ("network", kept["networks"])):
        for name in names:
            try:
                info = json.loads(run(["docker", kind, "inspect", name]))[0]
                labels = info["Config"]["Labels"] if kind in ("container", "image") else info["Labels"]
                assert labels["asservat.test"] == run_id
                run(["docker", kind, "rm", "-f", "-v", name] if kind == "container" else ["docker", kind, "rm", name])
            except Exception: failures.append(name)
    if work is not None and not failures:
        try:
            shutil.rmtree(work)
        except OSError:
            failures.append(str(work))
    report = {"runId": run_id, "manifest": str(path), "cleanupFailures": failures}
    try:
        report["leftovers"] = kept_leftovers(run_id)
        report["workDirectoryRemoved"] = work is not None and not work.exists()
    except (subprocess.CalledProcessError, OSError) as exc:
        report["leftoverCheckError"] = type(exc).__name__
        failures.append("leftover-verification")
    if any(report.get("leftovers", {}).values()):
        failures.append("leftovers")
    (ROOT/"test/results"/("kept-cleanup-"+run_id+".json")).write_text(json.dumps(report, indent=2)+"\n")
    if failures:
        print("Kept fixture cleanup failed for:", ", ".join(failures), flush=True)
        return 1
    Path(path).unlink()
    print("Kept fixture removed:", run_id, "- verified no labelled container, volume, network, image or kind cluster is left", flush=True)
    return 0


# Development-only fast focus loop (docs/development-workflow.md). A keep run
# is an ordinary fresh installation whose fixtures stay up afterwards; a rerun
# runs only the focus on it. Neither is a qualification, and CI refuses both.
RERUN_FOCUSES = ("manual-logs",)
KEPT_INSTALLED_MODE = "installed-focus"
# The keep run extends the synthetic reviewer token and owner issuer root to
# three hours; the connector and worker fixture PKI roots stay at two. Reruns
# stop 90 minutes after the keep run started, inside all of them.
KEPT_INSTALLED_SECONDS = 90 * 60
# The keep run's synthetic capacity funds this many focus runs in total
# (installedKeptRuns in Go): the keep run and three reruns.
KEPT_INSTALLED_RUNS = 4
DEVELOPMENT_ENVIRONMENT = ("ASSERVAT_INSTALLED_KEEP", "ASSERVAT_INSTALLED_STATE", "ASSERVAT_INSTALLED_RERUN", "ASSERVAT_INSTALLED_RERUN_ID", "ASSERVAT_INSTALLED_RELEASE_IMAGE")
RERUN_TEST = "TestInstalledFocusRerunWithKeptInstallation"


def refuse_development_mode_in_ci(option):
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"):
        raise RuntimeError(option + " is a development-only loop and never runs in CI; qualification always uses a fresh installation")


def image_hashes(image_dir):
    """The rebuilt hub image's content: product binary, fixture proxy and console."""
    hashes = {name: hashlib.sha256((image_dir/name).read_bytes()).hexdigest() for name in ("asservat", "provider-proxy")}
    digest = hashlib.sha256()
    for path in sorted((image_dir/"console").rglob("*")):
        if path.is_file():
            digest.update(str(path.relative_to(image_dir/"console")).encode() + b"\0" + path.read_bytes())
    hashes["console"] = digest.hexdigest()
    return hashes


def load_kept_image(tag, cluster, run_id):
    """Load one rebuilt image into the kept hub node; returns its digest reference."""
    node = cluster+"-control-plane"
    if run(["docker", "inspect", "--format", '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', node]) != cluster or run_id not in cluster:
        raise RuntimeError("kept hub node ownership differs")
    run(["kind", "load", "docker-image", tag, "--name", cluster])
    native = "docker.io/library/"+tag
    matches = [row.split()[2] for row in run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "ls"]).splitlines() if row.split()[0] == native]
    if len(matches) != 1 or not matches[0].startswith("sha256:"):
        raise RuntimeError("loaded rebuilt image identity unavailable")
    reference = "docker.io/library/asservat-context-worker@"+matches[0]
    run(["docker", "exec", node, "ctr", "-n", "k8s.io", "images", "tag", native, reference])
    return reference


def rerun_installed(path):
    """Run only the kept focus on a kept installation. Development only."""
    refuse_development_mode_in_ci("--rerun-installed")
    began, started_at = time.monotonic(), time.time()
    kept = json.loads(Path(path).read_text())
    run_id = kept.get("runId", "")
    if kept.get("mode") != KEPT_INSTALLED_MODE or not re.fullmatch(r"[a-z0-9-]{4,64}", run_id) or kept.get("focus") not in RERUN_FOCUSES:
        raise ValueError("not a --keep-installed manifest")
    work = kept_work_directory(kept, path)
    if work is None or not work.is_dir():
        raise ValueError("kept private directory differs from the manifest")
    if time.time() > kept["notAfter"]:
        raise RuntimeError("kept installation is older than its synthetic credential window; tear it down (--cleanup-kept) and keep a fresh one")
    for name in kept["clusters"]:
        if run_id not in name or run(["docker", "inspect", "--format", '{{ index .Config.Labels "io.x-k8s.kind.cluster" }}', name+"-control-plane"]) != name:
            raise RuntimeError("kept cluster missing or not owned: "+name)
    for name in kept["containers"]:
        info = json.loads(run(["docker", "inspect", name]))[0]
        if info["Config"]["Labels"].get("asservat.test") != run_id or (not name.endswith("-seed") and not info["State"]["Running"]):
            raise RuntimeError("kept fixture container missing, foreign or stopped: "+name)
    number = kept["reruns"] + 1
    if number >= KEPT_INSTALLED_RUNS:
        raise RuntimeError("kept installation's synthetic capacity funds no further focus run; tear it down (--cleanup-kept) and keep a fresh one")
    results = ROOT/"test/results"
    report = {"qualification": False, "scope": "development-only focus rerun on a kept installation; never a qualification",
              "runId": run_id, "rerun": number, "focus": kept["focus"], "manifest": str(path),
              "skipped": ["cluster and fixture creation", "unified bootstrap runner", "installer continuation", "regional install"],
              "phaseSeconds": {}, "sourceHashes": source_hashes(), "goTestExit": None}

    def phase(name):
        report["phaseSeconds"][name] = round(time.monotonic()-began, 1)
    scratch = Path(tempfile.mkdtemp(prefix="asservat-rerun-build-", dir=tempfile.gettempdir()))
    exit_code = 1
    go_started = False
    try:
        image_dir = scratch/"image"
        image_dir.mkdir()
        build_env = dict(os.environ, TMPDIR=str(scratch), CGO_ENABLED="0")
        build_hub_binaries(image_dir, build_env)
        build_console(image_dir, build_env)
        hashes = image_hashes(image_dir)
        phase("imageInputsBuilt")
        env = qualification_environment(os.environ, kept["fixtures"], scratch, False, False)
        env.update({"ASSERVAT_INSTALLED_RERUN": kept["state"], "ASSERVAT_INSTALLED_RERUN_ID": str(number), "ASSERVAT_JOURNEY_FOCUS": kept["focus"]})
        report["imageChanged"] = hashes != kept["imageHashes"]
        if report["imageChanged"]:
            # The product's own image change (installer-upgrade) moves hub-api,
            # hub-worker, key service, publisher and federation to this image.
            (image_dir/"Dockerfile").write_text("FROM scratch\nCOPY asservat /asservat\nCOPY provider-proxy /provider-proxy\nCOPY console /usr/share/asservat/console\nUSER 65532:65532\n")
            tag = "asservat-context-worker:"+run_id+"-r"+str(number)
            if tag not in kept["rerunImages"]:  # a retried number reuses its tag
                kept["rerunImages"].append(tag)
            write_environment_report(Path(path), kept)  # teardown removes it even if this run fails
            run(["docker", "build", "--network=none", "--label", "asservat.test="+run_id, "-t", tag, str(image_dir)])
            env["ASSERVAT_INSTALLED_RELEASE_IMAGE"] = load_kept_image(tag, kept["clusters"][0], run_id)
            report["releaseImage"] = env["ASSERVAT_INSTALLED_RELEASE_IMAGE"]
            phase("imageLoaded")
        command = ["go", "test", "-count=1", "-v", "-run", "^"+RERUN_TEST+"$", "-timeout", "18m", "./test/integration"]
        # Only a launched focus spends a funded run; a build or load failure
        # before it can be retried with the same number.
        go_started = True
        exit_code = record_go_output(command, env, results, report, "installed-focus-rerun")
        phase("goTestEnd")
        report["goTestExit"] = exit_code
        output = (results/"installed-focus-rerun.log").read_bytes().decode("utf-8", errors="replace")
        report["passedTests"] = [line.strip().split()[2] for line in output.splitlines() if line.strip().startswith("--- PASS: Test")]
        if RERUN_TEST+"/"+kept["focus"] not in report["passedTests"]:
            exit_code = 1
        if report["imageChanged"]:
            # A failed run may have stopped anywhere in the image change; the
            # next rerun then changes the image again instead of assuming it.
            kept["imageHashes"] = hashes if exit_code == 0 else None
            kept["hubImage"] = report["releaseImage"] if exit_code == 0 else None
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        if go_started:
            kept["reruns"] = number
        write_environment_report(Path(path), kept)  # atomic: an interrupt keeps it readable
        report["sourceUnchangedDuringTest"] = report["sourceHashes"] == source_hashes()
        if not report["sourceUnchangedDuringTest"]:
            exit_code = 1
        report["testExit"] = exit_code
        report["wallSeconds"] = round(time.monotonic()-began, 1)
        report["startedAt"] = started_at
        report["harnessState"] = "finished"
        write_environment_report(results/"installed-focus-rerun-environment.json", report)
        print("Rerun", number, "of", kept["focus"], "on kept", run_id, "exit", exit_code, "in", report["wallSeconds"], "s (not a qualification); phases:", report["phaseSeconds"], flush=True)
    return exit_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", dest="test_pattern", help="Optional Go test pattern; recorded in the report. Default runs the full suite.")
    parser.add_argument("--initial-handover", action="store_true", help="Qualify the original installer handover on its own fresh database; incompatible with --run.")
    parser.add_argument("--initial-schema-handover", action="store_true", help="Qualify product schema initialization and original activation handover on an empty database; no fixture migrations or runtime grants.")
    parser.add_argument("--initial-bootstrap-chain", action="store_true", help="Qualify all four fixed bootstrap commands in a Restricted runner and the original activation Pod on an empty database.")
    parser.add_argument("--helm-cluster", action="store_true", help="ADR-193 step 6: the packaged chart in mode=cluster runs the regional installer hook with a synthetic offer and record, on the --helm-bootstrap registry/node infrastructure.")
    parser.add_argument("--helm-bootstrap", action="store_true", help="Actual chart/four-command empty-database chain with authenticated TLS registry and two owned cold-image nodes.")
    parser.add_argument("--regional-context-start", choices=("first", "continuation", "journey"), help="Qualify actual signed same-port H2 context start; journey adds the shared operation factory, publication and native download. Owns its exact fresh-fixture test selection; synthetic authority remains explicit.")
    parser.add_argument("--runtime-object-roundtrip", action="store_true", help="Qualify inert generated resource defaults in one owned API, using the exact package-local test; no installer authority claim.")
    parser.add_argument("--owner-provider-auth", action="store_true", help="Qualify fixed owner Kubernetes authentication against the pinned provider and one owned API; no installed-runtime qualification.")
    parser.add_argument("--runtime-provider-pair", action="store_true", help="Continue the original fresh bootstrap chain through selected worker2/owner2 resources and real provider/SQL worker inputs; requires --initial-bootstrap-chain.")
    parser.add_argument("--runtime-provider-owner", action="store_true", help="Continue the original running worker through owner roles, projection and actual in-Pod paired identity; requires --initial-bootstrap-chain --runtime-provider-pair --runtime-provider-worker.")
    parser.add_argument("--installer-continuation", action="store_true", help="ADR-183: after the original bootstrap chain, run the actual installer-continue Pod and the actual applier through worker and owner launch; requires --initial-bootstrap-chain --runtime-provider-pair.")
    parser.add_argument("--keep-on-failure", action="store_true", help="Local debugging: on failure keep this run's own clusters and labelled containers, record them, and skip the Go fixtures' own cleanup. Remove them with --cleanup-kept.")
    parser.add_argument("--keep-installed", action="store_true", help="Development only, never a qualification: keep this fresh installation and its fixtures after the focus for --rerun-installed. Requires the installer continuation and a rerun focus; refused in CI.")
    parser.add_argument("--rerun-installed", metavar="MANIFEST", help="Development only, never a qualification: rebuild the hub image, move the kept hub to it if it changed, and run only the kept focus; writes test/results/installed-focus-rerun-environment.json.")
    parser.add_argument("--cleanup-kept", metavar="MANIFEST", help="Remove one kept run's recorded resources after checking each belongs to that run, then verify none is left; writes test/results/kept-cleanup-<run>.json.")
    parser.add_argument("--runtime-provider-worker", action="store_true", help="Continue the original provider pair through actual launch and in-Pod accepted owner observation; requires --initial-bootstrap-chain --runtime-provider-pair.")
    args = parser.parse_args()
    if args.cleanup_kept:
        raise SystemExit(cleanup_kept(args.cleanup_kept))
    (ROOT/"test/results").mkdir(parents=True, exist_ok=True)
    if args.rerun_installed:
        raise SystemExit(rerun_installed(args.rerun_installed))
    if (args.initial_handover or args.initial_schema_handover or args.initial_bootstrap_chain) and args.test_pattern is not None:
        parser.error("Installation qualification cannot be combined with --run")
    if sum((args.initial_handover, args.initial_schema_handover, args.initial_bootstrap_chain)) > 1:
        parser.error("Select exactly one installation qualification")
    if args.test_pattern is not None and not 1 <= len(args.test_pattern) <= 256:
        parser.error("--run must contain 1 to 256 characters")
    raise SystemExit(main(args.test_pattern, initial_handover=args.initial_handover, initial_schema_handover=args.initial_schema_handover, initial_bootstrap_chain=args.initial_bootstrap_chain, helm_bootstrap=args.helm_bootstrap, regional_context_start=args.regional_context_start, runtime_object_roundtrip=args.runtime_object_roundtrip, owner_provider_auth=args.owner_provider_auth, runtime_provider_pair=args.runtime_provider_pair, runtime_provider_worker=args.runtime_provider_worker, runtime_provider_owner=args.runtime_provider_owner, installer_continuation=args.installer_continuation, helm_cluster=args.helm_cluster, keep_on_failure=args.keep_on_failure, keep_installed=args.keep_installed))
