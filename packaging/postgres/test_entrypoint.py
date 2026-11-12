"""Local process/config tests only: no database, image or Kubernetes effects."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).parent


class PostgresEntrypoint(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / "private"
        self.private.mkdir()
        self.data = self.root / "data"
        self.repo = self.root / "backup"
        self.repo.mkdir()
        self.log = self.root / "calls.jsonl"
        for name in ("ca.crt", "server.crt", "server.key", "backup.pgpass", "backup-cipher",
                     "administrator-password", "ddl-verifier", "backup-verifier", "keycloak-verifier"):
            (self.private / name).write_text("synthetic-secret-marker")
        script = (SOURCE / "entrypoint.sh").read_text()
        for old, new in {
            "/var/lib/postgresql/18/docker": str(self.data),
            "/run/asservat/postgres-private": str(self.private),
            "/run/asservat/postgres": str(self.root / "work"),
            "/var/lib/pgbackrest": str(self.repo),
        }.items():
            script = script.replace(old, new)
        self.script = self.root / "entrypoint.sh"
        self.script.write_text(script)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = '''#!/usr/bin/env python3
import os,sys,json,pathlib,time
name=pathlib.Path(sys.argv[0]).name
body=sys.stdin.read() if name=='psql' else ''
with open(os.environ['TEST_LOG'],'a') as f: f.write(json.dumps([name,sys.argv[1:],body])+'\\n')
if name=='initdb':
 p=pathlib.Path(os.environ['PGDATA']);p.mkdir(exist_ok=True);(p/'PG_VERSION').write_text('18\\n')
if name=='pgbackrest' and 'backup' in sys.argv:
 pathlib.Path(os.environ['TEST_CHILD']).write_text(str(os.getpid()))
 while True: time.sleep(1)
'''
        for name in ("initdb", "pg_ctl", "psql", "postgres", "pg_isready", "pgbackrest"):
            p = self.bin / name
            p.write_text(fake)
            p.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin) + ":" + os.environ["PATH"],
                        TEST_LOG=str(self.log), TEST_CHILD=str(self.root / "child"),
                        PGHOST="trial-postgres.hub.svc", PGMAXCONNECTIONS="117", KEYCLOAK_DATABASE="false")

    def run_server(self):
        return subprocess.run(["bash", str(self.script), "server"], env=self.env,
                              capture_output=True, text=True, timeout=10)

    def calls(self):
        return [json.loads(x) for x in self.log.read_text().splitlines()]

    def test_initialization_is_local_then_exact_nonroot_server_and_replay(self):
        result = self.run_server()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual([x[0] for x in calls], ["initdb", "pg_ctl", "psql", "pg_ctl", "postgres"])
        self.assertIn("listen_addresses=''", " ".join(calls[1][1]))
        self.assertIn("NOSUPERUSER", calls[2][2])
        self.assertIn("CONNECTION LIMIT 2", calls[2][2])
        self.assertIn("GRANT pg_read_all_settings TO asservat_backup", calls[2][2])
        self.assertNotIn("CREATE ROLE keycloak", calls[2][2])
        self.assertNotIn("synthetic-secret-marker", result.stdout + result.stderr)
        self.assertIn("max_connections=117", calls[-1][1])
        config = (self.root / "work/pgbackrest.conf").read_text()
        self.assertIn("repo1-cipher-type=aes-256-cbc", config)
        self.assertIn("archive-async=n", config)
        self.assertNotIn("archive-push-queue-max", config)
        self.assertEqual(self.run_server().returncode, 0)
        self.assertEqual(sum(x[0] == "initdb" for x in self.calls()), 1)

    def test_keycloak_is_independent_and_capacity_is_exact(self):
        self.env.update(KEYCLOAK_DATABASE="true", PGMAXCONNECTIONS="122")
        self.assertEqual(self.run_server().returncode, 0)
        self.assertIn("CREATE ROLE keycloak", "".join(x[2] for x in self.calls()))
        self.assertIn("max_connections=122", self.calls()[-1][1])
        self.env["PGMAXCONNECTIONS"] = "117"
        self.assertNotEqual(self.run_server().returncode, 0)

    def test_existing_uninitialized_or_wrong_major_directory_refuses(self):
        self.data.mkdir()
        (self.data / "PG_VERSION").write_text("17\n")
        self.assertNotEqual(self.run_server().returncode, 0)
        self.assertFalse(self.log.exists())
        (self.data / "PG_VERSION").unlink()
        (self.data / "partial").touch()
        self.assertNotEqual(self.run_server().returncode, 0)
        self.assertFalse(self.log.exists())

    def test_backup_cancel_joins_owned_active_command(self):
        self.data.mkdir()
        (self.data / "asservat-initialized").touch()
        p = subprocess.Popen(["bash", str(self.script), "backup"], env=self.env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: p.kill() if p.poll() is None else None)
        until = time.monotonic() + 5
        while not (self.root / "child").exists() and time.monotonic() < until:
            time.sleep(0.01)
        self.assertTrue((self.root / "child").exists())
        child = int((self.root / "child").read_text())
        p.send_signal(signal.SIGTERM)
        _, err = p.communicate(timeout=5)
        self.assertEqual(p.returncode, 0, err)
        with self.assertRaises(ProcessLookupError):
            os.kill(child, 0)
        self.assertFalse((self.repo / "last-success").exists())


if __name__ == "__main__":
    unittest.main()
