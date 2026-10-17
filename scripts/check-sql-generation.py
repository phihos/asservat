#!/usr/bin/env python3
"""Generate into a private temporary directory and reject checked-in query drift."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import yaml

ROOT = Path(__file__).resolve().parents[1]
tool = sys.argv[1]
version = subprocess.check_output([tool, "version"], text=True).strip()
if version != "v1.31.1": raise SystemExit("sqlc v1.31.1 is required; run make sql-tools")
with tempfile.TemporaryDirectory(prefix="asservat-sqlc-", dir=os.environ.get("TMPDIR")) as tmp:
    work = Path(tmp)
    target = work/"generated"
    shutil.copytree(ROOT/"migrations",work/"migrations")
    config = yaml.safe_load((ROOT/"sqlc.yaml").read_text())
    config["sql"][0]["gen"]["go"]["out"] = "generated"
    path = work/"sqlc.json"
    path.write_text(json.dumps(config))
    subprocess.run([tool, "generate", "-f", str(path)], check=True, cwd=ROOT)
    expected = ROOT/"internal/adapters/postgres/custodydb"
    generated = {p.name: p.read_bytes() for p in target.glob("*.go")}
    checked = {p.name: p.read_bytes() for p in expected.glob("*.go")}
    if not generated or generated != checked: raise SystemExit("SQL bindings drifted; run the pinned sqlc generate")
    print("SQL generation OK:", len(generated), "files match sqlc", version)
