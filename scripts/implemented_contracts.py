"""Contract source for runtime consumers.

specs/contracts/implemented/ holds the earlier version of each contract whose
runtime consumer (embedded Go schema, generated CRD or console types) does not
yet implement the canonical ADR-330 version. Spec gates validate the canonical
files; runtime generators read through this module. Delete a file there in the
change that makes its runtime implement the canonical contract.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "specs/contracts"
IMPLEMENTED = CANONICAL / "implemented"


def path(name):
    candidate = IMPLEMENTED / name
    return candidate if candidate.exists() else CANONICAL / name


def schema_names():
    return sorted({p.name for p in CANONICAL.glob("*.schema.json")} | {p.name for p in IMPLEMENTED.glob("*.schema.json")})
