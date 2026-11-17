#!/usr/bin/env python3
"""Embed the canonical public tool contracts for runtime validation.

Each tool of specs/contracts/mcp-tools.json is written with its references
resolved into local $defs, so runtime validation never uses the network.
Schemas alone never register an operation; the composed services do.

Tools listed in specs/contracts/implemented/legacy-tools.txt still run the
earlier contract: their embedded files stay as they are until the runtime
follows the canonical tool, which then removes its line. activate_policy and
request_policy_grant remain until hub-side acceptance (specs/policy-automation.md)
replaces them.
"""
import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "specs/contracts"
DEST = ROOT / "internal/contracts/investigation-schemas"
PREFIX = "https://asservat.io/spec/v1/"
LEGACY = CONTRACTS / "implemented/legacy-tools.txt"


def localize(root, documents):
    definitions, known = {}, {}

    def visit(value, document=None):
        if isinstance(value, list):
            return [visit(x, document) for x in value]
        if not isinstance(value, dict):
            return value
        out = {}
        for key, item in value.items():
            if key in ("$id", "$schema") or key.startswith("x-"):
                continue
            if key != "$ref":
                out[key] = visit(item, document)
                continue
            if item.startswith(PREFIX):
                name, _, fragment = item[len(PREFIX):].partition("#")
            elif item.startswith("#") and document:
                name, fragment = document, item[1:]
            else:
                raise ValueError("Unqualified schema reference: " + item)
            identity = name + "#" + fragment
            if identity not in known:
                known[identity] = "d" + str(len(known))
                target = documents[name]
                if fragment:
                    for segment in fragment[1:].split("/"):
                        target = target[segment.replace("~1", "/").replace("~0", "~")]
                else:
                    target = {k: v for k, v in target.items() if k != "$defs"}
                definitions[known[identity]] = visit(target, name)
            out[key] = "#/$defs/" + known[identity]
        return out

    result = visit(root)
    if definitions:
        result["$defs"] = definitions
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    documents = {p.name: json.loads(p.read_text()) for p in CONTRACTS.glob("*.schema.json")}
    legacy = {line + ".json" for line in LEGACY.read_text().split()} if LEGACY.exists() else set()
    result = {}
    for tool in json.loads((CONTRACTS / "mcp-tools.json").read_text())["tools"]:
        if tool["name"] + ".json" in legacy:
            continue
        description = copy.deepcopy(tool)
        description.pop("enabledByDefault", None)
        description["inputSchema"] = localize(description["inputSchema"], documents)
        description["outputSchema"] = localize(description["outputSchema"], documents)
        result[tool["name"] + ".json"] = (json.dumps(description, indent=2) + "\n").encode()
    if args.write:
        DEST.mkdir(parents=True, exist_ok=True)
        for stale in DEST.glob("*.json"):
            if stale.name not in result and stale.name not in legacy:
                stale.unlink()
        for name, value in result.items():
            (DEST / name).write_bytes(value)
    actual = {p.name: p.read_bytes() for p in DEST.glob("*.json") if p.name not in legacy}
    missing = sorted(n for n in legacy if not (DEST / n).exists())
    if missing:
        raise SystemExit("Missing legacy investigation schemas: " + ", ".join(missing))
    if result != actual:
        raise SystemExit("Investigation schema drift; run scripts/investigation-schemas.py --write and review")
    print("Investigation schemas OK: canonical tools; all references local")


if __name__ == "__main__":
    main()
