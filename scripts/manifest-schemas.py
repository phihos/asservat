#!/usr/bin/env python3
"""Copy/check closed canonical schema graphs for offline embedding."""
import argparse
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/"specs/contracts"
PREFIX="https://asservat.io/spec/v1/"

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--bundle", choices=["manifest", "permissions", "control", "policies"], default="manifest")
    args=parser.parse_args()
    dest=ROOT/("internal/adapters/objectstore/manifest/schemas" if args.bundle=="manifest" else "internal/adapters/kubernetes/permission-schemas")
    pending=(["manifest.schema.json","framed-storage.schema.json","pod-status.schema.json"] if args.bundle=="manifest" else ["access-binding.schema.json","permission-source.schema.json","identity-settings.schema.json","browser-settings.schema.json","submission-trust.schema.json","work-trust.schema.json","fleet-settings.schema.json","installation-witness.schema.json","retention-policy.schema.json","retention-topology.schema.json"])
    if args.bundle=="control":
        dest=ROOT/"internal/adapters/jose/schemas"
        pending=["internal-work.schema.json"]
    if args.bundle=="policies":
        dest=ROOT/"internal/adapters/kubernetes/policy-schemas"
        pending=["policy.schema.json"]
    graph={}
    def visit(v):
        if isinstance(v,dict):
            for k,x in v.items():
                if k=="$ref":
                    if x.startswith("#"): continue
                    if not x.startswith(PREFIX): raise ValueError("Nonlocal schema reference")
                    name=x[len(PREFIX):].split("#",1)[0]
                    if "/" in name or name not in {p.name for p in SOURCE.glob("*.schema.json")}: raise ValueError("Unknown schema")
                    pending.append(name)
                else: visit(x)
        elif isinstance(v,list):
            for x in v: visit(x)
    while pending:
        name=pending.pop()
        if name in graph: continue
        b=(SOURCE/name).read_bytes();graph[name]=b;visit(json.loads(b))
    if args.write:
        dest.mkdir(parents=True,exist_ok=True)
        for name,b in graph.items(): (dest/name).write_bytes(b)
    actual={p.name:p.read_bytes() for p in dest.glob("*.json")}
    if actual!=graph: raise SystemExit(f"{args.bundle} schema bundle drift: run python3 scripts/manifest-schemas.py --bundle {args.bundle} --write and review")
    print(args.bundle,"schema bundle OK:",len(graph),"canonical local resources, byte-identical; no runtime network loader")

if __name__=="__main__": main()
