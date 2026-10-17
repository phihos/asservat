#!/usr/bin/env python3
"""Check real product Go imports against the reviewed component catalog."""
import json
from pathlib import Path
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[1]
catalog = yaml.safe_load((ROOT/"docs/architecture/catalog.yaml").read_text())
components = {c["id"]: c for c in catalog["components"]}
roots = [(path, c["id"]) for c in components.values() for path in c["package_roots"]]
module = subprocess.check_output(["go", "list", "-m"], cwd=ROOT, text=True).strip()
output = subprocess.check_output(["go", "list", "-json", "./..."], cwd=ROOT, text=True)
dependencies = subprocess.check_output(["go", "list", "-deps", "./..."], cwd=ROOT, text=True).splitlines()
if any(p == "golang.org/x/crypto/openpgp" or p.startswith("golang.org/x/crypto/openpgp/") for p in dependencies):
    raise ValueError("Unmaintained OpenPGP package is forbidden (GO-2026-5932); maintained x/crypto primitives remain allowed")
decoder, packages = json.JSONDecoder(), []
while output.strip():
    value, end = decoder.raw_decode(output.lstrip())
    output = output.lstrip()[end:]
    packages.append(value)


def relative(path):
    return path.removeprefix(module+"/")


def owner(path):
    path = relative(path)
    if path in {"cmd/asservat", "internal/bootstrap"} or path.startswith("internal/bootstrap/"):
        return "bootstrap"
    if path == "test" or path.startswith("test/"):
        return "test"
    matches = [cid for root, cid in roots if path == root or path.startswith(root+"/")]
    if len(matches) != 1:
        raise ValueError(f"Unmapped/ambiguous package: {path}: {matches}")
    return matches[0]


def wire_contract(path):
    path = relative(path)
    return any(path == root or path.startswith(root+"/") for root in ("api/v1alpha1", "internal/contracts"))


edges = 0
for package in packages:
    source = owner(package["ImportPath"])
    if source == "test":
        if package.get("GoFiles"):
            raise ValueError("Test infrastructure must not become a product package")
        continue
    for imported in package.get("Imports", []):
        if not imported.startswith(module+"/"):
            if source != "bootstrap" and components[source]["layer"] == "domain":
                # net/netip provides pure address values/parsing, unlike net's
                # sockets and DNS. Network I/O imports remain forbidden here.
                allowed = {"errors", "fmt", "strings", "strconv", "bytes", "cmp", "slices", "sort", "math", "math/bits", "time", "unicode", "unicode/utf8", "net/netip"}
                if imported not in allowed:
                    raise ValueError(f"Domain import is not a pure value utility: {imported}")
            if source != "bootstrap" and components[source]["layer"] in {"domain", "application"} and "." in imported.split("/")[0]:
                raise ValueError(f"Third-party protocol type leaked into {source}: {imported}")
            continue
        target = owner(imported)
        if wire_contract(package["ImportPath"]) and not wire_contract(imported):
            raise ValueError(f"Shared wire contract imports behavior: {imported}")
        if target == "test" or (target == "bootstrap" and source != "bootstrap"):
            raise ValueError(f"Invalid dependency {source} -> {target}")
        if source == "bootstrap":
            continue
        if source != target and target not in components[source]["allowed_dependencies"]:
            raise ValueError(f"Undeclared dependency {source} -> {target}: {imported}")
        source_layer, target_layer = components[source]["layer"], components[target]["layer"]
        if source_layer == "adapter" and target_layer == "transport" and not wire_contract(imported):
            raise ValueError(f"Adapter imports a transport handler instead of shared DTOs: {imported}")
        if source_layer in {"application", "domain", "transport"} and target_layer == "adapter":
            raise ValueError(f"Concrete adapter imported outside bootstrap/adapter: {imported}")
        edges += 1
    if source != "bootstrap" and components[source]["layer"] == "domain":
        for file in package.get("GoFiles", []):
            text = (Path(package["Dir"])/file).read_text()
            if "time.Now(" in text or "time.Sleep(" in text:
                raise ValueError("Inject time values into domain rules")

print(f"Go architecture OK: {len(packages)} packages, {edges} internal import edges; catalog ownership and layer/dependency rules checked")
