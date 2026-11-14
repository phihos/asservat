#!/usr/bin/env python3
"""Every upper bound in a canonical contract needs a stated reason.

Maintainer rule (AGENTS.md, 2026-11-14): a limit stays only with a resource cost
and a bound derived from it, an external protocol/API constraint, or an explicit
maintainer decision. This gate walks the canonical contracts (not the runtime
copies under specs/contracts/implemented/) and fails on any maxLength, maxItems,
maxProperties, maximum or exclusiveMaximum that no ALLOW entry below explains.
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
KEYWORDS = ("maxLength", "maxItems", "maxProperties", "maximum", "exclusiveMaximum")
SAFE_INTEGER = 2**53 - 1

# (keyword, value, property-name regex or None for any, file regex or None, reason)
ALLOW = [
    ("maximum", SAFE_INTEGER, None, None, "JSON exact-integer range (2^53-1) needed by RFC 8785 hashing and JavaScript clients"),
    ("maxItems", 0, None, None, "structural: the list must be empty in this conditional branch"),
    ("maxItems", 1, r"effectiveRetention|podBindings|selected_pods", None, "structural: exactly one entry in this conditional branch"),
    ("maxLength", 63, r"namespace|namespaces|excludedNamespaces|container_name|containerName|cluster|clusters|matchLabels|labels", None, "RFC 1123 DNS label: Kubernetes namespace, container and cluster names, label values"),
    ("maxLength", 63, r"name", r"permission-common", "RFC 1123 DNS label: namespaceRef names a Kubernetes namespace"),
    ("maxLength", 253, r"name|name_prefix|pod_name|policy|policy_name|recipe|workload|workload_name", None, "RFC 1123 DNS subdomain: Kubernetes object names"),
    ("maxLength", 15, r"portName|declaredPortName", None, "IANA service name (RFC 6335): Kubernetes container port names"),
    ("maxLength", 47, r"setupAccount", r"small-openbao", "the 30-character installation name plus the fixed '-bootstrap-runner' suffix"),
    ("maxLength", 30, r"name", r"small-openbao", "installation name prefix: derived object names stay RFC 1123 DNS labels (charts/asservat/values.yaml)"),
    ("maxLength", 36, None, None, "UUID text form (RFC 9562)"),
    ("maxLength", 64, r"\w*[dD]igest", None, "lowercase hex SHA-256"),
    ("maxLength", 43, r"X-CSRF-Token|csrf_token|state", None, "unpadded base64url of a 32-byte token"),
    ("maxLength", 44, r"material", r"local-key-secret", "padded base64 of a 32-byte key"),
    ("maxLength", 255, r"executableName|executable_name|filename", None, "Linux NAME_MAX"),
    ("maxLength", 4096, r"path|filePath|logical_path|executable_path|executablePath|workingDirectory", None, "Linux PATH_MAX"),
    ("maxLength", 131072, r"argv|commandArgv|value", None, "Linux MAX_ARG_STRLEN per argument"),
    ("maxLength", 4096, r"reason", None, "free-text reasons bound stored audit record size (specs/apis.md)"),
    ("maxLength", 1024, r"versionID", None, "S3 object version IDs are at most 1024 bytes"),
    ("maxLength", 1572864, r"manifest_yaml", None, "Kubernetes API server request limit (1.5 MiB) for the staged object"),
    ("maxLength", 5464, r"data", r"log-record", "base64 of a 4096-byte log fragment; log record bytes protect collector memory (specs/apis.md)"),
    ("maxLength", 179, r"value", r"syscall-arguments", "'base64:' plus 128 argument bytes: reviewed syscall argument observation budget (specs/syscalls.md)"),
    ("maxLength", 64, r"namespaceUID|podUID", r"pod-status", "the pod-status byte reservation is derived from the projection's worst case under these maxima (check-specs.py)"),
    ("maxLength", 128, r"resourceVersion", r"pod-status", "the pod-status byte reservation is derived from the projection's worst case under these maxima (check-specs.py)"),
    ("maxItems", 6, r"arguments", None, "a Linux syscall has at most six arguments"),
    ("maxItems", 6, r"pressureTriggers", None, "Linux PSI: three resources x some/full"),
    ("maxItems", 4096, r"program", None, "kernel BPF_MAXINSNS"),
    ("maxItems", 4, r"program", None, "classic BPF instruction (code, jt, jf, k)"),
    ("maximum", 65535, r"program", None, "classic BPF opcode is 16 bits"),
    ("maximum", 255, r"program", None, "classic BPF jump offsets are 8 bits"),
    ("maximum", 4294967295, r"program", None, "classic BPF constant is 32 bits"),
    ("maximum", 4096, r"filter_instructions", None, "kernel BPF_MAXINSNS"),
    ("maximum", 65535, r"port|ports|peer_port|remote_port|minimum_port|maximum_port|value", None, "TCP/UDP port is 16 bits"),
    ("maximum", 65535, r"snaplen|bytes|length", None, "IP packet length field is 16 bits"),
    ("maximum", 65534, r"offset", None, "last byte offset inside a 65535-byte packet"),
    ("maximum", 511, r"mask|value", None, "TCP flags field is 9 bits"),
    ("maximum", 255, r"exit_codes|exitCodes", None, "Linux exit status is 8 bits"),
    ("maximum", 64, r"signals", None, "Linux SIGRTMAX"),
    ("maximum", 4095, r"errno", None, "Linux MAX_ERRNO"),
    ("maximum", 4194304, r"pid|hostPID|display_pid|value", None, "Linux PID_MAX_LIMIT"),
    ("maximum", 599, r"status|value", None, "HTTP status code range (RFC 9110)"),
    ("maximum", 4294967295, r"databaseOID", None, "PostgreSQL OID is 32 bits"),
    ("maximum", 2147483647, r"restartCount", None, "Kubernetes ContainerStatus.restartCount is int32"),
    ("maximum", 10000000, r"stallMicroseconds|windowMicroseconds", None, "Linux PSI trigger window is at most 10 s"),
    ("maximum", 1, r"fraction|threshold", None, "a fraction lies in [0, 1]"),
    ("maximum", 3, r"revision|expected_revision", None, "a grant has at most three revisions: request, decision, revocation"),
    ("maximum", 32768, r"maxHeaderBytes", None, "common HTTP server header block limit (nginx 4 x 8 KiB)"),
    ("maximum", 32768, r"length|bytes_returned", None, "hex output of 32 KiB fits the 96 KiB MCP result bound (specs/apis.md)"),
    ("maximum", 4096, r"maxBytesPerEvent", None, "reviewed syscall argument observation budget (specs/syscalls.md)"),
    ("maximum", 30000, r"wait_ms", None, "30 s MCP status wait (ADR-335)"),
    ("maximum", 8388608, r"nativeBytes", r"framed-storage", "8 MiB frame: encoder/reader memory per frame (artifact-format.md)"),
    ("maximum", 8454144, r"dataBytes", r"framed-storage", "8 MiB frame plus 64 KiB authentication overhead (artifact-format.md)"),
    ("maximum", 256, r"frameCount", r"framed-storage", "256 frames per index page (artifact-format.md)"),
    ("maxItems", 256, r"frames", r"framed-storage", "256 frames per index page (artifact-format.md)"),
    ("maximum", 2147483648, r"nativeBytes", r"framed-storage", "256 frames x 8 MiB per index page (artifact-format.md)"),
    ("maximum", 2164260864, r"dataBytes", r"framed-storage", "256 frames x (8 MiB + 64 KiB) per index page (artifact-format.md)"),
    ("maximum", 327680, r"indexBytes", r"framed-storage", "320 KiB index page (artifact-format.md)"),
]


def files():
    yield from sorted((ROOT / "specs/contracts").glob("*.json"))
    yield from sorted((ROOT / "docs/interfaces").glob("*.yaml"))


def load(path):
    return json.loads(path.read_text()) if path.suffix == ".json" else yaml.safe_load(path.read_text())


# Schema and OpenAPI structure keys; the property name of a bound is the nearest other key.
STRUCTURE = {"properties", "patternProperties", "items", "prefixItems", "additionalProperties", "propertyNames",
             "contains", "not", "if", "then", "else", "oneOf", "anyOf", "allOf", "$defs", "schema", "schemas",
             "components", "paths", "content", "requestBody", "responses", "headers", "parameters",
             "valueSchema", "x-field-bindings", "tools", "inputSchema", "outputSchema",
             "get", "put", "post", "patch", "delete"}


def bounds(node, path=(), param=""):
    """Yield (path, node, keyword, value, property name) for every upper bound."""
    if isinstance(node, dict):
        if isinstance(node.get("in"), str) and isinstance(node.get("name"), str):
            param = node["name"]  # OpenAPI parameter: its schema is named by the parameter
        for key, value in node.items():
            if key in KEYWORDS and isinstance(value, (int, float)) and not isinstance(value, bool):
                yield path, node, key, value, param or property_name(path)
            yield from bounds(value, path + (key,), param if key == "schema" else "")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from bounds(value, path + (str(index),))


def property_name(path):
    for index in range(len(path) - 1, -1, -1):
        part = path[index]
        if index and path[index - 1] in ("properties", "patternProperties"):
            return part
        if part not in STRUCTURE and not part.isdigit() and not part.startswith("application/"):
            return part
    return ""


def reason(rel, keyword, value, name):
    for k, v, field, file, why in ALLOW:
        if k == keyword and v == value and (field is None or re.fullmatch(field, name)) and (file is None or re.search(file, rel)):
            return why
    return None


def main():
    kept, failures = Counter(), []
    for path in files():
        rel = str(path.relative_to(ROOT))
        for where, _, keyword, value, name in bounds(load(path)):
            why = reason(rel, keyword, value, name)
            if why is None:
                failures.append(f"{rel}: /{'/'.join(where)}: {keyword} {value} ({name or '-'}) has no stated reason")
            else:
                kept[why] += 1
    if failures:
        print("\n".join(failures))
        print(f"FAIL: {len(failures)} unexplained contract bounds; remove them or add an ALLOW entry with its reason")
        return 1
    print(f"PASS: {sum(kept.values())} contract bounds, each explained by one of {len(kept)} stated reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
