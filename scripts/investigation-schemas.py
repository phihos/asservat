#!/usr/bin/env python3
"""Generate the implemented pod-status subset of canonical public contracts.

This does not advertise the full planned capture surface. All references in the
tool descriptions are local, and runtime validation never uses the network.
Schemas alone never register or advertise an application service.
"""
import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "specs/contracts"
DEST = ROOT / "internal/contracts/investigation-schemas"
PREFIX = "https://asservat.io/spec/v1/"
NAMES = ["list_diagnostics", "preview_capture", "request_capture", "resolve_capture_request", "get_capture", "get_case", "prepare_artifact_download", "get_artifact_download", "cancel_artifact_download", "get_file_excerpt", "get_query_result", "activate_policy", "get_policy_status", "deactivate_policy"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    catalog = {t["name"]: t for t in json.loads((SOURCE / "mcp-tools.json").read_text())["tools"]}
    common = json.loads((SOURCE / "mcp-result.schema.json").read_text())
    documents = {p.name: json.loads(p.read_text()) for p in SOURCE.glob("*.schema.json")}

    def localize(root):
        definitions, known = {}, {}

        def visit(value, document=None):
            if isinstance(value, list):
                return [visit(x, document) for x in value]
            if not isinstance(value, dict):
                return value
            out = {}
            for key, item in value.items():
                if key in ("$id", "$schema"):
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
                    label = "d" + str(len(known))
                    known[identity] = label
                    target = documents[name]
                    if fragment:
                        if not fragment.startswith("/"):
                            raise ValueError("Only JSON pointer schema references are supported")
                        for segment in fragment[1:].split("/"):
                            target = target[segment.replace("~1", "/").replace("~0", "~")]
                    definitions[label] = visit(target, name)
                out[key] = "#/$defs/" + known[identity]
            return out

        result = visit(root)
        if definitions:
            result["$defs"] = definitions
        return result

    result = {}
    for name in NAMES:
        tool = catalog[name]
        if name in ("get_file_excerpt", "get_query_result"):
            # Canonical get_query_result remains extensible to other specified
            # tools. Only this runtime subset pins the implemented projection.
            description = copy.deepcopy(tool)
            description.pop("enabledByDefault", None)
            output = copy.deepcopy(common)
            output.pop("$id", None)
            output["properties"]["data_class"] = {"const": "metadata"}
            output["properties"]["provenance"] = {"type": "array", "maxItems": 0}
            for key, fixed in (("truncated", False), ("next_cursor", None), ("narrowing_hint", None)):
                output["properties"][key] = {"const": fixed}
            branches = copy.deepcopy(tool["outputSchema"]["allOf"][1]["oneOf"])
            data = branches[0]["properties"]["data"]
            if name == "get_file_excerpt":
                data["properties"]["logical_path"] = {"const": "pod-status.txt"}
                data["properties"]["lines"]["maxItems"] = 14
            else:
                data["properties"]["tool_name"] = {"const": "get_file_excerpt"}
                # The Go validator additionally applies the original output
                # schema and relational request/timing checks to this object.
            output["allOf"] = [{"oneOf": branches}]
            description["inputSchema"] = localize(description["inputSchema"])
            description["outputSchema"] = localize(output)
            result[name + ".json"] = (json.dumps(description, indent=2) + "\n").encode()
            continue
        if name in ("activate_policy", "get_policy_status", "deactivate_policy"):
            # ADR-228: the runtime implements the whole canonical contract.
            description = copy.deepcopy(tool)
            description.pop("enabledByDefault", None)
            output = copy.deepcopy(common)
            output.pop("$id", None)
            output["properties"]["provenance"] = {"type": "array", "maxItems": 0}
            output["properties"]["truncated"] = {"const": False}
            output["properties"]["next_cursor"] = {"type": "null"}
            output["properties"]["narrowing_hint"] = {"type": "null"}
            output["properties"]["data_class"] = {"const": "metadata"}
            output["allOf"] = [{"oneOf": copy.deepcopy(tool["outputSchema"]["allOf"][1]["oneOf"])}]
            description["inputSchema"] = localize(description["inputSchema"])
            description["outputSchema"] = localize(output)
            result[name + ".json"] = (json.dumps(description, indent=2) + "\n").encode()
            continue
        keys = {
            "list_diagnostics": ["target_ref"],
            "preview_capture": ["target_ref", "preset_ref", "requested_retention_seconds"],
            "request_capture": ["preview_id", "idempotency_key", "continue_acquisition"],
            "resolve_capture_request": ["preview_id", "idempotency_key"],
            "get_capture": ["capture_id"],
            "get_case": ["case_id"],
 "prepare_artifact_download": ["artifact_id","idempotency_key"],
 "get_artifact_download": ["download_id"],
 "cancel_artifact_download": ["download_id","idempotency_key"],
        }[name]
        props = {k: copy.deepcopy(tool["inputSchema"]["properties"][k]) for k in keys}
        if "preset_ref" in props:
            props["preset_ref"]["properties"]["name"] = {"const": "pod-status"}
        input_schema = {"type": "object", "additionalProperties": False, "properties": props,
                        "required": [k for k in keys if k not in ("requested_retention_seconds", "continue_acquisition")]}
        branches = tool["outputSchema"]["allOf"][1]["oneOf"]
        success = copy.deepcopy(next(b for b in branches if b["properties"]["status"].get("const") == "ok"))
        error = copy.deepcopy(next(b for b in branches if b["properties"]["status"].get("const") == "error"))
        data = success["properties"]["data"]
        output_keys = {
            "list_diagnostics": ["diagnostics"],
            "preview_capture": ["preview_id", "expires_at", "execution_digest", "pod_count", "max_bytes", "max_process_starts", "approval_required", "capture_enabled", "blockers", "warnings", "navigation_uri", "lifecycle_plan", "capture_assessment", "preset_ref", "target_ref", "selected_pods", "pod_selection"],
            "request_capture": ["capture_id", "phase", "navigation_uri", "operation"],
            "resolve_capture_request": None,
            "get_capture": ["capture_id", "revision", "phase", "actions", "case_id", "navigation_uri", "retry_after_seconds", "can_cancel", "blockers", "operation"],
            "get_case": ["case", "artifacts", "timeline"],
 "prepare_artifact_download": None,
 "get_artifact_download": None,
 "cancel_artifact_download": None,
        }[name]
        if name=="cancel_artifact_download":
            success["properties"]["data"]={"$ref":PREFIX+"artifact-download.schema.json#/$defs/cancelReceipt"}
        if output_keys is not None:
            data["properties"] = {k: v for k, v in data["properties"].items() if k in output_keys}
        # Preserve the exact preset conditions, including retention anchors.
        # Localizing below also closes references within these conditions.
        if name == "preview_capture":
            data["required"] = output_keys
            data["properties"]["preset_ref"]["properties"]["name"] = {"const": "pod-status"}
        if name == "list_diagnostics":
            row = data["properties"]["diagnostics"]["items"]
            row["properties"].pop("diagnostic_handle", None)
            row.pop("oneOf", None)
            row.pop("allOf", None)
            row["required"] = list(row["properties"])
            row["properties"]["preset_ref"]["properties"]["name"] = {"const": "pod-status"}
            data["properties"]["diagnostics"]["maxItems"] = 1
        if name == "get_case":
            # Ordinary verified pod-status metadata only. No raw/shared/native
            # file metadata, invented titles or historical timeline projection.
            case = data["properties"]["case"]
            case["properties"] = {k: v for k, v in case["properties"].items()
                                  if k in ("case_id", "status", "access")}
            case["properties"]["status"] = {"const": "Ready"}
            case["properties"]["access"] = {"const": "ordinary"}
            artifacts = data["properties"]["artifacts"]
            artifacts["minItems"] = 1
            row = artifacts["items"]["properties"]
            row["kind"] = {"const": "pod-status"}
            row["data_class"] = {"const": "metadata"}
            row["completeness"] = {"const": "complete"}
            notice = copy.deepcopy(documents["capture-assessment.schema.json"]["$defs"]["artifactNotice"])
            notice["properties"].pop("handlingPolicyRef", None)
            notice["properties"]["classification"] = {"const": "potentialPersonalData"}
            notice["properties"]["mayContain"] = {"const": ["personalIdentifiers", "networkAddresses", "paths"]}
            notice["properties"]["deletionState"] = {"const": "scheduled"}
            notice["properties"]["preservationException"] = {"const": False}
            row["handling_notice"] = notice
            data["properties"]["timeline"]["maxItems"] = 0
        output_schema = copy.deepcopy(common)
        output_schema.pop("$id", None)
        output_schema["properties"]["provenance"] = {"type": "array", "maxItems": 0}
        output_schema["properties"]["truncated"] = {"const": False}
        output_schema["properties"]["next_cursor"] = {"type": "null"}
        output_schema["properties"]["narrowing_hint"] = {"type": "null"}
        output_schema["properties"]["data_class"] = {"const": "metadata"}
        output_schema["allOf"] = [{"oneOf": [success, error]}]
        result[name + ".json"] = (json.dumps({
            "name": name,
            "description": {
                "list_diagnostics": "List the supported pod-status preset for a currently authorized named workload. No evidence collection.",
                "preview_capture": "Review a bounded whole-pod Kubernetes status snapshot, selected Pod, impact and data handling. No collection; only pod-status/v1 is supported by this runtime.",
                "request_capture": "Submit the reviewed pod-status preview using a stable idempotency key. Acceptance is not collection or evidence success. Retry an uncertain result with the same key and preview. Ordinary accepted replay is passive; continue_acquisition:true explicitly attempts the original accepted acquisition with current rights, without new keys or another attempt.",
                "resolve_capture_request": tool["description"],
                "get_capture": "Read authorized pod-status capture progress. No evidence bytes. Finalizing is not publication; Indeterminate must not be automatically recaptured.",
                "prepare_artifact_download": "Prepare an ordinary pod-status native download with a stable idempotency key. Retry unknown replies with the same key. Only an explicit acknowledged continuation may repeat preparation automatically.",
 "cancel_artifact_download": tool["description"],
 "get_artifact_download": "Read current authorized download status and verified native metadata. Never starts, repairs or decrypts evidence. Native file bytes use the authenticated content path, not MCP.",
 "get_case": "Read a currently authorized ordinary case of verified pod-status artifacts and effective handling dates. Artifact digest is the verified ciphertext-copy version, not native file SHA-256. No native bytes, raw or shared access.",
            }[name],
            "annotations": tool["annotations"],
            "inputSchema": localize(input_schema),
            "outputSchema": localize(output_schema),
        }, indent=2) + "\n").encode()
    if args.write:
        DEST.mkdir(parents=True, exist_ok=True)
        for name, value in result.items():
            (DEST / name).write_bytes(value)
    actual = {p.name: p.read_bytes() for p in DEST.glob("*.json")}
    if result != actual:
        raise SystemExit("Investigation schema drift; run scripts/investigation-schemas.py --write and review")
    print("Investigation schemas OK: bounded runtime subsets; all references local; registration remains explicit")


if __name__ == "__main__":
    main()
