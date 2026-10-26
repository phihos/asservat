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
NAMES = ["list_diagnostics", "preview_capture", "request_capture", "resolve_capture_request", "get_capture", "get_case", "prepare_artifact_download", "get_artifact_download", "cancel_artifact_download", "get_file_excerpt", "get_query_result", "activate_policy", "get_policy_status", "deactivate_policy", "create_share", "list_shares", "revoke_share", "explain_access", "list_capture_history", "get_capture_settings", "preview_access_change", "transfer_share"]


def history_subset(name, tool):
    """ADR-236 increment: pod-status history by the target_ref selector only
    (no handles, discovery origin or pending replies); settings are the
    canonical captureSettings record. Every runtime input/output is valid
    canonically."""
    description = copy.deepcopy(tool)
    description.pop("enabledByDefault", None)
    schema = description["inputSchema"]
    props = schema["properties"]
    branches = copy.deepcopy(tool["outputSchema"]["allOf"][1]["oneOf"])
    success = next(b for b in branches if b["properties"]["status"].get("const") == "ok")
    error = next(b for b in branches if b["properties"]["status"].get("const") == "error")
    if name == "list_capture_history":
        for key in ("target_handle", "cluster_id", "target"):
            props.pop(key)
        props["origin"] = {"enum": ["manual", "policy", "all"]}
        schema.pop("oneOf")
        schema["required"] = ["target_ref"]
        description["description"] = ("List recent accepted pod-status captures of a currently authorized named workload, newest first, for seven days after acceptance: "
                                      "your own requests and those whose retained audience you currently belong to. Origin manual (default), policy or all; "
                                      "at most limit entries (default 20, maximum 100) and next_cursor for more. A recreated workload starts a new history. "
                                      "Repeat one with preview_capture history_capture_id. No evidence or settings are read.")
    else:
        success["properties"]["data"] = {"$ref": PREFIX + "capture-history.schema.json#/$defs/record"}
        description["description"] = ("Read the repeatable settings of one visible capture-history entry: its authored target, recipe, dependency pins and requested retention. "
                                       "No reason, recipients, grants, credentials or old pod selection. Repeat it with preview_capture history_capture_id.")
    return description, [success, error]


def share_subset(name, tool):
    """ADR-232 increment 1: one concrete pod-status artifact per share, the
    get_case read only, no sharing intents, cursors or pending replies;
    increment 4 adds default team management (owned rows carry revision,
    created_by and managed_by); ADR-238 adds the management selection and
    transfer_share. Every runtime input/output is
    valid canonically."""
    description = copy.deepcopy(tool)
    description.pop("enabledByDefault", None)
    schema = description["inputSchema"]
    props = schema["properties"]
    branches = copy.deepcopy(tool["outputSchema"]["allOf"][1]["oneOf"])
    success = next(b for b in branches if b["properties"]["status"].get("const") == "ok")
    error = next(b for b in branches if b["properties"]["status"].get("const") == "error")
    data = success["properties"]["data"]
    if name == "create_share":
        # ADR-238: the optional management selection is the canonical one.
        props["artifacts"]["minItems"] = props["artifacts"]["maxItems"] = 1
        props["recipients"]["maxItems"] = 8
        props["data_classes"] = {"const": ["metadata"]}
        props["operations"] = {"const": ["get_case"]}
        description["description"] = ("Share one stored pod-status artifact (its exact digest from get_case) with up to eight users or groups of your identity provider until expires_at "
                                      "(at most seven days, never past the artifact's retention). Recipients can read it with get_case; download, inspection of other artifacts and capture rights are not shared. "
                                      "Needs the evidence-owner role on the workload and the evidence:share scope. By default your owner teams manage the share; an installation administrator may also name owner teams they do not belong to; "
                                      "management may instead name some of the owner teams you belong to (mode teams) or only you (mode creator). Repeat an uncertain request with the same idempotency key.")
        data["properties"] = {k: v for k, v in data["properties"].items() if k in ("share_id", "phase")}
        data["properties"]["phase"] = {"const": "Active"}
    elif name == "list_shares":
        # ADR-238: the cursor pages only the administrator view.
        props.pop("include_intents")
        schema.pop("allOf")
        description["description"] = ("List the shares you created (view owned, every phase) or currently manage through a pinned owner team (unrevoked, unexpired), "
                                      "with revision, created_by and managed_by; or the shares you can currently read (view received, Active only). "
                                      "Installation administrators may page through every share management-only with view administration and cursor "
                                      "(IDs, phase, expiry, revision, created_by, managed_by; never recipients or evidence). "
                                      "Most recent first, at most limit (default 20, maximum 100).")
        data["properties"] = {k: v for k, v in data["properties"].items() if k == "shares"}
        row = data["properties"]["shares"]["items"]
        row["properties"].pop("origin")
        row["properties"]["phase"] = {"enum": ["Active", "Expired", "Revoked", "Suspended"]}
        row["properties"]["revision"] = {"type": "integer", "minimum": 1, "maximum": 1000000000}
    elif name == "revoke_share":
        props.pop("sharing_intent_id")
        schema.pop("oneOf")
        schema["required"] = ["share_id", "expected_revision", "idempotency_key"]
        description["description"] = ("Revoke a share you created or currently manage through a pinned owner team; installation administrators may revoke any share. "
                                      "Each transfer and the revocation add one revision (list_shares shows the current one). Recipients lose access at their next read; "
                                      "independent rights are unchanged and revoking never grants a read. Repeating with the same idempotency key is harmless.")
        data["properties"].pop("sharing_intent_id")
        data.pop("oneOf")
        data["required"] = ["share_id", "phase", "revision"]
        data["properties"]["revision"] = {"type": "integer", "minimum": 2, "maximum": 1000000000}
    else:
        # ADR-238: transfer of one concrete share's management.
        props.pop("sharing_intent_id")
        schema.pop("oneOf")
        schema["required"] = ["share_id", "expected_revision", "idempotency_key", "management"]
        description["description"] = ("Replace the owner teams managing a share you currently manage (an audited transfer). Name owner teams you belong to now (mode teams), "
                                      "or, as the share's creator, only yourself (mode creator). Installation administrators may assign any owner teams that currently hold "
                                      "evidence-owner for the artifact (mode teams), also to recover a Suspended share. Creator, recipients, artifact and expiry stay unchanged; "
                                      "the share is suspended when no new manager keeps the evidence-owner role. Managing grants no read. Repeating with the same idempotency key is harmless.")
        data["properties"].pop("sharing_intent_id")
        data.pop("oneOf")
        data["required"] = ["share_id", "phase", "revision", "managed_by"]
        data["properties"]["phase"] = {"const": "Active"}
    return description, [success, error]


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
        if name in ("activate_policy", "get_policy_status", "deactivate_policy", "create_share", "list_shares", "revoke_share", "explain_access", "list_capture_history", "get_capture_settings", "preview_access_change", "transfer_share"):
            # ADR-228: the runtime implements the whole canonical contract.
            # ADR-232: the share tools implement a bounded subset.
            # ADR-234: explain_access implements the whole canonical contract.
            # ADR-236: the two history tools implement a bounded subset.
            # ADR-237: preview_access_change implements the whole contract (browser-only transport).
            description = copy.deepcopy(tool)
            description.pop("enabledByDefault", None)
            branches = copy.deepcopy(tool["outputSchema"]["allOf"][1]["oneOf"])
            if name in ("create_share", "list_shares", "revoke_share", "transfer_share"):
                description, branches = share_subset(name, tool)
            if name in ("list_capture_history", "get_capture_settings"):
                description, branches = history_subset(name, tool)
            output = copy.deepcopy(common)
            output.pop("$id", None)
            output["properties"]["provenance"] = {"type": "array", "maxItems": 0}
            output["properties"]["truncated"] = {"const": False}
            if name != "preview_access_change", "list_shares":
                output["properties"]["next_cursor"] = {"type": "null"}
            else:
                # ADR-237: the preview pages its bounded result.
                output["properties"]["next_cursor"] = {"anyOf": [{"type": "string", "pattern": "^[0-9]{1,7}:[0-9a-f]{32}$"}, {"type": "null"}]}
            output["properties"]["narrowing_hint"] = {"type": "null"}
            output["properties"]["data_class"] = {"const": "metadata"}
            if name == "list_capture_history":
                output["properties"]["next_cursor"] = copy.deepcopy(common["properties"]["next_cursor"])  # a cursor or null
            if name == "get_capture_settings":
                output["properties"]["data_class"] = {"enum": ["metadata", "extract"]}  # extract on success
            output["allOf"] = [{"oneOf": branches}]
            description["inputSchema"] = localize(description["inputSchema"])
            description["outputSchema"] = localize(output)
            result[name + ".json"] = (json.dumps(description, indent=2) + "\n").encode()
            continue
        keys = {
            "list_diagnostics": ["target_ref"],
            "preview_capture": ["target_ref", "preset_ref", "requested_retention_seconds", "sharing", "history_capture_id"],
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
        if "sharing" in props:
            # ADR-235: capture-time sharing of the one pod-status result with
            # up to eight recipients and an optional absolute end; no output
            # selection, reason override or management selection.
            sharing = copy.deepcopy(documents["sharing-request.schema.json"]["$defs"]["capture"])
            for k in ("outputSelection", "maxArtifactsPerCapture", "reason", "management"):
                sharing["properties"].pop(k)
            sharing["properties"]["recipients"]["maxItems"] = 8
            props["sharing"] = sharing
        input_schema = {"type": "object", "additionalProperties": False, "properties": props,
                        "required": [k for k in keys if k not in ("requested_retention_seconds", "continue_acquisition", "sharing", "history_capture_id")]}
        if name == "preview_capture":
            # ADR-236: either a named target with the preset, or one history
            # entry whose target and requested retention are restored.
            input_schema["required"] = []
            input_schema["oneOf"] = [
                {"required": ["target_ref", "preset_ref"], "not": {"required": ["history_capture_id"]}},
                {"required": ["history_capture_id"], "not": {"anyOf": [{"required": [k]} for k in ("target_ref", "preset_ref", "requested_retention_seconds")]}},
            ]
        branches = tool["outputSchema"]["allOf"][1]["oneOf"]
        success = copy.deepcopy(next(b for b in branches if b["properties"]["status"].get("const") == "ok"))
        error = copy.deepcopy(next(b for b in branches if b["properties"]["status"].get("const") == "error"))
        data = success["properties"]["data"]
        output_keys = {
            "list_diagnostics": ["diagnostics"],
            "preview_capture": ["preview_id", "expires_at", "execution_digest", "pod_count", "max_bytes", "max_process_starts", "approval_required", "capture_enabled", "blockers", "warnings", "navigation_uri", "lifecycle_plan", "capture_assessment", "preset_ref", "target_ref", "selected_pods", "pod_selection"],
            "request_capture": ["capture_id", "phase", "navigation_uri", "operation"],
            "resolve_capture_request": None,
            "get_capture": ["capture_id", "revision", "phase", "actions", "case_id", "navigation_uri", "retry_after_seconds", "can_cancel", "blockers", "operation", "sharing"],
            "get_case": ["case", "artifacts", "timeline"],
 "prepare_artifact_download": None,
 "get_artifact_download": None,
 "cancel_artifact_download": None,
        }[name]
        if name=="cancel_artifact_download":
            success["properties"]["data"]={"$ref":PREFIX+"artifact-download.schema.json#/$defs/cancelReceipt"}
        if output_keys is not None:
            optional = ["repeated_from_capture_id"] if name == "preview_capture" else []
            data["properties"] = {k: v for k, v in data["properties"].items() if k in output_keys + optional}
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
            # Verified pod-status metadata only (ordinary or ADR-232 shared). No raw/native
            # file metadata, invented titles or historical timeline projection.
            case = data["properties"]["case"]
            case["properties"] = {k: v for k, v in case["properties"].items()
                                  if k in ("case_id", "status", "access")}
            case["properties"]["status"] = {"const": "Ready"}
            # ADR-232: "shared" when a share admitted an artifact of the view.
            case["properties"]["access"] = {"enum": ["ordinary", "shared"]}
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
                "preview_capture": "Review a bounded whole-pod Kubernetes status snapshot, selected Pod, impact and data handling. No collection; only pod-status/v1 is supported by this runtime. Optional sharing shares the published result with up to eight users or groups of your identity provider (needs evidence-owner and the evidence:share scope; default 24 hours, at most seven days); get_capture reports sharing separately. Collect again: pass history_capture_id from list_capture_history (optionally with sharing) to restore its target and requested retention into a fresh preview with every current check.",
                "request_capture": "Submit the reviewed pod-status preview using a stable idempotency key. Acceptance is not collection or evidence success. Retry an uncertain result with the same key and preview. Ordinary accepted replay is passive; continue_acquisition:true explicitly attempts the original accepted acquisition with current rights, without new keys or another attempt.",
                "resolve_capture_request": tool["description"],
                "get_capture": "Read authorized pod-status capture progress. No evidence bytes. Finalizing is not publication; Indeterminate must not be automatically recaptured.",
                "prepare_artifact_download": "Prepare an ordinary pod-status native download with a stable idempotency key. Retry unknown replies with the same key. Only an explicit acknowledged continuation may repeat preparation automatically.",
 "cancel_artifact_download": tool["description"],
 "get_artifact_download": "Read current authorized download status and verified native metadata. Never starts, repairs or decrypts evidence. Native file bytes use the authenticated content path, not MCP.",
 "get_case": "Read a currently authorized case of verified pod-status artifacts and effective handling dates: ordinary access, or artifacts an evidence owner shared with you (access shared). Artifact digest is the verified ciphertext-copy version, not native file SHA-256. No native bytes or raw access; shared artifacts cannot be downloaded.",
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
