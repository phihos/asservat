#!/usr/bin/env python3
"""Offline specification checks. These do not test the proposed runtime."""
from __future__ import annotations

import copy
import base64
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

try:
    import yaml
    from jsonschema import Draft202012Validator, FormatChecker
    from referencing import Registry, Resource
except ImportError as exc:
    raise SystemExit(
        "Install development dependencies in a virtual environment: "
        "python -m pip install -r requirements-spec.txt"
    ) from exc

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://asservat.io/spec/v1/"
checks = 0


def require(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise ValueError(message)


def read(path: Path):
    return json.loads(path.read_text()) if path.suffix == ".json" else yaml.safe_load(path.read_text())


def canonical_digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def collection_spec(doc: dict) -> dict:
    """Fixture projection only; production resolver must also freeze referenced scope."""
    excluded = {"grantRef", "sharing", "suspended", "reason", "idempotencyKey"}
    return {"kind": doc["kind"], "spec": {k: copy.deepcopy(v) for k, v in doc["spec"].items() if k not in excluded}}


def duration_seconds(value: str) -> float:
    if value == "0s":
        return 0
    match = re.fullmatch(r"([1-9][0-9]*)(ms|s|m|h|d)", value)
    require(match is not None, "Invalid duration")
    return int(match[1]) * {"ms": .001, "s": 1, "m": 60, "h": 3600, "d": 86400}[match[2]]


def timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def framed_storage_checks(doc: dict) -> None:
    layout = doc["encryption"]
    frames = max(1, (layout["nativeBytes"] + 8388607) // 8388608)
    require(len(layout["pages"]) == (frames + 255) // 256, "Wrong framed index page count")
    native = data = index = count = 0
    for number, page in enumerate(layout["pages"]):
        n = min(256, frames-count)
        wanted_native = min(n*8388608, layout["nativeBytes"]-native)
        require(page["number"] == number and page["firstFrame"] == count and page["frameCount"] == n, "Non-contiguous frame sequence")
        require(page["nativeOffset"] == native and page["nativeBytes"] == wanted_native, "Non-contiguous native index")
        require(page["dataOffset"] == data and 1 <= page["dataBytes"] <= wanted_native+n*65536, "Invalid encrypted data span")
        require(page["indexOffset"] == index, "Non-contiguous encrypted index")
        native += page["nativeBytes"]; data += page["dataBytes"]; index += page["indexBytes"]; count += n
    require((native, data, index, count) == (layout["nativeBytes"], layout["dataBytes"], layout["indexBytes"], frames), "Framed totals disagree")
    require(layout["binding"]["clusterID"] == doc["target"]["clusterID"] and layout["binding"]["artifactID"] == doc["artifactID"] and layout["binding"]["mediaType"] == doc["mediaType"], "Framed binding disagrees with manifest")
    require(layout["nativeBytes"] == doc["sizes"]["plaintextBytes"] and layout["dataBytes"] == doc["sizes"]["ciphertextBytes"], "Framed size disagrees with manifest")
    require(layout["nativeSHA256"] == doc["hashes"]["plaintextSHA256"] and layout["dataSHA256"] == doc["hashes"]["ciphertextSHA256"], "Framed digest disagrees with manifest")


def sharing_origin_checks(share: dict, intent: dict, manifests: dict) -> None:
    """Static fixture consistency only; live authority/SQL/local CAS checks need runtime tests."""
    spec, parent = share["spec"], intent["spec"]
    origin = spec["origin"]
    require(origin["sharingIntentID"] == intent["id"], "Unknown sharing intent")
    require(intent["status"]["phase"] in {"Active", "Draining", "Completed"}, "Intent cannot authorize disclosure")
    if parent["source"]["kind"] == "DebugCapture":
        require(origin["captureUID"] == parent["source"]["resourceUID"], "Share from another capture")
    selections = {s["id"]: s for s in parent["resolvedSelections"]}
    require(origin["selectionID"] in selections, "Unknown sharing selection")
    selection = selections[origin["selectionID"]]
    approvals = {s["selectionID"]: s for s in intent["status"]["selectionApprovals"]}
    approval = approvals[origin["selectionID"]]
    require(approval["phase"] == "Approved", "Selection lacks approval")
    require(share["status"].get("approvedBy") == approval["approvedBy"] and share["status"].get("approvedAt") == approval["approvedAt"], "Share lost approver provenance")
    require(spec["createdBy"] == parent["createdBy"] and spec["management"] == parent["management"] and spec["recipients"] == parent["recipients"], "Share exceeds approved audience")
    require(spec["dataClasses"] == [selection["dataClass"]], "Share mixes selection classes")
    require(set(spec["operations"]) <= set(selection["operations"]), "Share exceeds selection operations")
    require(timestamp(spec["notAfter"]) <= timestamp(parent["notAfter"]), "Share outlives intent")
    require(len(spec["artifacts"]) <= parent["maxArtifactsPerCapture"], "Share exceeds artifact budget")
    visited = set()

    def lineage(ref, stack, selected=False):
        require(ref["artifactID"] in manifests, "Missing lineage manifest")
        require(ref["artifactID"] not in stack and len(stack) < 64, "Invalid lineage graph")
        visited.add(ref["artifactID"])
        require(len(visited) <= 256, "Lineage exceeds manifest budget")
        m = manifests[ref["artifactID"]]
        require(ref["digest"] == m["hashes"]["plaintextSHA256"], "Artifact digest mismatch")
        source = m.get("collectionProvenance", {})
        require(source.get("captureUID") == origin["captureUID"] and source.get("actionID") == selection["actionID"], "Foreign acquisition origin")
        require(source.get("planDigest") == parent["source"]["planDigest"], "Changed acquisition plan")
        require(m["target"]["clusterID"] == parent["source"]["clusterID"] and m["accessProvenance"]["namespaceUID"] == parent["source"]["namespaceUID"], "Foreign cluster or namespace")
        require(m["collector"]["recipeDigest"] == parent["source"]["recipeDigest"], "Changed recipe")
        require(timestamp(spec["notAfter"]) <= timestamp(m["expiresAt"]), "Share outlives artifact or parent")
        if selected:
            require(m["caseID"] == spec["caseID"] and m["dataClass"] == selection["dataClass"], "Wrong case or output class")
            if selection["dataClass"] != "raw":
                require(m["provenance"].get("projectionDigest") == selection["projectionDigest"], "Changed output projection")
        for ref in m["provenance"]["parentArtifacts"]:
            lineage(ref, stack | {m["artifactID"]})

    for artifact in spec["artifacts"]:
        lineage(artifact, set(), selected=True)


def guidance_checks(data: dict) -> None:
    kind = data.get("kind")
    if kind == "discoveryPage":
        summary = data["summary"]
        start, end = timestamp(summary["started_at"]), timestamp(summary["ended_at"])
        require(start <= end < timestamp(data["expires_at"]), "Invalid discovery chronology")
        coverage = summary["coverage"]
        require(coverage["covered_pods"] <= coverage["requested_pods"], "Discovery exceeds selected pods")
        require(not coverage["traffic_complete"] or (coverage["dropped_packets"] == 0 and coverage["stop_reason"] in {"completed", "duration"}), "Incomplete traffic advertised as complete")
        processes = data.get("processes", [])
        require(len({item["process_ref"] for item in processes}) == len(processes), "Duplicate process identity")
        for process in processes:
            require(start <= timestamp(process["observed_at"]) <= end, "Process observed outside discovery interval")
        for flow in data.get("flows", []):
            if flow["protocol"] != "unknown" and flow["protocol_basis"]["confidence"] == "observed":
                require(summary["capture_mode"] == "rawPackets" and "classifier_digest" in summary, "Application protocol lacks approved payload classifier source")
            if flow["process_basis"]["confidence"] == "unknown":
                require(not flow["process_refs"], "Unknown process association has candidates")
    if kind == "diagnosticRecommendations":
        for rec in data["recommendations"]:
            params = rec.get("packet_parameters")
            if params:
                # Reuse packet contract semantics through a synthetic bounded action.
                semantic_checks({"kind": "EvidenceRecipe", "spec": {
                    "actions": [{"id": "recommended-packets", "kind": "packetCapture", "parameters": params,
                                 "required": True, "impact": rec["impact"],
                                 "limits": {"maxBytes": rec["max_bytes"], "timeout": "2h"}}],
                    "maxTotalBytes": rec["max_bytes"], "maxDuration": "2h"}})
            if "ring_sizing" in rec:
                size = rec["ring_sizing"]
                numerator = size["retained_bytes_per_second"] * size["history_seconds"] * size["burst_factor"]
                needed = max(2, (numerator + size["segment_bytes"] - 1) // size["segment_bytes"] + 1)
                require(size["segments"] == needed, "Sizing omits required segment/history allowance")
                require(size["ring_bytes"] == size["segments"] * size["segment_bytes"], "Sizing bytes do not match segments")
                ring = params["ring"]
                require((ring["maxBytes"], ring["maxSegments"], ring["segmentBytes"]) == (size["ring_bytes"], size["segments"], size["segment_bytes"]), "Sizing differs from proposed packet plan")
                require(duration_seconds(params["before"]) == size["history_seconds"], "Sizing differs from proposed history")
            if "process_selector" in rec:
                batch = rec["process_batch"]
                require(batch["maxProcesses"] * batch["maxBytesPerProcess"] <= rec["max_bytes"], "Suggested process batch exceeds bytes")
                require(rec["max_process_starts"] >= batch["maxProcesses"], "Suggested process starts omit batch fanout")
                if rec["process_inventory_complete"] and rec["process_match_count"] > batch["maxProcesses"]:
                    require(bool(rec["blockers"]), "Too many matching processes advertised as executable")


def history_selector_fixture_key(cluster_id, namespace_uid, target):
    """Explicit grouping fixture, not live resolution or production key derivation."""
    key = {"clusterID": cluster_id, "namespaceUID": namespace_uid}
    if "workloadRef" in target:
        ref = target["workloadRef"]
        require(bool(ref.get("uid")), "Grouping requires resolved workload identity")
        key["workload"] = {"kind": ref["kind"], "uid": ref["uid"]}
    else:
        key["podSelector"] = target["podSelector"]
    # Production indexes use keyed digests. This checks only canonical grouping.
    return canonical_digest(key)


def capture_history_checks(data):
    if data.get("kind") == "captureHistoryPage":
        entries = data["history"]
        require(len({r["capture_id"] for r in entries}) == len(entries), "Duplicate capture history entry")
        order = [(timestamp(r["accepted_at"]), r["capture_id"]) for r in entries]
        require(order == sorted(order, reverse=True), "History ordering differs from cursor contract")
        for row in entries:
            require(timestamp(row["accepted_at"]) < timestamp(row["summary_expires_at"]), "Invalid history summary lifetime")
            if "settings_expires_at" in row:
                require(timestamp(row["accepted_at"]) < timestamp(row["settings_expires_at"]) <= timestamp(row["summary_expires_at"]), "Settings exceed history deadline")
            require(row.get("repeated_from_capture_id") != row["capture_id"], "Capture cannot repeat itself")
    if data.get("kind") == "captureSettings":
        require(timestamp(data["accepted_at"]) < timestamp(data["expires_at"]), "Invalid settings lifetime")
        settings = data["settings"]
        require(canonical_digest(settings) == data["settings_digest"], "History settings digest mismatch")
        spec = settings["recipe_spec"]
        semantic_checks({"kind": "EvidenceRecipe", "spec": spec})
        pins = settings["dependency_pins"]
        require(len({(p["role"], p["digest"], canonical_digest(p.get("source", {}))) for p in pins}) == len(pins), "Duplicate history dependency pin")
        require({"role": "recipe", "digest": canonical_digest(spec)} in pins, "History recipe pin mismatch")


def capture_assessment_checks(doc):
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    assessment = doc if doc.get("schemaVersion") == "capture-assessment/v1" else data.get("capture_assessment")
    if assessment:
        generated, valid = timestamp(assessment["generatedAt"]), timestamp(assessment["validUntil"])
        require(0 < (valid - generated).total_seconds() <= 300, "Invalid assessment freshness window")
        metrics = assessment["basis"]["metrics"]
        if "observedAt" in metrics:
            require(timestamp(metrics["observedAt"]) <= generated, "Assessment metrics come from the future")
            if metrics["state"] == "fresh":
                require((generated - timestamp(metrics["observedAt"])).total_seconds() <= 60, "Fresh assessment metrics are stale")
        actions = assessment["actions"]
        ids = [a["actionID"] for a in actions]
        require(len(ids) == len(set(ids)), "Duplicate assessment action")
        levels = {"unknown": -1, "low": 0, "moderate": 1, "high": 2}
        combined = assessment["combinedImpact"]
        require(levels[combined["level"]] >= max(levels[a["impact"]["level"]] for a in actions), "Combined assessment hides known impact")
        require(set(combined["effects"]) >= {e for a in actions for e in a["impact"]["effects"]}, "Combined assessment hides an effect")
        if metrics["state"] != "fresh" or any(a["impact"]["hasUnknowns"] for a in actions) or any(i["kind"] == "combinedCostUnknown" for i in assessment["interactions"]):
            require(combined["hasUnknowns"], "Assessment hides uncertainty")
        for item in [*assessment["interactions"], *assessment["alternatives"]]:
            require(set(item["actionIDs"]) <= set(ids), "Assessment refers to a foreign action")
        ongoing = any(a["executionMode"] == "ongoing" for a in actions)
        require(ongoing or assessment["scope"]["observationPods"] == 0, "On-trigger assessment invents ongoing scope")
        for action in actions:
            retention = action["retention"]
            require(retention["accessAgeSeconds"] + retention["deletionBudgetSeconds"] <= retention["maximumAgeSeconds"], "Deletion budget added outside retention maximum")
            require(retention["accessAgeSeconds"] <= retention["deleteAgeSeconds"] <= min(retention["maximumAgeSeconds"], retention["accessAgeSeconds"] + retention["deletionBudgetSeconds"]), "Invalid effective deletion age")
            exposure = action["data"]
            require(not (set(exposure["retainedPossible"]) & set(exposure["transientOnly"])), "Data labeled both retained and transient-only")
        for quantity in [q for a in actions for q in a["quantities"]] + assessment["combinedQuantities"]:
            require(quantity["lower"] <= quantity["upper"], "Reversed impact quantity range")
            if "measuredAt" in quantity:
                require(timestamp(quantity["measuredAt"]) <= generated, "Impact measurement comes from the future")
        if "execution_digest" in data:
            require(assessment["planDigest"] == data["execution_digest"], "Assessment bound to another plan")
            require(valid <= timestamp(data["expires_at"]), "Assessment outlives preview")
            lifecycle = {a["actionID"]: a for a in data["lifecycle_plan"]["actions"]}
            require(set(ids) == set(lifecycle), "Assessment omits plan actions")
            require(all(a["executionMode"] == lifecycle[a["actionID"]]["executionMode"] for a in actions), "Assessment changes action lifecycle")
            require(assessment["scope"]["incidentPods"] == data["pod_count"], "Assessment changes incident fanout")
            if any(i["blocking"] for i in assessment["interactions"]):
                require(bool(data["blockers"]) and not data["capture_enabled"], "Blocking assessment conflict can still capture")
    notices = [doc] if "deletionState" in doc and "deleteBy" in doc else []
    for artifact in data.get("artifacts", []):
        notice = artifact["handling_notice"]
        require(notice["expiresAt"] == artifact["expires_at"], "Artifact notice expiry disagrees")
        notices.append(notice)
    for notice in notices:
        cutoff, deadline, asof = (timestamp(notice[k]) for k in ("expiresAt", "deleteBy", "asOf"))
        require(cutoff <= deadline, "Notice deletion precedes access cutoff")
        require((notice["deletionState"] == "restrictedPreservation") == notice["preservationException"], "Preservation notice mismatch")
        if notice["deletionState"] == "overdue":
            require(asof > deadline, "Deletion is not overdue yet")
        if asof > deadline:
            require(notice["deletionState"] in {"verified", "overdue", "unknown", "restrictedPreservation"}, "Notice hides overdue deletion")


def action_execution_mode(action):
    registry = read(ROOT / "specs/contracts/action.schema.json")["x-execution-modes"]
    return action.get("executionMode", registry[action["kind"]]["default"])


def action_lifecycle_plan_fixture(recipe, request_kind):
    """Resolved timing projection for synthetic recipes, not a source/session scheduler."""
    records = []
    for action in recipe["actions"]:
        mode = action_execution_mode(action)
        item = {"actionID": action["id"], "kind": action["kind"], "executionMode": mode}
        if mode == "ongoing":
            item.update({"activation": "policyArming" if request_kind == "DebugPolicy" else "manualSession",
                         "requestedBefore": action["parameters"]["before"], "after": action["parameters"]["after"]})
        elif action["kind"] in {"packetCapture", "syscallTrace"}:
            item.update({"requestedBefore": action["parameters"]["before"], "after": action["parameters"]["after"]})
        records.append(item)
    scope = ("allAuthorizedWithinObservationLimits" if request_kind == "DebugPolicy" else "acceptedCapturePods") if any(a["executionMode"] == "ongoing" for a in records) else "none"
    return {"schemaVersion": "action-lifecycle/v1", "requestKind": request_kind, "actions": records, "ongoingPodScope": scope}


def capture_profile_definition_digest(profile):
    spec = profile["spec"]
    return canonical_digest({k: spec[k] for k in ("name", "version", "definition")})


def compile_composition_fixture(composition, catalog):
    """Finite contract fixture expansion; no Kubernetes resolver, authorizer or runtime scheduler."""
    registry = read(ROOT / "specs/contracts/capture-composition.schema.json")["x-field-bindings"]
    ids = [c["id"] for c in composition["components"]]
    require(len(ids) == len(set(ids)), "Duplicate composition component ID")
    actions, bindings, aliases, resolved = [], [], [], []
    dedup, generated_ids = {}, set()
    def identifier(prefix, component_id, local_id):
        return prefix + __import__("hashlib").sha256((component_id + "\0" + local_id).encode()).hexdigest()[:24]
    for component in composition["components"]:
        reference = component["profileRef"]
        key = tuple(reference[k] for k in ("catalog", "name", "version"))
        require(key in catalog, "Unknown pinned capture profile")
        profile = catalog[key]
        require(profile["spec"]["availability"]["enabled"], "Capture profile is disabled")
        semantic_checks(profile)
        definition = profile["spec"]["definition"]
        recipe = copy.deepcopy(definition["recipe"])
        local = {a["id"]: a for a in recipe["actions"]}
        editable = {(e["actionID"], e["field"]) for e in definition["editableFields"]}
        seen = set()
        for override in component.get("overrides", []):
            pair = (override["actionID"], override["field"])
            require(pair not in seen, "Duplicate profile override")
            seen.add(pair)
            require(pair in editable, "Unexposed profile field")
            binding = registry[override["field"]]
            action = local[override["actionID"]]
            require(action["kind"] in binding["actionKinds"], "Override/action kind mismatch")
            destination = action
            for key in binding["path"][:-1]:
                destination = destination[key]
            destination[binding["path"][-1]] = copy.deepcopy(override["value"])
        action_ids = {name: identifier("a", component["id"], name) for name in local}
        endpoint_ids = {b["name"]: identifier("e", component["id"], b["name"]) for b in recipe.get("endpointBindings", [])}
        for name in [*action_ids.values(), *endpoint_ids.values()]:
            require(name not in generated_ids, "Generated composition ID collision")
            generated_ids.add(name)
        replacement = {}
        for action in recipe["actions"]:
            action["executionMode"] = action_execution_mode(action)
            local_id = action["id"]
            generated = action_ids[local_id]
            action["id"] = generated
            action["dependsOn"] = [action_ids[d] for d in action.get("dependsOn", [])]
            if not action["dependsOn"]:
                action.pop("dependsOn")
            params = action["parameters"]
            if action["kind"] == "httpDiagnostic" and params["endpointRef"] in endpoint_ids:
                params["endpointRef"] = endpoint_ids[params["endpointRef"]]
            if action["kind"] == "profile" and params["source"]["kind"] == "httpEndpoint" and params["source"]["profileRef"] in endpoint_ids:
                params["source"]["profileRef"] = endpoint_ids[params["source"]["profileRef"]]
            signature_input = copy.deepcopy({k: v for k, v in action.items() if k not in {"id", "required"}})
            signature_params = signature_input["parameters"]
            for binding in recipe.get("endpointBindings", []):
                bound = {k: v for k, v in binding.items() if k != "name"}
                if action["kind"] == "profile" and signature_params["source"].get("profileRef") == endpoint_ids[binding["name"]]:
                    signature_params["source"]["profileRef"] = bound
                if action["kind"] == "httpDiagnostic" and signature_params.get("endpointRef") == endpoint_ids[binding["name"]]:
                    signature_params["endpointRef"] = bound
            if action["kind"] in {"liveCore", "kernelCore", "command", "profile", "packetCapture", "syscallTrace"}:
                signature_input.pop("dependsOn", None)
            signature = canonical_digest(signature_input)
            mergeable = action["kind"] in {"kubernetesSnapshot", "processSnapshot", "networkSnapshot"} and not action.get("dependsOn")
            deduplicated = mergeable and signature in dedup
            if deduplicated:
                previous = dedup[signature]
                previous["required"] = previous["required"] or action["required"]
                replacement[generated] = previous["id"]
                generated = previous["id"]
            else:
                require(not (action["kind"] in {"liveCore", "kernelCore", "command", "profile", "packetCapture", "syscallTrace"} and signature in dedup), "Duplicate expensive acquisition")
                dedup[signature] = action
                actions.append(action)
            aliases.append({"componentID": component["id"], "localActionID": local_id, "actionID": generated, "deduplicated": deduplicated})
        # Internal dependencies on deduplicated aliases resolve to the one acquisition.
        for action in actions:
            if "dependsOn" in action:
                action["dependsOn"] = [replacement.get(d, d) for d in action["dependsOn"]]
        for binding in recipe.get("endpointBindings", []):
            binding["name"] = endpoint_ids[binding["name"]]
            bindings.append(binding)
        resolved.append({"componentID": component["id"], "profileRef": reference,
                         "sourceUID": profile["metadata"].get("uid", "fixture-" + profile["metadata"]["name"]),
                         "sourceClusterID": "00000000-0000-4000-8000-000000000001" if reference["catalog"] == "namespace" else "00000000-0000-4000-8000-000000000010",
                         "sourceNamespaceUID": "fixture-namespace-" + profile["metadata"]["namespace"],
                         "definitionDigest": capture_profile_definition_digest(profile)})
    require(len(actions) <= 16 and len(bindings) <= 16, "Expanded composition exceeds recipe cardinality")
    recipe = {"description": "Expanded capture profile composition fixture.", "actions": actions,
              "maxTotalBytes": composition["maxTotalBytes"], "maxDuration": composition["maxDuration"]}
    if bindings:
        recipe["endpointBindings"] = bindings
    semantic_checks({"kind": "EvidenceRecipe", "spec": recipe})
    provenance = {"authored": composition, "resolvedProfiles": resolved, "actionMap": aliases}
    return recipe, provenance


def recording_save_checks(doc: dict) -> None:
    """Offline shape/fixture constraints; does not prove live source authority or leases."""
    if doc.get("schemaVersion") == "recording-save/v1":
        sources = doc["sources"]
        ids = [r["sourceSessionID"] for r in sources]
        require(ids == sorted(set(ids)), "Recording sources must be unique and sorted")
        pairs = [(r["podUID"], r["actionID"]) for r in sources]
        require(len(set(pairs)) == len(pairs), "Two source epochs selected for one pod action")
        require(len({r["podUID"] for r in sources}) <= doc["incidentPodLimit"], "Save exceeds policy incident pod cap")
        require({p["role"] for p in doc["dependencies"]} == {"collectionCeiling", "retention"}, "Save lacks independent ceiling/retention pins")
        require(duration_seconds(doc["finalizeTimeout"]) <= 300, "Unbounded save finalization")
        for source in sources:
            require(duration_seconds(source["before"]) > 0, "Recording save has no history window")
    data = doc.get("data", doc)
    if not isinstance(data, dict):
        return
    if data.get("kind") in {"recordingPage", "recordingSavePreview"}:
        rows = data.get("recordings", data.get("selected_recordings", []))
        handles = [r["recording_handle"] for r in rows]
        require(len(handles) == len(set(handles)), "Duplicate recording handle")
        for row in rows:
            require(0 < (timestamp(row["handle_expires_at"]) - timestamp(row["observed_at"])).total_seconds() <= 60, "Recording handle exceeds freshness bound")
            require(not row["save_eligible"] or not row["blockers"], "Blocked recording advertised as savable")
            require(not row["save_eligible"] or duration_seconds(row["maximum_before"]) > 0, "Zero-history recorder advertised as savable")
    if data.get("kind") == "recordingSavePreview":
        rows = data["selected_recordings"]
        require(len({r["policy_uid"] for r in rows}) == 1, "Save mixes policies")
        windows = data["windows"]
        require(len(windows) == len(rows) and {w["recording_handle"] for w in windows} == {r["recording_handle"] for r in rows}, "Save window/selection mismatch")
        bounds = {r["recording_handle"]: duration_seconds(r["maximum_before"]) for r in rows}
        require(all(duration_seconds(w["before"]) <= bounds[w["recording_handle"]] for w in windows), "Save widens configured history")
        require(not any(not r["save_eligible"] for r in rows) or data["blockers"], "Save hides source blockers")
        a = data["capture_assessment"]
        require(a["planDigest"] == data["save_scope_digest"], "Save assessment scope mismatch")
        require(a["validUntil"] == data["expires_at"], "Save assessment expiry mismatch")
        require(0 < (timestamp(data["expires_at"]) - timestamp(a["generatedAt"])).total_seconds() <= 60, "Save preview exceeds freshness bound")
        require(all(timestamp(data["expires_at"]) <= timestamp(r["handle_expires_at"]) for r in rows), "Save outlives source handles")
        require({a_["actionID"] for a_ in a["actions"]} == {r["action_id"] for r in rows}, "Save assessment includes unselected actions")
        require(all(a_["executionMode"] == "ongoing" for a_ in a["actions"]), "Save assessment starts on-trigger work")
        pods = len({r["pod_uid"] for r in rows})
        require(a["scope"]["incidentPods"] == pods and a["scope"]["observationPods"] == pods, "Save assessment pod count mismatch")
    if data.get("kind") == "recordingSaveSettings":
        require(timestamp(data["accepted_at"]) < timestamp(data["expires_at"]), "Invalid saved-recording settings lifetime")
        require(canonical_digest(data["settings"]) == data["settings_digest"], "Recording-save settings digest mismatch")
        windows = data["settings"]["action_windows"]
        require(len({w["actionID"] for w in windows}) == len(windows), "Duplicate saved action preference")
        require(data["settings"]["policy"]["clusterID"] == data["cluster_id"] and data["settings"]["policy"]["namespaceUID"] == data["namespace_uid"], "Recording settings cross scope")


def pod_status_preview_checks(doc):
    """Synthetic contract checks, never target observation or runtime authority."""
    data = doc.get("data") if isinstance(doc.get("data"), dict) else {}
    if data.get("preset_ref") != {"name": "pod-status", "version": "v1"}:
        return
    target, pods = data["target_ref"], data["selected_pods"]
    require(len(pods) == data["pod_count"] == 1, "Pod-status selection must contain exactly one pod")
    pod = pods[0]
    require((pod["cluster_id"], pod["namespace"]) == (target["cluster_id"], target["namespace"]), "Selected pod crosses requested scope")
    if target["kind"] == "Pod":
        require(pod["name"] == target["name"] and data["pod_selection"] == "explicitPod", "Explicit pod selection changed")
    else:
        require((pod["workload"]["kind"], pod["workload"]["name"]) == (target["kind"], target["name"]) and data["pod_selection"] == "lexicalEligiblePod", "Selected pod belongs to another named workload")
    if pod["workload"]["kind"] == "Pod":
        require((pod["workload"]["name"], pod["workload"]["uid"]) == (pod["name"], pod["uid"]), "Unowned pod has a different workload identity")
    assessment = data["capture_assessment"]
    require(all(a["retention"]["anchorRule"] == "submissionPreparation" for a in assessment["actions"]), "Pod-status retention must include waiting after submission")
    require((timestamp(assessment["validUntil"]) - timestamp(assessment["generatedAt"])).total_seconds() <= 5, "Pod-status assessment renewed observation freshness")
    require(not data["capture_enabled"] or not data["blockers"], "Blocked pod-status preview enables collection")
    require(len(json.dumps(doc, separators=(",", ":")).encode()) <= 32768, "Pod-status preview exceeds hard structured-result bound")


def semantic_checks(doc: dict) -> None:
    pod_status_preview_checks(doc)
    recording_save_checks(doc)
    capture_assessment_checks(doc)
    if isinstance(doc.get("data"), dict):
        guidance_checks(doc["data"])
        capture_history_checks(doc["data"])
    kind, spec = doc.get("kind"), doc.get("spec", {})
    if doc.get("schemaVersion") == "artifact/v1" and kind in {"liveCore", "kernelCore"}:
        require(doc["privacy"]["evidenceType"] == "coreDump", "Known core mislabeled for privacy retention")

    if doc.get("schemaVersion") == "collection-scope/v1":
        if doc["collection"]["kind"] == "DebugPolicy":
            authority = doc["policyAuthority"]
            require(doc["executor"] == {"issuer": "urn:asservat:installation:" + authority["installationID"], "subject": "policy:" + doc["source"]["resourceUID"], "clientID": "policy-executor", "identityType": "workload"}, "Policy executor is not installation/policy bound")
            require(0 < (timestamp(authority["notAfter"]) - timestamp(authority["issuedAt"])).total_seconds() <= 31536000, "Invalid finite policy authority")
            owners = authority["ownerAssignments"]
            require(len({o["assignmentID"] for o in owners}) == len(owners), "Duplicate automation owner assignment")
            require(all(o["basisUID"] == authority["delegation"]["uid"] for o in owners), "Automation owner does not match delegation")
        require(len({canonical_digest(p) for p in doc["dependencies"]}) == len(doc["dependencies"]), "Duplicate execution dependency pin")
        effective = doc.get("effectiveRetention", [])
        action_ids = [r["actionID"] for r in effective]
        require(action_ids == sorted(set(action_ids)), "Effective retention actions must be unique and sorted")
        retention_digests = {p["digest"] for p in doc["dependencies"] if p["role"] == "retention"}
        for retention in effective:
            require(retention["deletionBudgetSeconds"] < retention["maximumAgeSeconds"], "Effective retention leaves no usable time")
            refs = retention["policyRefs"]
            uids = [p["uid"] for p in refs]
            require(uids == sorted(set(uids)), "Effective retention policy identities must be unique and sorted")
            require(all(p["digest"] in retention_digests for p in refs), "Effective retention lacks policy dependency")
        if doc["collection"]["spec"]["recipeRef"]["name"] == "builtin-pod-status-v1":
            require(len(effective) == 1 and effective[0]["actionID"] == "pod-status", "Implemented context scope lacks exact effective retention")
            require(effective[0]["privacyClass"] == "potentialPersonalData" and effective[0]["evidenceType"] == "context", "Context compiler privacy classification drift")
            require("retention" in doc["collection"]["spec"] and duration_seconds(doc["collection"]["spec"]["retention"]) == effective[0]["requestedAgeSeconds"], "Requested and resolved retention disagree")
            require({p["role"] for p in doc["dependencies"]} == {"collector", "projection", "recipe", "collectionCeiling", "retention"}, "Context compiler lacks mechanism or policy pins")
        if doc["collection"]["kind"] == "DebugCapture":
            bindings = doc["podBindings"]
            pod_ids = [p["podUID"] for p in bindings]
            require(pod_ids == sorted(set(pod_ids)), "Manual pod bindings must be unique and sorted")
            require(len(bindings) <= doc["collection"]["spec"]["target"]["maxPods"], "Manual pod set exceeds incident bound")
        pins = [p for p in doc["dependencies"] if p["role"] == "captureProfile"]
        provenance = doc.get("profileComposition")
        require(bool(pins) == bool(provenance), "Composition source pins/provenance mismatch")
        if provenance:
            expected = [{"role": "captureProfile", "digest": p["definitionDigest"], "source": {"clusterID": p["sourceClusterID"], "namespaceUID": p["sourceNamespaceUID"], "resourceUID": p["sourceUID"]}} for p in provenance["resolvedProfiles"]]
            require(all(p in pins for p in expected) and all(p in expected for p in pins), "Composition dependency identity mismatch")
    lifecycle = doc if doc.get("schemaVersion") == "action-lifecycle/v1" else doc.get("data", {}).get("lifecycle_plan")
    if lifecycle:
        ids = [a["actionID"] for a in lifecycle["actions"]]
        require(len(ids) == len(set(ids)), "Duplicate lifecycle action")
        ongoing = [a for a in lifecycle["actions"] if a["executionMode"] == "ongoing"]
        require(bool(ongoing) == (lifecycle["ongoingPodScope"] != "none"), "Lifecycle observation scope mismatch")
        registry = read(ROOT / "specs/contracts/action.schema.json")["x-execution-modes"]
        for a in lifecycle["actions"]:
            require(a["executionMode"] in registry[a["kind"]]["allowed"], "Invalid action lifecycle category")
    acquisition = doc.get("actionLifecycle")
    if not acquisition and doc.get("executionMode") and "triggeredAt" in doc:
        acquisition = doc
    if acquisition and acquisition["executionMode"] == "ongoing":
        require(acquisition["triggerKind"] != "naturalCrash", "Ring save is not a kernel core acquisition")
        if acquisition["historyCoverage"] == "full":
            require(timestamp(acquisition["sourceStartedAt"]) <= timestamp(acquisition["triggeredAt"]) - timedelta(seconds=duration_seconds(acquisition["requestedBefore"])), "Unarmed source claims full history")
            if acquisition["gapReasons"]:
                require(acquisition["windowCoverage"] == "partial" and set(acquisition["gapReasons"]) <= {"targetGone", "sourceLost"} and "sourceStoppedAt" in acquisition and timestamp(acquisition["sourceStoppedAt"]) >= timestamp(acquisition["triggeredAt"]), "Full history has unexplained gaps")
        if "sourceStoppedAt" in acquisition:
            stopped = timestamp(acquisition["sourceStoppedAt"])
            require(stopped >= timestamp(acquisition["sourceStartedAt"]), "Source stopped before starting")
            if duration_seconds(acquisition["requestedBefore"]) and stopped < timestamp(acquisition["triggeredAt"]):
                require(acquisition["historyCoverage"] != "full", "Stopped source claims later full history")
            if stopped < timestamp(acquisition["triggeredAt"]) + timedelta(seconds=duration_seconds(acquisition["after"])):
                require(acquisition["windowCoverage"] != "full", "Stopped source claims full future window")
        if acquisition["windowCoverage"] == "full":
            require(not acquisition["gapReasons"], "Full window has explicit gaps")
            require(not duration_seconds(acquisition["requestedBefore"]) or acquisition["historyCoverage"] == "full", "Full window lacks requested history")
    if kind == "CaptureProfile":
        definition = spec["definition"]
        semantic_checks({"kind": "EvidenceRecipe", "spec": definition["recipe"]})
        actions = {a["id"]: a for a in definition["recipe"]["actions"]}
        registry = read(ROOT / "specs/contracts/capture-composition.schema.json")["x-field-bindings"]
        pairs = [(e["actionID"], e["field"]) for e in definition["editableFields"]]
        require(len(pairs) == len(set(pairs)), "Duplicate editable profile field")
        for action_id, field in pairs:
            require(action_id in actions, "Editable field references unknown action")
            require(actions[action_id]["kind"] in registry[field]["actionKinds"], "Editable field/action mismatch")
    if isinstance(doc.get("data"), dict) and doc["data"].get("kind") == "syscallSummary":
        for row in doc["data"]["rows"]:
            require(row["errors"] <= row["count"] and row["paired_count"] <= row["count"], "Invalid syscall summary counters")
    if kind in {"DebugCapture", "DebugPolicy"} and "sharing" in spec:
        selections = spec["sharing"].get("outputSelection", {}).get("outputs", [])
        keys = [(s["actionID"], s["dataClass"], canonical_digest(s.get("projectionRef"))) for s in selections]
        require(len(keys) == len(set(keys)), "Duplicate sharing selection")
        require(all(r["id"] != "*" for r in spec["sharing"]["recipients"]), "Wildcard sharing recipient")
    management = spec.get("management") or spec.get("sharing", {}).get("management")
    if management and management["mode"] == "teams":
        teams = management["teams"]
        subjects = [team.get("subject", team) for team in teams]
        identities = [(subject["issuer"], subject["id"]) for subject in subjects]
        require(len(identities) == len(set(identities)), "Duplicate managing team")
        require(all(subject["kind"] == "Group" and subject["id"] != "*" for subject in subjects), "Invalid managing team")
        if kind in {"SharingIntent", "EvidenceShare"}:
            assignment_ids = [a for team in teams for a in team["assignmentIDs"]]
            require(len(assignment_ids) == len(set(assignment_ids)), "Manager assignment reused across teams")
    if kind == "SharingIntent":
        state = doc["status"]
        selections = {s["id"]: s for s in spec["resolvedSelections"]}
        approvals = {a["selectionID"]: a for a in state["selectionApprovals"]}
        require(len(selections) == len(spec["resolvedSelections"]), "Duplicate resolved selection")
        require(len(approvals) == len(state["selectionApprovals"]) and set(approvals) == set(selections), "Approval selection mismatch")
        require(0 < (timestamp(spec["notAfter"]) - timestamp(spec["acceptedAt"])).total_seconds() <= 7 * 86400, "Invalid sharing lifetime")
        require(state["registeredCaptures"] <= spec["maxCaptures"], "Sharing capture budget exceeded")
        require(state["materializedArtifacts"] <= state["registeredCaptures"] * spec["maxArtifactsPerCapture"], "Sharing artifact budget exceeded")
        for key, approval in approvals.items():
            if approval["phase"] == "Approved":
                require(timestamp(spec["acceptedAt"]) <= timestamp(approval["approvedAt"]) < timestamp(spec["notAfter"]), "Approval outside intent lifetime")
                approver = approval["approvedBy"]
                if selections[key]["independentApprovalRequired"]:
                    require(approver["identityType"] == "human", "Sharing reviewer must be human")
                    require((approver["issuer"], approver["subject"]) != (spec["createdBy"]["issuer"], spec["createdBy"]["subject"]), "Sharing self approval")
                elif spec["management"]["mode"] == "creator":
                    require(approver == spec["createdBy"], "Personal selection lost creator approval provenance")
                # Team approver authority is verified by the live evaluator, not a static fixture.
    if kind == "EvidenceRecipe":
        actions = spec["actions"]
        bindings = spec.get("endpointBindings", [])
        require(len({item["name"] for item in bindings}) == len(bindings), "Duplicate endpoint binding name")
        ids = [a["id"] for a in actions]
        require(len(ids) == len(set(ids)), "Duplicate action ID")
        require(sum(a["limits"]["maxBytes"] for a in actions) <= spec["maxTotalBytes"], "Recipe sum exceeds total budget")
        edges = {a["id"]: a.get("dependsOn", []) for a in actions}

        def visit(node, stack):
            require(node in edges, f"Missing action dependency: {node}")
            require(node not in stack, "Action dependency cycle")
            for parent in edges[node]:
                visit(parent, stack | {node})

        for a in actions:
            visit(a["id"], set())
            mode = action_execution_mode(a)
            if mode == "ongoing":
                require(a["kind"] in {"packetCapture", "syscallTrace"}, "Unsupported ongoing action")
                require(not a.get("dependsOn"), "Ongoing source cannot wait on incident actions")
            elif a["kind"] in {"packetCapture", "syscallTrace"}:
                require(duration_seconds(a["parameters"]["before"]) == 0, "On-trigger recorder claims prehistory")

            if a["kind"] == "packetCapture":
                params = a["parameters"]
                ring, profile, peers = params["ring"], params["profile"], params["peers"]
                require(len(params.get("filter", "").encode("utf-8")) <= 4096, "Packet filter exceeds UTF-8 byte cap")
                seconds = duration_seconds
                require(ring["segmentBytes"] * ring["maxSegments"] <= ring["maxBytes"], "Ring segment allocation exceeds bytes")
                require(seconds(params["before"]) <= seconds(ring["maxAge"]) <= 3600, "Invalid ring history bound")
                require(seconds(peers["maxStaleness"]) <= 5, "Peer freshness exceeds ceiling")
                require(ring["segmentBytes"] <= params["maxFrozenBytes"] <= a["limits"]["maxBytes"], "Invalid frozen output reservation")
                require(seconds(params["before"]) + seconds(params["after"]) > 0, "Empty packet window")
                require(seconds(params["after"]) < seconds(a["limits"]["timeout"]), "Packet action lacks completion margin")
                for entry in peers["entries"]:
                    if "cidrs" in entry:
                        import ipaddress
                        for cidr in entry["cidrs"]:
                            ipaddress.ip_network(cidr, strict=False)
                require(peers["protocol"] != "icmp" or "ports" not in peers, "ICMP cannot select ports")
                if profile["kind"] in {"httpHeaders", "rawPackets"}:
                    require(a["impact"] in {"sensitiveRead", "intrusive"}, "Sensitive packet acquisition mislabeled")
                if profile["kind"] == "httpHeaders":
                    require(peers["protocol"] == "tcp", "HTTP/1 requires TCP peers")
                    require(profile["maxHeaderBytes"] <= profile["maxReassemblyBytesPerFlow"] <= profile["maxReassemblyBytes"], "HTTP parser memory cannot contain header/flow")
                    require(seconds(profile["idleTimeout"]) <= 30, "HTTP idle state exceeds bound")
                if profile["kind"] == "rawPackets":
                    protocols = [rule["protocol"] for rule in profile.get("protocolSnaplen", [])]
                    require(len(protocols) == len(set(protocols)), "Ambiguous raw protocol snaplen rules")
            if a["kind"] == "syscallTrace":
                params = a["parameters"]
                ring = params["ring"]
                require(ring["segmentBytes"] * ring["maxSegments"] <= ring["maxBytes"], "Syscall ring exceeds allocation")
                require(duration_seconds(params["before"]) <= duration_seconds(ring["maxAge"]) <= 3600, "Invalid syscall ring history")
                require(duration_seconds(params["before"]) + duration_seconds(params["after"]) > 0, "Empty syscall interval")
                require(duration_seconds(params["after"]) <= 60 and duration_seconds(params["after"]) < duration_seconds(a["limits"]["timeout"]), "Invalid syscall completion deadline")
                require(ring["segmentBytes"] <= params["maxFrozenBytes"] <= a["limits"]["maxBytes"], "Invalid syscall frozen reservation")
                if params["mode"] == "arguments":
                    require(a["impact"] in {"sensitiveRead", "intrusive"}, "Syscall arguments mislabeled as observe")
            require(duration_seconds(a["limits"]["timeout"]) <= duration_seconds(spec["maxDuration"]), "Action exceeds recipe deadline")
            if a["kind"] == "liveCore" and "batch" in a["parameters"]:
                batch = a["parameters"]["batch"]
                require(batch["maxProcesses"] * batch["maxBytesPerProcess"] <= a["limits"]["maxBytes"], "Process batch exceeds action bytes")
                require(duration_seconds(batch["maxStopPerProcess"]) <= duration_seconds(batch["maxTotalStop"]) < duration_seconds(a["limits"]["timeout"]), "Invalid batch stop/deadline budget")
                selector = a["parameters"].get("processSelector")
                if selector:
                    require(selector["includeDescendants"] or selector["maxDepth"] == 0, "Descendant depth without descendants")
            if a["kind"] == "logs":
                require(duration_seconds(a["parameters"]["before"]) + duration_seconds(a["parameters"]["after"]) > 0, "Empty log window")
                require(duration_seconds(a["parameters"]["after"]) < duration_seconds(a["limits"]["timeout"]), "Log window lacks completion margin")
            if a["kind"] == "profile" and "duration" in a["parameters"]:
                require(duration_seconds(a["parameters"]["duration"]) < duration_seconds(a["limits"]["timeout"]), "Profile lacks setup/shutdown margin")
            if a["kind"] == "command":
                require(a["parameters"]["argv"][0].startswith("/"), "Command executable must be absolute")
                require(a["impact"] == "intrusive", "Custom command must be intrusive")
            if a["kind"] in {"liveCore", "runtimeDiagnostic", "profile"}:
                require(a["impact"] == "intrusive", "Diagnostic action needs impact classification")
    if kind in {"DebugPolicy", "DebugCapture"} and "presetRef" not in spec:
        require(spec["target"]["namespace"] == doc["metadata"]["namespace"], "Cross-namespace request target")
        if kind == "DebugCapture":
            require(spec["target"]["selection"] != "triggeringPod", "Manual capture has no trigger pod")
    if kind == "DebugPolicy" and "presetRef" not in spec:
        require(spec["target"].get("workloadRef", {}).get("kind") != "Pod", "Direct Pod is ad hoc only")
        for detector in spec["detectors"]:
            options = detector["options"]
            if "eventWindow" in detector:
                require(duration_seconds(detector["eventWindow"]) <= 300, "Event window exceeds correlation bound")
            for key in ("sampleInterval", "pollInterval"):
                if key in options:
                    require(duration_seconds(options[key]) >= 1, "Detector interval below minimum")
            if "window" in options:
                require(duration_seconds(options["window"]) <= 300, "Detector window exceeds bound")
        if "evaluation" in spec:
            require(duration_seconds(spec["evaluation"]["rearmFor"]) <= 300, "Rearm exceeds bound")
        ids = [d["id"] for d in spec["detectors"]]
        require(len(ids) == len(set(ids)), "Duplicate detector ID")
        require(spec["target"]["namespace"] == doc["metadata"]["namespace"], "Cross-namespace policy target")

        def expression(value, depth=0):
            require(depth <= 8, "Expression too deep")
            if "detector" in value:
                require(value["detector"] in ids, "Unknown expression detector")
            for key in ("all", "any"):
                for child in value.get(key, []):
                    expression(child, depth + 1)
            if "not" in value:
                expression(value["not"], depth + 1)
            if "for" in value:
                require(duration_seconds(value["for"]["duration"]) <= 300, "Hold exceeds correlation bound")
                expression(value["for"]["expression"], depth + 1)
            if "count" in value:
                require(duration_seconds(value["count"]["within"]) <= 300, "Count window exceeds bound")
                require(value["count"]["detector"] in ids, "Unknown count detector")
            if "sequence" in value:
                require(duration_seconds(value["sequence"]["within"]) <= 300, "Sequence window exceeds bound")
                require(all(x in ids for x in value["sequence"]["detectors"]), "Unknown sequence detector")

        expression(spec["when"])
    if kind == "AccessGrant":
        require(spec["target"]["kind"] == {"rawQuery": "artifact", "policy": "policy", "adHocCapture": "capture"}[spec["grantType"]], "Grant target shape mismatch")
        if spec["grantType"] == "policy":
            authority = spec["policyAuthority"]
            require(spec["policyExecutor"] == {"issuer": "urn:asservat:installation:" + authority["installationID"], "subject": "policy:" + spec["target"]["policyUID"], "clientID": "policy-executor", "identityType": "workload"}, "Grant executor is not policy-bound")
            require(timestamp(authority["issuedAt"]) <= timestamp(spec["issuedAt"]) < timestamp(spec["notAfter"]) <= timestamp(authority["notAfter"]), "Grant outlives team authority")
            require(all(spec["limits"][key] <= authority["limits"][key] for key in ("maxExecutions", "maxBytes")), "Grant widens team limits")
        age = (timestamp(spec["notAfter"]) - timestamp(spec["issuedAt"])).total_seconds()
        maximum = spec["approvalPolicyRef"]["maxAgeSeconds"] if spec["grantType"] == "policy" else (28800 if spec["grantType"] == "rawQuery" else 3600)
        require(0 < age <= maximum, "Grant exceeds approval lifetime")
        if "resultAccess" in spec:
            result = spec["resultAccess"]
            require(timestamp(spec["issuedAt"]) < timestamp(result["notAfter"]) <= timestamp(spec["notAfter"]), "Result access exceeds parent lifetime")
            counters = doc["status"]["resultAccessCounters"]
            require(counters["artifactsRegistered"] <= result["maxArtifacts"], "Result artifact count exceeded")
            require(counters["bytesReserved"] + counters["bytesSpent"] <= result["maxBytes"], "Result byte pool exceeded")
            require(counters["operationsReserved"] + counters["operationsSpent"] <= result["maxOperations"], "Result operation pool exceeded")
        if "observationLimits" in spec:
            require(doc["status"].get("observedBytesReserved", 0) + doc["status"].get("observedBytesSpent", 0) <= spec["observationLimits"]["maxObservedBytes"], "Observation grant exceeded")
        else:
            require(not any(k in doc["status"] for k in ("observedBytesReserved", "observedBytesSpent")), "Observation counters without limits")
        if "maxObservedEvents" in spec.get("observationLimits", {}):
            require(doc["status"].get("observedEventsReserved", 0) + doc["status"].get("observedEventsSpent", 0) <= spec["observationLimits"]["maxObservedEvents"], "Observation event grant exceeded")
        else:
            require(not any(k in doc["status"] for k in ("observedEventsReserved", "observedEventsSpent")), "Event counters without observation limit")
        if doc.get("status", {}).get("phase") == "Approved":
            require("approver" in spec, "Approved grant lacks approver")
            approver, requester = spec["approver"], spec["requester"]
            require(approver["identityType"] == "human", "Approver must be human")
            require((approver["issuer"], approver["subject"]) != (requester["issuer"], requester["subject"]), "Self approval")
        state = doc.get("status", {})
        require(state.get("reservedBytes", 0) + state.get("spentBytes", 0) <= spec["limits"]["maxBytes"], "Grant byte budget exceeded")
        require(state.get("executionsReserved", 0) + state.get("executionsSpent", 0) <= spec["limits"]["maxExecutions"], "Grant execution budget exceeded")
    if doc.get("schemaVersion") == "approval-policy/v1":
        limits = doc["policyGrants"]
        require(limits["defaultAgeSeconds"] <= limits["maxAgeSeconds"], "Approval default exceeds maximum")
        require(limits["renewalNoticeSeconds"] < limits["defaultAgeSeconds"], "Renewal notice exceeds default lifetime")
    if kind == "EvidenceShare":
        require(not spec["includeFutureArtifacts"] and not spec["allowReshare"], "Share broadens future/delegation scope")
        raw_ops = {"read_memory", "debugger_command", "pcap_query", "syscall_query", "download_artifact"}
        require(not raw_ops.intersection(spec["operations"]) or "raw" in spec["dataClasses"], "Raw operation in extract-only share")
        if "raw" in spec["dataClasses"] and doc.get("status", {}).get("phase") == "Active":
            approver = doc["status"].get("approvedBy")
            require(bool(approver), "Active raw share lacks independent approval")
            require(approver["identityType"] == "human", "Raw share approver must be human")
            require(bool(doc["status"].get("approvedAt")), "Raw share approval timestamp missing")
            require((approver["issuer"], approver["subject"]) != (spec["createdBy"]["issuer"], spec["createdBy"]["subject"]), "Raw share self approval")
    if kind == "AccessBinding":
        require(all(subject["id"] != "*" for subject in spec["subjects"]), "Wildcard permission subject")
    if kind == "PermissionSource":
        mapping = spec.get("metadataMapping", {})
        if mapping.get("mode") == "valueMap":
            require(all(group != "*" for groups in mapping["values"].values() for group in groups), "Wildcard mapped group")
    if kind == "EvidenceStoragePool":
        for dimension in ("bytes", "objects"):
            protected = sum(item["workloadSlots"] * item["protectedPerWorkload"][dimension] for item in spec["protectedAllocations"])
            fixed = sum(spec[field][dimension] for field in ("safetyHeadroom", "systemReserve", "sharedBurst"))
            require(protected + fixed <= spec["capacity"][dimension], "Storage pool overcommits " + dimension)
        names = [item["budgetPolicyRef"] for item in spec["protectedAllocations"]]
        require(len(names) == len(set(names)), "Duplicate budget profile allocation")
    if kind == "EvidenceBudgetPolicy":
        workload = spec["workload"]
        for dimension in ("bytes", "objects"):
            require(0 < workload["contextReserve"][dimension] < workload["protected"][dimension] <= workload["hardLimit"][dimension], "Invalid workload protected/context/hard capacity")
        require(workload["maxConcurrentExpensive"] <= spec["node"]["maxConcurrentExpensive"], "Workload concurrency exceeds node ceiling")
        require(workload["maxSpoolBytes"] <= spec["node"]["maxSpoolBytes"], "Workload spool exceeds node capacity")
        require(workload["dump"]["burst"] <= workload["dump"]["maxStartsPerRollingHour"], "Dump burst exceeds hourly start budget")
        envelope = spec["namespaceEnvelope"]
        require(envelope["maxWorkloadAccounts"] * workload["protected"]["bytes"] <= envelope["maxStoredBytes"], "Namespace cannot back protected bytes")
        require(envelope["maxWorkloadAccounts"] * workload["protected"]["objects"] <= envelope["maxObjects"], "Namespace cannot back protected object slots")
    if kind == "EvidenceRetentionPolicy":
        budget = spec["deletionBudgetSeconds"]
        require(all(age > budget for age in spec["maxima"].values()), "Retention maximum leaves no deletion budget")
        require(all(0 < age <= spec["maxima"][key] for key, age in spec["defaults"].items()), "Retention default exceeds maximum")
        require(all(rule["maxAgeSeconds"] > budget for rule in spec["rules"]), "Rule leaves no usable retention interval")
        names = [rule["name"] for rule in spec["rules"]]
        require(len(names) == len(set(names)), "Duplicate retention rule name")
    if doc.get("schemaVersion") == "artifact/v1":
        if doc["encryption"]["format"] == "asservat-framed/v1":
            framed_storage_checks(doc)
        retention = doc["retention"]
        anchor = timestamp(retention["anchorAt"])
        cutoff = timestamp(doc["expiresAt"])
        delete_by = timestamp(retention["deleteBy"])
        hard_limit = anchor + timedelta(seconds=retention["resolvedMaxAgeSeconds"])
        budget = timedelta(seconds=retention["deletionBudgetSeconds"])
        require(anchor <= timestamp(doc["startedAt"]) <= timestamp(doc["completedAt"]) < cutoff, "Invalid collection/retention chronology")
        require(cutoff <= hard_limit - budget, "Access consumes deletion budget")
        require(cutoff <= anchor + timedelta(seconds=retention["requestedAgeSeconds"]), "Retention restarts after acquisition")
        require(cutoff <= delete_by <= min(hard_limit, cutoff + budget), "Deletion deadline exceeds maximum")
        if doc["provenance"]["parentArtifacts"]:
            require(retention["anchorBasis"] == "parent", "Derived evidence loses parent anchor")
            require("parentExpiresAt" in retention and "parentDeleteBy" in retention, "Derived evidence lacks inherited deadlines")
            require(cutoff <= timestamp(retention["parentExpiresAt"]) and delete_by <= timestamp(retention["parentDeleteBy"]), "Derivative outlives parent")


def main() -> None:
    # jsonschema intentionally accepts unknown/uninstalled format checkers.
    # A fresh validation environment must not silently skip URI/time checks.
    checker = FormatChecker()
    for name in ("date-time", "ipv4", "ipv6", "uri", "uuid"):
        require(name in checker.checkers,
                f"Missing {name} format validator; install requirements-spec.txt in the validation environment")
    schemas = {}
    for path in sorted((ROOT / "specs/contracts").glob("*.schema.json")):
        schema = read(path)
        Draft202012Validator.check_schema(schema)
        require(schema["$id"] not in schemas, "Duplicate schema ID")
        schemas[schema["$id"]] = schema
    registry = Registry().with_resources((key, Resource.from_contents(value)) for key, value in schemas.items())

    def check_refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                document, _, fragment = value["$ref"].partition("#")
                require(document in schemas, f"Unregistered schema reference: {value['$ref']}")
                pointed = schemas[document]
                for part in fragment.strip("/").split("/") if fragment else []:
                    token = part.replace("~1", "/").replace("~0", "~")
                    if isinstance(pointed, list):
                        require(re.fullmatch(r"0|[1-9][0-9]*", token) is not None,
                                f"Invalid array index in schema reference: {value['$ref']}")
                        pointed = pointed[int(token)]
                    else:
                        pointed = pointed[token]
            for child in value.values():
                check_refs(child)
        elif isinstance(value, list):
            for child in value:
                check_refs(child)

    for schema in schemas.values():
        check_refs(schema)

    def validate(doc, schema):
        Draft202012Validator(schema, registry=registry, format_checker=FormatChecker()).validate(doc)

    catalog = read(ROOT / "specs/contracts/mcp-tools.json")
    tools = {tool["name"]: tool for tool in catalog["tools"]}
    require(len(tools) == len(catalog["tools"]), "Duplicate MCP tool name")
    for tool in tools.values():
        check_refs(tool)
        for field in ("inputSchema", "outputSchema"):
            Draft202012Validator.check_schema(tool[field])
        require(tool["inputSchema"].get("additionalProperties") is False, "MCP input allows unknown arguments")
    require(not tools["request_capture"]["enabledByDefault"], "Capture tool must default disabled")
    browser_contract = read(ROOT / "docs/interfaces/browser-openapi.yaml")
    for name in ("get_file_excerpt", "get_query_result"):
        require(browser_contract["components"]["schemas"]["McpOutput_" + name] == tools[name]["outputSchema"], "Query browser/MCP output contracts differ")
        require(tools[name]["annotations"]["readOnlyHint"], "Approved query semantics changed")
    query_success = tools["get_query_result"]["outputSchema"]["allOf"][1]["oneOf"][0]["properties"]["data"]
    require("const" not in query_success["properties"]["tool_name"], "Canonical query catalog excludes future specified tools")
    for name in ("request_capture", "resolve_capture_request"):
        operation = browser_contract["paths"]["/api/v1/operations/" + name]["post"]
        header = next(parameter for parameter in operation["parameters"] if parameter["name"] == "Idempotency-Key")
        key = tools[name]["inputSchema"]["properties"]["idempotency_key"]
        require(header["schema"]["minLength"] == key["minLength"] and header["schema"]["maxLength"] == key["maxLength"], "Request key header/body constraints differ")
    require(browser_contract["paths"]["/api/v1/operations/resolve_capture_request"]["post"]["summary"] == tools["resolve_capture_request"]["description"], "Request resolution browser/MCP authority descriptions differ")
    resolution = tools["resolve_capture_request"]
    require(resolution["enabledByDefault"], "Own request resolution must remain available without new collection")
    require(resolution["annotations"] == {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False}, "Request resolution must declare its bounded closure mutation")

    registered = read(ROOT / "specs/examples.yaml")["examples"]
    examples = {}
    for item in registered:
        path = ROOT / item["file"]
        doc = read(path)
        require("schema" in item or "input_tool" in item, "Example lacks schema/tool input contract")
        if "schema" in item:
            validate(doc, schemas[item["schema"]])
        if "input_tool" in item:
            validate(doc, tools[item["input_tool"]]["inputSchema"])
        semantic_checks(doc)
        if "tool" in item:
            validate(doc, tools[item["tool"]]["outputSchema"])
        examples[path.name] = doc
    actual = {str(p.relative_to(ROOT)) for p in (ROOT / "examples").glob("*") if p.suffix in {".yaml", ".json"}}
    require(actual == {x["file"] for x in registered}, "Unregistered or missing example")
    profile_catalog = {}
    for doc in examples.values():
        if doc.get("kind") == "CaptureProfile":
            namespace = doc["metadata"]["namespace"]
            catalog_name = {"asservat-builtin-profiles": "builtin", "asservat-profiles": "organization"}.get(namespace, "namespace")
            key = (catalog_name, doc["spec"]["name"], doc["spec"]["version"])
            require(key not in profile_catalog, "Duplicate fixture catalog reference")
            profile_catalog[key] = doc
    # Every kind has one immutable default and a schema-constrained mode set.
    action_schema = schemas[BASE + "action.schema.json"]
    mode_registry = action_schema["x-execution-modes"]
    require(set(mode_registry) == {b["properties"]["kind"]["const"] for b in action_schema["oneOf"]}, "Unclassified action kind")
    for branch in action_schema["oneOf"]:
        kind = branch["properties"]["kind"]["const"]
        contract = branch["properties"]["executionMode"]
        require(contract["default"] == mode_registry[kind]["default"], "Execution default registry/schema mismatch")
        require(contract.get("enum", [contract.get("const")]) == mode_registry[kind]["allowed"], "Execution modes registry/schema mismatch")
    for request_kind, example in (("DebugPolicy", "lifecycle-plan-policy.json"), ("DebugCapture", "lifecycle-plan-manual.json")):
        expected = action_lifecycle_plan_fixture(examples["recipe-trigger-lifecycles.yaml"]["spec"], request_kind)
        require(examples[example] == expected, "Lifecycle projection differs from mixed recipe")
    require([a["executionMode"] for a in examples["lifecycle-plan-policy.json"]["actions"]] == ["ongoing", "ongoing", "onTrigger"], "Mixed lifecycle regression")
    require(examples["lifecycle-plan-post-trigger.json"] == action_lifecycle_plan_fixture(examples["recipe-post-trigger-only.yaml"]["spec"], "DebugPolicy"), "Post-trigger recorder plan drift")
    for row in examples["mcp-profiles-result.json"]["data"]["profiles"]:
        ref = row["profile_ref"]
        profile = profile_catalog[(ref["catalog"], ref["name"], ref["version"])]
        require(row["execution_modes"] == sorted({action_execution_mode(a) for a in profile["spec"]["definition"]["recipe"]["actions"]}), "Catalog hides execution modes")
    composition_schema = schemas[BASE + "capture-composition.schema.json"]
    def compile_checked(composition, profile_sources=None):
        validate(composition, composition_schema)
        recipe, provenance = compile_composition_fixture(composition, profile_catalog if profile_sources is None else profile_sources)
        validate(recipe, schemas[BASE + "recipe.schema.json"]["properties"]["spec"])
        validate(provenance, composition_schema["$defs"]["provenance"])
        return recipe, provenance
    for doc in examples.values():
        if doc.get("kind") in {"DebugCapture", "DebugPolicy"} and "profileComposition" in doc["spec"]:
            recipe, provenance = compile_checked(doc["spec"]["profileComposition"])
            if doc["kind"] == "DebugPolicy":
                require(not any(a["parameters"].get("process") == "selectedPID" for a in recipe["actions"]), "Composed policy pins an ad hoc PID")
            aliases = {a["actionID"] for a in provenance["actionMap"]}
            require(all(o["actionID"] in aliases for o in doc["spec"].get("sharing", {}).get("outputSelection", {}).get("outputs", [])), "Composed share selects unknown action")
    composition = examples["mcp-composition-preview-input.json"]["profile_composition"]
    expanded, composition_provenance = compile_checked(composition)
    require(expanded == examples["recipe-composed-expanded.yaml"]["spec"], "Composition expansion fixture drift")
    require(examples["mcp-composition-preview-result.json"]["data"]["lifecycle_plan"] == action_lifecycle_plan_fixture(expanded, "DebugCapture"), "Composition preview hides lifecycle")

    require(composition_provenance == examples["mcp-composition-preview-result.json"]["data"]["profile_composition"], "Composition provenance fixture drift")
    composed_scope = examples["resolved-composition-scope.json"]
    require(composed_scope["profileComposition"] == composition_provenance, "Resolved composition provenance drift")
    require(composed_scope["collection"]["spec"]["recipeRef"]["digest"] == canonical_digest(expanded), "Composed scope recipe digest drift")
    require(canonical_digest(composed_scope) == examples["mcp-composition-preview-result.json"]["data"]["execution_digest"], "Composed preview scope digest drift")
    history = examples["mcp-composed-settings-result.json"]["data"]["settings"]
    require(history["profile_composition"] == composition_provenance and history["recipe_spec"] == expanded, "Composed history snapshot drift")
    profile_detail = examples["mcp-profile-definition-result.json"]["data"]
    source = profile_catalog[tuple(profile_detail["profile_ref"][k] for k in ("catalog", "name", "version"))]
    require(profile_detail["definition"] == source["spec"]["definition"] and profile_detail["definition_digest"] == capture_profile_definition_digest(source), "Catalog definition projection drift")
    assessed = examples["assessment-mixed-policy.json"]
    mixed = examples["recipe-trigger-lifecycles.yaml"]["spec"]
    require({a["actionID"] for a in assessed["actions"]} == {a["id"] for a in mixed["actions"]}, "Mixed assessment action drift")
    declared_rings = sum(a["parameters"]["ring"]["maxBytes"] for a in mixed["actions"] if a["kind"] in {"packetCapture", "syscallTrace"})
    declared_output = sum(a["limits"]["maxBytes"] for a in mixed["actions"])
    by_quantity = {(q["phase"], q["dimension"]): q for q in assessed["combinedQuantities"]}
    require(by_quantity[("whileArmed", "collectorMemoryBytes")]["upper"] == declared_rings * 20, "Ongoing assessment undercounts observation pods")
    require(by_quantity[("perIncident", "outputBytes")]["upper"] == declared_output, "Incident assessment multiplies by observation pods")
    core_assessment = next(a for a in assessed["actions"] if a["actionID"] == "core")
    require(core_assessment["retention"]["accessAgeSeconds"] == 21300 and core_assessment["retention"]["deleteAgeSeconds"] == 21600, "Core warning uses incorrect deletion arithmetic")
    for action in examples["assessment-go-profile.json"]["actions"]:
        require("userContent" not in action["data"]["retainedPossible"] and "profileLabels" in action["data"]["retainedPossible"], "Go profile mislabeled as full object heap")
    require(len(examples["mcp-shared-case-notice-result.json"]["data"]["artifacts"]) == 1 and examples["mcp-shared-case-notice-result.json"]["data"]["artifacts"][0]["data_class"] == "extract", "Shared notice exposes the raw source fixture")
    for name in ("mcp-preview-result.json", "mcp-repeat-preview-result.json", "mcp-composition-preview-result.json"):
        require(len(json.dumps(examples[name], separators=(",", ":")).encode()) <= 32768, "Synthetic assessed preview exceeds hard MCP bytes")
    recipes = {doc["metadata"]["name"]: doc for doc in examples.values() if doc.get("kind") == "EvidenceRecipe"}
    policies = {doc["metadata"]["name"]: doc for doc in examples.values() if doc.get("kind") == "DebugPolicy"}
    for doc in examples.values():
        if doc.get("kind") in {"DebugPolicy", "DebugCapture"} and "recipeRef" in doc["spec"]:
            ref = doc["spec"]["recipeRef"]
            require(ref["name"] in recipes, "Example references unknown recipe")
            require(ref["digest"] == canonical_digest(recipes[ref["name"]]["spec"]), "Recipe digest mismatch")
            actions = {a["id"] for a in recipes[ref["name"]]["spec"]["actions"]}
            selections = doc["spec"].get("sharing", {}).get("outputSelection", {}).get("outputs", [])
            require(all(s["actionID"] in actions for s in selections), "Sharing names unknown action")
    for doc in policies.values():
        if "recipeRef" in doc["spec"]:
            recipe = recipes[doc["spec"]["recipeRef"]["name"]]
            require(not any(a["parameters"].get("process") == "selectedPID" for a in recipe["spec"]["actions"]), "Recurring recipe pins an ad hoc PID")
    # A current delegation can sponsor an unchanged historical assignment.
    continued_policy = copy.deepcopy(examples["resolved-policy-scope.json"])
    continued_policy["policyAuthority"]["ownerAssignments"][0]["basisDigest"] = "sha256:" + "a" * 64
    semantic_checks(continued_policy)
    grant = examples["grant-policy.yaml"]["spec"]["target"]
    require(grant["executionDigest"] == canonical_digest(examples["resolved-policy-scope.json"]), "Grant collection scope digest mismatch")
    require(examples["grant-policy.yaml"]["spec"]["policyAuthority"] == examples["resolved-policy-scope.json"]["policyAuthority"] and examples["grant-policy.yaml"]["spec"]["policyExecutor"] == examples["resolved-policy-scope.json"]["executor"], "Grant and accepted team authority disagree")
    require(examples["grant-policy.yaml"]["spec"]["approvalPolicyRef"]["digest"] == canonical_digest(examples["approval-policy.yaml"]), "Approval policy digest mismatch")
    require(examples["grant-ad-hoc.yaml"]["spec"]["target"]["executionDigest"] == canonical_digest(examples["resolved-capture-scope.json"]), "Ad hoc scope digest mismatch")
    core_scope = examples["resolved-sharing-capture-scope.json"]
    core_target = examples["manifest-core.json"]["target"]
    require({k: core_target[k] for k in ("podUID", "nodeUID", "nodeBootID")} in core_scope["podBindings"], "Core example differs from approved pod bindings")
    for name, source in [("resolved-recording-policy-scope.json", "policy-trigger-lifecycles.yaml"), ("resolved-policy-scope.json", "policy-statefulset.yaml"), ("resolved-capture-scope.json", "capture-manual.yaml"), ("resolved-sharing-capture-scope.json", "capture-with-raw-sharing.yaml")]:
        scope = examples[name]
        require(scope["collection"] == collection_spec(examples[source]), "Resolved fixture differs from authored collection fields")
        require(any(d["role"] == "recipe" and d["digest"] == scope["collection"]["spec"]["recipeRef"]["digest"] for d in scope["dependencies"]), "Resolved scope lacks recipe dependency")
    for policy in policies.values():
        if policy["spec"].get("recordingSaves", {}).get("enabled") and "recipeRef" in policy["spec"]:
            recipe = recipes[policy["spec"]["recipeRef"]["name"]]["spec"]
            require(any(action_execution_mode(a) == "ongoing" for a in recipe["actions"]), "Recording saves enabled without ongoing actions")
    save_scope = examples["resolved-recording-save.json"]
    source_scope = examples["resolved-recording-policy-scope.json"]
    require(source_scope["collection"]["spec"]["recordingSaves"]["enabled"], "Example save policy is not enabled")
    require(save_scope["policy"]["executionDigest"] == canonical_digest(source_scope), "Save uses wrong policy scope")
    require(save_scope["executor"] == source_scope["executor"], "Save transfers policy execution identity")
    require(save_scope["policy"]["policyUID"] == source_scope["source"]["resourceUID"] and save_scope["policy"]["clusterID"] == source_scope["source"]["clusterID"], "Save crosses policy identity")
    require(save_scope["workloadUID"] == source_scope["collection"]["spec"]["target"]["workloadRef"]["uid"], "Save crosses workload identity")
    require(save_scope["incidentPodLimit"] == source_scope["collection"]["spec"]["target"]["maxPods"], "Save changes incident cap")
    sr = recipes[source_scope["collection"]["spec"]["recipeRef"]["name"]]["spec"]
    source_actions = {a["id"]: a for a in sr["actions"]}
    for selected in save_scope["sources"]:
        action = source_actions[selected["actionID"]]
        require(action_execution_mode(action) == "ongoing" and selected["kind"] == action["kind"], "Save selects non-recording action")
        require(selected["sourceDefinitionDigest"] == canonical_digest(action), "Synthetic source definition drift")
        require(duration_seconds(selected["before"]) <= duration_seconds(action["parameters"]["before"]), "Save widens source history")
        require(selected["maxBytes"] <= action["limits"]["maxBytes"], "Save widens source bytes")
    sp = examples["mcp-recording-save-preview-result.json"]["data"]
    require(sp["save_scope_digest"] == canonical_digest(save_scope) and sp["capture_id"] == save_scope["captureID"], "Save preview differs from immutable scope")
    require({(r["pod_uid"], r["action_id"]) for r in sp["selected_recordings"]} == {(r["podUID"], r["actionID"]) for r in save_scope["sources"]}, "Save preview selects different sources")
    require(len(json.dumps(sp, separators=(",", ":")).encode()) <= 24576, "Save preview exceeds default result bytes")
    acq = examples["lifecycle-recording-save.json"]
    require(acq["sourceSessionID"] in {r["sourceSessionID"] for r in save_scope["sources"]} and acq["recordingSaveOrigin"]["policyExecutionDigest"] == save_scope["policy"]["executionDigest"], "Save acquisition lost source origin")
    require(examples["mcp-recording-save-input.json"]["preview_id"] == sp["preview_id"], "Save submit lost preview identity")
    require(examples["mcp-recording-save-result.json"]["data"]["capture_id"] == save_scope["captureID"], "Save result lost capture identity")
    sm = examples["manifest-recording-save.json"]
    require(sm["collectionProvenance"]["planDigest"] == canonical_digest(save_scope) and sm["collectionProvenance"]["captureUID"] == save_scope["captureID"], "Saved artifact lost execution identity")
    require(sm["actionLifecycle"] == acq and sm["retention"]["anchorBasis"] == "oldestRingSegment", "Saved artifact reset acquisition provenance")
    require(timestamp(sm["retention"]["anchorAt"]) < timestamp(acq["triggeredAt"]), "Saved artifact incorrectly starts retention at click")
    toggled = copy.deepcopy(source_scope)
    toggled["collection"]["spec"]["recordingSaves"]["enabled"] = False
    require(canonical_digest(toggled) != canonical_digest(source_scope), "Save permission edit leaves reviewed scope unchanged")
    original = collection_spec(policies["ledger-memory"])
    plumbing = copy.deepcopy(policies["ledger-memory"])
    plumbing["spec"].update({"suspended": True, "grantRef": "00000000-0000-4000-8000-000000000099", "sharing": {"changed": True}})
    require(collection_spec(plumbing) == original, "Plumbing changed collection scope")
    plumbing["spec"]["budgets"]["burst"] += 1
    require(collection_spec(plumbing) != original, "Execution change left scope unchanged")
    assignment = examples["manifest.json"]["accessProvenance"]["assignments"][0]
    binding = examples["access-binding.yaml"]["spec"]
    require(assignment["basisDigest"] == canonical_digest(binding), "Permission provenance digest mismatch")
    require(assignment["subject"] in binding["subjects"] and assignment["role"] in binding["roles"], "Permission provenance exceeds binding")
    retention_policy = examples["retention-policy.yaml"]["spec"]
    retention = examples["manifest.json"]["retention"]
    require(retention["policyRefs"][0]["digest"] == canonical_digest(retention_policy), "Retention provenance digest mismatch")
    core_limit = next(rule["maxAgeSeconds"] for rule in retention_policy["rules"] if rule["name"] == "core-and-heap")
    require(retention["resolvedMaxAgeSeconds"] <= core_limit, "Manifest exceeds example core retention policy")
    pool = examples["storage-pool.yaml"]
    budget = examples["budget-policy.yaml"]
    allocation = pool["spec"]["protectedAllocations"][0]
    require(budget["spec"]["poolRef"] == pool["metadata"]["name"], "Unknown example storage pool")
    require(allocation["budgetPolicyRef"] == budget["metadata"]["name"], "Unknown example budget profile")
    require(allocation["protectedPerWorkload"] == budget["spec"]["workload"]["protected"], "Pool and profile allocation disagree")
    require(budget["spec"]["workload"]["upload"]["bytesPerSecond"] <= pool["spec"]["upload"]["bytesPerSecond"], "Workload upload exceeds pool ceiling")
    manifests = {doc["artifactID"]: doc for doc in examples.values() if doc.get("schemaVersion") == "artifact/v1"}
    intent = examples["sharing-intent.yaml"]
    capture = examples["capture-with-raw-sharing.yaml"]
    require(intent["spec"]["requestDigest"] == canonical_digest(capture["spec"]["sharing"]), "Sharing request digest mismatch")
    require(intent["spec"]["source"]["planDigest"] == canonical_digest(examples["resolved-sharing-capture-scope.json"]), "Sharing plan digest mismatch")
    require(intent["spec"]["source"]["recipeDigest"] == capture["spec"]["recipeRef"]["digest"], "Sharing recipe digest mismatch")
    owner_binding = examples["access-binding-owners.yaml"]["spec"]
    require("evidence-owner" in owner_binding["roles"], "Managers lack owner role in fixture")
    require(all(team["subject"] in owner_binding["subjects"] for team in intent["spec"]["management"]["teams"]), "Example manager exceeds owner binding")
    require([team["subject"] for team in intent["spec"]["management"]["teams"]] == capture["spec"]["sharing"]["management"]["teams"], "Resolved manager mismatch")
    for doc in examples.values():
        if doc.get("kind") == "EvidenceShare":
            if "origin" in doc["spec"]:
                sharing_origin_checks(doc, intent, manifests)
            for artifact in doc["spec"]["artifacts"]:
                if artifact["artifactID"] in manifests:
                    manifest = manifests[artifact["artifactID"]]
                    parse_time = lambda value: datetime.fromisoformat(value.replace("Z", "+00:00"))
                    require(parse_time(doc["spec"]["notAfter"]) <= parse_time(manifest["expiresAt"]), "Example share outlives evidence")

    requirements, scenarios = {}, {}
    for path in (ROOT / "specs").glob("*.md"):
        text = path.read_text()
        for pattern, dest in ((r"^## (REQ-[A-Z]+-\d+)\b", requirements), (r"^### (SC-[A-Z]+-\d+)\b", scenarios)):
            for identifier in re.findall(pattern, text, re.M):
                require(identifier not in dest, f"Duplicate identifier: {identifier}")
                dest[identifier] = str(path.relative_to(ROOT))
    tasks = set(re.findall(r"^### (TASK-\d+)\b", (ROOT / "docs/implementation-plan.md").read_text(), re.M))
    matrix = read(ROOT / "specs/traceability.yaml")["requirements"]
    require(len({x["requirement"] for x in matrix}) == len(matrix), "Duplicate traceability row")
    require({x["requirement"] for x in matrix} == set(requirements), "Unmapped or unknown requirement")
    covered = set()
    for row in matrix:
        require(row["spec"] == requirements[row["requirement"]], "Wrong requirement file")
        require(bool(row["scenarios"]) and bool(row["tasks"]), "Requirement lacks acceptance or implementation mapping")
        require(set(row["scenarios"]) <= set(scenarios), "Unknown acceptance scenario")
        require(set(row["tasks"]) <= tasks, "Unknown implementation task")
        covered.update(row["scenarios"])
    require(covered == set(scenarios), "Unmapped acceptance scenario")

    links = 0
    for path in ROOT.rglob("*.md"):
        # Installed development dependencies contain upstream-relative links;
        # they are not part of Asservat's authored specification.
        if {".venv", "node_modules"}.intersection(path.parts):
            continue
        for dest in re.findall(r"\[[^\]\n]+\]\(([^)\n]+)\)", path.read_text()):
            target = dest.strip("<>").split(' "', 1)[0]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            require((path.parent / unquote(parsed.path)).exists(), f"Broken local link in {path.relative_to(ROOT)}: {target}")
            links += 1

    negative_checks = 0

    def rejects(doc, schema_name, mutate, semantic=False):
        nonlocal negative_checks
        invalid = copy.deepcopy(doc)
        mutate(invalid)
        try:
            validate(invalid, schemas[BASE + schema_name + ".schema.json"])
            if semantic:
                semantic_checks(invalid)
        except (ValueError, __import__("jsonschema").ValidationError):
            negative_checks += 1
            return
        raise ValueError("Invalid example accepted: " + schema_name)

    # Synthetic installation provenance, never an installable credential example.
    # Cross-object order, identity and deadline checks have separate runtime tests.
    owner_id = lambda n: f"00000000-0000-4000-8000-{n:012d}"
    owner_ref = lambda name, n: {"name": name, "uid": owner_id(n)}
    owner_roles = {
        "format": "asservat-owner-identity-roles/v1",
        "installationID": owner_id(1), "initialClaimID": owner_id(2),
        "clusterID": owner_id(3), "namespace": owner_ref("hub", 4),
        "ownerConfigurationUID": owner_id(5), "resources": owner_ref("resources", 6),
        "resourceSetupID": owner_id(7), "resourceBinding": "a" * 64,
        "ownerLayout": "asservat-owner-installed/v1",
        "deployment": owner_ref("owner", 8), "serviceAccount": owner_ref("owner", 9),
        "layoutDigest": "b" * 64,
    }
    validate(owner_roles, schemas[BASE + "owner-identity-roles.schema.json"])
    for mutation in (
        lambda d: d.update(resourceBinding="0" * 64),
        lambda d: d.update(ownerLayout="asservat-hub-worker-installed/v1"),
        lambda d: d.update(sqlAdministrator="forbidden"),
        lambda d: d.pop("resources"),
    ):
        rejects(owner_roles, "owner-identity-roles", mutation)
    owner_entries = []
    for index, purpose in enumerate(("enrollment", "audit", "activation", "registry")):
        owner_entries.append({"purpose": purpose, "password": "a" * 42 + str(index),
            "claim": {"operationID": owner_id(10 + index),
                "claimedAt": "2026-10-12T12:00:01Z", "until": "2026-10-12T12:00:05Z",
                "databaseOID": 16384, "postmasterAt": "2026-10-12T11:00:00Z"},
            "receipt": {"roleName": "as_" + owner_id(1).replace("-", "") + f"_own_{index:02d}",
                "roleOID": 17000 + index, "layoutDigest": "b" * 64}})
    owner_state = {"format": "asservat-owner-identity-role-state/v1", "input": owner_roles,
        "operationID": owner_id(14), "createdAt": "2026-10-12T12:00:00Z",
        "until": "2026-10-12T12:30:00Z", "roles": owner_entries}
    validate(owner_state, schemas[BASE + "owner-identity-role-state.schema.json"])
    for mutation in (
        lambda d: d["roles"].pop(),
        lambda d: d["roles"][0].update(purpose="configuration-fleet"),
        lambda d: d["roles"][0]["receipt"].update(roleName="as_" + "a" * 32 + "_pub_00"),
        lambda d: d["roles"][0].update(password="short"),
    ):
        rejects(owner_state, "owner-identity-role-state", mutation)
    owner_manifest = {"format": "asservat-owner-identity-credentials/v1", "input": owner_roles,
        "rootUID": owner_id(15), "setupID": owner_id(14),
        "roles": [{k: v for k, v in entry.items() if k != "password"} for entry in owner_entries]}
    validate(owner_manifest, schemas[BASE + "owner-identity-credentials.schema.json"])
    rejects(owner_manifest, "owner-identity-credentials", lambda d: d["roles"][0].update(password="forbidden"))
    rejects(owner_manifest, "owner-identity-credentials", lambda d: d["roles"][0].pop("receipt"))
    owner_activation = {"input": owner_roles, "roleRoot": owner_ref("owner-roles", 15),
        "roleSetupID": owner_id(14), "resourcesCreatedAt": "2026-10-12T12:00:00Z",
        "resourcesUntil": "2026-10-12T12:30:00Z"}
    validate(owner_activation, schemas[BASE + "owner-identity-activation.schema.json"])
    rejects(owner_activation, "owner-identity-activation", lambda d: d.update(recoveryApproved=True))
    rejects(owner_activation, "owner-identity-activation", lambda d: d.pop("roleSetupID"))

    # Private key payloads are synthesized here, never published as installable
    # Secret examples. Runtime tests cover scope, duplicate versions/material,
    # byte bounds and active-version presence beyond JSON Schema's contract.
    local_key = {
        "format": "asservat-local-keys/v1",
        "installationID": "00000000-0000-4000-8000-000000000001",
        "purpose": "artifact", "keyID": "synthetic-only", "activeVersion": 1,
        "keys": [{"version": 1, "material": base64.b64encode(bytes(range(32))).decode("ascii")}],
    }
    for purpose in ("artifact", "audit", "browser-credentials", "policy-submission"):
        local_key["purpose"] = purpose
        validate(local_key, schemas[BASE + "local-key-secret.schema.json"])
    for mutation in (
        lambda d: d.update(format="another-format"),
        lambda d: d.update(installationID="00000000-0000-0000-0000-000000000000"),
        lambda d: d.update(purpose="any-purpose"),
        lambda d: d.update(keyID="../key"),
        lambda d: d.update(activeVersion=0),
        lambda d: d.update(activeVersion=2147483648),
        lambda d: d.update(keys=[]),
        lambda d: d.update(keys=d["keys"] * 17),
        lambda d: d.update(password="default"),
        lambda d: d.pop("activeVersion"),
        lambda d: d["keys"][0].update(version=-1),
        lambda d: d["keys"][0].update(material=base64.b64encode(bytes(32)).decode("ascii")),
        lambda d: d["keys"][0].update(material=base64.b64encode(bytes(31)).decode("ascii")),
        lambda d: d["keys"][0].update(material="A" * 42 + "B="),
        lambda d: d["keys"][0].update(plaintext="unexpected"),
    ):
        rejects(local_key, "local-key-secret", mutation)

    # Private RPC examples use synthetic byte strings, never installable keys.
    key_scope = {"installationID": local_key["installationID"], "purpose": "artifact", "keyID": "synthetic-only"}
    key_configuration = {"format": "asservat-local-key-configuration/v1", **key_scope,
                         "recoveryEpoch": "00000000-0000-4000-8000-000000000003",
                         "revision": 1, "suspended": False,
                         "secret": {"name": "keys-v1", "uid": "synthetic-key-uid", "sha256": "1" * 64}}
    validate(key_configuration, schemas[BASE + "local-key-configuration.schema.json"])
    for mutation in [lambda d: d.update(revision=0), lambda d: d.update(revision=2147483648),
                     lambda d: d.update(privateKey="forbidden"), lambda d: d.update(purpose="policy-submission"),
                     lambda d: d.update(signingPublicKey="AQ=="), lambda d: d.update(suspended="false"),
                     lambda d: d["secret"].update(sha256="0" * 64), lambda d: d["secret"].update(name="../keys"),
                     lambda d: d["secret"].update(name="keys\n"), lambda d: d["secret"].update(uid=""),
                     lambda d: d["secret"].update(sha256="1" * 64 + "\n")]:
        rejects(key_configuration, "local-key-configuration", mutation)
    worker_configuration = {
        "format": "asservat-worker-configuration/v1", "installationID": local_key["installationID"],
        "clusterID": "00000000-0000-4000-8000-000000000002",
        "recoveryEpoch": "00000000-0000-4000-8000-000000000003", "revision": 1, "suspended": False,
        "namespace": {"name": "workers", "uid": "namespace-uid"},
        "serviceAccount": {"name": "acquisition", "uid": "account-uid"},
        "priorityClass": {"name": "acquisition", "uid": "priority-uid"},
        "controlConfig": {"name": "worker-control", "uid": "control-uid", "sha256": "1" * 64},
        "image": "synthetic.invalid/worker@sha256:" + "1" * 64, "imagePullSecrets": [],
        "cpuMillis": 100, "memoryBytes": 64 * 1024 * 1024, "maxRuntimeSeconds": 60,
    }
    validate(worker_configuration, schemas[BASE + "worker-configuration.schema.json"])
    for mutation in [lambda d: d.update(revision=0), lambda d: d.update(revision=2147483648),
                     lambda d: d.pop("suspended"), lambda d: d.update(suspended=None),
                     lambda d: d.update(command=["sh"]), lambda d: d.update(administrators=["self"]),
                     lambda d: d.update(cpuMillis=4001), lambda d: d.update(memoryBytes=8589934593),
                     lambda d: d.update(maxRuntimeSeconds=28801), lambda d: d.update(maxRuntimeSeconds=29),
                     lambda d: d.update(image="synthetic.invalid/worker:latest"),
                     lambda d: d.update(image=d["image"] + "\n"),
                     lambda d: d.update(imagePullSecrets=["same", "same"]),
                     lambda d: d.update(imagePullSecrets=["../secret"]),
                     lambda d: d.update(imagePullSecrets=["a", "b", "c", "d", "e"]),
                     lambda d: d["namespace"].update(name="wrong.namespace"),
                     lambda d: d["namespace"].update(uid=""),
                     lambda d: d["serviceAccount"].update(name="account\n"),
                     lambda d: d["priorityClass"].update(name="../priority"),
                     lambda d: d["controlConfig"].update(sha256="0" * 64),
                     lambda d: d["controlConfig"].update(sha256="1" * 64 + "\n")]:
        rejects(worker_configuration, "worker-configuration", mutation)

    owner_configuration = {
        "format": "asservat-hub-owner-configuration/v1", "installationID": local_key["installationID"],
        "clusterID": worker_configuration["clusterID"], "issuerEpoch": worker_configuration["recoveryEpoch"],
        "revision": 1, "suspended": False,
        "namespace": {"name": "hub", "uid": local_key["installationID"]},
        "service": {"name": "owner", "uid": local_key["installationID"]},
        "deployment": {"name": "hub", "uid": local_key["installationID"]},
        "serviceAccount": {"name": "hub", "uid": local_key["installationID"]},
        "port": 9443, "issuerRoots": ["AQ=="],
    }
    validate(owner_configuration, schemas[BASE + "owner-configuration.schema.json"])
    for mutation in [lambda d: d.pop("suspended"), lambda d: d.update(suspended=None),
                     lambda d: d.update(privateKey="forbidden"), lambda d: d.update(endpoint="https://callback.invalid"),
                     lambda d: d.update(revision=0), lambda d: d.update(revision=2147483648),
                     lambda d: d.update(port=443), lambda d: d.update(port=65536),
                     lambda d: d.update(issuerRoots=[]), lambda d: d.update(issuerRoots=["AQ==", "AQ=="]),
                     lambda d: d.update(issuerRoots=["not base64"]),
                     lambda d: d["service"].update(name="../service"), lambda d: d["service"].update(name="1service"),
                     lambda d: d["namespace"].update(uid="not-a-uuid"),
                     lambda d: d["deployment"].update(name="hub\n"),
                     lambda d: d["deployment"].update(name="a..b"),
                     lambda d: d["serviceAccount"].update(uid="00000000-0000-0000-0000-000000000000")]:
        rejects(owner_configuration, "owner-configuration", mutation)

    worker_control = {"format": "asservat-worker-control/v1", "installationID": local_key["installationID"],
                      "clusterID": "00000000-0000-4000-8000-000000000002", "endpoint": "https://control.invalid",
                      "serverRoots": ["AQ=="], "issuerRoots": ["Ag=="]}
    validate(worker_control, schemas[BASE + "worker-control.schema.json"])
    for mutation in [lambda d: d.update(endpoint="http://control.invalid"),
                     lambda d: d.update(endpoint="https://token@control.invalid"),
                     lambda d: d.update(endpoint="https://control.invalid/path"),
                     lambda d: d.update(endpoint="https://control.invalid?token=x"),
                     lambda d: d.update(endpoint="https://control.invalid#fragment"),
                     lambda d: d.update(endpoint="https://control.invalid\n"),
                     lambda d: d.update(serverRoots=[]), lambda d: d.update(issuerRoots=None),
                     lambda d: d.update(issuerRoots=["AQ==", "AQ=="]),
                     lambda d: d.update(serverRoots=["AQ==", "Ag==", "Aw==", "BA==", "BQ=="]),
                     lambda d: d.update(privateKey="forbidden"), lambda d: d.update(token="forbidden"),
                     lambda d: d.update(command=["sh"]), lambda d: d.pop("clusterID"),
                     lambda d: d.update(address=""), lambda d: d.update(address="owner.hub.svc"),
                     lambda d: d.update(address="owner.hub.svc:09443"),
                     lambda d: d.update(address="token@owner.hub.svc:9443"),
                     lambda d: d.update(address="owner.hub.svc:9443/path")]:
        rejects(worker_control, "worker-control", mutation)
    # ADR-204 decision 9: optional connectivity-only dial address.
    addressed_control = copy.deepcopy(worker_control)
    addressed_control["address"] = "owner.hub.svc:9443"
    validate(addressed_control, schemas[BASE + "worker-control.schema.json"])

    owner_deployment = {
        "format": "asservat-owner-deployment/v1", "installationID": local_key["installationID"],
        "clusterID": worker_control["clusterID"], "permissionRootID": local_key["installationID"],
        "namespace": {"name": "hub", "uid": local_key["installationID"]},
        "configurationUID": local_key["installationID"],
        "configurationProbes": [{"configMap": "owner-pool", "serviceAccount": "owner-config-probe"}],
        "schedulingLeases": [{"lease": "reconcile", "serviceAccount": "reconciler"}],
        "kubernetes": {"endpoint": "https://api.invalid", "roots": ["AQ=="]},
        "workloadGuard": {"name": "owner", "policyUID": local_key["installationID"], "policyGeneration": 1,
                          "bindingUID": local_key["installationID"], "bindingResourceVersion": "1",
                          "administrators": [{"kind": "Group", "name": "installers"}]},
        "postgres": {"host": "postgres.hub.svc", "port": 5432, "database": "asservat",
                     "roots": ["AQ=="], "maxConnections": 2},
        "auditStore": {"endpoint": "https://store.invalid", "roots": ["AQ=="], "region": "local", "bucket": "audit"},
        "keyService": {"endpoint": "https://keys.invalid", "roots": ["AQ=="], "auditMount": "audit",
                       "auditKey": "records", "pkiMount": "owner", "serverRole": "server", "clientRole": "client"},
        "connections": 2, "concurrency": 1}
    validate(owner_deployment, schemas[BASE + "owner-deployment.schema.json"])
    capacity_owner = copy.deepcopy(owner_deployment)
    capacity_owner["capacityProbe"] = {"serviceAccount": {"name": "configuration-worker", "uid": local_key["installationID"]}}
    validate(capacity_owner, schemas[BASE + "owner-deployment.schema.json"])
    # Structural examples only: runtime independently verifies original receipts,
    # exact workload identity and current accepted authority.
    local_owner = {"source": {"name": "owner-pool", "uid": local_key["installationID"]},
                   "pool": copy.deepcopy(owner_configuration), "deployment": copy.deepcopy(capacity_owner)}
    local_owner["pool"].update(nativePort=9444, nativeBootstrap="owner-bootstrap/v1")
    local_owner["deployment"]["observation"] = {
        "format": "owner-observation/v1", "templateDigest": "1" * 64,
        "imageDigest": "2" * 64, "protectionDigest": "3" * 64,
        "peers": [{"installationID": local_key["installationID"], "clusterID": worker_control["clusterID"],
                   "issuerEpoch": owner_configuration["issuerEpoch"], "peerID": local_key["installationID"],
                   "roots": ["AQ=="]}], "activation": copy.deepcopy(owner_activation)}
    validate(local_owner, schemas[BASE + "capacity-local-owner.schema.json"])
    for mutation in [lambda d: d.update(token="forbidden"), lambda d: d.update(endpoint="https://override.invalid"),
                     lambda d: d.pop("source"), lambda d: d["source"].update(uid="replacement"),
                     lambda d: d["pool"].update(revision=2), lambda d: d["pool"].update(suspended=True),
                     lambda d: d["pool"].update(port=9445), lambda d: d["pool"].update(nativePort=9445),
                     lambda d: d["pool"].pop("nativeBootstrap"), lambda d: d["deployment"].pop("observation"),
                     lambda d: d["deployment"].pop("capacityProbe"), lambda d: d["deployment"].update(native={}),
                     lambda d: d["deployment"]["observation"].pop("activation")]:
        rejects(local_owner, "capacity-local-owner", mutation)

    provider_auth = {"format": "asservat-owner-kubernetes-auth/v1", "authMount": "owner-kubernetes",
                     "authMountAccessor": "auth_kubernetes_fixture",
                     "serviceAccount": {"name": "owner", "uid": local_key["installationID"]},
                     "auditCredentials": {"name": "owner-audit", "uid": worker_control["clusterID"]},
                     "recipeSHA256": "a" * 64}
    validate(provider_auth, schemas[BASE + "owner-provider-auth.schema.json"])
    for mutation in [lambda d: d.update(token="forbidden"), lambda d: d.update(tokenTTL=90000),
                     lambda d: d.update(role="arbitrary"), lambda d: d.update(reviewer="forbidden"),
                     lambda d: d.pop("auditCredentials"), lambda d: d.update(authMount="token"),
                     lambda d: d.update(authMount="nested/path"), lambda d: d.update(authMount="owner\n"),
                     lambda d: d.update(authMountAccessor=""), lambda d: d.update(recipeSHA256="0" * 64),
                     lambda d: d.update(recipeSHA256="a" * 64 + "\n"),
                     lambda d: d["serviceAccount"].update(uid="not-a-uuid"),
                     lambda d: d["auditCredentials"].update(token="forbidden")]:
        rejects(provider_auth, "owner-provider-auth", mutation)
    # Fresh provider-installed selection is one original worker2/owner2 pair.
    # These are public structural fixtures, not accepted source, provider setup,
    # storage capability, current native enforcement or installation authority.
    provider_owner = copy.deepcopy(local_owner["deployment"])
    provider_owner["observation"]["activation"]["input"]["ownerLayout"] = "asservat-owner-installed/v2"
    provider_owner["providerAuthentication"] = copy.deepcopy(provider_auth)
    validate(provider_owner, schemas[BASE + "owner-deployment.schema.json"])
    for mutation in [lambda d: d.pop("providerAuthentication"),
                     lambda d: d["observation"]["activation"]["input"].update(ownerLayout="asservat-owner-installed/v1"),
                     lambda d: d.pop("observation"), lambda d: d.update(native={}),
                     lambda d: d["observation"].pop("activation")]:
        rejects(provider_owner, "owner-deployment", mutation)
    bounded_pool = copy.deepcopy(local_owner["pool"])
    bounded_pool["nativeCandidateLimit"] = 1024
    validate(bounded_pool, schemas[BASE + "owner-configuration.schema.json"])
    for mutation in [lambda d: d.update(nativeCandidateLimit=0),
                     lambda d: d.update(nativeCandidateLimit=1025),
                     lambda d: d.update(nativeCandidateLimit=1.5),
                     lambda d: d.pop("nativePort"), lambda d: d.pop("nativeBootstrap")]:
        rejects(bounded_pool, "owner-configuration", mutation)

    installed_name = "asservat-" + owner_id(1).replace("-", "")
    worker_selection = {"authMount": "configuration-auth", "authMountAccessor": "auth_configuration_original",
                        "auditCredentials": owner_ref(installed_name + "-worker-providers", 20)}
    owner_selection = {"authMount": "owner-auth", "authMountAccessor": "auth_owner_original",
                       "auditCredentials": owner_ref(installed_name + "-owner-audit", 21)}
    for selection, name in ((worker_selection, "configuration-provider-selection"),
                            (owner_selection, "owner-provider-selection")):
        validate(selection, schemas[BASE + name + ".schema.json"])
        for mutation in [lambda d: d.update(authMount="token"), lambda d: d.update(authMount="nested/auth"),
                         lambda d: d.update(authMount="auth\n"), lambda d: d.update(authMountAccessor=""),
                         lambda d: d.update(authMountAccessor="a" * 129),
                         lambda d: d["auditCredentials"].update(name=d["auditCredentials"]["name"] + "\n"),
                         lambda d: d["auditCredentials"].update(uid="replacement"),
                         lambda d: d["auditCredentials"].update(secretAccessKey="forbidden"),
                         lambda d: d.update(versionedAudit=True)]:
            rejects(selection, name, mutation)

    resources = {"format": "asservat-initial-runtime-resources/v1", "bindingDigest": "a" * 64,
                 "setupID": owner_id(7), "createdAt": "2026-10-12T12:00:00Z",
                 "until": "2026-10-12T12:30:00Z", "objects": []}
    validate(resources, schemas[BASE + "initial-runtime-resources.schema.json"])
    worker_resources = copy.deepcopy(resources)
    worker_resources["workerLayout"] = "asservat-hub-worker-installed/v1"
    validate(worker_resources, schemas[BASE + "initial-runtime-resources.schema.json"])
    legacy_pair = copy.deepcopy(worker_resources)
    legacy_pair["ownerLayout"] = "asservat-owner-installed/v1"
    validate(legacy_pair, schemas[BASE + "initial-runtime-resources.schema.json"])
    provider_pair = copy.deepcopy(resources)
    provider_pair.update(workerLayout="asservat-hub-worker-installed/v2", ownerLayout="asservat-owner-installed/v2",
                         workerProvider=worker_selection, ownerProvider=owner_selection)
    validate(provider_pair, schemas[BASE + "initial-runtime-resources.schema.json"])
    for mutation in [lambda d: d.pop("workerLayout"), lambda d: d.pop("ownerLayout"),
                     lambda d: d.pop("workerProvider"), lambda d: d.pop("ownerProvider"),
                     lambda d: d.update(workerLayout="asservat-hub-worker-installed/v1"),
                     lambda d: d.update(ownerLayout="asservat-owner-installed/v1"),
                     lambda d: d.update(versionedAudit=False)]:
        rejects(provider_pair, "initial-runtime-resources", mutation)
    for legacy in (resources, worker_resources, legacy_pair):
        rejects(legacy, "initial-runtime-resources", lambda d: d.update(workerProvider=worker_selection))
        rejects(legacy, "initial-runtime-resources", lambda d: d.update(ownerProvider=owner_selection))

    worker_input_claim = {"operationID": owner_id(22), "configurationRoot": owner_ref("configuration-root", 23),
                          "configurationSetupID": owner_id(24), "sqlProjection": owner_ref("configuration-sql", 25),
                          "publicDigest": "c" * 64, "auditCredentials": worker_selection["auditCredentials"],
                          "claimedAt": "2026-10-12T12:00:01Z", "until": "2026-10-12T12:00:05Z"}
    validate(worker_input_claim, schemas[BASE + "configuration-worker-input-claim.schema.json"])
    worker_input_claim["receipt"] = {"configuration": owner_ref("worker-inputs", 26), "resourceVersion": "7",
                                     "observedAt": "2026-10-12T12:00:03Z"}
    validate(worker_input_claim, schemas[BASE + "configuration-worker-input-claim.schema.json"])
    provider_pair["workerInputs"] = worker_input_claim
    validate(provider_pair, schemas[BASE + "initial-runtime-resources.schema.json"])
    for mutation in [lambda d: d.update(publicDigest="0" * 64), lambda d: d.update(publicDigest="c" * 64 + "\n"),
                     lambda d: d.pop("configurationSetupID"), lambda d: d.pop("sqlProjection"),
                     lambda d: d.update(password="forbidden"), lambda d: d.update(secretPayloadSHA256="c" * 64),
                     lambda d: d["receipt"].pop("observedAt"),
                     lambda d: d["receipt"]["configuration"].update(uid="replacement")]:
        rejects(worker_input_claim, "configuration-worker-input-claim", mutation)
    for legacy in (resources, worker_resources, legacy_pair):
        rejects(legacy, "initial-runtime-resources", lambda d: d.update(workerInputs=worker_input_claim))
    worker_auth = copy.deepcopy(provider_auth)
    worker_auth.update(format="asservat-configuration-kubernetes-auth/v1", **worker_selection)
    validate(worker_auth, schemas[BASE + "configuration-provider-auth.schema.json"])
    for mutation in [lambda d: d.update(format="asservat-owner-kubernetes-auth/v1"),
                     lambda d: d.update(recipeSHA256="0" * 64), lambda d: d.update(token="forbidden"),
                     lambda d: d.update(serverRole="owner-sign"), lambda d: d.pop("serviceAccount")]:
        rejects(worker_auth, "configuration-provider-auth", mutation)
    worker_provider_binding = {"selection": worker_selection, "inputOperationID": worker_input_claim["operationID"],
                               "publicDigest": worker_input_claim["publicDigest"],
                               "configuration": worker_input_claim["receipt"]["configuration"]}
    validate(worker_provider_binding, schemas[BASE + "configuration-worker-provider-binding.schema.json"])
    for mutation in [lambda d: d.pop("configuration"), lambda d: d.update(publicDigest="0" * 64),
                     lambda d: d.update(password="forbidden"), lambda d: d.update(selection=None)]:
        rejects(worker_provider_binding, "configuration-worker-provider-binding", mutation)

    # The declared provider profile must not be silently ignored by the legacy loader.
    rejects(owner_deployment, "owner-deployment", lambda d: d.update(providerAuthentication=provider_auth))
    for mutation in [lambda d: d.update(capacityProbe=None),
                     lambda d: d["capacityProbe"].update(namespace="other"),
                     lambda d: d["capacityProbe"]["serviceAccount"].pop("uid"),
                     lambda d: d["capacityProbe"]["serviceAccount"].update(uid="not-a-uid"),
                     lambda d: d["capacityProbe"].update(resources=["secrets"])]:
        rejects(capacity_owner, "owner-deployment", mutation)
    for mutation in [lambda d: d.update(token="forbidden"), lambda d: d.update(format="future"),
                     lambda d: d.update(concurrency=0), lambda d: d.update(connections=65),
                     lambda d: d.pop("configurationUID"), lambda d: d.update(permissionRootID="invalid"),
                     lambda d: d["postgres"].update(host="/run/postgresql"),
                     lambda d: d["postgres"].update(maxConnections=5), lambda d: d["postgres"].update(port=65536),
                     lambda d: d["postgres"].update(password="forbidden"),
                     lambda d: d["keyService"].update(endpoint="http://keys.invalid"),
                     lambda d: d["keyService"].update(endpoint="https://keys.invalid?token=forbidden"),
                     lambda d: d["keyService"].update(auditMount="../audit"),
                     lambda d: d["keyService"].update(roots=[]),
                     lambda d: d.pop("schedulingLeases"), lambda d: d.update(schedulingLeases=None),
                     lambda d: d.update(schedulingLeases=d["schedulingLeases"] * 2),
                     lambda d: d.update(schedulingLeases=[{"lease": "lease-" + str(i), "serviceAccount": "reconciler"} for i in range(5)]),
                     lambda d: d["schedulingLeases"][0].update(lease="*"),
                     lambda d: d["schedulingLeases"][0].update(serviceAccount="../foreign"),
                     lambda d: d["schedulingLeases"][0].update(namespace="other"),
                     lambda d: d.pop("configurationProbes"), lambda d: d.update(configurationProbes=None),
                     lambda d: d.update(configurationProbes=d["configurationProbes"] * 2),
                     lambda d: d["configurationProbes"][0].update(configMap="*"),
                     lambda d: d["configurationProbes"][0].update(serviceAccount="../other"),
                     lambda d: d["configurationProbes"][0].update(group="system:authenticated"),
                     lambda d: d["workloadGuard"].update(administrators=[]),
                     lambda d: d["workloadGuard"].update(policyGeneration=9007199254740992),
                     lambda d: d["workloadGuard"]["administrators"][0].update(kind="ServiceAccount")]:
        rejects(owner_deployment, "owner-deployment", mutation)

    hub_worker = {k: copy.deepcopy(owner_deployment[k]) for k in
                  ["installationID", "clusterID", "namespace", "kubernetes", "postgres", "auditStore"]}
    hub_worker.update(format="asservat-hub-worker-deployment/v1",
                      fleetSource={"name": "fleet", "uid": local_key["installationID"]},
                      ownerSource={"name": "owner", "uid": worker_control["clusterID"]},
                      leaderLease={"name": "reconcile", "uid": local_key["installationID"]},
                      fleetGuard=copy.deepcopy(owner_deployment["workloadGuard"]),
                      ownerGuard=copy.deepcopy(owner_deployment["workloadGuard"]),
                      keyService={k: owner_deployment["keyService"][k] for k in ["endpoint", "roots", "auditMount", "auditKey"]})
    hub_worker["fleetGuard"]["name"] = "fleet-guard"
    validate(hub_worker, schemas[BASE + "hub-worker-deployment.schema.json"])
    for mutation in [lambda d: d.update(recoveryAccepted=True), lambda d: d.update(token="forbidden"),
                     lambda d: d["keyService"].update(serverRole="owner-sign"),
                     lambda d: d["leaderLease"].update(uid="replacement"),
                     lambda d: d["fleetSource"].update(name="../fleet"),
                     lambda d: d["postgres"].update(maxConnections=8), lambda d: d.pop("ownerGuard")]:
        rejects(hub_worker, "hub-worker-deployment", mutation)

    initial = {k: copy.deepcopy(hub_worker[k]) for k in
               ["installationID", "clusterID", "namespace", "kubernetes", "postgres", "auditStore", "fleetSource", "fleetGuard", "keyService"]}
    initial.update(format="asservat-initial-installer/v1", issuerEpoch=initial["installationID"],
                   witness={"name": "witness", "uid": initial["installationID"]},
                   writerAccount={"name": "writer", "uid": initial["installationID"]},
                   probeAccount={"name": "probe", "uid": worker_control["clusterID"]},
                   pod={"name": "installer", "uid": initial["installationID"]},
                   configuration="installer-inputs", podSpecDigest="01" * 32,
                   witnessGuard=copy.deepcopy(hub_worker["ownerGuard"]),
                   workloadGuard=copy.deepcopy(hub_worker["ownerGuard"]))
    validate(initial, schemas[BASE + "initial-installer.schema.json"])
    initial_versioned = copy.deepcopy(initial)
    initial_versioned["format"] = "asservat-initial-installer/v2"
    validate(initial_versioned, schemas[BASE + "initial-installer.schema.json"])
    for mutation in [lambda d: d.update(format="asservat-initial-installer/v999"),
                     lambda d: d.update(requireAuditVersions=False),
                     lambda d: d["auditStore"].update(requireVersions=False)]:
        rejects(initial_versioned, "initial-installer", mutation)
    for mutation in [lambda d: d.update(activate=True), lambda d: d.update(password="forbidden"),
                     lambda d: d.pop("workloadGuard"), lambda d: d.update(podSpecDigest="00" * 32),
                     lambda d: d.update(podSpecDigest="AB" * 32), lambda d: d.update(configuration="../outside"),
                     lambda d: d["pod"].update(uid="replacement"), lambda d: d["keyService"].update(rootKey="forbidden")]:
        rejects(initial, "initial-installer", mutation)

    initial_sql = dict(format="asservat-initial-sql-credentials/v1", installationID=initial["installationID"],
                       planDigest="01" * 32, notBefore="2026-10-11T12:00:00Z", notAfter="2026-10-11T12:15:00Z")
    for field, role, char in [("preparation", "prepare", "A"), ("audit", "audit", "E"), ("activation", "activate", "I")]:
        initial_sql[field] = dict(username="asservat_init_" + initial["installationID"].replace("-", "") + "_" + role, password=char * 43)
    validate(initial_sql, schemas[BASE + "initial-sql-credentials.schema.json"])
    for mutation in [lambda d: d.update(endpoint="https://untrusted.invalid"), lambda d: d.update(planDigest="00" * 32),
                     lambda d: d.pop("notAfter"), lambda d: d.update(notAfter="not-a-date"),
                     lambda d: d["activation"].update(username="postgres"), lambda d: d["audit"].update(password="short"),
                     lambda d: d["preparation"].update(password="A" * 42 + "B")]:
        rejects(initial_sql, "initial-sql-credentials", mutation)

    preparation = dict(format="asservat-initial-preparation/v1", installationID=initial["installationID"],
                       requestID=initial["clusterID"], planDigest="01" * 32,
                       namespace=copy.deepcopy(initial["namespace"]), guard=copy.deepcopy(initial["workloadGuard"]),
                       creates=[dict(operationID=initial["installationID"], kind="ServiceAccount", name="writer", specDigest="02" * 32)])
    validate(preparation, schemas[BASE + "initial-preparation.schema.json"])
    preparation["creates"][0]["receipt"] = dict(uid=initial["clusterID"], resourceVersion="123")
    validate(preparation, schemas[BASE + "initial-preparation.schema.json"])
    for mutation in [lambda d: d.update(password="forbidden"), lambda d: d.update(approved=True),
                     lambda d: d["creates"][0].update(kind="Command"), lambda d: d["creates"][0].update(name="../other"),
                     lambda d: d["creates"][0].update(specDigest="00" * 32), lambda d: d["creates"][0].update(receipt=None),
                     lambda d: d["creates"][0]["receipt"].update(uid="replacement"),
                     lambda d: d.update(creates=d["creates"] * 65), lambda d: d.pop("guard")]:
        rejects(preparation, "initial-preparation", mutation)

    owner_credentials = [{"username": "registry", "password": "synthetic-only"},
                         {"accessKeyID": "synthetic", "secretAccessKey": "synthetic-only", "sessionToken": ""}]
    for credential in owner_credentials:
        validate(credential, schemas[BASE + "owner-credentials.schema.json"])
        for mutation in [lambda d: d.update(endpoint="https://untrusted.invalid"), lambda d: d.clear()]:
            rejects(credential, "owner-credentials", mutation)
    rejects(owner_credentials[0], "owner-credentials", lambda d: d.update(password="nul\0forbidden"))
    rejects(owner_credentials[1], "owner-credentials", lambda d: d.update(sessionToken="invalid\nheader"))
    rejects(owner_credentials[1], "owner-credentials", lambda d: d.pop("sessionToken"))

    owner_trust = {"format": "asservat-owner-worker-trust/v1", "controls": []}
    validate(owner_trust, schemas[BASE + "owner-worker-trust.schema.json"])
    owner_trust["controls"] = [base64.b64encode(json.dumps(worker_control).encode()).decode()]
    validate(owner_trust, schemas[BASE + "owner-worker-trust.schema.json"])
    for mutation in [lambda d: d.update(controls=None), lambda d: d.update(controls=["not-base64"]),
                     lambda d: d.update(controls=d["controls"] * 2), lambda d: d.update(controls=["A" * 87388]),
                     lambda d: d.update(token="forbidden"), lambda d: d.update(format="future")]:
        rejects(owner_trust, "owner-worker-trust", mutation)

    enrollment_request = {"format": "asservat-worker-enrollment/v1", "installationID": local_key["installationID"],
                          "sessionID": "00000000-0000-4000-8000-000000000002",
                          "workerID": "00000000-0000-4000-8000-000000000003", "nonce": "A" * 43,
                          "csr": base64.b64encode(bytes(32)).decode("ascii")}
    enrollment_response = {k: v for k, v in enrollment_request.items() if k != "csr"}
    enrollment_response.update(certificate="AQ==", chain=[])
    for doc in (enrollment_request, enrollment_response):
        validate(doc, schemas[BASE + "worker-enrollment.schema.json"])
    for mutation in [lambda d: d.update(credential="human-token"), lambda d: d.update(principal="admin"),
                     lambda d: d.update(callback="https://untrusted.invalid"), lambda d: d.update(epoch=24),
                     lambda d: d.update(nonce="A" * 42 + "B"), lambda d: d.update(nonce="A" * 43 + "\n"),
                     lambda d: d.update(csr=None), lambda d: d.update(csr="AQ=="),
                     lambda d: d.update(csr="x" * 10928), lambda d: d.pop("sessionID"),
                     lambda d: d.update(workerID="arbitrary")]:
        rejects(enrollment_request, "worker-enrollment", mutation)
    for mutation in [lambda d: d.update(chain=None), lambda d: d.update(chain=["AQ=="] * 4),
                     lambda d: d.update(chain=[""]), lambda d: d.update(certificate="x" * 21852),
                     lambda d: d.update(privateKey="forbidden"), lambda d: d.pop("chain")]:
        rejects(enrollment_response, "worker-enrollment", mutation)

    owner_relay = {"format": "asservat-owner-relay/v2", "enrollment": copy.deepcopy(enrollment_request),
                   "locator": {"requestID": enrollment_request["sessionID"], "podUID": enrollment_request["workerID"],
                               "processEpoch": enrollment_request["workerID"], "fence": 1,
                               "started": "2026-10-10T12:00:00Z", "until": "2026-10-10T12:00:20Z"}}
    validate(owner_relay, schemas[BASE + "owner-relay.schema.json"])
    for mutation in [lambda d: d.update(callback="https://untrusted.invalid"),
                     lambda d: d.update(credential="human-token"), lambda d: d.pop("locator"),
                     lambda d: d["locator"].update(fence=0), lambda d: d["locator"].update(fence=9007199254740992),
                     lambda d: d["locator"].update(processEpoch="invalid"), lambda d: d["locator"].pop("until"),
                     lambda d: d["locator"].update(until="never"), lambda d: d["locator"].update(address="10.0.0.1"),
                     lambda d: d["enrollment"].update(credential="human-token")]:
        rejects(owner_relay, "owner-relay", mutation)

    owner_response = {"format": "asservat-owner-relay/v2", "until": "2026-10-10T12:00:05Z",
                      "enrollment": copy.deepcopy(enrollment_response)}
    validate(owner_response, schemas[BASE + "owner-relay.schema.json"])
    for mutation in [lambda d: d.update(format="asservat-owner-relay/v1"), lambda d: d.pop("until"),
                     lambda d: d.update(until="never"), lambda d: d.update(renewalToken="forbidden"),
                     lambda d: d["enrollment"].update(chain=None), lambda d: d["enrollment"].pop("nonce")]:
        rejects(owner_response, "owner-relay", mutation)

    key_request = {"format": "asservat-local-key-rpc/v1", "scope": key_scope,
                   "authorityID": "00000000-0000-4000-8000-000000000002", "operation": "wrap",
                   "binding": "YmluZGluZw==", "input": "a2V5"}
    key_sealed = {"reference": f"asservat-local-keyset/v1/{local_key['installationID']}/artifact/synthetic-only/1",
                  "ciphertext": "Y2lwaGVydGV4dA=="}
    key_unwrap = copy.deepcopy(key_request)
    key_unwrap.pop("input")
    key_unwrap.update(operation="unwrap", sealed=key_sealed)
    key_sign = copy.deepcopy(key_request)
    key_sign.pop("binding")
    key_sign["scope"]["purpose"] = "policy-submission"
    key_sign.update(operation="sign", version=1)
    key_response = {"format": "asservat-local-key-rpc/v1", "operation": "wrap", "sealed": key_sealed,
                    "requestSHA256": "a" * 64, "validUntil": "2026-10-10T12:00:00Z"}
    key_opened = copy.deepcopy(key_response)
    key_opened.pop("sealed")
    key_opened.update(operation="unwrap", output="a2V5")
    key_signature = copy.deepcopy(key_opened)
    key_signature.update(operation="sign", output=base64.b64encode(bytes(range(64))).decode("ascii"))
    for doc in (key_request, key_unwrap, key_sign, key_response, key_opened, key_signature):
        validate(doc, schemas[BASE + "local-key-service.schema.json"])
    for mutation in (
        lambda d: d.update(format="wrong"),
        lambda d: d.update(operation="encrypt-payload"),
        lambda d: d.update(authorityID="00000000-0000-0000-0000-000000000000"),
        lambda d: d.update(input=None),
        lambda d: d.update(input="a2V5\n"),
        lambda d: d.update(input=base64.b64encode(bytes(4099)).decode("ascii")),
        lambda d: d.update(binding=base64.b64encode(bytes(2050)).decode("ascii")),
        lambda d: d.update(sealed={}),
        lambda d: d.update(version=1),
        lambda d: d.update(peer="forged"),
        lambda d: d["scope"].update(purpose="policy-submission"),
    ):
        rejects(key_request, "local-key-service", mutation)
    rejects(key_unwrap, "local-key-service", lambda d: d.update(input="a2V5"))
    rejects(key_unwrap, "local-key-service", lambda d: d.pop("sealed"))
    rejects(key_sign, "local-key-service", lambda d: d.update(binding="a2V5"))
    rejects(key_sign, "local-key-service", lambda d: d["scope"].update(purpose="artifact"))
    rejects(key_sign, "local-key-service", lambda d: d.update(version=0))
    rejects(key_response, "local-key-service", lambda d: d.update(output="a2V5"))
    rejects(key_opened, "local-key-service", lambda d: d.update(sealed={}))
    rejects(key_response, "local-key-service", lambda d: d.update(requestSHA256="A" * 64))
    rejects(key_response, "local-key-service", lambda d: d.update(validUntil="2026-10-10T12:00:00+00:00"))
    rejects(key_signature, "local-key-service", lambda d: d.update(output="a2V5"))

    rejects(examples["recipe-context.yaml"], "recipe", lambda d: d["spec"]["actions"][0].pop("limits"))
    rejects(examples["policy-deployment.yaml"], "policy", lambda d: d["spec"].update({"unlimited": True}))
    rejects(examples["share-extract.yaml"], "share", lambda d: d["spec"].update({"allowReshare": True}))
    rejects(examples["share-extract.yaml"], "share", lambda d: d["spec"]["operations"].append("read_memory"), True)
    rejects(examples["grant-policy.yaml"], "grant", lambda d: d["spec"].update({"approver": d["spec"]["requester"]}), True)
    rejects(examples["case-event.json"], "event", lambda d: d["data"].update({"logText": "sensitive"}))
    rejects(examples["mcp-backtrace-result.json"], "mcp-result", lambda d: d.update({"truncated": True, "narrowing_hint": None}))
    rejects(examples["recipe-pprof.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].pop("duration"))
    rejects(examples["recipe-pprof.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].update({"url": "http://unapproved.invalid"}))
    rejects(examples["recipe-pprof-template.yaml"], "recipe", lambda d: d["spec"]["endpointBindings"][0].update({"url": "http://unapproved.invalid"}))
    # ADR-201: the eBPF sampler is runtime "any", CPU only, with no endpoint fields.
    ebpf = examples["profile-metadata-ebpf.json"]
    rejects(ebpf, "profile", lambda d: d["acquisition"].update({"sourceRef": "api-local-pprof"}))
    rejects(ebpf, "profile", lambda d: d.update({"runtime": "go"}))
    rejects(ebpf, "profile", lambda d: d.pop("detectedRuntimes"))
    rejects(ebpf, "profile", lambda d: d.update({"profileType": "heap"}))
    rejects(examples["profile-metadata.json"], "profile", lambda d: d.update({"runtime": "any"}))
    rejects(examples["profile-metadata.json"], "profile", lambda d: d["acquisition"].update({"unattributedSamples": 1}))
    rejects(examples["recipe-pprof.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"]["source"].update({"kind": "ebpfSampler"}))
    rejects(examples["recipe-pprof.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].update({"runtime": "any"}))
    sampler = copy.deepcopy(examples["recipe-pprof.yaml"])
    sampler["spec"]["actions"][0]["parameters"].update({"runtime": "any", "source": {"kind": "ebpfSampler"}})
    validate(sampler, schemas[BASE + "recipe.schema.json"])
    rejects(examples["access-binding.yaml"], "access-binding", lambda d: d["spec"]["subjects"][0].pop("issuer"))
    rejects(examples["access-binding.yaml"], "access-binding", lambda d: d["spec"]["subjects"][0].update({"id": "*"}), True)
    for field, value in [("effect", "Deny"), ("roles", ["evidence-reader"]), ("subjects", [{"kind": "User", "issuer": "https://id.example.invalid", "id": "person"}])]:
        rejects(examples["access-binding-automation.yaml"], "access-binding", lambda d, f=field, v=value: d["spec"].update({f: v}))
    rejects(examples["access-binding-automation.yaml"], "access-binding", lambda d: d["spec"]["automation"].update({"maxLifetimeSeconds": 0}))
    rejects(examples["access-binding-automation.yaml"], "access-binding", lambda d: d["spec"]["automation"].update({"allowedActions": ["download"]}))
    rejects(examples["resolved-policy-scope.json"], "collection-scope", lambda d: d.pop("policyAuthority"))
    rejects(examples["resolved-policy-scope.json"], "collection-scope", lambda d: d["executor"].update({"subject": "policy:another"}), True)
    rejects(examples["resolved-policy-scope.json"], "collection-scope", lambda d: d["policyAuthority"]["delegation"].update({"uid": "other-binding"}), True)
    rejects(examples["grant-policy.yaml"], "grant", lambda d: d["spec"].pop("policyExecutor"))
    rejects(examples["permission-source-exec.yaml"], "permission-source", lambda d: d["spec"].update({"role": "action-approver"}))
    rejects(examples["permission-source-exec.yaml"], "permission-source", lambda d: d["spec"].pop("identityMappingRef"))
    rejects(examples["permission-source-exec.yaml"], "permission-source", lambda d: d["spec"].pop("admissionParity"))
    rejects(examples["permission-source-workload.yaml"], "permission-source", lambda d: d["spec"]["protection"].pop("guardRef"))
    rejects(examples["permission-source-workload.yaml"], "permission-source", lambda d: d["spec"]["metadataMapping"].pop("values"))
    rejects(examples["permission-source-namespace.yaml"], "permission-source", lambda d: d["spec"].update({"maxDecisionAgeSeconds": 600}))
    rejects(examples["manifest.json"], "manifest", lambda d: d.pop("accessProvenance"))
    rejects(examples["policy-preset.yaml"], "policy", lambda d: d["spec"]["presetRef"].update({"version": "latest"}))
    rejects(examples["capture-preset.yaml"], "capture", lambda d: d["spec"].update({"recipeRef": {"name": "unreviewed"}}))
    rejects(examples["retention-policy.yaml"], "retention-policy", lambda d: d["spec"]["maxima"].update({"evidenceSeconds": 0}))
    rejects(examples["retention-policy.yaml"], "retention-policy", lambda d: d["spec"]["rules"][1].update({"maxAgeSeconds": 60}), True)
    rejects(examples["manifest.json"], "manifest", lambda d: d.pop("privacy"))
    rejects(examples["manifest.json"], "manifest", lambda d: d["privacy"].update({"classification": "verifiedNonPersonal"}))
    rejects(examples["manifest.json"], "manifest", lambda d: d.update({"expiresAt": "2026-10-12T12:00:02Z"}), True)
    rejects(examples["manifest.json"], "manifest", lambda d: d["retention"].update({"deleteBy": "2026-10-10T18:00:00Z"}), True)
    rejects(examples["manifest.json"], "manifest", lambda d: d["retention"].pop("parentExpiresAt"), True)
    rejects(examples["storage-pool.yaml"], "storage-pool", lambda d: d["spec"]["protectedAllocations"][0].update({"workloadSlots": 5}), True)
    rejects(examples["storage-pool.yaml"], "storage-pool", lambda d: d["spec"]["sharedBurst"].update({"objects": 40001}), True)
    rejects(examples["budget-policy.yaml"], "budget-policy", lambda d: d["spec"]["workload"]["hardLimit"].update({"bytes": 1}), True)
    rejects(examples["budget-policy.yaml"], "budget-policy", lambda d: d["spec"]["workload"].update({"onFull": "EvictOtherWorkload"}))
    rejects(examples["capture-with-sharing.yaml"], "capture", lambda d: d["spec"]["sharing"].update({"futureCaptures": {"enabled": True, "maxCaptures": 10}}))
    rejects(examples["capture-with-sharing.yaml"], "capture", lambda d: d["spec"]["sharing"].update({"owner": intent["spec"]["createdBy"]}))
    rejects(examples["capture-with-sharing.yaml"], "capture", lambda d: d["spec"]["sharing"]["recipients"][0].update({"id": "*"}), True)
    rejects(examples["policy-with-sharing.yaml"], "policy", lambda d: d["spec"]["sharing"].pop("futureCaptures"))
    rejects(examples["policy-with-sharing.yaml"], "policy", lambda d: d["spec"]["sharing"].pop("notAfter"))
    rejects(examples["policy-with-sharing.yaml"], "policy", lambda d: d["spec"]["sharing"]["futureCaptures"].update({"maxCaptures": 101}))
    rejects(capture, "capture", lambda d: d["spec"]["sharing"]["outputSelection"]["outputs"][0]["operations"].append("read_memory"))
    rejects(capture, "capture", lambda d: d["spec"]["sharing"]["outputSelection"]["outputs"][0].pop("projectionRef"))
    rejects(capture, "capture", lambda d: d["spec"]["sharing"]["outputSelection"]["outputs"][1].pop("operations"))
    rejects(capture, "capture", lambda d: d["spec"]["sharing"]["outputSelection"]["outputs"][1].update({"operations": ["get_case"]}))
    rejects(intent, "sharing-intent", lambda d: d["spec"].update({"maxCaptures": 2}))
    rejects(intent, "sharing-intent", lambda d: d["spec"].update({"notAfter": "2026-10-17T12:00:00Z"}), True)
    rejects(intent, "sharing-intent", lambda d: d["status"].update({"registeredCaptures": 2}), True)
    rejects(intent, "sharing-intent", lambda d: d["status"]["selectionApprovals"][1].update({"phase": "Approved", "approvedBy": d["spec"]["createdBy"], "approvedAt": d["spec"]["acceptedAt"]}), True)
    rejects(examples["manifest-core.json"], "manifest", lambda d: d.pop("collectionProvenance"))

    rejects(examples["grant-policy.yaml"], "grant", lambda d: d.pop("status"))
    rejects(examples["share-extract.yaml"], "share", lambda d: d.pop("status"))
    rejects(intent, "sharing-intent", lambda d: d.update({"apiVersion": "asservat.io/v1alpha1"}))
    rejects(intent, "sharing-intent", lambda d: d["spec"].update({"owner": d["spec"]["createdBy"]}))
    rejects(intent, "sharing-intent", lambda d: d["spec"]["management"]["teams"][0]["subject"].update({"kind": "User"}))
    rejects(intent, "sharing-intent", lambda d: d["spec"]["management"]["teams"][0]["subject"].update({"id": "*"}), True)
    rejects(intent, "sharing-intent", lambda d: d["spec"]["management"]["teams"][0].pop("assignmentIDs"))
    rejects(intent, "sharing-intent", lambda d: d["spec"]["management"]["teams"][1].update({"assignmentIDs": d["spec"]["management"]["teams"][0]["assignmentIDs"]}), True)
    rejects(capture, "capture", lambda d: d["spec"]["sharing"].update({"createdBy": intent["spec"]["createdBy"]}))
    rejects(capture, "capture", lambda d: d["spec"]["sharing"]["management"]["teams"][0].update({"assignmentIDs": ["forged"]}))
    rejects(examples["grant-policy.yaml"], "grant", lambda d: d.update({"metadata": {"name": "forged", "namespace": "payments"}}))
    http_recipe = examples["recipe-http-headers.yaml"]
    raw_recipe = examples["recipe-packets-raw.yaml"]
    def packet_mutation(change):
        return lambda d: change(d["spec"]["actions"][0]["parameters"])
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p.update({"filter": " "})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p.update({"filter": "x" * 4097})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["ring"].update({"maxSegments": 5})), True)
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["ring"].update({"maxAge": "10s"})), True)
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["ring"].update({"medium": "encryptedDisk"})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["peers"].update({"entries": []})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["peers"].update({"maxStaleness": "10s"})), True)
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["peers"]["entries"][0]["resourceRef"].pop("serviceMode")))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["peers"]["entries"][1]["resourceRef"].update({"serviceMode": "both"})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["profile"].update({"snaplen": 100})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["profile"].update({"protocol": "https"})))
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p["profile"].update({"maxReassemblyBytes": 100})), True)
    rejects(http_recipe, "recipe", lambda d: d["spec"]["actions"][0].update({"impact": "observe"}), True)
    rejects(raw_recipe, "recipe", packet_mutation(lambda p: p["profile"].update({"snaplen": 0})))
    rejects(raw_recipe, "recipe", packet_mutation(lambda p: p["profile"].update({"snaplen": 65536})))
    rejects(raw_recipe, "recipe", packet_mutation(lambda p: p["profile"]["protocolSnaplen"].append({"protocol": "tcp", "bytes": 64})), True)

    rejects(examples["recipe-selected-process.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].pop("processIdentity"))
    rejects(examples["recipe-selected-process.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].update({"process": "podMainProcesses"}))
    rejects(examples["capture-manual.yaml"], "capture", lambda d: d["spec"]["target"].update({"namespace": "another-team"}), True)
    rejects(examples["policy-deployment.yaml"], "policy", lambda d: d["spec"]["target"].update({"workloadRef": {"kind": "Pod", "apiVersion": "v1", "name": "pod"}}), True)
    rejects(examples["policy-deployment.yaml"], "policy", lambda d: d["spec"]["target"].update({"containers": {"names": ["app"]}}))
    rejects(examples["policy-preset.yaml"], "policy", lambda d: d["spec"]["target"].update({"containerNames": ["app"]}))
    rejects(examples["policy-deployment.yaml"], "policy", lambda d: d["spec"]["target"].update({"ordinals": [0]}))
    rejects(examples["grant-policy.yaml"], "grant", lambda d: d["spec"].update({"grantType": "adHocCapture"}))
    rejects(examples["grant-ad-hoc.yaml"], "grant", lambda d: d["spec"]["target"].pop("captureUID"))
    rejects(examples["grant-policy.yaml"], "grant", lambda d: d["status"].update({"executionsReserved": 12, "executionsSpent": 1}), True)
    rejects(examples["grant-policy.yaml"], "grant", lambda d: d["spec"].update({"notAfter": "2027-10-09T12:00:00Z"}), True)
    rejects(examples["approval-policy.yaml"], "approval-policy", lambda d: d["policyGrants"].update({"defaultAgeSeconds": 31536000}), True)
    rejects(examples["policy-deployment.yaml"], "policy", lambda d: d["spec"]["detectors"][1]["options"].update({"sampleInterval": "1ms"}), True)
    rejects(examples["policy-statefulset.yaml"], "policy", lambda d: d["spec"]["when"]["for"].update({"duration": "999d"}), True)
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p.update({"before": "0s", "after": "0s"})), True)
    rejects(http_recipe, "recipe", packet_mutation(lambda p: p.update({"maxFrozenBytes": 268435456})), True)
    rejects(examples["recipe-pprof.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].update({"duration": "1h"}), True)

    rejects(examples["recipe-worker-pool.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"]["processSelector"].update({"match": {}}))
    rejects(examples["recipe-worker-pool.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"].pop("batch"))
    rejects(examples["recipe-worker-pool.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"]["batch"].update({"maxProcesses": 3}), True)
    rejects(examples["recipe-worker-pool.yaml"], "recipe", lambda d: d["spec"]["actions"][0]["parameters"]["processSelector"]["match"].update({"containerName": "app"}))
    rejects(examples["grant-packet-observation.yaml"], "grant", lambda d: d["status"].update({"observedBytesSpent": 1073741824, "observedBytesReserved": 1}), True)

    rejects(examples["manifest-core.json"], "manifest", lambda d: d["target"].pop("hostPID"))
    rejects(examples["manifest-pod.json"], "manifest", lambda d: d["target"].update({"containerID": "invented"}))
    framed = examples["manifest-framed.json"]
    rejects(framed, "manifest", lambda d: d.pop("storageObjects"))
    rejects(framed, "manifest", lambda d: d["encryption"].update({"format": "asservat-framed/v2"}))
    rejects(framed, "manifest", lambda d: d["encryption"]["binding"].update({"artifactID": "00000000-0000-4000-8000-000000000099"}), True)
    rejects(framed, "manifest", lambda d: d["encryption"]["pages"][0].update({"nativeOffset": 1}), True)
    rejects(framed, "manifest", lambda d: d["encryption"]["pages"][0].update({"indexOffset": 1}), True)
    rejects(framed, "manifest", lambda d: d["encryption"]["pages"][0].update({"dataBytes": 4353}), True)
    rejects(framed, "manifest", lambda d: d["encryption"].update({"nativeSHA256": "0"*64}), True)
    rejects(examples["framed-index-page.json"], "framed-storage", lambda d: d["frames"][0].update({"codec": "gzip"}))
    rejects(examples["framed-commit.json"], "framed-storage", lambda d: d.update({"namespace": "sensitive-name"}))

    def rejects_origin(mutate):
        nonlocal negative_checks
        share_copy, intent_copy, manifests_copy = copy.deepcopy((examples["share-from-capture.yaml"], intent, manifests))
        mutate(share_copy, intent_copy, manifests_copy)
        try:
            sharing_origin_checks(share_copy, intent_copy, manifests_copy)
        except ValueError:
            negative_checks += 1
            return
        raise ValueError("Invalid automatic share accepted")

    rejects_origin(lambda s, i, m: i["status"].update({"phase": "Revoked"}))
    rejects_origin(lambda s, i, m: i["status"]["selectionApprovals"][0].update({"phase": "PendingApproval"}))
    rejects_origin(lambda s, i, m: s["spec"]["operations"].append("read_memory"))
    rejects_origin(lambda s, i, m: s["spec"].update({"notAfter": "2026-10-10T12:00:00Z"}))
    rejects_origin(lambda s, i, m: s["spec"]["recipients"][0].update({"id": "another-group"}))
    rejects_origin(lambda s, i, m: m["00000000-0000-4000-8000-000000000004"]["collectionProvenance"].update({"captureUID": "foreign-capture"}))
    rejects_origin(lambda s, i, m: m["00000000-0000-4000-8000-000000000003"]["provenance"].update({"projectionDigest": "9" * 64}))

    def rejects_tool_input(name, doc):
        nonlocal negative_checks
        try:
            validate(doc, tools[name]["inputSchema"])
        except __import__("jsonschema").ValidationError:
            negative_checks += 1
            return
        raise ValueError("Invalid MCP input accepted: " + name)

    resolution_pair = examples["mcp-resolve-capture-input.json"]
    for extra in ({"target_ref": {}}, {"capture_id": intent["id"]}, {"force": True}, {"idempotency_key": ""}):
        rejects_tool_input("resolve_capture_request", {**resolution_pair, **extra})
    for missing in ("preview_id", "idempotency_key"):
        rejects_tool_input("resolve_capture_request", {k: v for k, v in resolution_pair.items() if k != missing})
    for data in ({"state": "pending"}, {"state": "accepted"}, {"state": "closed", "capture_id": intent["id"]}, {"state": "closed", "target_ref": {}}, {"state": "closed", "phase": "Pending"}, {"state": "closed", "operation": "collect"}):
        invalid = copy.deepcopy(examples["mcp-resolve-capture-closed.json"])
        invalid["data"] = data
        try:
            validate(invalid, tools["resolve_capture_request"]["outputSchema"])
        except __import__("jsonschema").ValidationError:
            negative_checks += 1
        else:
            raise ValueError("Invalid request disposition accepted")
    for extra in ({"warnings": ["private target"]}, {"data_class": "extract"}, {"next_cursor": "private cursor"}):
        invalid = {**examples["mcp-resolve-capture-closed.json"], **extra}
        try:
            validate(invalid, tools["resolve_capture_request"]["outputSchema"])
        except __import__("jsonschema").ValidationError:
            negative_checks += 1
        else:
            raise ValueError("Closed receipt exposed envelope metadata")
    invalid = copy.deepcopy(examples["mcp-resolve-capture-closed.json"])
    invalid["status"] = "pending"
    try:
        validate(invalid, tools["resolve_capture_request"]["outputSchema"])
    except __import__("jsonschema").ValidationError:
        negative_checks += 1
    else:
        raise ValueError("Pending request disposition accepted")

    rejects_tool_input("list_shares", {"view": "received", "include_intents": True})
    revoke = {"sharing_intent_id": intent["id"], "expected_revision": 1, "idempotency_key": "revoke-001"}
    validate(revoke, tools["revoke_share"]["inputSchema"])
    rejects_tool_input("revoke_share", {**revoke, "share_id": "00000000-0000-4000-8000-000000000033"})
    rejects_tool_input("get_http_headers", {"case_id": intent["id"], "artifact_id": intent["id"], "include_body": True})
    rejects_tool_input("request_capture", {**examples["mcp-preview-capture-input.json"], "reason": "silently changed"})
    rejects_tool_input("preview_capture", {**examples["mcp-preview-input.json"], "target_handle": "duplicate-target"})
    rejects_tool_input("preview_capture", {**examples["mcp-preview-input.json"], "container_name": "app"})
    rejects_tool_input("cancel_capture", {"capture_id": intent["id"], "idempotency_key": "x"})
    for mutate in (lambda d: d["data"]["records"][0].update({"body": "sensitive"}),
                   lambda d: d["data"]["records"][0]["headers"][0].update({"name": "authorization"}),
                   lambda d: d.update({"data_class": "raw"})):
        invalid = copy.deepcopy(examples["mcp-http-headers-result.json"])
        mutate(invalid)
        try:
            validate(invalid, tools["get_http_headers"]["outputSchema"])
        except __import__("jsonschema").ValidationError:
            negative_checks += 1
        else:
            raise ValueError("Invalid HTTP extract output accepted")
    def rejects_guidance(name, example, mutate, semantic=False):
        nonlocal negative_checks
        invalid = copy.deepcopy(examples[example])
        mutate(invalid)
        try:
            validate(invalid, tools[name]["outputSchema"])
            if semantic:
                semantic_checks(invalid)
        except (__import__("jsonschema").ValidationError, ValueError):
            negative_checks += 1
            return
        raise ValueError("Invalid guidance output accepted: " + example)

    rejects_tool_input("recommend_diagnostics", {"target_handle": "t", "goal": "network", "auto_capture": True})
    rejects_tool_input("recommend_diagnostics", {"target_handle": "t", "goal": "network", "focus": {"process_refs": ["p"]}})
    rejects_tool_input("recommend_diagnostics", {"target_handle": "t", "goal": "network", "discovery_capture_ids": [intent["id"]] * 5})
    rejects_tool_input("recommend_diagnostics", {"target_handle": "t", "goal": "network", "preferences": {"history_seconds": 0}})
    rejects_tool_input("get_target_discovery", {"capture_id": intent["id"], "section": "rawPackets"})
    rejects_tool_input("get_target_discovery", {"capture_id": intent["id"], "section": "flows", "container_name": "app"})
    valid_focus = {"target_handle": "t", "goal": "hang", "discovery_capture_ids": [intent["id"]], "focus": {"process_refs": ["p"]}}
    validate(valid_focus, tools["recommend_diagnostics"]["inputSchema"])
    rejects_guidance("get_target_discovery", "mcp-discovery-processes-result.json", lambda d: d.update({"data_class": "metadata"}))
    rejects_guidance("get_target_discovery", "mcp-discovery-processes-result.json", lambda d: d["data"]["processes"][0].update({"argv": ["secret"]}))
    rejects_guidance("get_target_discovery", "mcp-discovery-processes-result.json", lambda d: d["data"]["processes"][0].update({"observed_at": "2026-10-09T13:00:00Z"}), True)
    rejects_guidance("get_target_discovery", "mcp-discovery-flows-result.json", lambda d: d["data"]["flows"][0].update({"payload": "secret"}))
    rejects_guidance("get_target_discovery", "mcp-discovery-flows-result.json", lambda d: d["data"]["summary"].update({"capture_mode": "networkHeaders"}), True)
    rejects_guidance("get_target_discovery", "mcp-discovery-flows-result.json", lambda d: d["data"]["summary"]["coverage"].update({"dropped_packets": 1}), True)
    rejects_guidance("get_target_discovery", "mcp-discovery-flows-result.json", lambda d: d["data"]["summary"]["coverage"].update({"covered_pods": 2}), True)
    rejects_guidance("recommend_diagnostics", "mcp-recommend-result.json", lambda d: d["data"]["recommendations"][0]["ring_sizing"].update({"segments": 8}), True)
    rejects_guidance("recommend_diagnostics", "mcp-recommend-result.json", lambda d: d["data"]["recommendations"][0]["ring_sizing"].update({"retained_bytes_per_second": 0}))
    rejects_guidance("recommend_diagnostics", "mcp-recommend-result.json", lambda d: d["data"]["recommendations"][0]["packet_parameters"]["ring"].update({"maxBytes": 16777216}), True)
    rejects_guidance("recommend_diagnostics", "mcp-recommend-result.json", lambda d: d["data"]["recommendations"][0]["packet_parameters"].update({"profile": {"kind": "rawPackets", "snaplen": 2048}}), True)
    rejects_guidance("recommend_diagnostics", "mcp-recommend-result.json", lambda d: d["data"]["recommendations"][0].update({"auto_approved": True}))
    rejects_tool_input("recommend_diagnostics", {"target_handle": "t", "goal": "network", "preferences": {"max_ring_bytes": 0}})
    rejects_guidance("recommend_diagnostics", "mcp-recommend-processes-result.json", lambda d: d["data"]["recommendations"][0]["process_batch"].update({"maxProcesses": 3}), True)
    rejects_guidance("recommend_diagnostics", "mcp-recommend-processes-result.json", lambda d: d["data"]["recommendations"][0].update({"max_process_starts": 1}), True)
    rejects_guidance("recommend_diagnostics", "mcp-recommend-processes-result.json", lambda d: d["data"]["recommendations"][0].update({"process_match_count": 3, "blockers": []}), True)
    def rejects_history(name, example, mutate):
        nonlocal negative_checks
        invalid = copy.deepcopy(examples[example])
        mutate(invalid)
        try:
            validate(invalid, tools[name]["outputSchema"])
            semantic_checks(invalid)
        except (__import__("jsonschema").ValidationError, ValueError):
            negative_checks += 1
            return
        raise ValueError("Invalid history output accepted: " + example)

    repeat_input = examples["mcp-repeat-preview-input.json"]
    for override in ({"target_handle": "another-target"}, {"preset_ref": {"name": "incident-context", "version": "v1"}}, {"diagnostic_handle": "other-recipe"}, {"grant_id": intent["id"]}, {"idempotency_key": "old-operation"}):
        rejects_tool_input("preview_capture", {**repeat_input, **override})
    rejects_tool_input("list_capture_history", {"target_handle": "t", "cluster_id": intent["id"]})
    rejects_tool_input("list_capture_history", {"cluster_id": intent["id"]})
    rejects_tool_input("list_capture_history", {"target_handle": "t", "limit": 101})
    rejects_tool_input("get_capture_settings", {"capture_id": intent["id"], "include_credentials": True})
    rejects_tool_input("request_capture", {"history_capture_id": intent["id"], "idempotency_key": "bypass-preview"})
    rejects_tool_input("preview_capture", {**repeat_input, "repeated_from_capture_id": intent["id"]})
    validate({**examples["mcp-preview-input.json"], "repeated_from_capture_id": intent["id"]}, tools["preview_capture"]["inputSchema"])
    rejects_history("list_capture_history", "mcp-history-result.json", lambda d: d["data"]["history"][0].pop("settings_expires_at"))
    rejects_history("list_capture_history", "mcp-history-result.json", lambda d: d["data"]["history"][0].update({"repeated_from_capture_id": d["data"]["history"][0]["capture_id"]}))
    rejects_history("list_capture_history", "mcp-history-result.json", lambda d: d["data"]["history"][0].update({"settings_expires_at": "2027-01-01T00:00:00Z"}))
    rejects_history("list_capture_history", "mcp-history-result.json", lambda d: d["data"]["history"].append(copy.deepcopy(d["data"]["history"][0])))
    rejects_history("get_capture_settings", "mcp-capture-settings-result.json", lambda d: d["data"]["settings"].update({"grantRef": intent["id"]}))
    rejects_history("get_capture_settings", "mcp-capture-settings-result.json", lambda d: d["data"]["settings"].update({"sharing": {"recipients": []}}))
    rejects_history("get_capture_settings", "mcp-capture-settings-result.json", lambda d: d.update({"data_class": "metadata"}))
    rejects_history("get_capture_settings", "mcp-capture-settings-result.json", lambda d: d["data"].update({"settings_digest": "0" * 64}))
    rejects_history("get_capture_settings", "mcp-capture-settings-result.json", lambda d: d["data"].update({"expires_at": "2026-10-08T12:00:00Z"}))
    def corrupt_history_recipe_pin(d):
        d["data"]["settings"]["dependency_pins"][0]["digest"] = "0" * 64
        d["data"]["settings_digest"] = canonical_digest(d["data"]["settings"])
    rejects_history("get_capture_settings", "mcp-capture-settings-result.json", corrupt_history_recipe_pin)
    target = examples["mcp-capture-settings-result.json"]["data"]["settings"]["target"]
    grouping = history_selector_fixture_key("cluster-A", "namespace-A", target)
    changed = copy.deepcopy(target); changed["maxPods"] = 3
    require(history_selector_fixture_key("cluster-A", "namespace-A", changed) == grouping, "Pod cap splits workload history")
    changed["workloadRef"]["name"] = "display-name-change"
    require(history_selector_fixture_key("cluster-A", "namespace-A", changed) == grouping, "Display name defines history identity")
    changed["workloadRef"]["uid"] = "new-workload"
    require(history_selector_fixture_key("cluster-A", "namespace-A", changed) != grouping, "Workload recreation inherits history")
    require(history_selector_fixture_key("cluster-A", "namespace-B", target) != grouping, "Namespace recreation inherits history")
    require(history_selector_fixture_key("cluster-B", "namespace-A", target) != grouping, "Another cluster inherits history")
    labels = {"podSelector": {"matchLabels": {"app": "ledger", "role": "worker"}}}
    reverse = {"podSelector": {"matchLabels": {"role": "worker", "app": "ledger"}}}
    require(history_selector_fixture_key("cluster-A", "namespace-A", labels) == history_selector_fixture_key("cluster-A", "namespace-A", reverse), "Label order splits selector history")
    reverse["podSelector"]["matchLabels"]["role"] = "proxy"
    require(history_selector_fixture_key("cluster-A", "namespace-A", labels) != history_selector_fixture_key("cluster-A", "namespace-A", reverse), "Different selector inherits history")
    # Composition fixtures are a contract compiler, not production scheduling/authorization tests.
    def rejects_composition(mutate, sources=None):
        nonlocal negative_checks
        invalid = copy.deepcopy(composition)
        mutate(invalid)
        try:
            compile_checked(invalid, sources)
        except (ValueError, __import__("jsonschema").ValidationError):
            negative_checks += 1
            return
        raise ValueError("Invalid composition accepted")
    rejects_composition(lambda d: d["components"].append(copy.deepcopy(d["components"][0])))
    rejects_composition(lambda d: d["components"][0]["profileRef"].update({"version": "latest"}))
    rejects_composition(lambda d: d["components"][0]["profileRef"].update({"version": "v999"}))
    rejects_composition(lambda d: d["components"][0]["overrides"][0].update({"field": "impact", "value": "observe"}))
    rejects_composition(lambda d: d["components"][0]["overrides"][0].update({"actionID": "missing"}))
    rejects_composition(lambda d: d["components"][0]["overrides"][0].update({"field": "commandArgv", "value": ["/bin/false"]}))
    rejects_composition(lambda d: d["components"][0]["overrides"][0].update({"value": 42}))
    rejects_composition(lambda d: d["components"][0]["overrides"].append(copy.deepcopy(d["components"][0]["overrides"][0])))
    rejects_composition(lambda d: d.update({"maxTotalBytes": 1}))
    rejects_composition(lambda d: d.update({"maxDuration": "1s"}))
    rejects_composition(lambda d: d.update({"components": d["components"] * 3}))
    disabled = copy.deepcopy(profile_catalog)
    disabled[("builtin", "http-headers", "v1")]["spec"]["availability"]["enabled"] = False
    rejects_composition(lambda d: None, disabled)
    def duplicate_expensive(d):
        item = copy.deepcopy(d["components"][0]); item["id"] = "again"; d["components"].append(item)
    rejects_composition(duplicate_expensive)
    def two_cpu(d):
        d.update({"components": [{"id": name, "profileRef": {"catalog": "builtin", "name": "go-cpu", "version": "v1"}} for name in ("first", "second")]})
    rejects_composition(two_cpu)
    dependency_sources = copy.deepcopy(profile_catalog)
    definition = dependency_sources[("builtin", "go-cpu", "v1")]["spec"]["definition"]
    context_action = copy.deepcopy(profile_catalog[("builtin", "process-context", "v1")]["spec"]["definition"]["recipe"]["actions"][0])
    definition["recipe"]["actions"].insert(0, context_action)
    definition["recipe"]["actions"][1]["dependsOn"] = [context_action["id"]]
    definition["recipe"]["maxTotalBytes"] += context_action["limits"]["maxBytes"]
    rejects_composition(two_cpu, dependency_sources)

    # The two independent process/socket snapshots share acquisitions, preserving four aliases.
    repeated_context = copy.deepcopy(composition)
    repeated_context["components"] = [{"id": name, "profileRef": {"catalog": "builtin", "name": "process-context", "version": "v1"}} for name in ("first", "second")]
    folded, aliases = compile_checked(repeated_context)
    require(len(folded["actions"]) == 2 and len(aliases["actionMap"]) == 4 and sum(a["deduplicated"] for a in aliases["actionMap"]) == 2, "Context deduplication lost acquisition/alias identity")
    require(all(a["required"] for a in folded["actions"] if a["kind"] == "processSnapshot"), "Dedup weakened required context")
    cpu = {**repeated_context, "components": [{"id": "cpu", "profileRef": {"catalog": "builtin", "name": "go-cpu", "version": "v1"}}]}
    cpu_recipe, _ = compile_checked(cpu)
    require(cpu_recipe["actions"][0]["parameters"]["source"]["profileRef"] == cpu_recipe["endpointBindings"][0]["name"], "Expanded endpoint reference is dangling")
    # Check the expanded action ceiling independently of the eight-component ceiling.
    many_sources = copy.deepcopy(profile_catalog)
    first, second = [], []
    for group, destination in ((0, first), (1, second)):
        for i in range(9):
            action = copy.deepcopy(profile_catalog[("builtin", "process-context", "v1")]["spec"]["definition"]["recipe"]["actions"][0])
            action["id"] = "snapshot-" + str(i)
            action["limits"]["maxBytes"] += group * 100 + i
            destination.append(action)
    for name, actions in (("nine-first", first), ("nine-second", second)):
        definition = copy.deepcopy(many_sources[("builtin", "process-context", "v1")])
        definition["spec"].update({"name": name})
        definition["spec"]["definition"].update({"recipe": {"description": "Distinct synthetic context snapshots.", "actions": actions, "maxTotalBytes": 16777216, "maxDuration": "20s"}, "editableFields": []})
        many_sources[("builtin", name, "v1")] = definition
    def too_many(d):
        d["components"] = [{"id": name, "profileRef": {"catalog": "builtin", "name": name, "version": "v1"}} for name in ("nine-first", "nine-second")]
    rejects_composition(too_many, many_sources)
    rejects(examples["capture-profile-syscall-activity.yaml"], "capture-profile", lambda d: d["spec"]["definition"]["recipe"].update({"profileComposition": composition}))
    rejects(examples["capture-profile-syscall-activity.yaml"], "capture-profile", lambda d: d["spec"]["definition"]["editableFields"][0].update({"actionID": "missing"}), True)
    rejects(examples["capture-profile-syscall-activity.yaml"], "capture-profile", lambda d: d["spec"]["definition"]["editableFields"].append(copy.deepcopy(d["spec"]["definition"]["editableFields"][0])), True)
    rejects(examples["capture-composed.yaml"], "capture", lambda d: d["spec"].update({"recipeRef": examples["capture-manual.yaml"]["spec"]["recipeRef"]}))
    rejects(examples["policy-composed.yaml"], "policy", lambda d: d["spec"].update({"presetRef": {"name": "workload-failure", "version": "v1"}}))
    rejects_tool_input("preview_capture", {**examples["mcp-composition-preview-input.json"], "diagnostic_handle": "another-plan"})
    rejects_tool_input("preview_capture", {**repeat_input, "profile_composition": composition})
    rejects_tool_input("list_capture_profiles", {"target_handle": "t", "limit": 101})
    rejects_tool_input("get_capture_profile", {"target_handle": "t", "profile_ref": {"catalog": "builtin", "name": "go-cpu", "version": "latest"}})
    def syscall_change(change):
        return lambda d: change(d["spec"]["actions"][0]["parameters"])
    argument_recipe = examples["recipe-syscall-arguments.yaml"]
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p.update({"mode": "metadata"})))
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p.pop("arguments")))
    rejects(argument_recipe, "recipe", lambda d: d["spec"]["actions"][0].update({"impact": "observe"}), True)
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p.update({"processes": "hostProcesses"})))
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p.update({"before": "0s", "after": "0s"})), True)
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p.update({"after": "61s"})), True)
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p["ring"].update({"maxSegments": 8})), True)
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p.update({"maxFrozenBytes": 1})), True)
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p["arguments"].update({"maxBytesPerEvent": 4097})))
    rejects(argument_recipe, "recipe", syscall_change(lambda p: p["syscalls"].update({"names": ["write", "write"]})))
    rejects_tool_input("syscall_query", {k: v for k, v in examples["mcp-syscall-query-input.json"].items() if k != "grant_id"})
    rejects_tool_input("get_syscall_events", {"case_id": intent["id"], "artifact_id": intent["id"], "include_arguments": True})
    rejects_guidance("get_syscall_events", "mcp-syscall-events-result.json", lambda d: d["data"]["events"][0].update({"arguments": []}))
    rejects_guidance("get_syscall_summary", "mcp-syscall-summary-result.json", lambda d: d["data"]["rows"][0].update({"errors": 11}), True)
    rejects_guidance("syscall_query", "mcp-syscall-query-result.json", lambda d: d.update({"data_class": "extract"}))
    rejects(examples["share-extract.yaml"], "share", lambda d: d["spec"]["operations"].append("syscall_query"), True)
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d.update({"data_class": "metadata"}))
    # Event grants and profile identity changes need independent evidence from output limits.
    event_grant = copy.deepcopy(examples["grant-packet-observation.yaml"])
    event_grant["spec"]["observationLimits"]["maxObservedEvents"] = 100
    event_grant["status"].update({"observedEventsReserved": 50, "observedEventsSpent": 50})
    validate(event_grant, schemas[BASE + "grant.schema.json"]); semantic_checks(event_grant)
    rejects(event_grant, "grant", lambda d: d["status"].update({"observedEventsSpent": 51}), True)
    rejects(event_grant, "grant", lambda d: d["status"].pop("observedEventsReserved"))
    rejects(event_grant, "grant", lambda d: d["spec"]["observationLimits"].pop("maxObservedEvents"), True)
    changed_profile = copy.deepcopy(profile_catalog[("builtin", "go-cpu", "v1")])
    prior_digest = capture_profile_definition_digest(changed_profile)
    changed_profile["spec"]["availability"] = {"enabled": False, "deprecated": True}
    require(capture_profile_definition_digest(changed_profile) == prior_digest, "Availability mutates immutable definition identity")
    changed_profile["spec"]["definition"]["recipe"]["actions"][0]["parameters"]["duration"] = "11s"
    require(capture_profile_definition_digest(changed_profile) != prior_digest, "Action edit leaves definition identity unchanged")
    rejects(composed_scope, "collection-scope", lambda d: d.pop("profileComposition"), True)
    rejects(composed_scope, "collection-scope", lambda d: next(p for p in d["dependencies"] if p["role"] == "captureProfile").pop("source"))
    rejects(composed_scope, "collection-scope", lambda d: next(p for p in d["dependencies"] if p["role"] == "captureProfile")["source"].update({"namespaceUID": "replacement-namespace"}), True)
    # Both approved metadata projections are permitted in explicit extract selections.
    share_request = copy.deepcopy(examples["capture-with-sharing.yaml"])
    share_request["spec"]["sharing"]["outputSelection"] = {"mode": "explicit", "outputs": [{"actionID": "syscalls", "dataClass": "extract", "projectionRef": {"name": "syscall-metadata", "version": "v1"}, "operations": ["get_syscall_summary", "get_syscall_events"]}]}
    validate(share_request, schemas[BASE + "capture.schema.json"])
    rejects(share_request, "capture", lambda d: d["spec"]["sharing"]["outputSelection"]["outputs"][0]["operations"].append("syscall_query"))
    # Lifecycle categories, invalid phase dependencies and history claims.
    mixed_recipe = examples["recipe-trigger-lifecycles.yaml"]
    rejects(mixed_recipe, "recipe", lambda d: d["spec"]["actions"][2].update({"executionMode": "ongoing"}))
    rejects(mixed_recipe, "recipe", lambda d: d["spec"]["actions"][0].update({"executionMode": "onTrigger"}))
    rejects(mixed_recipe, "recipe", lambda d: d["spec"]["actions"][1].update({"executionMode": "periodic"}))
    rejects(mixed_recipe, "recipe", lambda d: d["spec"]["actions"][0].update({"dependsOn": ["core"]}))
    def implicit_ongoing_dependency(d):
        d["spec"]["actions"][0].pop("executionMode")
        d["spec"]["actions"][0]["dependsOn"] = ["core"]
    rejects(mixed_recipe, "recipe", implicit_ongoing_dependency)
    rejects(examples["recipe-pprof-template.yaml"], "recipe", lambda d: d["spec"]["actions"][0].update({"executionMode": "ongoing"}))
    rejects(examples["recipe-intrusive.yaml"], "recipe", lambda d: next(a for a in d["spec"]["actions"] if a["kind"] == "command").update({"executionMode": "ongoing"}))
    rejects(examples["recipe-basic-context.yaml"], "recipe", lambda d: next(a for a in d["spec"]["actions"] if a["kind"] == "logs").update({"executionMode": "ongoing"}))
    rejects(examples["recipe-post-trigger-only.yaml"], "recipe", lambda d: d["spec"]["actions"][1]["parameters"].update({"before": "1s"}))
    # Post-trigger snapshots can wait on a particular saved window; source startup cannot.
    waiting = copy.deepcopy(mixed_recipe)
    waiting["spec"]["actions"][2]["dependsOn"] = ["traffic"]
    validate(waiting, schemas[BASE + "recipe.schema.json"]); semantic_checks(waiting)
    # A zero lookback remains an explicitly ongoing source, not an implicit mode switch.
    zero_history = copy.deepcopy(mixed_recipe)
    zero_history["spec"]["actions"][0]["parameters"]["before"] = "0s"
    require(action_lifecycle_plan_fixture(zero_history["spec"], "DebugPolicy")["actions"][0]["activation"] == "policyArming", "Zero history silently changes activation")
    rejects(examples["lifecycle-plan-policy.json"], "action-lifecycle", lambda d: d["actions"][0].update({"activation": "manualSession"}))
    rejects(examples["lifecycle-plan-manual.json"], "action-lifecycle", lambda d: d["actions"][0].update({"activation": "policyArming"}))
    rejects(examples["lifecycle-plan-policy.json"], "action-lifecycle", lambda d: d.update({"ongoingPodScope": "acceptedCapturePods"}))
    rejects(examples["lifecycle-plan-policy.json"], "action-lifecycle", lambda d: d.update({"ongoingPodScope": "none"}), True)
    rejects(examples["lifecycle-plan-policy.json"], "action-lifecycle", lambda d: d["actions"].append(d["actions"][0]), True)
    rejects(examples["lifecycle-plan-policy.json"], "action-lifecycle", lambda d: d["actions"][0].update({"kind": "liveCore"}))
    rejects(examples["lifecycle-snapshot.json"], "action-lifecycle", lambda d: d.pop("sourceSessionID"))
    rejects(examples["lifecycle-snapshot.json"], "action-lifecycle", lambda d: d.update({"sourceStartedAt": "2026-10-09T12:00:25Z"}), True)
    rejects(examples["lifecycle-snapshot.json"], "action-lifecycle", lambda d: d.update({"executionMode": "onTrigger"}))
    rejects(examples["lifecycle-snapshot.json"], "action-lifecycle", lambda d: d.update({"gapReasons": ["sourceLost"]}), True)
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d["data"].pop("lifecycle_plan"))
    rejects_guidance("list_capture_profiles", "mcp-profiles-result.json", lambda d: d["data"]["profiles"][0].pop("execution_modes"))
    # A typed profile-mode change cannot leave a positive before window behind.
    def mode_only_edit(d):
        d["components"][0]["overrides"].append({"actionID": "http", "field": "actionExecutionMode", "value": "onTrigger"})
    rejects_composition(mode_only_edit)
    future_only = copy.deepcopy(composition)
    mode_only_edit(future_only)
    future_only["components"][0]["overrides"].append({"actionID": "http", "field": "packetBefore", "value": "0s"})
    future_recipe, _ = compile_checked(future_only)
    require(future_recipe["actions"][0]["executionMode"] == "onTrigger", "Typed lifecycle override lost")
    rejects(examples["lifecycle-plan-post-trigger.json"], "action-lifecycle", lambda d: d["actions"][0].update({"requestedBefore": "30s"}))
    rejects(examples["lifecycle-plan-post-trigger.json"], "action-lifecycle", lambda d: d["actions"][0].pop("after"))
    for name in ["mcp-backtrace-result.json", "mcp-discovery-flows-result.json", "mcp-discovery-processes-result.json", "mcp-http-headers-result.json", "mcp-profile-result.json", "mcp-syscall-events-result.json", "mcp-syscall-query-result.json", "mcp-syscall-summary-result.json"]:
        require(any(w.startswith("SensitiveDataHandling:") and "cannot be recalled" in w for w in examples[name]["warnings"]), "Direct evidence fixture lost handling reminder")
    # Final review: bind concrete ad hoc pods, complete windows and acquisition identity.
    scope = examples["resolved-capture-scope.json"]
    context_scope = examples["resolved-context-scope.json"]
    require(context_scope["collection"]["spec"]["recipeRef"]["digest"] == canonical_digest(examples["recipe-pod-status.json"]["spec"]), "Compiled context recipe digest mismatch")
    api_scope = copy.deepcopy(context_scope)
    api_scope["podBindings"] = [{"podUID": context_scope["podBindings"][0]["podUID"], "executionClass": "kubernetesAPI"}]
    validate(api_scope, schemas[BASE + "collection-scope.schema.json"])
    semantic_checks(api_scope)
    rejects(api_scope, "collection-scope", lambda d: d["podBindings"][0].pop("executionClass"))
    for field in ("nodeUID", "nodeBootID"):
        rejects(api_scope, "collection-scope", lambda d, f=field: d["podBindings"][0].update({f: "00000000-0000-4000-8000-000000000999"}))
    rejects(api_scope, "collection-scope", lambda d: d["collection"]["spec"]["recipeRef"].update({"name": "different-recipe"}))
    rejects(api_scope, "collection-scope", lambda d: d["collection"]["spec"]["target"].update({"maxPods": 2}))
    rejects(api_scope, "collection-scope", lambda d: d["podBindings"].append({"podUID": "another-pod", "executionClass": "kubernetesAPI"}))
    rejects(context_scope, "collection-scope", lambda d: d.pop("effectiveRetention"), True)
    rejects(context_scope, "collection-scope", lambda d: d["effectiveRetention"][0].update({"deletionBudgetSeconds": 86400}), True)
    rejects(context_scope, "collection-scope", lambda d: d["effectiveRetention"][0].update({"privacyClass": "verifiedNonPersonal"}), True)
    rejects(context_scope, "collection-scope", lambda d: d["effectiveRetention"][0]["policyRefs"].append({**d["effectiveRetention"][0]["policyRefs"][0], "generation": 2}), True)
    rejects(context_scope, "collection-scope", lambda d: d["effectiveRetention"][0]["policyRefs"][0].update({"digest": "f"*64}), True)
    rejects(context_scope, "collection-scope", lambda d: d["collection"]["spec"].update({"retention": "7200s"}), True)
    rejects(scope, "collection-scope", lambda d: d.pop("podBindings"))
    rejects(scope, "collection-scope", lambda d: d["podBindings"].append({**d["podBindings"][0], "nodeUID": "another-node"}), True)
    rejects(scope, "collection-scope", lambda d: d["podBindings"].append({**d["podBindings"][0], "podUID": "z-extra-pod"}), True)
    rejects(examples["resolved-policy-scope.json"], "collection-scope", lambda d: d.update({"podBindings": scope["podBindings"]}))
    for field in ("podUID", "nodeUID", "nodeBootID"):
        replacement = copy.deepcopy(scope)
        replacement["podBindings"][0][field] = "00000000-0000-4000-8000-000000000999"
        require(canonical_digest(replacement) != canonical_digest(scope), "Pod replacement retained manual approval identity")
    rejects(examples["manifest-core.json"], "manifest", lambda d: d.update({"target": examples["manifest-pod.json"]["target"]}))
    rejects(examples["manifest-core.json"], "manifest", lambda d: d.pop("actionLifecycle"))
    rejects(examples["recipe-basic-context.yaml"], "recipe", lambda d: next(a for a in d["spec"]["actions"] if a["kind"] == "logs")["parameters"].update({"after": "5m"}), True)
    for metric in ("cpuThrottledRatio", "memoryPSI", "cpuPSI", "ioPSI"):
        rejects(examples["policy-statefulset.yaml"], "policy", lambda d, m=metric: d["spec"]["detectors"][0]["options"].update({"metric": m, "threshold": 1.1}))
    rejects(examples["policy-statefulset.yaml"], "policy", lambda d: d["spec"]["detectors"][0].update({"kind": "manual", "options": {}}))
    retired = examples["lifecycle-snapshot-retired.json"]
    rejects(retired, "action-lifecycle", lambda d: d.update({"windowCoverage": "full"}), True)
    rejects(retired, "action-lifecycle", lambda d: d.update({"sourceStoppedAt": "2026-10-09T12:00:29Z"}), True)
    rejects(retired, "action-lifecycle", lambda d: d.pop("windowCoverage"))
    rejects(retired, "action-lifecycle", lambda d: d.update({"sourceStoppedAt": "2026-10-09T11:59:00Z"}), True)
    # Recording saves cannot turn into collection, expand audience input or replay old sessions.
    zero_history_inventory = copy.deepcopy(examples["mcp-recordings-result.json"])
    zero_history_inventory["data"]["recordings"][0].update({"maximum_before": "0s", "available_before_seconds": 0, "save_eligible": False, "blockers": ["NoHistoryConfigured"]})
    validate(zero_history_inventory, tools["list_recordings"]["outputSchema"]); semantic_checks(zero_history_inventory)
    rejects_guidance("list_recordings", "mcp-recordings-result.json", lambda d: d["data"]["recordings"][0].update({"maximum_before": "0s"}), True)
    for field in ("after", "argv", "grant_id", "executor", "filter", "target"):
        rejects_tool_input("preview_recording_save", {**examples["mcp-recording-save-preview-input.json"], field: "forbidden"})
    rejects_tool_input("preview_recording_save", {"recording_handles": []})
    rejects_tool_input("preview_recording_save", {"recording_handles": ["same", "same"]})
    rejects_tool_input("preview_recording_save", {"recording_handles": [str(i) for i in range(17)]})
    rejects_tool_input("preview_recording_save", {"recording_handles": ["opaque"], "before": "0s"})
    rejects_tool_input("list_recordings", {"target_handle": "opaque", "include_payload": True})
    rejects_tool_input("request_capture", {**examples["mcp-recording-save-input.json"], "recipe_digest": "f"*64})
    rejects_tool_input("request_capture", {**examples["mcp-recording-save-input.json"], "after": "10s"})
    rs = examples["resolved-recording-save.json"]
    rejects(rs, "recording-save", lambda d: d["sources"][0].update({"kind": "liveCore"}))
    rejects(rs, "recording-save", lambda d: d["sources"][0].update({"after": "1s"}))
    rejects(rs, "recording-save", lambda d: d["sources"][0].pop("nodeBootID"))
    rejects(rs, "recording-save", lambda d: d["sources"][0].update({"argv": ["/bin/sh"]}))
    rejects(rs, "recording-save", lambda d: d["sources"][1].update({"sourceSessionID": d["sources"][0]["sourceSessionID"]}), True)
    rejects(rs, "recording-save", lambda d: d["sources"][1].update({"actionID": d["sources"][0]["actionID"]}), True)
    rejects(rs, "recording-save", lambda d: d["sources"][1].update({"podUID": "another-pod"}), True)
    rejects(rs, "recording-save", lambda d: d["dependencies"][1].update({"role": "collectionCeiling"}), True)
    rejects(rs, "recording-save", lambda d: d.update({"finalizeTimeout": "1d"}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"]["windows"][0].update({"before": "1h"}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"]["selected_recordings"][1].update({"policy_uid": "another-policy"}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"]["windows"].pop(), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"].update({"save_scope_digest": "0"*64}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"]["selected_recordings"][0].update({"handle_expires_at": "2026-10-09T12:10:00Z"}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"]["selected_recordings"][0].update({"save_eligible": False}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"]["capture_assessment"]["actions"][0].update({"executionMode": "onTrigger"}), True)
    rejects_guidance("preview_recording_save", "mcp-recording-save-preview-result.json", lambda d: d["data"].pop("capture_assessment"))
    rejects(examples["lifecycle-recording-save.json"], "action-lifecycle", lambda d: d.pop("recordingSaveOrigin"))
    rejects(examples["lifecycle-recording-save.json"], "action-lifecycle", lambda d: d.update({"triggerKind": "manual"}))
    rejects(examples["lifecycle-recording-save.json"], "action-lifecycle", lambda d: d.update({"after": "10s"}))
    rejects_guidance("get_capture_settings", "mcp-recording-save-settings-result.json", lambda d: d["data"]["settings"].update({"sourceSessionID": "expired"}))
    rejects_guidance("get_capture_settings", "mcp-recording-save-settings-result.json", lambda d: d["data"].update({"settings_digest": "0"*64}), True)
    rejects_guidance("list_capture_history", "mcp-recording-save-history-result.json", lambda d: d["data"]["history"][0].update({"action_kinds": ["liveCore"]}))
    rejects_guidance("list_capture_history", "mcp-recording-save-history-result.json", lambda d: d["data"]["history"][0].update({"repeat_state": "available"}))
    report = examples["assessment-mixed-policy.json"]
    rejects(report, "capture-assessment", lambda d: d["combinedImpact"].update({"level": "low"}), True)
    rejects(report, "capture-assessment", lambda d: d["combinedImpact"].update({"hasUnknowns": False}), True)
    rejects(report, "capture-assessment", lambda d: d["combinedImpact"].update({"effects": []}), True)
    rejects(report, "capture-assessment", lambda d: d["actions"].append(d["actions"][0]), True)
    rejects(report, "capture-assessment", lambda d: d["alternatives"][0].update({"actionIDs": ["another-workload"]}), True)
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["data"].update({"classification": "verifiedNonPersonal"}))
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["data"].update({"transientOnly": d["actions"][0]["data"]["retainedPossible"]}), True)
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["retention"].update({"accessAgeSeconds": 86400}), True)
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["retention"].update({"deleteAgeSeconds": 999999}), True)
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["retention"].update({"anchorRule": "uploadCompletion"}))
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["retention"].update({"managedCopiesOnly": False}))
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["quantities"][0].update({"basis": "qualifiedMeasurement"}))
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["quantities"][0].update({"lower": 9999999999}), True)
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["quantities"][0].pop("sourceRef"))
    rejects(report, "capture-assessment", lambda d: d["actions"][0]["quantities"][0].pop("coverage"))
    rejects(report, "capture-assessment", lambda d: d.update({"validUntil": "2026-10-09T12:06:00Z"}), True)
    rejects(report, "capture-assessment", lambda d: d["basis"].update({"metrics": {"state": "fresh", "observedAt": "2026-10-09T11:55:00Z"}}), True)
    rejects(report, "capture-assessment", lambda d: d["basis"].update({"metrics": {"state": "fresh", "observedAt": "2026-10-09T12:01:00Z"}}), True)
    rejects(report, "capture-assessment", lambda d: d["basis"].update({"metrics": {"state": "fresh"}}))
    rejects(report, "capture-assessment", lambda d: d["handlingCodes"].remove("externalCopiesNotRecalled"))
    rejects(examples["assessment-unknown-command.json"], "capture-assessment", lambda d: d["actions"][0]["impact"].update({"hasUnknowns": False}))
    rejects(examples["assessment-unknown-command.json"], "capture-assessment", lambda d: d["scope"].update({"observationPods": 10}), True)
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d["data"].pop("capture_assessment"))
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d["data"]["capture_assessment"].update({"planDigest": "0"*64}), True)
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d["data"]["capture_assessment"]["actions"].pop(), True)
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d["data"]["capture_assessment"]["scope"].update({"incidentPods": 2}), True)
    rejects_guidance("preview_capture", "mcp-composition-preview-result.json", lambda d: d["data"]["capture_assessment"]["interactions"][0].update({"blocking": True}), True)
    # Fixed pod-status preset remains distinct from broader presets and profiles.
    narrow = examples["mcp-pod-status-preview-input.json"]
    for kind, name in (("Deployment", "api"), ("StatefulSet", "api"), ("Pod", "api-a")):
        variant = copy.deepcopy(narrow)
        variant["target_ref"].update({"kind": kind, "name": name})
        validate(variant, tools["preview_capture"]["inputSchema"])
    validate({"target_handle": "existing-scoped-handle"}, tools["list_diagnostics"]["inputSchema"])
    direct = copy.deepcopy(examples["mcp-pod-status-preview-result.json"])
    direct["data"]["target_ref"].update({"kind": "Pod", "name": "api-a"})
    direct["data"]["pod_selection"] = "explicitPod"
    validate(direct, tools["preview_capture"]["outputSchema"])
    semantic_checks(direct)  # Direct Pod keeps its actual Deployment budget identity.
    legacy_catalog = copy.deepcopy(examples["mcp-pod-status-diagnostics-result.json"])
    legacy_row = legacy_catalog["data"]["diagnostics"][0]
    legacy_row.pop("preset_ref")
    legacy_row["diagnostic_handle"] = "existing-scoped-diagnostic"
    validate(legacy_catalog, tools["list_diagnostics"]["outputSchema"])
    rejects_tool_input("list_diagnostics", {})
    rejects_tool_input("list_diagnostics", {**examples["mcp-pod-status-diagnostics-input.json"], "target_handle": "ambiguous"})
    for seconds in (1, 315360000):
        validate({**narrow, "requested_retention_seconds": seconds}, tools["preview_capture"]["inputSchema"])
    defaults = copy.deepcopy(narrow)
    defaults.pop("requested_retention_seconds")
    validate(defaults, tools["preview_capture"]["inputSchema"])
    for seconds in (0, -1, 315360001, 1.5, None, True, "3600"):
        rejects_tool_input("preview_capture", {**narrow, "requested_retention_seconds": seconds})
    rejects_tool_input("preview_capture", {"history_capture_id": intent["id"], "requested_retention_seconds": 60})
    validate({**narrow, "repeated_from_capture_id": intent["id"]}, tools["preview_capture"]["inputSchema"])
    rejects_tool_input("request_capture", {"preview_id": intent["id"], "idempotency_key": "same-review", "requested_retention_seconds": 60})
    for extra in ({"diagnostic_handle": "another-diagnostic"}, {"profile_composition": examples["mcp-composition-preview-input.json"]["profile_composition"]}, {"history_capture_id": intent["id"]}, {"container_name": "app"}):
        rejects_tool_input("preview_capture", {**narrow, **extra})
    rejects_tool_input("preview_capture", {**narrow, "preset_ref": {"name": "pod-status", "version": "latest"}})
    rejects_tool_input("preview_capture", {**narrow, "preset_ref": {"name": "builtin-pod-status-v1", "version": "v1"}})
    forged = copy.deepcopy(narrow)
    forged["target_ref"]["uid"] = "caller-selected-identity"
    rejects_tool_input("preview_capture", forged)
    rejects(examples["capture-pod-status-preset.json"], "capture", lambda d: d["spec"]["target"].update({"maxPods": 2}))
    rejects(examples["capture-preset.yaml"], "capture", lambda d: d["spec"]["target"]["workloadRef"].update({"kind": "Pod"}))
    rejects_guidance("list_diagnostics", "mcp-pod-status-diagnostics-result.json", lambda d: d["data"]["diagnostics"][0].update({"diagnostic_handle": "fake-bound-handle"}))
    rejects_guidance("list_diagnostics", "mcp-pod-status-diagnostics-result.json", lambda d: d["data"]["diagnostics"][0].pop("preset_ref"))
    # These fail schema/semantic checks rather than accepting a concealed replica,
    # workload substitution, container selector or wider mechanism under one label.
    for field in ("selected_pods", "target_ref", "pod_selection"):
        rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d, f=field: d["data"].pop(f))
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"].update({"max_bytes": 8192}))
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"]["selected_pods"].append(copy.deepcopy(d["data"]["selected_pods"][0])))
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"]["selected_pods"][0].update({"container_name": "app"}))
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"]["lifecycle_plan"]["actions"].append({"actionID": "logs", "kind": "logs", "executionMode": "onTrigger"}))
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"]["selected_pods"][0].update({"namespace": "foreign"}), True)
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"]["selected_pods"][0]["workload"].update({"name": "foreign"}), True)
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"].update({"pod_selection": "explicitPod"}), True)
    rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d: d["data"]["capture_assessment"].update({"validUntil": "2026-10-10T12:00:06Z"}), True)
    for anchor in ("firstAcquisitionOrEarlierSource", "uploadCompletion", "previewCreation"):
        rejects_guidance("preview_capture", "mcp-pod-status-preview-result.json", lambda d, a=anchor: d["data"]["capture_assessment"]["actions"][0]["retention"].update({"anchorRule": a}))
    # Generic assessment and other presets retain their qualified older-source
    # rule. The exact pod-status correction does not reinterpret other evidence.
    validate(examples["assessment-go-profile.json"], schemas[BASE + "capture-assessment.schema.json"])
    validate(examples["mcp-preview-result.json"], tools["preview_capture"]["outputSchema"])
    selected = examples["mcp-pod-status-preview-result.json"]["data"]
    require(selected["execution_digest"] == canonical_digest(examples["resolved-context-scope.json"]), "Pod-status example lost its exact reviewed scope")
    require(selected["selected_pods"][0]["uid"] == examples["resolved-context-scope.json"]["podBindings"][0]["podUID"], "Pod-status projection changed pinned UID")
    require(selected["selected_pods"][0]["workload"]["uid"] == examples["resolved-context-scope.json"]["collection"]["spec"]["target"]["workloadRef"]["uid"], "Pod-status projection changed actual workload identity")
    require(examples["recipe-pod-status.json"]["spec"]["maxTotalBytes"] == selected["max_bytes"], "Pod-status preset hides a different recipe limit")
    notice = examples["artifact-handling-notice.json"]
    rejects(notice, "capture-assessment", lambda d: d.update({"externalCopiesRecallable": True}))
    rejects(notice, "capture-assessment", lambda d: d.update({"deleteBy": "2026-10-09T17:00:00Z"}), True)
    rejects(notice, "capture-assessment", lambda d: d.update({"asOf": "2026-10-09T18:10:00Z"}), True)
    rejects(notice, "capture-assessment", lambda d: d.update({"deletionState": "overdue"}), True)
    rejects(notice, "capture-assessment", lambda d: d.update({"deletionState": "restrictedPreservation"}), True)
    rejects_guidance("list_artifacts", "mcp-artifact-notices-result.json", lambda d: d["data"]["artifacts"][0].pop("handling_notice"))
    rejects_guidance("get_case", "mcp-shared-case-notice-result.json", lambda d: d["data"]["artifacts"][0]["handling_notice"].update({"expiresAt": "2026-10-09T17:00:00Z"}), True)
    rejects(examples["manifest-core.json"], "manifest", lambda d: d["privacy"].update({"evidenceType": "context"}), True)
    # Positive qualification-shape fixture only, not a real measured performance claim.
    measured = copy.deepcopy(report)
    measured["actions"][0]["quantities"][0].update({"basis": "qualifiedMeasurement", "sourceRef": "synthetic-qualification-only", "measuredAt": "2026-10-08T12:00:00Z", "environmentDigest": "a"*64, "coverage": "Synthetic measured artifact bytes for one fixture interval, not a configured bound or production observation."})
    validate(measured, schemas[BASE + "capture-assessment.schema.json"]); semantic_checks(measured)
    print(f"PASS: {len(schemas)} schemas, {len(tools)} MCP tools, {len(examples)} examples, "
          f"{len(requirements)} requirements, {len(scenarios)} scenarios, {len(tasks)} tasks, "
          f"{links} local links, {negative_checks} rejected invalid examples ({checks} assertions).")
    print("Documentation/contract validation only; no Kubernetes/runtime feasibility claim.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
