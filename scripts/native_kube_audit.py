"""Bounded, fixture-only Metadata audit. Raw events never enter artifacts.

Uses the Kind auditing mount/backend pattern and kubeadm v1beta4 structured
arguments. This is test infrastructure, not a product audit or authority path.
"""
import datetime
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

LOG_DIRECTORY = "/var/log/asservat-native-audit"
POLICY_PATH = "/etc/kubernetes/asservat-native-audit-policy.json"
MAX_LINE = 64 * 1024
MAX_FILE = 32 * 1024 * 1024 + MAX_LINE
MAX_FILES = 4
MAX_EVENTS = 131072
PHASE_NAMES = frozenset(("setup", "idle-baseline", "recording", "prepare-unpaced", "unpaced", "prepare-paced", "paced", "prepare-range", "range-first", "range-resume", "prepare-stale", "stale-ifrange", "prepare-revoked", "revoked", "prepare-cancelled", "request-cancelled", "joined-cleanup", "prepare-concurrent-a", "prepare-concurrent-b", "concurrent"))
CATEGORIES = ("serviceAccountGet", "tokenReviewCreate")


def configure(config, work, index):
    policy = {"apiVersion": "audit.k8s.io/v1", "kind": "Policy",
              # Count arrival attempts, including background calls still in
              # flight at export. One event per call, never body/completion data.
              "omitStages": ["ResponseStarted", "ResponseComplete", "Panic"], "rules": [
                  {"level": "Metadata", "verbs": ["get"], "resources": [{"group": "", "resources": ["serviceaccounts"]}]},
                  {"level": "Metadata", "verbs": ["create"], "resources": [{"group": "authentication.k8s.io", "resources": ["tokenreviews"]}]},
                  {"level": "Metadata", "verbs": ["get"], "nonResourceURLs": ["/readyz"]},
                  {"level": "None"}]}
    path = Path(work) / ("native-audit-policy-" + str(index) + ".json")
    path.write_text(json.dumps(policy))
    node = config["nodes"][0]
    if node.get("role") != "control-plane":
        raise ValueError("native audit requires the original control plane")
    node.setdefault("extraMounts", []).append({"hostPath": str(path), "containerPath": POLICY_PATH, "readOnly": True})
    args = {"audit-policy-file": POLICY_PATH, "audit-log-path": LOG_DIRECTORY + "/audit.log",
            "audit-log-maxage": "1", "audit-log-maxbackup": "3", "audit-log-maxsize": "32",
            "audit-log-mode": "blocking-strict", "audit-log-compress": "false"}
    patch = {"apiVersion": "kubeadm.k8s.io/v1beta4", "kind": "ClusterConfiguration", "apiServer": {
        "extraArgs": [{"name": name, "value": value} for name, value in args.items()],
        "extraVolumes": [
            {"name": "native-audit-policy", "hostPath": POLICY_PATH, "mountPath": POLICY_PATH, "readOnly": True, "pathType": "File"},
            {"name": "native-audit-logs", "hostPath": LOG_DIRECTORY, "mountPath": LOG_DIRECTORY, "readOnly": False, "pathType": "DirectoryOrCreate"}]}}
    node.setdefault("kubeadmConfigPatches", []).append(json.dumps(patch))


def owned_node(cluster, container=None):
    if not re.fullmatch(r"asservat-context-[a-z0-9-]+-[01]", cluster):
        raise ValueError("native audit cluster is not owned")
    if container is not None and not re.fullmatch(r"[a-f0-9]{64}", container):
        raise ValueError("native audit container ID is not exact")
    name = cluster + "-control-plane"
    info = json.loads(subprocess.check_output(["docker", "inspect", container or name], text=True, stderr=subprocess.DEVNULL, timeout=5))
    if len(info) != 1:
        raise ValueError("native audit control plane is ambiguous")
    item = info[0]
    labels = item["Config"]["Labels"]
    if item["Name"] != "/" + name or labels.get("io.x-k8s.kind.cluster") != cluster or labels.get("io.x-k8s.kind.role") != "control-plane" or not re.fullmatch(r"[a-f0-9]{64}", item["Id"]):
        raise ValueError("native audit control plane identity changed")
    if container and item["Id"] != container:
        raise ValueError("native audit control plane was replaced")
    return {"cluster": cluster, "id": item["Id"]}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("native audit timestamp missing")
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(?:Z|\+00:00)", value)
    if not match:
        raise ValueError("native audit timestamp must be bounded UTC")
    seconds = datetime.datetime.fromisoformat(match[1]).replace(tzinfo=datetime.timezone.utc)
    return int(seconds.timestamp()) * 1_000_000_000 + int((match[2] or "").ljust(9, "0"))


def phases_from_report(path):
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("native phase report is too large")
    phases = json.loads(path.read_text())["phases"]
    if not isinstance(phases, list) or not 1 <= len(phases) <= 24:
        raise ValueError("native phases are unavailable")
    seen = set()
    previous_end = None
    for phase in phases:
        if not isinstance(phase, dict) or not {"name", "startedAt", "finishedAt"} <= phase.keys() or phase["name"] not in PHASE_NAMES or phase["name"] in seen:
            raise ValueError("native phase shape is not fixed")
        seen.add(phase["name"])
        start, end = timestamp(phase["startedAt"]), timestamp(phase["finishedAt"])
        if not 0 < end - start <= 18 * 60 * 1_000_000_000:
            raise ValueError("native phase has an invalid original interval")
        if previous_end is not None and start < previous_end:
            raise ValueError("native phase intervals overlap or move backwards")
        previous_end = end
    if max(timestamp(p["finishedAt"]) for p in phases) - min(timestamp(p["startedAt"]) for p in phases) > 18 * 60 * 1_000_000_000:
        raise ValueError("native phases exceed their test envelope")
    # Other root-owned per-phase numeric measurements are not audit fields.
    return [{key: phase[key] for key in ("name", "startedAt", "finishedAt")} for phase in phases]


# Stat each fixed file and export only that finite prefix. Appends after stat
# cannot make collection unbounded. Rotation/truncation during export produces
# framing/coverage/duplicate failure, never guessed zero counts. No host chmod.
EXPORT = r'''set -eu
cd /var/log/asservat-native-audit
count=0
for f in audit.log audit-*.log; do
  [ -e "$f" ] || continue
  [ -f "$f" ] && [ ! -L "$f" ] || exit 1
  count=$((count+1)); [ "$count" -le 4 ] || exit 1
  size=$(stat -c %s -- "$f")
  [ "$size" -le 33619968 ] || exit 1
  printf '%s %s\n' "$size" "$f"
  head -c "$size" -- "$f"
  printf '\n'
done
[ "$count" -gt 0 ]
'''


def aggregate(stream, phases):
    counts = [{"name": p["name"], "startedAt": p["startedAt"], "finishedAt": p["finishedAt"], **dict.fromkeys(CATEGORIES, 0)} for p in phases]
    intervals = [(timestamp(p["startedAt"]), timestamp(p["finishedAt"])) for p in phases]
    seen, files = set(), set()
    earliest, latest, total_bytes, markers = None, None, 0, 0
    while True:
        header = stream.readline(128)
        if not header:
            break
        match = re.fullmatch(rb"(0|[1-9][0-9]{0,8}) (audit(?:-[0-9TZ+_.-]{1,64})?\.log)\n", header)
        if not match or match[2] in files or len(files) == MAX_FILES:
            raise ValueError("native audit export framing is incomplete")
        size = int(match[1])
        if size > MAX_FILE:
            raise ValueError("native audit file exceeds its bound")
        files.add(match[2]); total_bytes += size
        remaining = size
        while remaining:
            line = stream.readline(min(remaining + 1, MAX_LINE + 1))
            if not line or len(line) > remaining or len(line) > MAX_LINE or not line.endswith(b"\n"):
                raise ValueError("native audit contains a truncated or oversized event")
            remaining -= len(line)
            event = json.loads(line)
            if not isinstance(event, dict) or event.get("apiVersion") != "audit.k8s.io/v1" or event.get("kind") != "Event" or event.get("level") != "Metadata" or event.get("stage") != "RequestReceived" or "requestObject" in event or "responseObject" in event:
                raise ValueError("native audit event violates metadata-only policy")
            audit_id = event.get("auditID", "")
            if not isinstance(audit_id, str) or not re.fullmatch(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}", audit_id) or audit_id in seen or len(seen) == MAX_EVENTS:
                raise ValueError("native audit events are duplicated or exceed bounds")
            seen.add(audit_id)
            received, stage_at = timestamp(event.get("requestReceivedTimestamp")), timestamp(event.get("stageTimestamp"))
            if stage_at < received:
                raise ValueError("native audit stage predates request")
            if event.get("verb") == "get" and urlsplit(event.get("requestURI", "")).path == "/readyz":
                earliest = received if earliest is None else min(earliest, received)
                latest = received if latest is None else max(latest, received)
                markers += 1
                continue
            ref = event.get("objectRef", {})
            if not isinstance(ref, dict):
                raise ValueError("native audit resource category missing")
            group, resource, verb = ref.get("apiGroup", ""), ref.get("resource"), event.get("verb")
            if group == "" and resource == "serviceaccounts" and verb == "get":
                category = "serviceAccountGet"
            elif group == "authentication.k8s.io" and resource == "tokenreviews" and verb == "create":
                category = "tokenReviewCreate"
            else:
                raise ValueError("native audit contains an unexpected category")
            for count, (start, end) in zip(counts, intervals):
                if start <= received < end:
                    count[category] += 1
        if stream.read(1) != b"\n":
            raise ValueError("native audit export was truncated")
    if not files or earliest is None or earliest > min(a for a, _ in intervals) or latest < max(b for _, b in intervals):
        raise ValueError("native audit lost original phase coverage or rotated logs")
    return {"complete": True, "scope": "background-inclusive request attempts received within each phase; readyz coverage markers excluded",
            "files": len(files), "events": len(seen), "bytes": total_bytes, "coverageMarkers": markers, "phases": counts}


def collect(report, nodes, work):
    phases = phases_from_report(report)
    if len(nodes) != 2:
        raise ValueError("native audit requires both owned clusters")
    results = []
    for index, (node, _) in enumerate(nodes):
        owned_node(node["cluster"], node["id"])
        path = Path(work) / ("private-native-audit-export-" + str(index))
        path.touch(mode=0o600, exist_ok=False)
        try:
            with path.open("wb") as output:
                subprocess.run(["docker", "exec", "--user", "0", node["id"], "timeout", "15s", "sh", "-ec", EXPORT], stdout=output, stderr=subprocess.DEVNULL, check=True, timeout=20)
            with path.open("rb") as source:
                results.append({"clusterOrdinal": index + 1, **aggregate(source, phases)})
        finally:
            path.unlink(missing_ok=True)
    return {"complete": True, "level": "Metadata", "maxLogFilesPerCluster": MAX_FILES,
            "maxLogMiBPerFile": 32, "fixtureCoverageRequests": 4, "clusters": results}
