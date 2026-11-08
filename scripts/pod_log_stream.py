"""Stream owned fixture Pod logs to files while an installed test runs.

The Go tests collect hub/regional/collector logs only in their cleanup, which
never runs when the job limit or go test -timeout ends the process. This
follower writes every container instance's log to its own file under the
results directory as the lines arrive, so the CI artifact keeps them however
the run ends. Test harness only: synthetic owned kind clusters, no product
authority.
"""
import json
import re
import subprocess
import threading
from pathlib import Path

SKIP_NAMESPACES = frozenset(("kube-system", "kube-public", "kube-node-lease", "local-path-storage"))
# Bounds per run: followers (one kubectl per container instance) and bytes per
# instance. A noisy container cannot fill the runner disk or the artifact.
MAX_FOLLOWERS = 128
LIMIT_BYTES = 16 * 1024 * 1024


def _safe(part):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", part)[:120] or "_"


def container_instances(pods):
    """(namespace, pod, container, restartCount) for every started container."""
    for pod in pods.get("items", []):
        meta, status = pod.get("metadata", {}), pod.get("status", {})
        namespace, name = meta.get("namespace", ""), meta.get("name", "")
        if not namespace or not name or namespace in SKIP_NAMESPACES:
            continue
        for key in ("initContainerStatuses", "containerStatuses", "ephemeralContainerStatuses"):
            for container in status.get(key) or []:
                state = container.get("state") or {}
                if "running" in state or "terminated" in state:
                    yield namespace, name, container.get("name", ""), int(container.get("restartCount") or 0)


class PodLogStreamer:
    """Poll each cluster's Pods every interval and follow each new container
    instance with its own `kubectl logs -f` writing straight to a file (no
    pipe, so nothing here can block on a reader)."""

    def __init__(self, clusters, directory, interval=5.0, kubectl="kubectl", max_followers=MAX_FOLLOWERS):
        self.clusters = list(clusters)  # (name, kubeconfig)
        self.directory = Path(directory)
        self.interval = interval
        self.kubectl = kubectl
        self.max_followers = max_followers
        self.followed = {}
        self.dropped = 0
        self.poll_errors = 0
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = None

    def poll_once(self):
        for cluster, config in self.clusters:
            try:
                raw = subprocess.run([self.kubectl, "--kubeconfig", str(config), "--request-timeout=10s", "get", "pods", "-A", "-o", "json"],
                                     capture_output=True, text=True, timeout=20, check=True).stdout
                pods = json.loads(raw)
            except (OSError, subprocess.SubprocessError, ValueError):
                self.poll_errors += 1
                continue
            for namespace, pod, container, restarts in container_instances(pods):
                self._follow(cluster, config, namespace, pod, container, restarts)

    def _follow(self, cluster, config, namespace, pod, container, restarts):
        key = (cluster, namespace, pod, container, restarts)
        with self._lock:
            if key in self.followed or self._stop.is_set():
                return
            if len(self.followed) >= self.max_followers:
                self.dropped += 1
                return
            path = self.directory / _safe(cluster) / _safe(namespace) / (_safe(pod) + "_" + _safe(container) + "_" + str(restarts) + ".log")
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("ab", buffering=0) as out:
                try:
                    process = subprocess.Popen([self.kubectl, "--kubeconfig", str(config), "logs", "-f", "--timestamps", "--limit-bytes=" + str(LIMIT_BYTES), "-n", namespace, pod, "-c", container],
                                               stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True)
                except OSError:
                    self.poll_errors += 1
                    return
            self.followed[key] = process

    def _run(self):
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval)

    def start(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        self._thread = threading.Thread(target=self._run, name="pod-log-stream", daemon=True)
        self._thread.start()
        return self

    def stop(self, grace=5.0):
        """Stop polling and end every follower (their lines are already on disk)."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=30)  # one poll is bounded by 20 s per cluster call
        with self._lock:
            processes = list(self.followed.values())
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                process.kill()  # never wait again: stopping must stay bounded
        return {"followed": len(processes), "dropped": self.dropped, "pollErrors": self.poll_errors, "directory": str(self.directory)}
