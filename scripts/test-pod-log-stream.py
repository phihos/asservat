#!/usr/bin/env python3
"""PodLogStreamer regression with a fake kubectl; never touches a cluster."""
import json
import os
import shutil
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from pod_log_stream import PodLogStreamer, container_instances  # noqa: E402

# get pods prints $FAKE_PODS; logs -f prints one line naming its target and,
# like a running container, keeps its output open until killed.
FAKE = """#!/bin/sh
for a in "$@"; do
  if [ "$a" = get ]; then cat "$FAKE_PODS"; exit 0; fi
  if [ "$a" = logs ]; then
    shift $(( $# - 5 )); echo "line from $2/$5"; exec sleep 600
  fi
done
exit 2
"""


def pods(restarts):
    def pod(ns, name, container):
        return {"metadata": {"namespace": ns, "name": name}, "status": {"containerStatuses": [{"name": container, "restartCount": restarts, "state": {"running": {}}}]}}
    return {"items": [pod("asservat-hub", "hub-api-1", "hub"), pod("kube-system", "coredns", "coredns"),
                      {"metadata": {"namespace": "synthetic", "name": "pending"}, "status": {"containerStatuses": [{"name": "app", "state": {"waiting": {}}}]}}]}


class PodLogStream(unittest.TestCase):
    def setUp(self):
        scratch = Path(os.environ.get("TMPDIR") or Path.home() / ".cache/asservat-build/tmp")  # never the small /tmp
        scratch.mkdir(parents=True, exist_ok=True)
        self.dir = Path(tempfile.mkdtemp(dir=scratch))
        self.kubectl = self.dir / "kubectl"
        self.kubectl.write_text(FAKE)
        self.kubectl.chmod(self.kubectl.stat().st_mode | stat.S_IEXEC)
        self.pods = self.dir / "pods.json"
        os.environ["FAKE_PODS"] = str(self.pods)
        self.addCleanup(shutil.rmtree, self.dir, True)

    def wait_for(self, path):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if path.exists() and path.read_text():
                return path.read_text()
            time.sleep(0.05)
        self.fail("no streamed log at " + str(path))

    def test_selects_started_non_system_containers(self):
        self.assertEqual(list(container_instances(pods(0))), [("asservat-hub", "hub-api-1", "hub", 0)])

    def test_streams_while_running_follows_restarts_and_stops_bounded(self):
        self.pods.write_text(json.dumps(pods(0)))
        out = self.dir / "logs"
        streamer = PodLogStreamer([("c0", self.dir / "kube-0")], out, interval=0.05, kubectl=str(self.kubectl)).start()
        try:
            # Written while the follower is still running, not at stop.
            self.assertEqual(self.wait_for(out / "c0/asservat-hub/hub-api-1_hub_0.log").strip(), "line from asservat-hub/hub")
            self.pods.write_text(json.dumps(pods(1)))
            self.wait_for(out / "c0/asservat-hub/hub-api-1_hub_1.log")
        finally:
            began = time.monotonic()
            summary = streamer.stop()
        self.assertLess(time.monotonic() - began, 10)
        self.assertEqual((summary["followed"], summary["dropped"]), (2, 0))
        self.assertFalse((out / "c0/kube-system").exists())

    def test_follower_cap(self):
        self.pods.write_text(json.dumps(pods(0)))
        streamer = PodLogStreamer([("c0", "k0"), ("c1", "k1")], self.dir / "logs", kubectl=str(self.kubectl), max_followers=1)
        streamer.poll_once()
        summary = streamer.stop()
        self.assertEqual((summary["followed"], summary["dropped"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
