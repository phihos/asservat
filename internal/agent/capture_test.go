package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/api"
)

func TestMainPID(t *testing.T) {
	proc := t.TempDir()
	add := func(pid, ppid, started int, comm, cgroup string) {
		dir := filepath.Join(proc, fmt.Sprint(pid))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroup+"\n"), 0o644)
		stat := fmt.Sprintf("%d (%s) S %d %s %d 0", pid, comm, ppid, strings.Repeat("0 ", 17), started)
		os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	}
	const id = "0123abcd"
	scope := "/kubelet.slice/cri-containerd-" + id + ".scope"
	add(1, 0, 1, "systemd", "/init.scope")
	add(900, 1, 50, "containerd-shim", "/system.slice/containerd.service")
	add(1500, 900, 300, "sh", scope)             // a later exec session
	add(1200, 900, 100, "my app) S 1 (x", scope) // the main process, with a hostile name
	add(1201, 1200, 110, "worker", scope)
	add(1300, 900, 90, "other", "/kubelet.slice/cri-containerd-ffff.scope")
	os.WriteFile(filepath.Join(proc, "uptime"), nil, 0o644)

	if pid, err := mainPID(proc, id); err != nil || pid != 1200 {
		t.Fatal("main process", pid, err)
	}
	if _, err := mainPID(proc, "absent"); err == nil {
		t.Fatal("found a process of an absent container")
	}
}

// A recording is interrupted after its duration and its output until then is
// uploaded; a tool that fails by itself reports its error output.
func TestRecord(t *testing.T) {
	a := &Agent{}
	var got bytes.Buffer
	up := func(_ string, r io.Reader) error { _, err := io.Copy(&got, r); return err }
	started := time.Now()
	if err := a.record(t.Context(), t.Context(), 300*time.Millisecond, "out", up, "sh", "-c", "echo recorded; exec sleep 30"); err != nil {
		t.Fatal(err)
	}
	if got.String() != "recorded\n" || time.Since(started) > 5*time.Second {
		t.Fatal("recording", got.String(), time.Since(started))
	}
	if err := a.record(t.Context(), t.Context(), time.Minute, "out", up, "sh", "-c", "echo broken filter >&2; exit 1"); err == nil || !strings.Contains(err.Error(), "broken filter") {
		t.Fatal("tool failure", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(100*time.Millisecond, cancel)
	if err := a.record(ctx, ctx, time.Minute, "out", up, "sh", "-c", "exec sleep 30"); err == nil {
		t.Fatal("a cancelled recording reported success")
	}
	// Stopping ends the time frame: the recording keeps what it has.
	frame, stop := context.WithCancel(t.Context())
	time.AfterFunc(300*time.Millisecond, stop)
	got.Reset()
	started = time.Now()
	if err := a.record(t.Context(), frame, time.Minute, "out", up, "sh", "-c", "echo recorded so far; exec sleep 30"); err != nil || got.String() != "recorded so far\n" || time.Since(started) > 5*time.Second {
		t.Fatal("a stopped recording", err, got.String(), time.Since(started))
	}
}

// A sync stops the tasks that are no longer open and keeps the others.
func TestSyncStopsTasksThatAreNoLongerOpen(t *testing.T) {
	stopped := map[string]bool{}
	ended := map[string]bool{}
	a := &Agent{running: map[string]task{}}
	for _, key := range []string{"capture-1/pod-a", "capture-2/pod-a", "capture-2/pod-b"} {
		a.running[key] = task{cancel: func() { stopped[key] = true }, stop: func() { ended[key] = true }}
	}
	a.handle(t.Context(), api.Command{Type: "sync", Tasks: []api.Command{{Type: "task", ID: "capture-2", Task: &api.TaskAssignment{Pod: "pod-a", Started: true}}}})
	if !stopped["capture-1/pod-a"] || stopped["capture-2/pod-a"] || !stopped["capture-2/pod-b"] || len(stopped) != 2 {
		t.Fatal("stopped", stopped)
	}
	stopped = map[string]bool{}
	a.handle(t.Context(), api.Command{Type: "cancel", ID: "capture-2"})
	if !stopped["capture-2/pod-a"] || !stopped["capture-2/pod-b"] || len(stopped) != 2 || len(ended) != 0 {
		t.Fatal("cancelled", stopped, ended)
	}
	// A stop ends the time frame of the capture's tasks without cancelling them.
	stopped = map[string]bool{}
	a.handle(t.Context(), api.Command{Type: "stop", ID: "capture-1"})
	if !ended["capture-1/pod-a"] || len(ended) != 1 || len(stopped) != 0 {
		t.Fatal("stopped", ended, stopped)
	}
}
