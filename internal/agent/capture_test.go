package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	corev1 "k8s.io/api/core/v1"

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

	if pid, err := mainPID(proc, id, false); err != nil || pid != 1200 {
		t.Fatal("main process", pid, err)
	}
	if _, err := mainPID(proc, "absent", false); err == nil {
		t.Fatal("found a process of an absent container")
	}
	// A capture finds a container's processes once and may come to one of
	// them much later. A process that ended meanwhile, whose number went to
	// another process, of the node or of someone else's pod, is not the one
	// that was found: no tool is set on it and nothing of it is sent.
	a := &Agent{Proc: proc}
	known := &processes{}
	pod := &corev1.Pod{}
	if all, main, err := known.of(a, pod, id); err != nil || main != 1200 || len(all) != 3 {
		t.Fatal(all, main, err)
	}
	if !known.same(proc, 1201) || !known.same(proc, 1200) {
		t.Fatal("a process that is still there is taken for another")
	}
	add(1201, 1, 5000, "kubelet", "/system.slice/kubelet.service") // the number, given to a process of the node
	if known.same(proc, 1201) {
		t.Fatal("another process with the same number is taken for the one that was found")
	}
	os.RemoveAll(filepath.Join(proc, "1500"))
	if known.same(proc, 1500) || known.same(proc, 1300) {
		t.Fatal("a process that is gone, or one that was never found, is taken for one of the container")
	}
	if !(*processes)(nil).same(proc, 1300) {
		t.Fatal("without a memory of the processes there is nothing to compare")
	}
	add(1201, 1200, 110, "worker", scope)
	add(1500, 900, 300, "sh", scope)

	// The agent's own container: the kernel shows the agent the cgroup of
	// its own processes as the root of its cgroup namespace, without the
	// container's ID.
	const own = "9999ffff"
	os.MkdirAll(filepath.Join(proc, "self"), 0o755)
	os.WriteFile(filepath.Join(proc, "self", "cgroup"), []byte("0::/\n"), 0o644)
	add(2000, 900, 400, "asservat", "/")
	add(2001, 2000, 410, "tcpdump", "/")
	if _, err := mainPID(proc, own, false); err == nil {
		t.Fatal("found the agent's processes for another pod's container")
	}
	if all, main, err := containerPIDs(proc, own, true); err != nil || main != 2000 || len(all) != 2 {
		t.Fatal("the agent's own container", all, main, err)
	}
	if pid, err := mainPID(proc, id, true); err != nil || pid != 1200 {
		t.Fatal("a container with its ID, asked as the agent's own", pid, err)
	}
}

// fakeProc writes a node's /proc with a container's main process (1200) and
// its worker among the given number of other processes, and returns it with
// a function that adds a process.
func fakeProc(t testing.TB, id string, others int) (string, func(pid, ppid, started int, cgroup string)) {
	t.Helper()
	proc := t.TempDir()
	add := func(pid, ppid, started int, cgroup string) {
		dir := filepath.Join(proc, fmt.Sprint(pid))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroup+"\n"), 0o644)
		stat := fmt.Sprintf("%d (app) S %d %s %d 0", pid, ppid, strings.Repeat("0 ", 17), started)
		os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644)
	}
	add(900, 1, 50, "/system.slice/containerd.service")
	add(1200, 900, 100, "/kubelet.slice/cri-containerd-"+id+".scope")
	add(1201, 1200, 110, "/kubelet.slice/cri-containerd-"+id+".scope")
	for i := range others {
		add(10000+i, 1, 200+i, fmt.Sprintf("/kubelet.slice/cri-containerd-other%d.scope", i/4))
	}
	return proc, add
}

func runningPod(container, id string) *corev1.Pod {
	return &corev1.Pod{
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: container}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{
			Name: container, ContainerID: "containerd://" + id, State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}},
		}}},
	}
}

// What asks for a container's main process again and again searches the
// node's processes once per instance of the container.
func TestMainPIDsSearchOncePerContainer(t *testing.T) {
	proc, add := fakeProc(t, "0123abcd", 10)
	a, pod, pids := &Agent{Proc: proc}, runningPod("app", "0123abcd"), mainPIDs{}
	if pid, err := pids.of(a, pod, "app"); err != nil || pid != 1200 {
		t.Fatal("main process", pid, err)
	}
	// A search would now find this one: the remembered process is not searched for again.
	add(1100, 900, 60, "/kubelet.slice/cri-containerd-0123abcd.scope")
	if pid, err := pids.of(a, pod, "app"); err != nil || pid != 1200 {
		t.Fatal("searched again", pid, err)
	}
	// A restarted container is another process.
	add(3000, 900, 500, "/kubelet.slice/cri-containerd-4567ef.scope")
	if pid, err := pids.of(a, runningPod("app", "4567ef"), "app"); err != nil || pid != 3000 {
		t.Fatal("restarted container", pid, err)
	}
	// The ID of a process that ended may be another container's by now.
	add(3000, 900, 600, "/kubelet.slice/cri-containerd-other.scope")
	if pid, err := pids.of(a, runningPod("app", "4567ef"), "app"); err == nil {
		t.Fatal("took another container's process for the remembered one", pid)
	}
	pod.Status.ContainerStatuses[0].State = corev1.ContainerState{}
	if _, err := pids.of(a, pod, "app"); err == nil {
		t.Fatal("found a container that does not run")
	}
}

// On a node with 5000 processes: the search, and asking what is remembered.
func BenchmarkMainPID(b *testing.B) {
	proc, _ := fakeProc(b, "0123abcd", 5000)
	a, pod := &Agent{Proc: proc}, runningPod("app", "0123abcd")
	b.Run("searched", func(b *testing.B) {
		for b.Loop() {
			if _, _, err := a.containerPID(pod, "app", nil); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("remembered", func(b *testing.B) {
		pids := mainPIDs{}
		for b.Loop() {
			if _, err := pids.of(a, pod, "app"); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// What the recordings of one capture ask about the pod's processes: packets,
// a trace, a core dump, a CPU profile and a memory profile.
func BenchmarkCaptureLookups(b *testing.B) {
	proc, _ := fakeProc(b, "0123abcd", 5000)
	a, pod := &Agent{Proc: proc}, runningPod("app", "0123abcd")
	for b.Loop() {
		known := &processes{}
		if _, err := a.podPID(pod, known); err != nil {
			b.Fatal(err)
		}
		for range 2 {
			if _, _, err := a.targets(pod, "", "", known); err != nil {
				b.Fatal(err)
			}
		}
		for _, kind := range []sampledKind{sampledCPU, sampledMemory} {
			a.cover(newSampledProfile(kind, 0), pod, known)
		}
	}
}

// The recordings of one capture, which run at once, search the node's
// processes once per container between them.
func TestCaptureSearchesOncePerContainer(t *testing.T) {
	proc, add := fakeProc(t, "0123abcd", 10)
	a, pod, known := &Agent{Proc: proc}, runningPod("app", "0123abcd"), &processes{}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			if pid, err := a.podPID(pod, known); err != nil || pid != 1200 {
				t.Error("main process", pid, err)
			}
		})
	}
	wg.Wait()
	// A search would now find this one as well, and as the main process.
	add(1100, 900, 60, "/kubelet.slice/cri-containerd-0123abcd.scope")
	if pids, _, err := a.targets(pod, "app", "", known); err != nil || len(pids) != 1 || pids[0] != 1200 {
		t.Fatal("searched again for a trace", pids, err)
	}
	p := newSampledProfile(sampledCPU, 0)
	if a.cover(p, pod, known); len(p.pids) != 2 || !p.pids[1200] || !p.pids[1201] {
		t.Fatal("searched again for a profile", p.pids)
	}
	// What does not belong to a capture searches each time.
	if pid, err := a.podPID(pod, nil); err != nil || pid != 1100 {
		t.Fatal("without a capture", pid, err)
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

// drips hands out a few bytes per read, as a tool's output arrives line by line.
type drips struct {
	left  []byte
	reads int
}

func (d *drips) Read(p []byte) (int, error) {
	if len(d.left) == 0 {
		return 0, io.EOF
	}
	d.reads++
	n := copy(p, d.left[:min(7, len(d.left))])
	d.left = d.left[n:]
	return n, nil
}

// An upload goes to the hub in full pieces, however small the pieces are in
// which a tool writes: each piece is a write to the network of its own.
func TestUploadInFullPieces(t *testing.T) {
	content := bytes.Repeat([]byte("a line of a trace\n"), 10000)
	var got bytes.Buffer
	var pieces []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The server reads what each network write brought.
		buf := make([]byte, 1<<20)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				pieces = append(pieces, n)
				got.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}))
	defer server.Close()
	a := &Agent{HubURL: server.URL, HTTP: server.Client()}
	source := &drips{left: bytes.Clone(content)}
	if err := a.upload(t.Context(), "capture", "pod", "trace", source); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), content) {
		t.Fatal("the upload changed the content", got.Len(), len(content))
	}
	// 180 kB in pieces of 7 bytes would be some 25000 writes.
	if len(pieces) > 100 {
		t.Fatalf("the upload reached the hub in %d pieces", len(pieces))
	}
	// A reader that ends, or fails, in the middle of a piece hands on what it had.
	short := full{r: io.MultiReader(strings.NewReader("abc"), iotest.ErrReader(io.ErrClosedPipe))}
	p := make([]byte, 10)
	if n, err := short.Read(p); n != 3 || err != nil {
		t.Fatal("the bytes before a failure", n, err)
	}
	if n, err := short.Read(p); n != 0 || err != io.ErrClosedPipe {
		t.Fatal("the failure", n, err)
	}
}

// A tool whose output is set aside is not held up by the upload: it has
// written everything, more than a pipe holds, before the upload reads.
func TestAsideDoesNotHoldTheTool(t *testing.T) {
	a := &Agent{Scratch: t.TempDir()}
	done := filepath.Join(t.TempDir(), "done")
	var got int64
	up := func(_ string, r io.Reader) error {
		if _, err := os.Stat(done); err != nil {
			t.Error("the upload began while the tool still wrote")
		}
		n, err := io.Copy(io.Discard, r)
		got = n
		return err
	}
	if err := a.record(t.Context(), t.Context(), 0, "out", a.aside(up), "sh", "-c", "head -c 1000000 /dev/zero; touch "+done); err != nil || got != 1000000 {
		t.Fatal(got, err)
	}
	if left, _ := os.ReadDir(a.Scratch); len(left) != 0 {
		t.Fatal("left in the scratch directory:", left)
	}
}
