package hub

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/coredesc"
)

// A synthetic Go program that waits where the test finds it.
const waitingProgram = `package main

import (
	"fmt"
	"os"
	"syscall"
)

func waitForInput() { os.Stdin.Read(make([]byte, 1)) }

func main() {
	// Lets the test's gcore, a sibling, attach.
	syscall.RawSyscall(syscall.SYS_PRCTL, 0x59616d61, ^uintptr(0), 0)
	fmt.Println("ready")
	waitForInput()
}
`

// The hub describes a core again whose description is from an older
// describer, from the core and the program's files that the capture holds:
// here a description without goroutines of a Go program without debug
// information.
func TestCoreIsDescribedAgain(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	for _, tool := range []string{"go", "gcore", "gdb"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte(waitingProgram), 0o644)
	build := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w", "-o", "waiting", "main.go")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	cmd := exec.Command(filepath.Join(dir, "waiting"))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stdin.Close(); cmd.Process.Kill(); cmd.Wait() })
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("program said %q: %v", line, err)
	}
	pid := strconv.Itoa(cmd.Process.Pid)
	if out, err := exec.Command("gcore", "-o", filepath.Join(dir, "core"), pid).CombinedOutput(); err != nil {
		t.Skipf("gcore cannot attach here: %v: %s", err, out)
	}
	corePath, root := filepath.Join(dir, "core."+pid), "/proc/"+pid+"/root"

	ctx := context.Background()
	store, err := OpenStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// The hub's streams beat often here, as a description outlasts many beats in production.
	h, err := New(Config{Store: store, Blobs: DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, WorkDir: t.TempDir(), StreamBeat: 20 * time.Millisecond,
		Users: []StaticUser{{Name: "alice", Token: "alice-token-of-the-describe-test"}}})
	if err != nil {
		t.Fatal(err)
	}
	c := api.Capture{ID: uuid.NewString(), Requester: "alice", State: api.StateQueued, ExpiresAt: time.Now().Add(time.Hour), Tasks: []api.Task{{Pod: "api-1", Node: "node-a", State: api.StateQueued}}}
	c.Cluster, c.Namespace, c.Workload = "c"+c.ID[:8], "payments", "Deployment/api"
	if err := store.CreateCapture(ctx, c); err != nil {
		t.Fatal(err)
	}
	defer h.remove(ctx, c.ID)
	add := func(name string, content []byte) {
		a, err := h.keep(ctx, name, bytes.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		if added, err := store.AddArtifact(ctx, c.ID, a); err != nil || !added {
			t.Fatal(added, err)
		}
	}
	core, err := os.ReadFile(corePath)
	if err != nil {
		t.Fatal(err)
	}
	const name = "api-1/core.app"
	add(name, core)
	// What an agent before version 2 said of it: gdb's threads alone.
	add(name+coredesc.Suffix, []byte(`{"executable":"`+filepath.Join(dir, "waiting")+`","threads":[],"mappings":[]}`))

	// Without the program's files nothing can be done, and the hub says so.
	if described, reason, err := h.describeAgain(ctx, c.ID, name); err != nil || described || !strings.Contains(reason, "program's files") {
		t.Fatal("without files:", described, reason, err)
	}
	report, err := coredesc.Describer{Scratch: dir}.Describe(ctx, corePath, root)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := coredesc.WriteFiles(&archive, root, coredesc.Files(report, root)); err != nil {
		t.Fatal(err)
	}
	add(name+coredesc.FilesSuffix, archive.Bytes())
	stdin.Close()
	cmd.Process.Kill()
	cmd.Wait() // the files on the node are gone

	// The viewer asks over HTTP. The answer starts with the spaces that
	// keep a proxy waiting. Here the viewer is closed while the hub works:
	// the work goes on, with its audit entry.
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	ask := func(ctx context.Context) *http.Response {
		req, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/captures/"+c.ID+"/describe", strings.NewReader(`{"name":"`+name+`"}`))
		req.Header.Set("Authorization", "Bearer alice-token-of-the-describe-test")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	open, closeViewer := context.WithCancel(ctx)
	res := ask(open)
	first := make([]byte, 2)
	if _, err := io.ReadFull(res.Body, first); err != nil || res.StatusCode != 200 || string(first) != "  " {
		t.Fatalf("the answer begins %q: %d %v", first, res.StatusCode, err)
	}
	closeViewer()
	res.Body.Close()
	described := func() bool {
		a, err := store.Artifact(ctx, c.ID, name+coredesc.Suffix)
		if err != nil {
			t.Fatal(err)
		}
		var report bytes.Buffer
		return h.plain(ctx, a, &report) == nil && coredesc.DescribedBy(report.Bytes()) == coredesc.Version
	}
	for i := 0; !described(); i++ {
		if i == 600 {
			t.Fatal("the core was not described after the viewer was closed")
		}
		time.Sleep(50 * time.Millisecond)
	}
	audited := func() bool {
		log, err := store.AuditLog(ctx, time.Now().Add(time.Hour), 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range log {
			if e.Action == "artifact.describe" && e.Capture != nil && *e.Capture == c.ID {
				return true
			}
		}
		return false
	}
	for i := 0; !audited(); i++ {
		if i == 100 {
			t.Fatal("no audit entry of the description")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// The next viewer finds it done.
	res = ask(ctx)
	answer, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if strings.TrimSpace(string(answer)) != `{"described":false,"reason":""}` {
		t.Fatalf("asked again: %q", answer)
	}
	stored, err := store.Artifact(ctx, c.ID, name+coredesc.Suffix)
	if err != nil {
		t.Fatal(err)
	}
	var anew bytes.Buffer
	if err := h.plain(ctx, stored, &anew); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Describer  int
		Goroutines []struct {
			Frames []struct{ Function, File string }
		}
	}
	if err := json.Unmarshal(anew.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range got.Goroutines {
		for _, f := range g.Frames {
			found = found || f.Function == "main.waitForInput" && filepath.Base(f.File) == "main.go"
		}
	}
	if got.Describer != coredesc.Version || !found {
		t.Fatalf("described anew by %d with %d goroutines, main.waitForInput among them: %v", got.Describer, len(got.Goroutines), found)
	}
	// Over MCP the core reads as its stacks, by its own name or its description's.
	for _, file := range []string{name, name + coredesc.Suffix} {
		call, _ := http.NewRequest("POST", server.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_artifact","arguments":{"id":"`+c.ID+`","name":"`+file+`"}}}`))
		call.Header.Set("Authorization", "Bearer alice-token-of-the-describe-test")
		res, err := http.DefaultClient.Do(call)
		if err != nil {
			t.Fatal(err)
		}
		said, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if !strings.Contains(string(said), "main.waitForInput") || !strings.Contains(string(said), "Goroutines (") || strings.Contains(string(said), "mappings") {
			t.Fatalf("read_artifact of %s: %.600s", file, said)
		}
	}
	// It is up to date now; and the work directory holds nothing of it.
	if described, _, err := h.describeAgain(ctx, c.ID, name); err != nil || described {
		t.Fatal("described twice:", described, err)
	}
	if left, _ := os.ReadDir(h.WorkDir); len(left) != 0 {
		t.Fatal("left in the work directory:", left)
	}
}

// Stands in for the Python that has pystack, which the hub's image has.
// It notes each run, and fails while a file says that it is broken.
const pystackStandIn = `#!/bin/sh
echo run >>$0.runs
[ -e $0.broken ] && exit 1
echo '{"runtime":"python","title":"Python threads","version":"3.12.1","threads":[{"id":1,"threadSystemId":1,"frames":[{"function":"handle_order","line":7}]}]}'
`

// An agent describes the core of a Python program without the Python
// stacks, which its image has no tool for, and says so. When the program's
// files have arrived, the last of a core's files, the hub adds the stacks
// to the description, with nobody opening the core. Where its tool fails,
// the description goes on awaiting them, and the hub tries once more after
// it has started anew.
func TestHubAddsTheRuntimeStacksThatTheAgentLeft(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	ctx := context.Background()
	store, err := OpenStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	c := api.Capture{ID: uuid.NewString(), Requester: "alice", State: api.StateRunning, ExpiresAt: time.Now().Add(time.Hour), Tasks: []api.Task{{Pod: "api-1", Node: "node-a", State: api.StateRunning}}}
	c.Cluster, c.Namespace, c.Workload = "c"+c.ID[:8], "payments", "Deployment/api"
	joined := Cluster{Name: c.Cluster, Token: "join-token-of-the-cluster-with-a-python-core-0123456789"}
	h, err := New(Config{Store: store, Blobs: DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, WorkDir: t.TempDir(), Clusters: []Cluster{joined}})
	if err != nil {
		t.Fatal(err)
	}
	h.pystack = filepath.Join(t.TempDir(), "python")
	if err := os.WriteFile(h.pystack, []byte(pystackStandIn), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateCapture(ctx, c); err != nil {
		t.Fatal(err)
	}
	defer h.remove(ctx, c.ID)
	server := httptest.NewServer(h.Handler())
	defer server.Close()

	// The program's files as the agent found them, and what it said of the core.
	const python, name = "/usr/bin/python3.12", "api-1/core.python3"
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, filepath.Dir(python)), 0o755)
	if err := os.WriteFile(filepath.Join(root, python), []byte("\x7fELF synthetic"), 0o755); err != nil {
		t.Fatal(err)
	}
	begun := []byte(`{"describer":` + strconv.Itoa(coredesc.Version) + `,"executable":"` + python + `","threads":[],"mappings":[{"file":"` + python + `"}],"awaits":["python"]}`)
	var files bytes.Buffer
	if err := coredesc.WriteFiles(&files, root, coredesc.Files(begun, root)); err != nil {
		t.Fatal(err)
	}
	// Of a second core the program's files are no archive.
	const bad = "api-1/core.bad"
	for _, file := range []struct {
		name    string
		content []byte
	}{{name, []byte("synthetic core")}, {name + coredesc.Suffix, begun}, {name + coredesc.FilesSuffix, files.Bytes()},
		{bad, []byte("synthetic core")}, {bad + coredesc.Suffix, begun}, {bad + coredesc.FilesSuffix, bytes.Repeat([]byte("no archive "), 100)}} {
		req, _ := http.NewRequest("PUT", server.URL+"/agent/captures/"+c.ID+"/artifacts/"+file.name, bytes.NewReader(file.content))
		req.Header.Set("Authorization", "Bearer "+joined.Token)
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode >= 300 {
			t.Fatal("upload", file.name, err, res)
		}
		res.Body.Close()
	}
	var report bytes.Buffer
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		described, err := store.Artifact(ctx, c.ID, name+coredesc.Suffix)
		if err != nil {
			t.Fatal(err)
		}
		report.Reset()
		if err := h.plain(ctx, described, &report); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(report.String(), "handle_order") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the hub did not add the Python stacks: %s", report.String())
		}
	}
	if left := coredesc.Awaits(report.Bytes()); len(left) != 0 {
		t.Fatal("still awaited:", left)
	}
	// It is complete: opening the core describes nothing again.
	if described, _, err := h.describeAgain(ctx, c.ID, name); err != nil || described {
		t.Fatal("described twice:", described, err)
	}
	// Files that are no archive are the core's fault, not the hub's: who
	// opens it is shown the description as it is. The work directory holds
	// nothing of either core then.
	if result := <-h.renew(ctx, User{Name: "alice"}, c.ID, bad); result.err != nil || result.described || result.reason == "" {
		t.Fatalf("a core with files that are no archive: %+v", result)
	}
	if left, _ := os.ReadDir(h.WorkDir); len(left) != 0 {
		t.Fatal("left in the work directory:", left)
	}

	// The tool fails on a third core: its description awaits the stacks as
	// before, who opens it is told so, and the tool is not run for it again.
	const later = "api-1/core.later"
	runs := func() int {
		b, _ := os.ReadFile(h.pystack + ".runs")
		return strings.Count(string(b), "run")
	}
	before := runs()
	os.WriteFile(h.pystack+".broken", nil, 0o600)
	add := func(name string, content []byte) {
		a, err := h.keep(ctx, name, bytes.NewReader(content))
		if err != nil {
			t.Fatal(err)
		}
		if added, err := store.AddArtifact(ctx, c.ID, a); err != nil || !added {
			t.Fatal(added, err)
		}
	}
	add(later, []byte("synthetic core"))
	add(later+coredesc.Suffix, begun)
	add(later+coredesc.FilesSuffix, files.Bytes())
	for range 2 {
		if result := <-h.renew(ctx, User{Name: "alice"}, c.ID, later); result.err != nil || result.described || result.reason == "" {
			t.Fatalf("a core that the tool fails on: %+v", result)
		}
	}
	described, err := store.Artifact(ctx, c.ID, later+coredesc.Suffix)
	if err != nil {
		t.Fatal(err)
	}
	report.Reset()
	if err := h.plain(ctx, described, &report); err != nil {
		t.Fatal(err)
	}
	if left := coredesc.Awaits(report.Bytes()); len(left) != 1 || runs() != before+1 {
		t.Fatalf("after the tool failed the description awaits %v, and the tool ran %d times", left, runs()-before)
	}
	// A hub that starts anew, here with the tool mended, tries once more.
	os.Remove(h.pystack + ".broken")
	h.mu.Lock()
	h.undescribed = map[string]bool{}
	h.mu.Unlock()
	if result := <-h.renew(ctx, User{Name: "alice"}, c.ID, later); result.err != nil || !result.described {
		t.Fatalf("after the hub started anew: %+v", result)
	}
}
