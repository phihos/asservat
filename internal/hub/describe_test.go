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
	// It is up to date now; and the work directory holds nothing of it.
	if described, _, err := h.describeAgain(ctx, c.ID, name); err != nil || described {
		t.Fatal("described twice:", described, err)
	}
	if left, _ := os.ReadDir(h.WorkDir); len(left) != 0 {
		t.Fatal("left in the work directory:", left)
	}
}
