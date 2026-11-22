package hub_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/trace"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"

	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/hub"
)

// sharkdStandIn answers like Wireshark's sharkd: one line per question. It
// answers "status" with the content of the loaded file and fails "check".
const sharkdStandIn = `#!/bin/sh
while read -r line; do
	id=$(printf %s "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
	case "$line" in
	*'"method":"load"'*) content=$(cat "$(printf %s "$line" | sed 's/.*"file":"\([^"]*\)".*/\1/')"); echo "a notice that answers nothing"; result='{"status":"OK"}' ;;
	*'"method":"check"'*) echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-5001,\"message\":\"Filter invalid\"}}"; continue ;;
	*) result="{\"content\":\"$content\",\"asked\":$(printf %s "$line" | sed 's/.*"params":\(.*\)}$/\1/')}" ;;
	esac
	echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"result\":$result}"
done
`

// viewed starts a hub with a capture of alice's that holds the given files,
// and returns the capture's ID and the hub's work directory.
func viewed(t *testing.T, files map[string][]byte, tools ...func(*hub.Config)) (fixture, string, string) {
	t.Helper()
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	sharkd, work := filepath.Join(t.TempDir(), "sharkd"), t.TempDir()
	if err := os.WriteFile(sharkd, []byte(sharkdStandIn), 0o700); err != nil {
		t.Fatal(err)
	}
	cluster := "view" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))[:10]
	joined := hub.Cluster{Name: cluster, Token: "join-token-of-the-cluster-with-viewed-files-0123456789"}
	config := hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Clusters: []hub.Cluster{joined}, WorkDir: work, Sharkd: sharkd,
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "mallory", Token: "mallory-token"}, {Name: "root", Token: "root-token", Groups: []string{"admins"}}}}
	for _, tool := range tools {
		tool(&config)
	}
	h, err := hub.New(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	t.Cleanup(server.Close) // after the agent's stream, which is closed by a later cleanup
	f := fixture{t, server.URL}
	commands := scriptedAgent(t, f, joined.Token, "node-a", func(q api.Query) api.Reply {
		return api.Reply{Allowed: true, Pods: []api.Pod{{Name: "api-1", Node: "node-a"}}, Selector: "app=api"}
	})

	var c api.Capture
	code, b := f.call("alice-token", "POST", "/api/captures", api.CaptureRequest{Cluster: cluster, Namespace: "payments", Workload: "Deployment/api", DurationSeconds: 10,
		Recordings: []api.Recording{{Kind: api.KindPcap}, {Kind: api.KindPodState}}})
	json.Unmarshal(b, &c)
	if code != 201 {
		t.Fatal("request", code, string(b))
	}
	select {
	case <-commands:
	case <-time.After(10 * time.Second):
		t.Fatal("no task")
	}
	for name, content := range files {
		req, _ := http.NewRequest("PUT", server.URL+"/agent/captures/"+c.ID+"/artifacts/"+name, bytes.NewReader(content))
		req.Header.Set("Authorization", "Bearer "+joined.Token)
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode != 204 && res.StatusCode != 200 {
			t.Fatal("upload", name, err, res)
		}
		res.Body.Close()
	}
	return f, c.ID, work
}

// A packet capture opens in the browser: the hub loads it into sharkd for as
// long as the opening stream lasts and passes the viewer's questions on. The
// decrypted file has no name once it is loaded.
func TestPacketCaptureView(t *testing.T) {
	f, capture, work := viewed(t, map[string][]byte{"api-1/capture.pcap": []byte("synthetic packets"), "api-1/pod.json": []byte("{}")})
	c := api.Capture{ID: capture}
	server := struct{ URL string }{f.url}

	// The capture tells which files have a viewer.
	viewers := map[string]string{}
	for _, a := range f.capture("alice-token", c.ID).Artifacts {
		viewers[a.Name] = a.Viewer
	}
	if viewers["api-1/capture.pcap"] != "pcap" || viewers["api-1/pod.json"] != "kube" {
		t.Fatal("viewers", viewers)
	}
	// Only the packet viewer has the hub open the file.
	views := "/api/captures/" + c.ID + "/views/"
	if code, b := f.call("alice-token", "GET", views+"api-1/pod.json", nil); code != 400 {
		t.Fatal("a file that the browser reads", code, string(b))
	}
	if code, _ := f.call("mallory-token", "GET", views+"api-1/capture.pcap", nil); code != 404 {
		t.Fatal("another user's file", code)
	}

	// The view's ID arrives on a stream that keeps the view open.
	ctx, closeStream := context.WithCancel(t.Context())
	defer closeStream()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+views+"api-1/capture.pcap", nil)
	req.Header.Set("Authorization", "Bearer alice-token")
	stream, err := http.DefaultClient.Do(req)
	if err != nil || stream.StatusCode != 200 {
		t.Fatal("open", err, stream)
	}
	defer stream.Body.Close()
	line, err := bufio.NewReader(stream.Body).ReadString('\n')
	view, found := strings.CutPrefix(strings.TrimSpace(line), "data: ")
	if err != nil || !found {
		t.Fatal("no view", line, err)
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Fatal("the decrypted file kept its name", left)
	}

	// sharkd got the decrypted file and gets the viewer's questions.
	code, b := f.call("alice-token", "POST", "/api/views/"+view+"/status", map[string]int{"limit": 3})
	if code != 200 || !strings.Contains(string(b), `"content":"synthetic packets"`) || !strings.Contains(string(b), `"asked":{"limit":3}`) {
		t.Fatal("status", code, string(b))
	}
	if code, b := f.call("alice-token", "POST", "/api/views/"+view+"/check", map[string]string{"filter": "tcp.port =="}); code != 400 || !strings.Contains(string(b), "Filter invalid") {
		t.Fatal("sharkd's refusal", code, string(b))
	}
	// Of sharkd's statistics, those that count packets pass.
	if code, b := f.call("alice-token", "POST", "/api/views/"+view+"/tap", map[string]string{"tap0": "conv:TCP", "tap1": "expert", "filter": "tcp"}); code != 200 || !strings.Contains(string(b), `"tap0":"conv:TCP"`) {
		t.Fatal("statistics", code, string(b))
	}
	for _, asked := range []map[string]any{{"tap0": "eo:http"}, {"tap0": "follow:TCP"}, {"tap0": 7}, {"file": "/etc/passwd"}} {
		if code, _ := f.call("alice-token", "POST", "/api/views/"+view+"/tap", asked); code != 400 {
			t.Fatal("other statistics", asked, code)
		}
	}
	// Only questions about the loaded capture pass; "load" would open files.
	if code, _ := f.call("alice-token", "POST", "/api/views/"+view+"/load", map[string]string{"file": "/etc/passwd"}); code != 400 {
		t.Fatal("load", code)
	}
	for token, name := range map[string]string{"mallory-token": "another user", "root-token": "an administrator who did not open it"} {
		if code, _ := f.call(token, "POST", "/api/views/"+view+"/status", nil); code != 404 {
			t.Fatal(name, code)
		}
	}
	var audit []hub.AuditEntry
	_, b = f.call("root-token", "GET", "/api/audit", nil)
	json.Unmarshal(b, &audit)
	viewed := false
	for _, e := range audit {
		viewed = viewed || e.Action == "artifact.view" && e.Capture != nil && *e.Capture == c.ID && e.Actor == "alice"
	}
	if !viewed {
		t.Fatal("the view is not in the audit log")
	}

	// A deleted capture takes its open views with it: the stream ends and
	// the view answers no more.
	other, err := http.DefaultClient.Do(req.Clone(t.Context()))
	if err != nil || other.StatusCode != 200 {
		t.Fatal("open again", err, other)
	}
	defer other.Body.Close()
	lines := bufio.NewReader(other.Body)
	line, _ = lines.ReadString('\n')
	second := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
	if code, _ := f.call("alice-token", "POST", "/api/views/"+second+"/status", nil); code != 200 {
		t.Fatal("second view", code)
	}
	defer func() {
		if code, _ := f.call("alice-token", "DELETE", "/api/captures/"+c.ID, nil); code != 204 && code != 200 {
			t.Fatal("delete", code)
		}
		lines.ReadString('\n') // the blank line of the event
		if _, err := lines.ReadString('\n'); err == nil {
			t.Fatal("the stream of a deleted capture's view stayed open")
		}
		if code, _ := f.call("alice-token", "POST", "/api/views/"+second+"/status", nil); code != 404 {
			t.Fatal("the view of a deleted capture", code)
		}
	}()

	// The view ends with its stream. The hub learns of the closed stream
	// from the connection, so the test can only wait for it.
	closeStream()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if code, _ := f.call("alice-token", "POST", "/api/views/"+view+"/status", nil); code == 404 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the view outlived its stream")
		}
	}
}

// openedView opens a file's view and returns its ID; the view lasts until
// the test ends.
func openedView(t *testing.T, f fixture, capture, name string) string {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), "GET", f.url+"/api/captures/"+capture+"/views/"+name, nil)
	req.Header.Set("Authorization", "Bearer alice-token")
	stream, err := http.DefaultClient.Do(req)
	if err != nil || stream.StatusCode != 200 {
		b, _ := io.ReadAll(stream.Body)
		t.Fatal("open", name, err, stream.StatusCode, string(b))
	}
	t.Cleanup(func() { stream.Body.Close() })
	line, _ := bufio.NewReader(stream.Body).ReadString('\n')
	return strings.TrimSpace(strings.TrimPrefix(line, "data: "))
}

// A profile in pprof's format is shown by pprof's own web interface, which
// the hub serves for the view.
func TestProfileView(t *testing.T) {
	// A synthetic profile: one sample in one function.
	function := &profile.Function{ID: 1, Name: "synthetic.Workload", Filename: "workload.go"}
	location := &profile.Location{ID: 1, Line: []profile.Line{{Function: function, Line: 7}}}
	var packed bytes.Buffer
	err := (&profile.Profile{
		SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}},
		Sample:     []*profile.Sample{{Location: []*profile.Location{location}, Value: []int64{1000}}},
		Location:   []*profile.Location{location}, Function: []*profile.Function{function},
	}).Write(&packed)
	if err != nil {
		t.Fatal(err)
	}
	// The same workload later: twice the samples.
	location.Line[0].Function.Name = "synthetic.Workload"
	var later bytes.Buffer
	err = (&profile.Profile{
		SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}},
		Sample:     []*profile.Sample{{Location: []*profile.Location{location}, Value: []int64{3000}}},
		Location:   []*profile.Location{location}, Function: []*profile.Function{function},
	}).Write(&later)
	if err != nil {
		t.Fatal(err)
	}
	f, capture, _ := viewed(t, map[string][]byte{"api-1/cpu.pprof": packed.Bytes(), "api-1/later.pprof": later.Bytes(), "api-1/heap.pprof": []byte("not a profile")})

	view := openedView(t, f, capture, "api-1/cpu.pprof")
	for _, page := range []string{"flamegraph", "top"} {
		if code, b := f.call("alice-token", "GET", "/api/views/"+view+"/pages/"+page, nil); code != 200 || !strings.Contains(string(b), "synthetic.Workload") || !strings.Contains(string(b), `/view/framed.css"><body`) {
			t.Fatal(page, code, len(b))
		}
	}
	// pprof's settings are not written from the browser, and the view is its opener's.
	if code, _ := f.call("alice-token", "POST", "/api/views/"+view+"/pages/saveconfig", nil); code != 404 && code != 405 {
		t.Fatal("saveconfig", code)
	}
	if code, _ := f.call("root-token", "GET", "/api/views/"+view+"/pages/top", nil); code != 404 {
		t.Fatal("another user's view", code)
	}
	// Against a base, pprof shows the difference: 3000 - 1000 nanoseconds are 2 microseconds.
	diff := openedView(t, f, capture, "api-1/later.pprof?base="+capture+"/api-1/cpu.pprof")
	if code, b := f.call("alice-token", "GET", "/api/views/"+diff+"/pages/top", nil); code != 200 || !strings.Contains(string(b), "accounting for 2us") {
		t.Fatal("difference to the base", code, string(b))
	}
	for base, want := range map[string]int{capture + "/api-1/missing.pprof": 404, "00000000-0000-0000-0000-000000000000/api-1/cpu.pprof": 404, capture + "/api-1/heap.pprof": 422} {
		if code, _ := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/later.pprof?base="+base, nil); code != want {
			t.Fatal("base", base, code)
		}
	}
	if code, b := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/heap.pprof", nil); code != 422 || !strings.Contains(string(b), "pprof cannot read this profile") {
		t.Fatal("a file that is no profile", code, string(b))
	}
}

// A Go execution trace is shown by Go's own trace tool, which the hub runs
// for the view. Its links start at the root of its own server; the hub
// leads them to the view's pages.
func TestExecutionTraceView(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("building Go's trace tool needs the go command")
	}
	tool := filepath.Join(t.TempDir(), "gotrace")
	if out, err := exec.Command("go", "build", "-o", tool, "cmd/trace").CombinedOutput(); err != nil {
		t.Fatal("build cmd/trace:", err, string(out))
	}
	// A synthetic trace: this test's own goroutines for a moment.
	var recorded bytes.Buffer
	if err := trace.Start(&recorded); err != nil {
		t.Skip("another trace is running:", err)
	}
	done := make(chan struct{})
	go func() { time.Sleep(5 * time.Millisecond); close(done) }()
	<-done
	trace.Stop()
	f, capture, work := viewed(t, map[string][]byte{"api-1/trace.out": recorded.Bytes(), "api-1/6060-trace.out": []byte("no trace")}, func(c *hub.Config) { c.GoTrace = tool })

	view := openedView(t, f, capture, "api-1/trace.out")
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Fatal("the decrypted trace kept its name", left)
	}
	pages := "/api/views/" + view + "/pages/"
	code, b := f.call("alice-token", "GET", pages, nil)
	if code != 200 || !strings.Contains(string(b), `href="`+pages+`goroutines"`) || strings.Contains(string(b), `href="/goroutines"`) || !strings.Contains(string(b), `/view/framed.css"><body`) {
		t.Fatal("the tool's first page", code, string(b))
	}
	if code, b := f.call("alice-token", "GET", pages+"goroutines", nil); code != 200 || !strings.Contains(string(b), "Goroutines") {
		t.Fatal("goroutine analysis", code, string(b))
	}
	// The viewer's requests for the trace itself are led to the view as well.
	if code, b := f.call("alice-token", "GET", pages+"trace", nil); code != 200 || !strings.Contains(string(b), pages+"jsontrace") || strings.Contains(string(b), "/view/framed.css") {
		t.Fatal("trace page", code, len(b))
	}
	if code, _ := f.call("root-token", "GET", pages, nil); code != 404 {
		t.Fatal("another user's view", code)
	}
	if code, b := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/6060-trace.out", nil); code != 422 || !strings.Contains(string(b), "cannot read this trace") {
		t.Fatal("a file that is no trace", code, string(b))
	}
}
