package hub_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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
// answers with the content of the loaded file and what it was asked, and
// fails "check". For a file that holds "summary" it answers the questions
// of a packet summary as sharkd does.
const sharkdStandIn = `#!/bin/sh
while read -r line; do
	id=$(printf %s "$line" | sed 's/.*"id":\([0-9]*\).*/\1/')
	result="{\"content\":\"$content\",\"asked\":$(printf %s "$line" | sed 's/.*"params":\(.*\)}$/\1/')}"
	case "$content/$line" in
	*'"method":"load"'*) content=$(cat "$(printf %s "$line" | sed 's/.*"file":"\([^"]*\)".*/\1/')"); echo "a notice that answers nothing"; result='{"status":"OK"}' ;;
	summary/*'"method":"check"'*) result='{"status":"OK"}' ;;
	summary/*'"method":"status"'*) result='{"frames":3,"duration":1.5}' ;;
	summary/*'"method":"tap"'*) result='{"taps":[{"tap":"expert","type":"expert","details":[{"f":2,"s":"Warn","g":"Sequence","m":"Previous segment not captured","p":"TCP"},{"f":3,"s":"Warn","g":"Sequence","m":"Previous segment not captured","p":"TCP"}]},{"tap":"conv:TCP","type":"conv","convs":[{"saddr":"10.0.0.1","sport":"40000","daddr":"10.0.0.2","dport":"8080","txf":2,"txb":300,"rxf":1,"rxb":900,"start":0,"stop":1.5}]},{"tap":"phs","type":"phs","protos":[{"proto":"eth","frames":3,"bytes":1200,"protos":[{"proto":"tcp","frames":3,"bytes":1200,"protos":[{"proto":"http","frames":2,"bytes":1000}]}]}]},{"tap":"conv:UDP","type":"conv","convs":[]}]}' ;;
	summary/*'"method":"frames"'*) result='[{"c":["2","0.500000","10.0.0.2","10.0.0.1","HTTP","900","HTTP/1.1 500 Internal Server Error"],"num":2}]' ;;
	*'"method":"check"'*) echo "{\"jsonrpc\":\"2.0\",\"id\":$id,\"error\":{\"code\":-5001,\"message\":\"Filter invalid\"}}"; continue ;;
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

// syntheticNettrace writes a .NET trace as the runtime does, with compressed
// event headers: four samples of one thread's stack, three of them in
// Shop.Burn under Shop.Main and two frames outside of .NET methods, and the
// methods' addresses after the samples, as the end of a trace reports them.
func syntheticNettrace() []byte {
	var trace bytes.Buffer
	le := func(values ...any) []byte {
		var b bytes.Buffer
		for _, v := range values {
			binary.Write(&b, binary.LittleEndian, v)
		}
		return b.Bytes()
	}
	wide := func(s string) []byte {
		var b []byte
		for _, r := range s {
			b = append(b, byte(r), 0)
		}
		return append(b, 0, 0)
	}
	str := func(s string) []byte { return append(le(int32(len(s))), s...) }
	object := func(name string, version int32, content []byte, block bool) {
		trace.Write([]byte{5, 5, 1})
		trace.Write(le(version, version))
		trace.Write(str(name))
		trace.WriteByte(6)
		if block {
			trace.Write(le(int32(len(content))))
			for trace.Len()%4 != 0 {
				trace.WriteByte(0)
			}
		}
		trace.Write(content)
		trace.WriteByte(6)
	}
	// An event with a compressed header: its description's ID, thread and stack as far as given, a time and its payload.
	event := func(id, thread, stack byte, payload []byte) []byte {
		flags, fields := byte(128), []byte{}
		for bit, value := range map[byte]byte{1: id, 4: thread, 8: stack} {
			if value != 0 {
				flags |= bit
			}
		}
		for _, value := range []byte{id, thread, stack} {
			if value != 0 {
				fields = append(fields, value)
			}
		}
		fields = append(fields, 1, byte(len(payload))) // the time since the event before, the payload's size
		return append(append([]byte{flags}, fields...), payload...)
	}
	events := func(blobs ...[]byte) []byte {
		return append(le(int16(20), int16(1), int64(0), int64(0)), bytes.Join(blobs, nil)...)
	}
	describe := func(id int32, provider string, number int32) []byte {
		payload := append(le(id), wide(provider)...)
		payload = append(payload, le(number)...)
		return event(0, 0, 0, append(append(payload, wide("")...), le(int64(0), int32(0), int32(0), int32(0))...))
	}
	method := func(start uint64, namespace, name string) []byte {
		payload := le(uint64(1), uint64(2), start, uint32(0x100), uint32(0), uint32(0))
		return event(2, 7, 0, append(append(payload, wide(namespace)...), wide(name)...))
	}
	trace.WriteString("Nettrace")
	trace.Write(str("!FastSerialization.1"))
	object("Trace", 4, le([8]int16{}, int64(0), int64(1000000000), int32(8), int32(42), int32(4), int32(1000000)), false)
	object("MetadataBlock", 2, events(describe(1, "Microsoft-DotNETCore-SampleProfiler", 0), describe(2, "Microsoft-Windows-DotNETRuntimeRundown", 144)), true)
	sample := le(int32(2))
	object("EventBlock", 2, events(event(1, 7, 1, sample), event(0, 0, 0, sample), event(0, 0, 0, sample), event(0, 0, 2, sample)), true)
	object("StackBlock", 2, append(le(int32(1), int32(2), int32(32), uint64(0x2010), uint64(0x1010), uint64(0x9999), uint64(0x9998)), le(int32(8), uint64(0x1020))...), true)
	object("SPBlock", 2, le(int64(0), int32(0)), true)
	object("EventBlock", 2, events(method(0x1000, "Shop", "Main"), method(0x2000, "Shop", "Burn")), true)
	trace.WriteByte(1)
	return trace.Bytes()
}

// A .NET trace opens in pprof's viewer as a profile of the runtime's stack
// samples, with the methods' names that the trace reports at its end.
func TestDotnetTraceView(t *testing.T) {
	trace := syntheticNettrace()
	f, capture, _ := viewed(t, map[string][]byte{"api-1/trace.nettrace": trace, "api-1/cut.nettrace": trace[:len(trace)-40], "api-1/other.nettrace": []byte("no trace")})
	view := openedView(t, f, capture, "api-1/trace.nettrace")
	code, b := f.call("alice-token", "GET", "/api/views/"+view+"/pages/top", nil)
	// Four samples of a millisecond each: three in Burn, one in Main itself.
	if code != 200 || !strings.Contains(string(b), "Shop.Burn") || !strings.Contains(string(b), "Shop.Main") || !strings.Contains(string(b), "of 4ms total") {
		t.Fatal(code, string(b))
	}
	code, b = f.call("alice-token", "GET", "/api/views/"+view+"/pages/flamegraph", nil)
	if code != 200 || !strings.Contains(string(b), "[native code]") {
		t.Fatal("frames outside of .NET methods", code, len(b))
	}
	for _, name := range []string{"cut.nettrace", "other.nettrace"} {
		if code, b := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/"+name, nil); code != 422 || !strings.Contains(string(b), ".NET trace") {
			t.Fatal(name, code, string(b))
		}
	}
}

// A JVM's flight recording opens in pprof's viewer as a profile of what the
// recorder sampled: where the threads ran, and where they allocated.
func TestFlightRecordingView(t *testing.T) {
	// Of a program made for this test, which spins in Burn.spin and allocates in Burn.hold for three seconds.
	recording, err := os.ReadFile("testdata/recording.jfr")
	if err != nil {
		t.Fatal(err)
	}
	if api.ViewerOf("api-1/jvm-recording.jfr") != "pprof" {
		t.Fatal("a flight recording has no viewer")
	}
	f, capture, _ := viewed(t, map[string][]byte{"api-1/jvm-recording.jfr": recording, "api-1/cut.jfr": recording[:len(recording)/2], "api-1/other.jfr": []byte("no recording")})
	view := openedView(t, f, capture, "api-1/jvm-recording.jfr")
	code, b := f.call("alice-token", "GET", "/api/views/"+view+"/pages/top", nil)
	if code != 200 || !strings.Contains(string(b), "Burn.spin") || strings.Contains(string(b), "of 0 total") {
		t.Fatal("where the threads ran", code, len(b))
	}
	code, b = f.call("alice-token", "GET", "/api/views/"+view+"/pages/top?si=allocated", nil)
	if code != 200 || !strings.Contains(string(b), "Burn.hold") || !strings.Contains(string(b), "MB total") {
		t.Fatal("where the threads allocated", code, len(b))
	}
	for _, name := range []string{"cut.jfr", "other.jfr"} {
		if code, b := f.call("alice-token", "GET", "/api/captures/"+capture+"/views/api-1/"+name, nil); code != 422 || !strings.Contains(string(b), "flight recording") {
			t.Fatal(name, code, string(b))
		}
	}
}

// An event stream that has nothing to say still writes a line now and then:
// a proxy in front of the hub ends a connection that stays silent (HAProxy
// after 50 seconds by default), and with its stream a view would end.
func TestStreamsStayOpenThroughProxies(t *testing.T) {
	profile := func() []byte {
		function := &profile.Function{ID: 1, Name: "synthetic.Workload"}
		location := &profile.Location{ID: 1, Line: []profile.Line{{Function: function}}}
		var packed bytes.Buffer
		p := &profile.Profile{SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}}, Function: []*profile.Function{function}, Location: []*profile.Location{location},
			Sample: []*profile.Sample{{Location: []*profile.Location{location}, Value: []int64{1}}}}
		if err := p.Write(&packed); err != nil {
			t.Fatal(err)
		}
		return packed.Bytes()
	}()
	f, capture, _ := viewed(t, map[string][]byte{"api-1/cpu.pprof": profile}, func(c *hub.Config) { c.StreamBeat = 20 * time.Millisecond })
	const join = "join-token-of-the-cluster-with-viewed-files-0123456789"
	for what, stream := range map[string][2]string{
		"a view":                {"/api/captures/" + capture + "/views/api-1/cpu.pprof", "alice-token"},
		"the captures' changes": {"/api/events", "alice-token"},
		"an agent's commands":   {"/agent/stream?node=node-1", join},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", f.url+stream[0], nil)
		req.Header.Set("Authorization", "Bearer "+stream[1])
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode != 200 {
			t.Fatal(what, err)
		}
		// A stream begins with at most two lines. More lines come although nothing happens.
		lines := bufio.NewReader(res.Body)
		for read := 0; read < 6; read++ {
			if _, err := lines.ReadString('\n'); err != nil {
				t.Fatalf("the stream of %s stayed silent after %d lines: %v", what, read, err)
			}
		}
		cancel()
		res.Body.Close()
	}
}

// An AI agent cannot open a viewer. Over MCP, a profile reads as pprof's
// list of the functions with the most weight, a .NET trace likewise, and a
// heap dump as its classes with the number and size of their objects.
func TestBinaryEvidenceReadsAsTextOverMCP(t *testing.T) {
	function := func(id uint64, name string) *profile.Function { return &profile.Function{ID: id, Name: name} }
	work, idle := function(1, "synthetic.Workload"), function(2, "synthetic.Idle")
	at := func(id uint64, f *profile.Function) *profile.Location {
		return &profile.Location{ID: id, Line: []profile.Line{{Function: f}}}
	}
	working, idling := at(1, work), at(2, idle)
	var packed bytes.Buffer
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}, {Type: "cpu", Unit: "nanoseconds"}},
		Function:   []*profile.Function{work, idle}, Location: []*profile.Location{working, idling},
		Sample: []*profile.Sample{{Location: []*profile.Location{working}, Value: []int64{9, 9000000}}, {Location: []*profile.Location{idling}, Value: []int64{1, 1000000}}},
	}
	if err := p.Write(&packed); err != nil {
		t.Fatal(err)
	}
	f, capture, workDir := viewed(t, map[string][]byte{"api-1/cpu.pprof": packed.Bytes(), "api-1/trace.nettrace": syntheticNettrace(), "api-1/heapdump.hprof": syntheticHeap(), "api-1/broken.pprof": []byte("\x00no profile"), "api-1/capture.pcap": []byte("summary")})
	read := func(arguments map[string]any) string {
		t.Helper()
		arguments["id"] = capture
		code, b := f.call("alice-token", "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "read_artifact", "arguments": arguments}})
		if code != 200 {
			t.Fatal(code, string(b))
		}
		var reply struct {
			Result struct {
				IsError bool
				Content []struct{ Text string }
			}
		}
		if err := json.Unmarshal(b, &reply); err != nil || len(reply.Result.Content) != 1 {
			t.Fatal(err, string(b))
		}
		if reply.Result.IsError {
			return "ERROR: " + reply.Result.Content[0].Text
		}
		var file struct{ Text string }
		if err := json.Unmarshal([]byte(reply.Result.Content[0].Text), &file); err != nil {
			t.Fatal(err, reply.Result.Content[0].Text)
		}
		return file.Text
	}
	// The profile's last kind of value by default, as pprof shows it: 90 % of 10 ms in the workload.
	if text := read(map[string]any{"name": "api-1/cpu.pprof"}); !strings.Contains(text, "synthetic.Workload") || !strings.Contains(text, "9ms") || !strings.Contains(text, "90.00%") || !strings.Contains(text, "samples, cpu") {
		t.Fatal("a profile", text)
	}
	if text := read(map[string]any{"name": "api-1/cpu.pprof", "sampleType": "samples"}); !strings.Contains(text, "synthetic.Workload") || strings.Contains(text, "9ms") {
		t.Fatal("another kind of value", text)
	}
	if text := read(map[string]any{"name": "api-1/cpu.pprof", "sampleType": "heap"}); !strings.HasPrefix(text, "ERROR") || !strings.Contains(text, "samples, cpu") {
		t.Fatal("a kind of value the profile has not", text)
	}
	// What one call chooses does not carry over to the next, although pprof
	// keeps its options for the whole program: a .NET trace's stacks sorted
	// by weight with callees put Main first, by own weight Burn, and the
	// viewer's page is sorted by own weight as well.
	first := func(text string) string {
		_, rows, _ := strings.Cut(text, "cum%\n")
		return strings.Fields(strings.SplitN(rows, "\n", 2)[0] + " -")[5]
	}
	if got := first(read(map[string]any{"name": "api-1/trace.nettrace", "cumulative": true, "sampleType": "samples"})); got != "Shop.Main" {
		t.Fatal("sorted by weight with callees", got)
	}
	plain := read(map[string]any{"name": "api-1/trace.nettrace"})
	if got := first(plain); got != "Shop.Burn" || !strings.Contains(plain, "Type: thread_time") {
		t.Fatal("the call before changed this one", got, plain)
	}
	view := openedView(t, f, capture, "api-1/cpu.pprof")
	if code, b := f.call("alice-token", "GET", "/api/views/"+view+"/pages/top", nil); code != 200 || !strings.Contains(string(b), "of 10ms total") {
		t.Fatal("the viewer after calls over MCP", code, string(b))
	}
	if text := read(map[string]any{"name": "api-1/trace.nettrace"}); !strings.Contains(text, "Shop.Burn") || !strings.Contains(text, "thread_time") {
		t.Fatal("a .NET trace", text)
	}
	if text := read(map[string]any{"name": "api-1/heapdump.hprof"}); !strings.Contains(text, "shop.Order") || !strings.Contains(text, "5 objects") || !strings.Contains(text, "byte[]") {
		t.Fatal("a heap dump", text)
	}
	if text := read(map[string]any{"name": "api-1/broken.pprof"}); !strings.HasPrefix(text, "ERROR") || !strings.Contains(text, "pprof cannot read") {
		t.Fatal("a file that is no profile", text)
	}
	// A packet capture reads as its statistics: how many packets over which
	// time, the protocols, who talked to whom, and what Wireshark remarks.
	text := read(map[string]any{"name": "api-1/capture.pcap"})
	for _, part := range []string{"3 packets over 1.5 s", "http", "10.0.0.1:40000", "10.0.0.2:8080", "1200 bytes", "2 × Warn", "Previous segment not captured", "filter"} {
		if !strings.Contains(text, part) {
			t.Fatalf("a packet capture lacks %q: %s", part, text)
		}
	}
	// Protocols, then conversations, then remarks, whatever order sharkd answers in.
	if protocols, talks, remarks := strings.Index(text, "Protocols"), strings.Index(text, "TCP conversations"), strings.Index(text, "expert information"); !(protocols < talks && talks < remarks) {
		t.Fatal("the order of a packet summary", text)
	}
	// With a display filter, as in Wireshark, it reads as the packets that match.
	if text := read(map[string]any{"name": "api-1/capture.pcap", "filter": "http.response.code >= 500"}); !strings.Contains(text, "500 Internal Server Error") || !strings.Contains(text, "10.0.0.2") {
		t.Fatal("packets by a display filter", text)
	}
	if left, _ := os.ReadDir(workDir); len(left) != 0 {
		t.Fatal("the decrypted capture is still in the work directory", left)
	}
}

// A hub without an alert token accepts neither alerts nor watches for them.
func TestAlertsNeedTheHubsToken(t *testing.T) {
	f, _, _ := viewed(t, map[string][]byte{"api-1/pod.json": []byte("{}")})
	code, b := f.call("alice-token", "POST", "/api/watches", map[string]any{"cluster": "any", "namespace": "payments", "workload": "Deployment/api", "kind": "pod-state",
		"when": map[string]any{"kind": "alert", "params": map[string]string{"name": "HighErrorRate"}}})
	if code != 400 || !strings.Contains(string(b), "alert token") {
		t.Fatal("a watch for an alert", code, string(b))
	}
	if code, _ := f.call("alice-token", "POST", "/api/alerts", map[string]any{"alerts": []any{}}); code != 404 {
		t.Fatal("an alert", code)
	}
}

// What the hub had decrypted into its work directory when it was killed is
// still there when it starts in the same pod: it removes that, and keeps
// the debug information that was downloaded.
func TestAStartingHubClearsWhatWasDecrypted(t *testing.T) {
	var work string
	viewed(t, map[string][]byte{"api-1/pod.json": []byte("{}")}, func(c *hub.Config) {
		work = c.WorkDir
		for _, left := range []string{"describe-123/core", "view-9.pcap", "dotnet-7/core", "debuginfod/kept"} {
			os.MkdirAll(filepath.Dir(filepath.Join(work, left)), 0o700)
			os.WriteFile(filepath.Join(work, left), []byte("x"), 0o600)
		}
	})
	left, _ := os.ReadDir(work)
	if len(left) != 1 || left[0].Name() != "debuginfod" {
		t.Fatal("after the start the work directory holds", left)
	}
}
