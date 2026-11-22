package hub_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// A packet capture opens in the browser: the hub loads it into sharkd for as
// long as the opening stream lasts and passes the viewer's questions on. The
// decrypted file has no name once it is loaded.
func TestPacketCaptureView(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sharkd, work := filepath.Join(t.TempDir(), "sharkd"), t.TempDir()
	if err := os.WriteFile(sharkd, []byte(sharkdStandIn), 0o700); err != nil {
		t.Fatal(err)
	}
	cluster := "view" + hex.EncodeToString([]byte(time.Now().Format("150405.000")))[:10]
	joined := hub.Cluster{Name: cluster, Token: "join-token-of-the-cluster-with-viewed-files-0123456789"}
	h, err := hub.New(hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Clusters: []hub.Cluster{joined}, WorkDir: work, Sharkd: sharkd,
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "mallory", Token: "mallory-token"}, {Name: "root", Token: "root-token", Groups: []string{"admins"}}}})
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
	for name, content := range map[string]string{"api-1/capture.pcap": "synthetic packets", "api-1/pod.json": "{}"} {
		req, _ := http.NewRequest("PUT", server.URL+"/agent/captures/"+c.ID+"/artifacts/"+name, strings.NewReader(content))
		req.Header.Set("Authorization", "Bearer "+joined.Token)
		res, err := http.DefaultClient.Do(req)
		if err != nil || res.StatusCode != 204 && res.StatusCode != 200 {
			t.Fatal("upload", name, err, res)
		}
		res.Body.Close()
	}

	// The capture tells which files have a viewer.
	viewers := map[string]string{}
	for _, a := range f.capture("alice-token", c.ID).Artifacts {
		viewers[a.Name] = a.Viewer
	}
	if viewers["api-1/capture.pcap"] != "pcap" || viewers["api-1/pod.json"] != "" {
		t.Fatal("viewers", viewers)
	}
	views := "/api/captures/" + c.ID + "/views/"
	if code, b := f.call("alice-token", "GET", views+"api-1/pod.json", nil); code != 400 {
		t.Fatal("a file without a viewer", code, string(b))
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
	code, b = f.call("alice-token", "POST", "/api/views/"+view+"/status", map[string]int{"limit": 3})
	if code != 200 || !strings.Contains(string(b), `"content":"synthetic packets"`) || !strings.Contains(string(b), `"asked":{"limit":3}`) {
		t.Fatal("status", code, string(b))
	}
	if code, b := f.call("alice-token", "POST", "/api/views/"+view+"/check", map[string]string{"filter": "tcp.port =="}); code != 400 || !strings.Contains(string(b), "Filter invalid") {
		t.Fatal("sharkd's refusal", code, string(b))
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
