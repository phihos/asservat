package hub_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/hub"
)

// approving starts a hub with one cluster, whose agent lets alice and bob
// capture in every namespace, and with the people of an installation:
// alice and bob who request, root and olga who administer.
func approving(t *testing.T, change func(*hub.Config)) (fixture, string) {
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
	cluster := "apv" + hex.EncodeToString([]byte(time.Now().Format("150405.000000")))[:14]
	joined := hub.Cluster{Name: cluster, Token: "join-token-of-the-cluster-that-approves-" + cluster}
	c := hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Clusters: []hub.Cluster{joined},
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "bob", Token: "bob-token"},
			{Name: "root", Token: "root-token", Groups: []string{"admins"}}, {Name: "olga", Token: "olga-token", Groups: []string{"admins"}}}}
	if change != nil {
		change(&c)
	}
	h, err := hub.New(c)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	t.Cleanup(server.Close) // after the agent's stream, which is closed by a later cleanup
	f := fixture{t, server.URL}
	scriptedAgent(t, f, joined.Token, "node-a", func(q api.Query) api.Reply {
		return api.Reply{Allowed: q.User == "alice" || q.User == "bob", Pods: []api.Pod{{Name: "api-1", Node: "node-a"}}, Selector: "app=api"}
	})
	return f, cluster
}

// An installation can ask that whoever requests a recording that needs
// approval says why: the approver decides by it, and the audit log keeps it.
func TestASensitiveRequestCanBeMadeToGiveItsReason(t *testing.T) {
	f, cluster := approving(t, func(c *hub.Config) { c.RequireReason = true })
	request := func(kind, reason string) api.CaptureRequest {
		return api.CaptureRequest{Cluster: cluster, Namespace: "payments", Workload: "Deployment/api", Reason: reason, Recordings: []api.Recording{{Kind: kind}}}
	}
	for _, path := range []string{"/api/captures", "/api/watches"} {
		for _, reason := range []string{"", "   "} {
			code, b := f.call("alice-token", "POST", path, request(api.KindCoredump, reason))
			if code != 400 || !strings.Contains(string(b), "reason") {
				t.Fatalf("%s: a core dump without a reason (%q): %d %s", path, reason, code, b)
			}
		}
		// An administrator's own request says why as well.
		if code, b := f.call("root-token", "POST", path, request(api.KindCoredump, "")); code != 400 {
			t.Fatalf("%s: an administrator's core dump without a reason: %d %s", path, code, b)
		}
		code, b := f.call("alice-token", "POST", path, request(api.KindCoredump, "the api hangs after the deploy of 14:00"))
		var made struct{ Reason string }
		json.Unmarshal(b, &made)
		if code != 201 || made.Reason != "the api hangs after the deploy of 14:00" {
			t.Fatalf("%s: a core dump with its reason: %d %s", path, code, b)
		}
		// What needs no approval needs no reason.
		if code, b := f.call("alice-token", "POST", path, request(api.KindLogs, "")); code != 201 {
			t.Fatalf("%s: logs without a reason: %d %s", path, code, b)
		}
	}
	var me struct{ ReasonRequired bool }
	if _, b := f.call("alice-token", "GET", "/api/me", nil); json.Unmarshal(b, &me) != nil || !me.ReasonRequired {
		t.Fatalf("the console is not told that a reason is required: %s", b)
	}

	// Without the setting nothing changes.
	f, cluster = approving(t, nil)
	if code, b := f.call("alice-token", "POST", "/api/captures", request(api.KindCoredump, "")); code != 201 {
		t.Fatalf("a core dump without a reason where none is required: %d %s", code, b)
	}
}
