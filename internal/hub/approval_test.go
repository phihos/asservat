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
	// The database is the other tests' too, which know these people: what
	// was requested here goes with the test.
	t.Cleanup(func() {
		for _, kind := range []string{"watches", "captures"} {
			var made []struct{ ID, Cluster string }
			_, b := f.call("root-token", "GET", "/api/"+kind, nil)
			json.Unmarshal(b, &made)
			for _, m := range made {
				if m.Cluster == cluster {
					f.call("root-token", "DELETE", "/api/"+kind+"/"+m.ID, nil)
				}
			}
		}
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

// An installation can ask for more than one approval. Each is another
// person's, none the requester's, and the recording starts with the last.
// One person's refusal is enough to deny.
func TestARequestCanNeedSeveralApprovals(t *testing.T) {
	f, cluster := approving(t, func(c *hub.Config) { c.Approvals = 2 })
	sensitive := api.CaptureRequest{Cluster: cluster, Namespace: "payments", Workload: "Deployment/api", Recordings: []api.Recording{{Kind: api.KindCoredump}}}
	type decided struct {
		State, Approver string
		Approvals       []string
	}
	ask := func(token, method, path string, body any) (int, decided) {
		t.Helper()
		code, b := f.call(token, method, path, body)
		var d decided
		json.Unmarshal(b, &d)
		return code, d
	}
	request := func(token, path string) string {
		t.Helper()
		code, b := f.call(token, "POST", path, sensitive)
		var made struct{ ID, State, Approver string }
		json.Unmarshal(b, &made)
		if code != 201 || made.Approver != "" || made.State != "" && made.State != api.StatePendingApproval {
			t.Fatalf("%s: a sensitive request: %d %s", path, code, b)
		}
		return made.ID
	}
	var me struct{ ApprovalsNeeded int }
	if _, b := f.call("alice-token", "GET", "/api/me", nil); json.Unmarshal(b, &me) != nil || me.ApprovalsNeeded != 2 {
		t.Fatalf("the console is not told how many approvals a request needs: %s", b)
	}

	for _, kind := range []string{"captures", "watches"} {
		at := "/api/" + kind + "/" + request("alice-token", "/api/"+kind)
		// The first approval starts nothing.
		code, d := ask("root-token", "POST", at+"/approve", nil)
		if code != 200 || d.Approver != "" || len(d.Approvals) != 1 || d.Approvals[0] != "root" || kind == "captures" && d.State != api.StatePendingApproval {
			t.Fatalf("%s: the first of two approvals: %d %+v", kind, code, d)
		}
		// The same person's second word is none.
		if code, _ := ask("root-token", "POST", at+"/approve", nil); code != 409 {
			t.Fatalf("%s: one administrator approved twice: %d", kind, code)
		}
		if code, _ := ask("alice-token", "POST", at+"/approve", nil); code != 403 {
			t.Fatalf("%s: the requester approved: %d", kind, code)
		}
		code, d = ask("olga-token", "POST", at+"/approve", nil)
		if code != 200 || d.Approver != "root, olga" || len(d.Approvals) != 2 || kind == "captures" && d.State == api.StatePendingApproval {
			t.Fatalf("%s: the second of two approvals: %d %+v", kind, code, d)
		}
		if code, _ := ask("olga-token", "POST", at+"/approve", nil); code != 409 {
			t.Fatalf("%s: approved once more after it was approved: %d", kind, code)
		}
	}

	// One refusal denies, also after an approval.
	at := "/api/captures/" + request("alice-token", "/api/captures")
	ask("root-token", "POST", at+"/approve", nil)
	if code, d := ask("olga-token", "POST", at+"/deny", nil); code != 200 || d.State != api.StateDenied {
		t.Fatalf("a refusal after an approval: %d %+v", code, d)
	}

	// Where an administrator may approve their own, theirs is the first.
	f, cluster = approving(t, func(c *hub.Config) { c.Approvals, c.AllowSelfApproval = 2, true })
	sensitive.Cluster = cluster
	code, b := f.call("root-token", "POST", "/api/captures", sensitive)
	var own struct {
		ID, State, Approver string
		Approvals           []string
	}
	json.Unmarshal(b, &own)
	if code != 201 || own.State != api.StatePendingApproval || own.Approver != "" || len(own.Approvals) != 1 || own.Approvals[0] != "root" {
		t.Fatalf("an administrator's own request of two approvals: %d %s", code, b)
	}
	if code, d := ask("olga-token", "POST", "/api/captures/"+own.ID+"/approve", nil); code != 200 || d.Approver != "root, olga" || d.State == api.StatePendingApproval {
		t.Fatalf("the second approval of an administrator's own request: %d %+v", code, d)
	}
}

// What was approved before a request could need several approvals reads
// as approved by its approver, also in the list of who approved: the hub
// fills that in when it starts. Who refused a capture approved it not.
func TestApprovalsFromBeforeNameTheirApprover(t *testing.T) {
	f, cluster := approving(t, nil)
	sensitive := api.CaptureRequest{Cluster: cluster, Namespace: "payments", Workload: "Deployment/api", Recordings: []api.Recording{{Kind: api.KindCoredump}}}
	ids := map[string]string{}
	for _, decision := range []string{"approve", "deny"} {
		code, b := f.call("alice-token", "POST", "/api/captures", sensitive)
		var made struct{ ID string }
		json.Unmarshal(b, &made)
		if code != 201 {
			t.Fatal(code, string(b))
		}
		if code, b := f.call("root-token", "POST", "/api/captures/"+made.ID+"/"+decision, nil); code != 200 {
			t.Fatal(decision, code, string(b))
		}
		ids[decision] = made.ID
	}
	// As a hub from before left them: an approver, and no list.
	store, err := hub.OpenStore(t.Context(), os.Getenv("ASSERVAT_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.ForgetApprovals(t.Context(), cluster); err != nil {
		t.Fatal(err)
	}
	// A hub that starts opens its store, which brings the schema up to date.
	again, err := hub.OpenStore(t.Context(), os.Getenv("ASSERVAT_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
	for decision, want := range map[string]string{"approve": "root", "deny": ""} {
		_, b := f.call("root-token", "GET", "/api/captures/"+ids[decision], nil)
		var c struct {
			Approver  string
			Approvals []string
		}
		json.Unmarshal(b, &c)
		if c.Approver != "root" || strings.Join(c.Approvals, ",") != want {
			t.Fatalf("a capture that was decided (%s) before: approver %q, approvals %v", decision, c.Approver, c.Approvals)
		}
	}
}
