package hub_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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
// alice and bob who request, root and olga who administer, carol whom the
// cluster's RBAC lets approve in the namespace payments, as it does bob,
// and dave who may nothing.
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
	cluster := fmt.Sprintf("apv%x", time.Now().UnixNano()) // one of its own for every hub of a test
	joined := hub.Cluster{Name: cluster, Token: "join-token-of-the-cluster-that-approves-" + cluster}
	c := hub.Config{Store: store, Blobs: hub.DirBlobs(t.TempDir()), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"}, Clusters: []hub.Cluster{joined},
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token"}, {Name: "bob", Token: "bob-token"}, {Name: "carol", Token: "carol-token"}, {Name: "dave", Token: "dave-token"},
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
		allowed := q.User == "alice" || q.User == "bob"
		if q.Op == "approves" {
			allowed = (q.User == "carol" || q.User == "bob") && q.Namespace == "payments"
		}
		return api.Reply{Allowed: allowed, Pods: []api.Pod{{Name: "api-1", Node: "node-a"}}, Selector: "app=api"}
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

// Who may approve in a namespace is the cluster's RBAC's to say, as who may
// capture there is: someone it lets approve sees the requests that wait
// in that namespace and decides them, without being an administrator and
// without getting at what is recorded.
func TestApprovingIsARightOfItsOwn(t *testing.T) {
	f, cluster := approving(t, nil)
	sensitive := func(namespace, reason string) api.CaptureRequest {
		return api.CaptureRequest{Cluster: cluster, Namespace: namespace, Workload: "Deployment/api", Reason: reason, Recordings: []api.Recording{{Kind: api.KindCoredump}}}
	}
	type request struct {
		ID, State, Approver, Requester, Namespace, Reason string
	}
	make1 := func(token, path string, in api.CaptureRequest) request {
		t.Helper()
		code, b := f.call(token, "POST", path, in)
		var r request
		json.Unmarshal(b, &r)
		if code != 201 {
			t.Fatalf("%s: %d %s", path, code, b)
		}
		return r
	}
	waiting := func(token string) (captures, watches []request) {
		t.Helper()
		code, b := f.call(token, "GET", "/api/approvals", nil)
		var list struct{ Captures, Watches []request }
		if json.Unmarshal(b, &list) != nil || code != 200 {
			t.Fatalf("approvals of %s: %d %s", token, code, b)
		}
		return list.Captures, list.Watches
	}
	payments := make1("alice-token", "/api/captures", sensitive("payments", "the api hangs"))
	orders := make1("alice-token", "/api/captures", sensitive("orders", "the orders too"))
	watch := make1("alice-token", "/api/watches", sensitive("payments", "when it crashes"))

	// Carol is shown what waits where she may approve, with who asks and why.
	captures, watches := waiting("carol-token")
	if len(captures) != 1 || captures[0].ID != payments.ID || captures[0].Requester != "alice" || captures[0].Reason != "the api hangs" || len(watches) != 1 || watches[0].ID != watch.ID {
		t.Fatalf("what waits for carol: %+v %+v", captures, watches)
	}
	// Others are shown nothing: not who may nothing, not the requester of her own.
	for _, token := range []string{"dave-token", "alice-token"} {
		if captures, watches := waiting(token); len(captures) != 0 || len(watches) != 0 {
			t.Fatalf("what waits for %s: %+v %+v", token, captures, watches)
		}
	}
	// An administrator approves everywhere, as before.
	if captures, watches := waiting("root-token"); len(captures) < 2 || len(watches) < 1 {
		t.Fatalf("what waits for an administrator: %+v %+v", captures, watches)
	}
	if code, _ := f.call("carol-token", "GET", "/api/captures/"+payments.ID, nil); code != 200 {
		t.Fatal("carol does not see the request she is to decide:", code)
	}
	for token, path := range map[string]string{"dave-token": payments.ID, "carol-token": orders.ID} {
		for _, act := range []string{"", "/approve", "/deny"} {
			method := "POST"
			if act == "" {
				method = "GET"
			}
			if code, _ := f.call(token, method, "/api/captures/"+path+act, nil); code != 404 {
				t.Fatalf("%s %s of a request that is not theirs to decide: %d", token, act, code)
			}
		}
	}
	if code, _ := f.call("dave-token", "POST", "/api/watches/"+watch.ID+"/approve", nil); code != 404 {
		t.Fatal("dave approved a watch:", code)
	}

	code, b := f.call("carol-token", "POST", "/api/captures/"+payments.ID+"/approve", nil)
	var decided request
	json.Unmarshal(b, &decided)
	if code != 200 || decided.Approver != "carol" || decided.State == api.StatePendingApproval {
		t.Fatalf("carol's approval: %d %s", code, b)
	}
	// What is recorded is not hers: with her decision the request is gone for her.
	if code, _ := f.call("carol-token", "GET", "/api/captures/"+payments.ID, nil); code != 404 {
		t.Fatal("carol sees the capture that she approved:", code)
	}
	code, b = f.call("carol-token", "POST", "/api/watches/"+watch.ID+"/approve", nil)
	json.Unmarshal(b, &decided)
	if code != 200 || decided.Approver != "carol" {
		t.Fatalf("carol's approval of a watch: %d %s", code, b)
	}
	if captures, watches := waiting("carol-token"); len(captures) != 0 || len(watches) != 0 {
		t.Fatalf("what waits for carol after she decided: %+v %+v", captures, watches)
	}
	// She may refuse as well.
	refused := make1("alice-token", "/api/captures", sensitive("payments", "once more"))
	if code, b := f.call("carol-token", "POST", "/api/captures/"+refused.ID+"/deny", nil); code != 200 || !strings.Contains(string(b), api.StateDenied) {
		t.Fatalf("carol's refusal: %d %s", code, b)
	}
	// Nobody approves their own request, also not who may approve there.
	own := make1("bob-token", "/api/captures", sensitive("payments", "bob's own"))
	if code, _ := f.call("bob-token", "POST", "/api/captures/"+own.ID+"/approve", nil); code != 403 {
		t.Fatal("bob approved his own request:", code)
	}
	if captures, _ := waiting("bob-token"); len(captures) != 0 {
		t.Fatalf("bob is shown his own request to approve: %+v", captures)
	}
	// A requester who may not approve is told so, of a request that is theirs to see.
	if code, _ := f.call("alice-token", "POST", "/api/captures/"+orders.ID+"/approve", nil); code != 403 {
		t.Fatal("alice approving her own:", code)
	}

	// Where several approvals are needed, hers and an administrator's count alike.
	f, cluster = approving(t, func(c *hub.Config) { c.Approvals = 2 })
	two := make1("alice-token", "/api/captures", sensitive("payments", "two are needed"))
	if code, _ := f.call("carol-token", "POST", "/api/captures/"+two.ID+"/approve", nil); code != 200 {
		t.Fatal("the first of two approvals, carol's:", code)
	}
	if captures, _ := waiting("carol-token"); len(captures) != 0 {
		t.Fatalf("carol is shown a request that has her approval: %+v", captures)
	}
	code, b = f.call("root-token", "POST", "/api/captures/"+two.ID+"/approve", nil)
	json.Unmarshal(b, &decided)
	if code != 200 || decided.Approver != "carol, root" {
		t.Fatalf("the second of two approvals: %d %s", code, b)
	}
}
