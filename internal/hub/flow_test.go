package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"asservat.local/asservat/internal/agent"
	"asservat.local/asservat/internal/api"
	"asservat.local/asservat/internal/hub"
)

// The flow test runs the hub with real PostgreSQL and a real agent against a
// fake Kubernetes API. Set ASSERVAT_TEST_DSN, for example
// postgres://postgres:pw@127.0.0.1:55432/postgres.
type fixture struct {
	t   *testing.T
	url string
}

func (f fixture) call(token, method, path string, body any) (int, []byte) {
	f.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.url+path, r)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b
}

func (f fixture) capture(token, id string) api.Capture {
	f.t.Helper()
	code, b := f.call(token, "GET", "/api/captures/"+id, nil)
	var c api.Capture
	if code != 200 || json.Unmarshal(b, &c) != nil {
		f.t.Fatal("get capture", code, string(b))
	}
	return c
}

// wait follows the event stream until the capture reaches one of the states.
func (f fixture) wait(token, id string, states ...string) api.Capture {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(f.t.Context(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", f.url+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 256)
	for {
		c := f.capture(token, id)
		for _, s := range states {
			if c.State == s {
				return c
			}
		}
		if _, err := res.Body.Read(buf); err != nil {
			f.t.Fatal("capture stayed", c.State, c.Message, err)
		}
	}
}

func TestCaptureFlow(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	blobDir := t.TempDir()
	h, err := hub.New(hub.Config{
		Store: store, Blobs: hub.DirBlobs(blobDir), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour, AdminGroups: []string{"admins"},
		Users: []hub.StaticUser{{Name: "alice", Token: "alice-token", Groups: []string{"payments"}}, {Name: "mallory", Token: "mallory-token"},
			{Name: "root", Token: "root-token", Groups: []string{"admins"}}, {Name: "root2", Token: "root2-token", Groups: []string{"admins"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h.Handler())
	defer server.Close()
	f := fixture{t, server.URL}

	// An administrator registers the cluster; its token connects the agent.
	cluster := "c" + strings.ReplaceAll(t.Name(), "/", "-") + hex.EncodeToString([]byte(time.Now().Format("150405.000")))[:8]
	cluster = strings.ToLower(cluster)
	if code, _ := f.call("alice-token", "POST", "/api/clusters", map[string]string{"name": cluster}); code != 403 {
		t.Fatal("a user added a cluster", code)
	}
	code, b := f.call("root-token", "POST", "/api/clusters", map[string]string{"name": cluster})
	var joined struct{ Token string }
	if code != 200 || json.Unmarshal(b, &joined) != nil || len(joined.Token) != 64 {
		t.Fatal("add cluster", code, string(b))
	}
	defer f.call("root-token", "DELETE", "/api/clusters/"+cluster, nil)

	labels := map[string]string{"app": "api"}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "payments", Labels: labels},
		Spec:   corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	elsewhere := pod.DeepCopy()
	elsewhere.Name, elsewhere.Spec.NodeName = "api-2", "node-b"
	third := pod.DeepCopy()
	third.Name, third.Spec.NodeName = "api-3", "node-c"
	fourth := pod.DeepCopy()
	fourth.Name, fourth.Spec.NodeName = "api-4", "node-d"
	kube := fake.NewClientset(pod, elsewhere, third, fourth, &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "payments"},
		Spec: appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: labels}}})
	// RBAC of the fake cluster: the payments group may exec in payments.
	kube.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview)
		a := sar.Spec.ResourceAttributes
		sar.Status.Allowed = a.Namespace == "payments" && a.Subresource == "exec" && len(sar.Spec.Groups) == 1 && sar.Spec.Groups[0] == "payments"
		return true, sar, nil
	})
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	node := &agent.Agent{HubURL: server.URL, Token: joined.Token, Node: "node-a", Kube: kube, HTTP: http.DefaultClient, Scratch: t.TempDir(), Proc: t.TempDir()}
	go node.Run(ctx)
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		_, b := f.call("alice-token", "GET", "/api/clusters", nil)
		if strings.Contains(string(b), `"node-a"`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect", string(b))
		}
	}

	request := func(token string, r api.CaptureRequest) (int, api.Capture) {
		t.Helper()
		code, b := f.call(token, "POST", "/api/captures", r)
		var c api.Capture
		json.Unmarshal(b, &c)
		return code, c
	}
	target := api.CaptureRequest{Cluster: cluster, Namespace: "payments", Workload: "Deployment/api", Pods: []string{"api-1"}}

	// Without the exec right in the namespace nothing is listed or captured.
	if code, _ := f.call("mallory-token", "GET", "/api/clusters/"+cluster+"/namespaces/payments/workloads", nil); code != 403 {
		t.Fatal("workloads listed without the exec right", code)
	}
	state := target
	state.Kind = api.KindPodState
	if code, _ := request("mallory-token", state); code != 403 {
		t.Fatal("captured without the exec right", code)
	}
	if code, b := f.call("alice-token", "GET", "/api/clusters/"+cluster+"/namespaces/payments/workloads", nil); code != 200 || string(b) != `["Deployment/api","Pod/api-1","Pod/api-2","Pod/api-3","Pod/api-4"]`+"\n" {
		t.Fatal("workloads", code, string(b))
	}

	// An ordinary capture starts at once and its files download unchanged.
	code, c := request("alice-token", state)
	if code != 201 || c.State != api.StateQueued || c.Sensitive || len(c.Tasks) != 1 {
		t.Fatal("request", code, c)
	}
	c = f.wait("alice-token", c.ID, api.StateCompleted, api.StateFailed)
	if c.State != api.StateCompleted || len(c.Artifacts) != 2 || c.Artifacts[1].Name != "api-1/pod.json" {
		t.Fatal("pod-state capture", c.State, c.Message, c.Tasks, c.Artifacts)
	}
	code, b = f.call("alice-token", "GET", "/api/captures/"+c.ID+"/artifacts/api-1/pod.json", nil)
	sum := sha256.Sum256(b)
	if code != 200 || !strings.Contains(string(b), `"nodeName": "node-a"`) || hex.EncodeToString(sum[:]) != c.Artifacts[1].SHA256 || int64(len(b)) != c.Artifacts[1].Size {
		t.Fatal("download", code, string(b))
	}
	if code, _ := f.call("mallory-token", "GET", "/api/captures/"+c.ID+"/artifacts/api-1/pod.json", nil); code != 404 {
		t.Fatal("another user downloaded the file", code)
	}
	if code, _ := f.call("mallory-token", "GET", "/api/captures/"+c.ID, nil); code != 404 {
		t.Fatal("another user read the capture", code)
	}

	// The same file through MCP.
	code, b = f.call("alice-token", "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "read_artifact", "arguments": map[string]any{"id": c.ID, "name": "api-1/pod.json"}}})
	if code != 200 || !strings.Contains(string(b), `nodeName`) || !strings.Contains(string(b), `"isError":false`) {
		t.Fatal("mcp read_artifact", code, string(b))
	}

	code, b = f.call("alice-token", "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "list_captures"}})
	if code != 200 || !strings.Contains(string(b), c.ID) {
		t.Fatal("mcp list_captures", code, string(b))
	}

	// A core dump waits for another administrator.
	core := target
	core.Kind, core.Reason = api.KindCoredump, "deadlock in production"
	code, pending := request("alice-token", core)
	if code != 201 || pending.State != api.StatePendingApproval || !pending.Sensitive {
		t.Fatal("sensitive request", code, pending)
	}
	if code, _ := f.call("alice-token", "POST", "/api/captures/"+pending.ID+"/approve", nil); code != 403 {
		t.Fatal("the requester approved", code)
	}
	if got := f.capture("alice-token", pending.ID); got.State != api.StatePendingApproval || got.Tasks[0].State != api.StateQueued {
		t.Fatal("capture started before approval", got)
	}
	code, mine := request("root-token", core)
	if code != 201 {
		t.Fatal(code)
	}
	if code, _ := f.call("root-token", "POST", "/api/captures/"+mine.ID+"/approve", nil); code != 403 {
		t.Fatal("an administrator approved their own request", code)
	}
	if code, _ := f.call("root2-token", "POST", "/api/captures/"+mine.ID+"/deny", nil); code != 200 {
		t.Fatal("deny", code)
	}
	if got := f.capture("root-token", mine.ID); got.State != api.StateDenied || got.Tasks[0].State != api.StateCancelled {
		t.Fatal("denied capture", got.State, got.Tasks)
	}
	if code, _ := f.call("root2-token", "POST", "/api/captures/"+mine.ID+"/approve", nil); code != 409 {
		t.Fatal("a denied capture was approved", code)
	}
	if code, _ := f.call("root-token", "POST", "/api/captures/"+pending.ID+"/approve", nil); code != 200 {
		t.Fatal("approve", code)
	}
	// The fake node has no such container process: the approved task runs
	// and fails there, which shows it was dispatched only now.
	done := f.wait("alice-token", pending.ID, api.StateCompleted, api.StateFailed)
	if done.State != api.StateFailed || done.Approver != "root" || !strings.Contains(done.Tasks[0].Message, "app") {
		t.Fatal("approved capture", done)
	}

	// A pod on a node without a connected agent stays queued until it connects.
	away := target
	away.Kind, away.Pods = api.KindLogs, []string{"api-2"}
	code, queued := request("alice-token", away)
	if code != 201 || queued.Tasks[0].Node != "node-b" {
		t.Fatal(code, queued)
	}
	other := &agent.Agent{HubURL: server.URL, Token: joined.Token, Node: "node-b", Kube: kube, HTTP: http.DefaultClient}
	go other.Run(ctx)
	if got := f.wait("alice-token", queued.ID, api.StateCompleted, api.StateFailed); got.State != api.StateCompleted || got.Artifacts[0].Name != "api-2/app.log" {
		t.Fatal("task queued for a reconnecting agent", got)
	}

	// A task whose agent restarted while it ran is reported as failed when
	// the node's agent connects again, instead of staying Running.
	lost := target
	lost.Kind, lost.Pods = api.KindLogs, []string{"api-3"}
	code, running := request("alice-token", lost)
	if code != 201 || running.Tasks[0].Node != "node-c" {
		t.Fatal(code, running)
	}
	if err := store.SetTask(t.Context(), running.ID, api.TaskStatus{Pod: "api-3", State: api.StateRunning}); err != nil {
		t.Fatal(err)
	}
	restarted := &agent.Agent{HubURL: server.URL, Token: joined.Token, Node: "node-c", Kube: kube, HTTP: http.DefaultClient}
	go restarted.Run(ctx)
	if got := f.wait("alice-token", running.ID, api.StateCompleted, api.StateFailed); got.State != api.StateFailed || !strings.Contains(got.Tasks[0].Message, "restarted") {
		t.Fatal("task of a restarted agent", got.State, got.Tasks)
	}

	// Agent-side rules: files belong to a pod of the capture, replies to the
	// asked cluster, and a connecting agent learns its node's open tasks.
	agentCall := func(token, method, path string, body io.Reader) int {
		req, _ := http.NewRequest(method, server.URL+path, body)
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	open := target
	open.Kind, open.Pods = api.KindLogs, []string{"api-4"}
	code, held := request("alice-token", open) // node-d has no agent: the task stays queued
	if code != 201 {
		t.Fatal(code, held)
	}
	for name, want := range map[string]int{"api-4/app.log": 200, "api-1/app.log": 400, "api-4/a/b": 400, "api-4": 400} {
		if got := agentCall(joined.Token, "PUT", "/agent/captures/"+held.ID+"/artifacts/"+name, strings.NewReader("line\n")); got != want {
			t.Errorf("upload %s: status %d, want %d", name, got, want)
		}
	}
	_, b = f.call("root-token", "POST", "/api/clusters", map[string]string{"name": cluster + "-other"})
	var foreign struct{ Token string }
	json.Unmarshal(b, &foreign)
	defer f.call("root-token", "DELETE", "/api/clusters/"+cluster+"-other", nil)
	if got := agentCall(foreign.Token, "PUT", "/agent/captures/"+held.ID+"/artifacts/api-4/x.log", strings.NewReader("x")); got != 404 {
		t.Error("another cluster's agent uploaded", got)
	}
	streamCtx, closeStream := context.WithCancel(t.Context())
	req, _ := http.NewRequestWithContext(streamCtx, "GET", server.URL+"/agent/stream?node=node-d", nil)
	req.Header.Set("Authorization", "Bearer "+joined.Token)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var first api.Command
	if err := json.NewDecoder(stream.Body).Decode(&first); err != nil || first.Type != "sync" || len(first.Tasks) != 1 || first.Tasks[0].ID != held.ID || first.Tasks[0].Task.Pod != "api-4" {
		t.Fatal("the stream does not start with the node's open tasks", first, err)
	}
	closeStream()
	stream.Body.Close()

	// A reply from another cluster's agent does not answer a cluster's query.
	req, _ = http.NewRequestWithContext(t.Context(), "GET", server.URL+"/agent/stream?node=only", nil)
	req.Header.Set("Authorization", "Bearer "+foreign.Token)
	if stream, err = http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	commands := json.NewDecoder(stream.Body)
	if err := commands.Decode(&first); err != nil || first.Type != "sync" {
		t.Fatal(first, err)
	}
	answered := make(chan int, 1)
	go func() {
		code, _ := f.call("mallory-token", "GET", "/api/clusters/"+cluster+"-other/namespaces/payments/workloads", nil)
		answered <- code
	}()
	var query api.Command
	if err := commands.Decode(&query); err != nil || query.Type != "query" || query.Query.Op != "review" || query.Query.User != "mallory" {
		t.Fatal("review query", query, err)
	}
	agentCall(joined.Token, "POST", "/agent/replies/"+query.ID, strings.NewReader(`{"allowed":true}`))
	select {
	case code := <-answered:
		t.Fatal("another cluster's agent answered the review", code)
	case <-time.After(300 * time.Millisecond):
	}
	agentCall(foreign.Token, "POST", "/agent/replies/"+query.ID, strings.NewReader(`{"allowed":false}`))
	if code := <-answered; code != 403 {
		t.Fatal("review", code)
	}
	stream.Body.Close()

	// After a cancellation the node's open tasks no longer include the task.
	if code, _ := f.call("alice-token", "POST", "/api/captures/"+held.ID+"/cancel", nil); code != 200 {
		t.Fatal("cancel", code)
	}
	if got := agentCall(joined.Token, "PUT", "/agent/captures/"+held.ID+"/artifacts/api-4/late.log", strings.NewReader("late")); got != 409 {
		t.Error("upload into a cancelled capture", got)
	}
	req, _ = http.NewRequestWithContext(t.Context(), "GET", server.URL+"/agent/stream?node=node-d", nil)
	req.Header.Set("Authorization", "Bearer "+joined.Token)
	if stream, err = http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	first = api.Command{}
	if err := json.NewDecoder(stream.Body).Decode(&first); err != nil || first.Type != "sync" || len(first.Tasks) != 0 {
		t.Fatal("a cancelled task is still open", first, err)
	}
	stream.Body.Close()

	// A corrupt stored file is an error for MCP, not partial text.
	if err := corrupt(blobDir); err != nil {
		t.Fatal(err)
	}
	code, b = f.call("alice-token", "POST", "/mcp", map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": "read_artifact", "arguments": map[string]any{"id": c.ID, "name": "api-1/pod.json"}}})
	if code != 200 || !strings.Contains(string(b), `"isError":true`) {
		t.Fatal("mcp read of a corrupt file", code, string(b))
	}

	// Cancel, delete and the audit trail.
	code, waiting := request("alice-token", core)
	if code != 201 {
		t.Fatal(code)
	}
	if code, _ := f.call("alice-token", "POST", "/api/captures/"+waiting.ID+"/cancel", nil); code != 200 {
		t.Fatal("cancel", code)
	}
	if code, _ := f.call("root-token", "POST", "/api/captures/"+waiting.ID+"/approve", nil); code != 409 {
		t.Fatal("a cancelled capture was approved", code)
	}
	if code, _ := f.call("alice-token", "DELETE", "/api/captures/"+c.ID, nil); code != 200 {
		t.Fatal("delete", code)
	}
	if code, _ := f.call("alice-token", "GET", "/api/captures/"+c.ID+"/artifacts/api-1/pod.json", nil); code != 404 {
		t.Fatal("a deleted capture's file is still served", code)
	}
	if code, _ := f.call("alice-token", "GET", "/api/audit", nil); code != 403 {
		t.Fatal("a user read the audit log", code)
	}
	_, b = f.call("root-token", "GET", "/api/audit?limit=200", nil)
	for _, action := range []string{"cluster.add", "capture.request", "capture.approve", "capture.deny", "capture.cancel", "capture.delete", "artifact.download", "artifact.read"} {
		if !strings.Contains(string(b), `"`+action+`"`) {
			t.Error("audit log lacks", action)
		}
	}
}

// Evidence is deleted when its retention ends.
func TestRetention(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dir := t.TempDir()
	h, err := hub.New(hub.Config{Store: store, Blobs: hub.DirBlobs(dir), MasterKey: bytes.Repeat([]byte{7}, 32), Retention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	go h.RunRetention(ctx)
	id := "00000000-0000-4000-8000-" + hex.EncodeToString([]byte(time.Now().Format("150405")))
	c := api.Capture{ID: id, Requester: "alice", State: api.StateCompleted, ExpiresAt: time.Now().Add(700 * time.Millisecond),
		CaptureRequest: api.CaptureRequest{Cluster: "retention", Namespace: "n", Workload: "Pod/p", Kind: api.KindLogs}}
	if err := store.CreateCapture(t.Context(), c); err != nil {
		t.Fatal(err)
	}
	h.Wake()
	if _, err := store.Capture(t.Context(), id); err != nil {
		t.Fatal("deleted before its expiry", err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, err := store.Capture(t.Context(), id); err == hub.ErrNotFound {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the expired capture was kept")
		}
	}
}

// Pods that finish at the same moment still complete the capture.
func TestConcurrentTasksCompleteTheCapture(t *testing.T) {
	dsn := os.Getenv("ASSERVAT_TEST_DSN")
	if dsn == "" {
		t.Skip("ASSERVAT_TEST_DSN is not set")
	}
	store, err := hub.OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for round := range 20 {
		c := api.Capture{ID: uuid.NewString(), Requester: "alice", State: api.StateQueued, ExpiresAt: time.Now().Add(time.Hour),
			CaptureRequest: api.CaptureRequest{Cluster: "concurrent", Namespace: "n", Workload: "Deployment/d", Kind: api.KindLogs}}
		for i := range 8 {
			c.Tasks = append(c.Tasks, api.Task{Pod: fmt.Sprint("pod-", i), Node: "node", State: api.StateQueued})
		}
		if err := store.CreateCapture(t.Context(), c); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for _, task := range c.Tasks {
			wg.Go(func() {
				if err := store.SetTask(t.Context(), c.ID, api.TaskStatus{Pod: task.Pod, State: api.StateCompleted}); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		got, err := store.Capture(t.Context(), c.ID)
		if err != nil || got.State != api.StateCompleted || got.FinishedAt == nil {
			t.Fatal("round", round, got.State, err)
		}
		if _, err := store.DeleteCapture(t.Context(), c.ID); err != nil {
			t.Fatal(err)
		}
	}
}

// corrupt flips the last byte of every stored blob.
func corrupt(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		b[len(b)-1] ^= 1
		if err := os.WriteFile(name, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}
