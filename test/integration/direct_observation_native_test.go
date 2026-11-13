package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestDirectNativeFixtureWireParity(t *testing.T) {
	// Standalone fixture binaries use ignored source files, as required by the
	// architecture gate. Their DTOs are not an importable product package.
	// Keep the test-only copy exact instead of silently drifting either codec.
	helper, err := os.ReadFile("../fixtures/observation-native/data.go")
	if err != nil {
		t.Fatal("native helper wire source unavailable", err)
	}
	local, err := os.ReadFile("direct_observation_native_data_test.go")
	if err != nil {
		t.Fatal("native test wire source unavailable", err)
	}
	helper = bytes.TrimPrefix(helper, []byte("//go:build ignore\n\n"))
	helper = bytes.Replace(helper, []byte("package main\n"), []byte("package integration\n"), 1)
	if !bytes.Equal(helper, local) {
		t.Fatal("native fixture input/output copy drifted")
	}
}

// The diagnostic reader must never render arbitrary helper output as a phase
// or error. This is independent of external services and changes no authority.
func TestDirectNativeFixtureDiagnosticLabels(t *testing.T) {
	for _, tc := range []struct {
		name, line string
		valid      bool
	}{
		{"phase", `{"Format":"observation-native-phase/v1","Phase":"regional-enrollment","Event":"end","Category":"deadline","ElapsedNanos":30000000000}`, true},
		{"projection-wait", `{"Format":"observation-native-phase/v1","Phase":"inputs-projection-missing","Event":"wait","Category":"none","ElapsedNanos":30000000000}`, true},
		{"legacy-failure", `{"Phase":"regional-enrollment","Category":"denied"}`, true},
		{"legacy-extra-payload-discarded", `{"Phase":"regional-enrollment","Category":"denied","Error":"private-sentinel","Request":{"token":"private-sentinel"}}`, true},
		{"unknown-phase", `{"Format":"observation-native-phase/v1","Phase":"private-sentinel","Event":"end","Category":"none","ElapsedNanos":1}`, false},
		{"unknown-category", `{"Phase":"inputs","Category":"private-sentinel"}`, false},
		{"unknown-event", `{"Format":"observation-native-phase/v1","Phase":"inputs","Event":"private-sentinel","Category":"none"}`, false},
		{"unknown-format", `{"Format":"private-sentinel","Phase":"inputs","Event":"begin","Category":"none"}`, false},
		{"negative-duration", `{"Format":"observation-native-phase/v1","Phase":"inputs","Event":"end","Category":"none","ElapsedNanos":-1}`, false},
		{"overlong-duration", `{"Format":"observation-native-phase/v1","Phase":"inputs","Event":"end","Category":"none","ElapsedNanos":1200000000001}`, false},
		{"overflow-duration", `{"Format":"observation-native-phase/v1","Phase":"inputs","Event":"end","Category":"none","ElapsedNanos":18446744073709551615}`, false},
		{"non-json", "private-sentinel", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, valid := directNativeDiagnosticLine([]byte(tc.line))
			if valid != tc.valid {
				t.Fatal("closed diagnostic classification mismatch")
			}
			out, err := json.Marshal(v)
			if err != nil || bytes.Contains(out, []byte("private-sentinel")) {
				t.Fatal("untrusted diagnostic data escaped closed labels")
			}
		})
	}
	if _, ok := directNativeDiagnosticLine(bytes.Repeat([]byte{' '}, 16385)); ok {
		t.Fatal("overlong diagnostic line accepted")
	}
}

type directNativeSetupTransport func(*http.Request) (*http.Response, error)

func (f directNativeSetupTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDirectNativeInputSetupDeadline(t *testing.T) {
	parent, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	originalEnd, _ := parent.Deadline()
	var deadlines []time.Time
	api, err := kubernetes.NewForConfigAndClient(&rest.Config{Host: "https://fixture.invalid"}, &http.Client{Transport: directNativeSetupTransport(func(r *http.Request) (*http.Response, error) {
		end, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("setup API request omitted original deadline")
		}
		deadlines = append(deadlines, end)
		body := ""
		status := http.StatusOK
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/fixture/secrets":
			status = http.StatusCreated
			body = `{"apiVersion":"v1","kind":"Secret","metadata":{"name":"owner-inputs","namespace":"fixture","uid":"input"}}`
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/fixture/pods/original":
			body = `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"original","namespace":"fixture","uid":"pod"},"status":{"phase":"Running","podIP":"10.0.0.7"}}`
		default:
			t.Fatal("unexpected setup API call")
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	x := &directNativeCluster{api: api, namespace: &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: "fixture"}}, pods: map[string]*core.Pod{"owner": {ObjectMeta: meta.ObjectMeta{Name: "original", Namespace: "fixture", UID: "pod"}, Status: core.PodStatus{Phase: core.PodPending}}}, inputUntil: map[string]time.Time{}}
	x.installInput(t, parent, "owner", Input{Mode: "owner", PodUID: "pod"})
	// A later, longer parent cannot replace the deadline retained before CREATE.
	later, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	x.waitPodRunning(t, later, "owner")
	if len(deadlines) != 2 || !x.inputUntil["owner"].Equal(originalEnd) || !deadlines[0].Equal(originalEnd) || !deadlines[1].Equal(originalEnd) {
		t.Fatal("create or running wait renewed original setup bound")
	}
}

func TestDirectNativePendingIdentity(t *testing.T) {
	controller := true
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "original", Namespace: "fixture", UID: "pod", OwnerReferences: []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "replica", UID: "rs", Controller: &controller}}}, Status: core.PodStatus{Phase: core.PodPending}}
	rs := &apps.ReplicaSet{ObjectMeta: meta.ObjectMeta{Name: "replica", Namespace: "fixture", UID: "rs", OwnerReferences: []meta.OwnerReference{{APIVersion: "apps/v1", Kind: "Deployment", Name: "deployment", UID: "deployment", Controller: &controller}}}}
	d := &apps.Deployment{ObjectMeta: meta.ObjectMeta{Name: "deployment", Namespace: "fixture", UID: "deployment"}}
	if !directNativePendingChain(pod, rs, d) {
		t.Fatal("exact Pending chain rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*core.Pod, *apps.ReplicaSet, *apps.Deployment)
	}{
		{"replacement-replicaset", func(_ *core.Pod, r *apps.ReplicaSet, _ *apps.Deployment) { r.UID = "replacement" }},
		{"replacement-deployment", func(_ *core.Pod, _ *apps.ReplicaSet, d *apps.Deployment) { d.UID = "replacement" }},
		{"extra-owner", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.OwnerReferences = append(p.OwnerReferences, p.OwnerReferences[0])
		}},
		{"missing-controller", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) { p.OwnerReferences[0].Controller = nil }},
		{"wrong-owner-kind", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) { p.OwnerReferences[0].Kind = "StatefulSet" }},
		{"wrong-namespace", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) { p.Namespace = "replacement" }},
		{"missing-pod-uid", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) { p.UID = "" }},
		{"deleting-pod", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) { v := meta.Now(); p.DeletionTimestamp = &v }},
		{"deleting-replicaset", func(_ *core.Pod, r *apps.ReplicaSet, _ *apps.Deployment) { v := meta.Now(); r.DeletionTimestamp = &v }},
		{"deleting-deployment", func(_ *core.Pod, _ *apps.ReplicaSet, d *apps.Deployment) { v := meta.Now(); d.DeletionTimestamp = &v }},
		{"running-before-input", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) { p.Status.Phase = core.PodRunning }},
		{"old-container-id", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.Status.ContainerStatuses = []core.ContainerStatus{{ContainerID: "containerd://original"}}
		}},
		{"known-running-state", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.Status.ContainerStatuses = []core.ContainerStatus{{State: core.ContainerState{Running: &core.ContainerStateRunning{}}}}
		}},
		{"terminated-state", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.Status.ContainerStatuses = []core.ContainerStatus{{State: core.ContainerState{Terminated: &core.ContainerStateTerminated{}}}}
		}},
		{"previous-termination", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.Status.ContainerStatuses = []core.ContainerStatus{{LastTerminationState: core.ContainerState{Terminated: &core.ContainerStateTerminated{}}}}
		}},
		{"restart", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.Status.ContainerStatuses = []core.ContainerStatus{{RestartCount: 1}}
		}},
		{"init-started", func(p *core.Pod, _ *apps.ReplicaSet, _ *apps.Deployment) {
			p.Status.InitContainerStatuses = []core.ContainerStatus{{ContainerID: "containerd://original-init"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, r, dep := pod.DeepCopy(), rs.DeepCopy(), d.DeepCopy()
			tc.mutate(p, r, dep)
			if directNativePendingChain(p, r, dep) {
				t.Fatal("changed or started original chain accepted")
			}
		})
	}
}

func (x *directNativeCluster) waitControl(t *testing.T, ctx context.Context, mode string) {
	t.Helper()
	end := time.Now().Add(60 * time.Second)
	for time.Now().Before(end) && ctx.Err() == nil {
		pod, e := x.api.CoreV1().Pods(x.namespace.Name).Get(ctx, x.pods[mode].Name, meta.GetOptions{})
		if e != nil || pod.UID != x.pods[mode].UID || pod.DeletionTimestamp != nil {
			x.closedDiagnostics(t, mode)
			t.Fatal("native original helper lost", mode)
		}
		for _, s := range pod.Status.ContainerStatuses {
			if s.RestartCount != 0 || s.State.Terminated != nil {
				x.closedDiagnostics(t, mode)
				t.Fatal("native helper setup failed; inspect closed fixture phase logs", mode)
			}
		}
		call, stop := context.WithTimeout(ctx, time.Second)
		result, e := x.control(call, mode, ControlRequest{Command: "status"})
		stop()
		if e == nil && result.OK {
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	// Preserve the original Pod state and bounded closed helper logs before
	// shutdown/namespace cleanup removes the evidence. No extra authority read
	// or retry is performed; the original setup wait has already ended.
	x.closedDiagnostics(t, mode)
	t.Fatal("native original helper not ready", mode)
}
func (x *directNativeCluster) waitAvailable(t *testing.T, ctx context.Context, want bool) {
	t.Helper()
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	for call.Err() == nil {
		got, e := x.control(call, "owner", ControlRequest{Command: "status"})
		if e != nil || !got.OK {
			t.Fatal("native local holder routing observation unavailable", e, got.Category)
		}
		if got.Available == want {
			return
		}
		select {
		case <-call.Done():
		case <-time.After(10 * time.Millisecond):
		}
	}
	t.Fatal("native exact holder availability did not settle")
}
func directNativeSnapshots(t *testing.T, ctx context.Context, a, r *directNativeCluster) [3]ControlResult {
	t.Helper()
	var out [3]ControlResult
	for i, role := range []struct {
		x    *directNativeCluster
		mode string
	}{{a, "hwork"}, {a, "owner"}, {r, "regional"}} {
		call, stop := context.WithTimeout(ctx, 3*time.Second)
		v, e := role.x.control(call, role.mode, ControlRequest{Command: "status"})
		stop()
		if e != nil || !v.OK {
			t.Fatal("native bounded counters unavailable", e, v.Category)
		}
		out[i] = v
	}
	return out
}
func directNativeMetricsDelta(a, b MetricsSnapshot) MetricsSnapshot {
	sub := func(x, y APISnapshot) APISnapshot {
		return APISnapshot{Requests: y.Requests - x.Requests, Denied: y.Denied - x.Denied, Errors: y.Errors - x.Errors, HeaderNanos: y.HeaderNanos - x.HeaderNanos}
	}
	out := MetricsSnapshot{Observer: sub(a.Observer, b.Observer), Probe: sub(a.Probe, b.Probe), SQL: map[string]PoolSnapshot{}}
	for k, y := range b.SQL {
		x := a.SQL[k]
		out.SQL[k] = PoolSnapshot{Acquires: y.Acquires - x.Acquires, AcquireNanos: y.AcquireNanos - x.AcquireNanos, EmptyAcquires: y.EmptyAcquires - x.EmptyAcquires, CancelledAcquires: y.CancelledAcquires - x.CancelledAcquires}
	}
	return out
}
