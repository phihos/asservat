package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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

// This is a reference H/A/R composition with actual product v2 listener and
// separate original Pods in two clusters. Initial issuer/accepted owner-source,
// recovery and storage-qualification roots remain explicit fixture authority.
// It does not select the installed runtime or run full installed HWORK load.
func TestDirectHolderObservationWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned direct H/A/R context fixture required")
	}
	raw, e := os.ReadFile(path)
	var f fixture
	var selection struct {
		DirectObservation struct {
			HelperSHA256                 string
			RuntimeSelection             bool
			FullInstalledHWORKBackground bool
		}
	}
	if e == nil && json.Unmarshal(raw, &selection) == nil && selection.DirectObservation.HelperSHA256 == "" {
		// Only the exact --run selection builds the helper image into both clusters.
		t.Skip("run scripts/test-context-storage.py --run '^TestDirectHolderObservationWithRealKubernetes$'")
	}
	if e != nil || json.Unmarshal(raw, &f) != nil || json.Unmarshal(raw, &selection) != nil || len(f.Clusters) != 2 || len(selection.DirectObservation.HelperSHA256) != 64 || selection.DirectObservation.RuntimeSelection || selection.DirectObservation.FullInstalledHWORKBackground {
		t.Fatal("exact native helper selection unavailable")
	}
	clear(raw)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	setup := time.Now()
	installation, epoch, root := custodyID(), custodyID(), custodyID()
	ownerCA, clientCA, serverCA := directNativeCA(t), directNativeCA(t), directNativeCA(t)
	a := newDirectNativeCluster(t, ctx, f, 0, installation)
	r := newDirectNativeCluster(t, ctx, f, 1, installation)
	pool := value.OwnerPool{InstallationID: installation, ClusterID: a.id, IssuerEpoch: epoch, Namespace: a.namespace.Name, NamespaceUID: string(a.namespace.UID), Service: a.service.Name, ServiceUID: string(a.service.UID), Deployment: "owner", DeploymentUID: string(a.deployments["owner"].UID), ServiceAccount: "owner", AccountUID: string(a.accounts["owner"].UID), Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile, NativeCandidateLimit: value.OwnerRegistrationsPerPool}
	owner := value.OwnerObservationPin{RootID: root, SourceUID: custodyID(), Pool: pool, TemplateDigest: a.template(t, "owner"), ImageDigest: a.image, ProtectionDigest: a.protection}
	caller := value.ClusterObservationCallerPin{RootID: root, InstallationID: installation, ClusterID: a.id, Namespace: a.plan.ControlNamespace, Account: "hwork", AccountUID: string(a.accounts["hwork"].UID), Deployment: "hwork", DeploymentUID: string(a.deployments["hwork"].UID), TemplateDigest: a.template(t, "hwork"), ImageDigest: a.image, ProtectionDigest: a.protection}
	if !owner.Valid() || !caller.Valid() {
		t.Fatal("native original owner/caller pins invalid")
	}
	accepted := value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: owner.SourceUID, Generation: 1, Digest: artifact.Digest{41}}, ProtectionDigest: owner.ProtectionDigest, IssuerRoots: [][]byte{ownerCA.DER}}
	sql := newDirectNativeSQL(t, ctx, f, accepted, root)
	sql.startSources(t, ctx, cancel, accepted)
	source := r.regionalSource(t, ctx, sql, root, installation, epoch, "", true, clientCA, serverCA)
	credential := r.clusterCredential(t, ctx, sql, value.ClusterCredentialProfile{RootID: root, PeerID: source.observation.Profile.Binding.PeerID, InstallationID: installation, ClusterID: r.id}, a.lifecycle)
	end, _ := ctx.Deadline()
	// Register cleanup before the first input can start credential work. A later
	// setup failure must still join every helper whose immutable input create
	// was attempted; an unknown create/control reply cannot certify completion.
	mounted := map[string]bool{}
	t.Cleanup(func() {
		for _, role := range []struct {
			x    *directNativeCluster
			mode string
		}{{r, "regional"}, {a, "owner"}, {a, "hwork"}} {
			if mounted[role.mode] {
				role.x.shutdown(t, role.mode)
			}
		}
	})
	// ADR-169: the regional process enrolls through the owner's lifecycle
	// channel, so its input is materialized only after the owner is ready.
	for _, mode := range []string{"owner", "hwork", "regional"} {
		x := a
		if mode == "regional" {
			x = r
			for _, ready := range []string{"owner", "hwork"} {
				a.waitPodRunning(t, ctx, ready)
				a.waitControl(t, ctx, ready)
			}
		}
		in := directNativePopulate(x.baseInput(t, mode, end), owner, caller, source, ownerCA, clientCA, serverCA, sql, a.dial, credential)
		switch mode {
		case "owner":
			// ADR-169: all connector effect duties are hub duties.
			in.SQL = directNativeSQLSet(t, sql, "owner-read", "owner-write", "owner-ack", "owner-activate", "connector-read", "connector-journal", "connector-ack", "connector-source", "recovery-read", "cluster-credential")
		case "hwork":
			in.SQL = directNativeSQLSet(t, sql, "owner-read")
		case "regional":
			in.SQL = directNativeSQLSet(t, sql, "owner-read")
		}
		mounted[mode] = true
		x.installInput(t, ctx, mode, in)
	}
	// Required inputs are materialized before containers start. Retain each
	// create attempt's original setup interval, then use the unchanged control
	// readiness wait; no enrollment, operation or uncertain POST is replayed.
	r.waitPodRunning(t, ctx, "regional")
	r.waitControl(t, ctx, "regional")
	t.Logf("native direct setup elapsed=%s source-refreshes=%d synthetic-initial-roots=true installed-runtime=false full-HWORK-background=false", time.Since(setup), sql.refreshes.Load())
	modes := []value.ClusterObservationPurpose{value.ObserveCapacityNamespaces, value.ObserveCapacityWorkloads, value.ObserveCapacityWorkload, value.ObserveCapacityNamespaceGuard, value.ObserveCapacityGuardedWorkload}
	// No new clients, token buckets or SQL pools between these independent
	// operations. Standby setup belongs to its own original socket interval.
	for _, purpose := range modes {
		t.Run(string(purpose), func(t *testing.T) {
			before := directNativeSnapshots(t, ctx, a, r)
			opened := time.Now()
			call, stop := context.WithTimeout(ctx, 5*time.Second)
			open, err := r.control(call, "regional", ControlRequest{Command: "open", ExchangeID: custodyID()})
			stop()
			if err != nil || !open.OK {
				t.Fatal("native original regional standby", err, open.Category)
			}
			a.waitAvailable(t, ctx, true)
			standby := directNativeSnapshots(t, ctx, a, r)
			ownerAt, fleetAt := time.Unix(0, sql.ownerObserved.Load()), time.Unix(0, sql.fleetObserved.Load())
			started := time.Now()
			n := started.UTC()
			ownerAge, fleetAge := n.Sub(ownerAt), n.Sub(fleetAt)
			request := value.ClusterObservationRequest{ID: custodyID(), Challenge: custodyID(), RootID: root, ClusterID: r.id, Purpose: purpose, RequestedAt: n, NotAfter: n.Add(5 * time.Second)}
			switch purpose {
			case value.ObserveCapacityWorkloads:
				request.Namespace = r.plan.ControlNamespace
				request.Kind = "Deployment"
			case value.ObserveCapacityWorkload, value.ObserveCapacityGuardedWorkload:
				request.Namespace = r.plan.ControlNamespace
				request.Workload = cfg.WorkloadRef{Kind: "Deployment", Name: "regional", UID: string(r.deployments["regional"].UID)}
				request.Keys = []string{"native-team"}
			}
			call, stop = context.WithDeadline(ctx, request.NotAfter)
			result, err := a.control(call, "hwork", ControlRequest{Command: "observe", Request: request})
			stop()
			receivedAt := time.Now().UTC()
			elapsed := time.Since(started)
			// Preserve the transfer verdict before later diagnostic I/O. A status
			// transport failure cannot replace this earlier outcome.
			t.Logf("native direct terminal purpose=%s success=%t transport-failed=%t category=%s elapsed=%s remaining=%s", purpose, err == nil && result.OK, err != nil, result.Category, elapsed, request.NotAfter.Sub(receivedAt))
			// Status reads only local process counters/last closed error categories;
			// they neither execute SQL nor manufacture a new source/request interval.
			after := directNativeSnapshots(t, ctx, a, r)
			report := map[string]any{"purpose": purpose, "success": err == nil && result.OK, "wholeNanos": elapsed.Nanoseconds(), "remainingNanos": request.NotAfter.Sub(receivedAt).Nanoseconds(), "standbyAgeNanos": n.Sub(opened).Nanoseconds(), "setupH": directNativeMetricsDelta(before[0].Metrics, standby[0].Metrics), "setupA": directNativeMetricsDelta(before[1].Metrics, standby[1].Metrics), "setupR": directNativeMetricsDelta(before[2].Metrics, standby[2].Metrics), "H": directNativeMetricsDelta(standby[0].Metrics, after[0].Metrics), "A": directNativeMetricsDelta(standby[1].Metrics, after[1].Metrics), "R": directNativeMetricsDelta(standby[2].Metrics, after[2].Metrics), "lastH": after[0].LastCategory, "sourceRefreshes": sql.refreshes.Load(), "originalOwnerSourceAgeNanos": ownerAge.Nanoseconds(), "originalFleetSourceAgeNanos": fleetAge.Nanoseconds()}
			report["regionalFinished"] = after[2].RegionalFinished
			report["regionalCategory"] = after[2].RegionalCategory
			encoded, _ := json.Marshal(report)
			t.Logf("native direct metrics %s", encoded)
			if err != nil || !result.OK || result.Result == nil {
				t.Fatal("native original direct request", err, result.Category)
			}
			digest, de := app.ClusterObservationRequestDigest(request)
			// Preserve both actual helper completion and host receipt instants before
			// diagnostic reads. A late result is never made usable by relabeling dates.
			if de != nil || result.CompletedAt.IsZero() || !result.CompletedAt.Before(request.NotAfter) || !result.Result.Matches(request, digest, result.CompletedAt) || !result.Result.Matches(request, digest, receivedAt) || elapsed >= 5*time.Second {
				t.Fatal("native exact original result/bound")
			}
			switch purpose {
			case value.ObserveCapacityNamespaces:
				if !slices.Contains(result.Result.Namespaces.Items, r.plan.ControlNamespace) {
					t.Fatal("native original namespace missing")
				}
			case value.ObserveCapacityWorkloads:
				if !slices.Contains(result.Result.Workloads.Items, cfg.WorkloadRef{Kind: "Deployment", Name: "regional", UID: string(r.deployments["regional"].UID)}) {
					t.Fatal("native original workload missing")
				}
			case value.ObserveCapacityWorkload:
				if result.Result.Workload.Labels["native-team"] != "test" {
					t.Fatal("native selected original label missing")
				}
			case value.ObserveCapacityGuardedWorkload:
				// ADR-197: the guard and the workload in one exchange, as the
				// regional enrollment consumes them.
				if result.Result.Workload.Labels["native-team"] != "test" || !slices.Equal(result.Result.Guard.Keys, []string{"native-team"}) {
					t.Fatal("native combined guard and workload missing")
				}
			case value.ObserveCapacityNamespaceGuard:
				if !slices.Equal(result.Result.Guard.Keys, []string{"native-team"}) {
					t.Fatal("native exact protected keys changed")
				}
			}
			call, stop = context.WithTimeout(ctx, 5*time.Second)
			joined, err := r.control(call, "regional", ControlRequest{Command: "join"})
			stop()
			if err != nil || !joined.OK {
				t.Fatal("native actual regional terminal join", err, joined.Category)
			}
			a.waitAvailable(t, ctx, false)
			call, stop = context.WithTimeout(ctx, 5*time.Second)
			closed, err := r.control(call, "regional", ControlRequest{Command: "close"})
			stop()
			if err != nil || !closed.OK {
				t.Fatal("native joined close", err, closed.Category)
			}
		})
		if t.Failed() {
			return
		}
	}
	t.Run("changed-original-regional-template-denies", func(t *testing.T) {
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		opened, err := r.control(call, "regional", ControlRequest{Command: "open", ExchangeID: custodyID()})
		stop()
		if err != nil || !opened.OK {
			t.Fatal("native mutation standby", err, opened.Category)
		}
		a.waitAvailable(t, ctx, true)
		// Privileged fixture administrator mutates the original actual Pod only;
		// no replacement profile, result or socket can adopt that change.
		if _, err = r.api.CoreV1().Pods(r.namespace.Name).Patch(ctx, r.pods["regional"].Name, types.MergePatchType, []byte(`{"metadata":{"annotations":{"asservat.io/native-original-mutation":"changed"}}}`), meta.PatchOptions{}); err != nil {
			t.Fatal("native original Pod mutation", err)
		}
		n := time.Now().UTC()
		q := value.ClusterObservationRequest{ID: custodyID(), Challenge: custodyID(), RootID: root, ClusterID: r.id, Purpose: value.ObserveCapacityNamespaces, RequestedAt: n, NotAfter: n.Add(5 * time.Second)}
		call, stop = context.WithDeadline(ctx, q.NotAfter)
		result, err := a.control(call, "hwork", ControlRequest{Command: "observe", Request: q})
		stop()
		if err == nil && (result.OK || result.Result != nil) {
			t.Fatal("changed original regional Pod disclosed metadata")
		}
		call, stop = context.WithTimeout(ctx, 5*time.Second)
		closed, closeErr := r.control(call, "regional", ControlRequest{Command: "close"})
		stop()
		if closeErr != nil || !closed.OK {
			t.Fatal("native mutation joined close", closeErr, closed.Category)
		}
		a.waitAvailable(t, ctx, false)
	})
	if sql.sourceFailure.Load() || sql.refreshes.Load() < 2 {
		t.Fatal("native background source lifetime failed")
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
