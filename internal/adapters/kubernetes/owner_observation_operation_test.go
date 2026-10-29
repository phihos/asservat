package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	access "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Real HTTPS and concrete readers; responses/native authority are synthetic.
// This is not the owned native Kubernetes/SQL/route availability qualification.
type ownerOperationFixture struct {
	t                   *testing.T
	mu                  sync.Mutex
	v                   ownerObjects
	other               *core.Pod
	policy              *admission.ValidatingAdmissionPolicy
	binding             *admission.ValidatingAdmissionPolicyBinding
	guard               *OwnerWorkloadProtection
	reader              *OwnerObservationOperationReader
	pin                 value.OwnerObservationPin
	start               time.Time
	clock               atomic.Int64
	observer, probe     atomic.Int32
	unknown, accept     bool
	blockPath           string
	entered, exited     chan struct{}
	blockOnce           sync.Once
	podReads            int
	podReadChange       func(int, *core.Pod)
	changeDuringInitial bool
	lastNamespaceExpiry bool
	namespaceReads      int
}

func newOwnerOperationFixture(t *testing.T) *ownerOperationFixture {
	t.Helper()
	f := &ownerOperationFixture{t: t, v: ownerFixtureObjects(), start: time.Now().UTC()}
	f.clock.Store(f.start.UnixNano())
	v := &f.v
	setInstalledOwnerEndpointPorts(v)
	d, rs, pod, image := connectorAPITemplateFixture()
	d.TypeMeta = v.deploy.TypeMeta
	d.ObjectMeta = v.deploy.ObjectMeta
	d.Spec.Replicas = ptr.To(int32(1))
	d.Spec.Selector = &meta.LabelSelector{MatchLabels: map[string]string{"app": "connector"}}
	d.Spec.Template.Spec.ServiceAccountName = v.pool.ServiceAccount
	rs.TypeMeta = v.rs.TypeMeta
	rs.ObjectMeta = v.rs.ObjectMeta
	rs.OwnerReferences = v.rs.OwnerReferences
	rs.Spec.Replicas = ptr.To(int32(1))
	rs.Spec.Template.Spec.ServiceAccountName = v.pool.ServiceAccount
	oldLabels := pod.Labels
	pod.TypeMeta = v.pod.TypeMeta
	pod.ObjectMeta = v.pod.ObjectMeta
	pod.Labels = oldLabels
	pod.Spec.ServiceAccountName = v.pool.ServiceAccount
	pod.Spec.DeprecatedServiceAccount = v.pool.ServiceAccount
	pod.Spec.NodeName = v.pod.Spec.NodeName
	pod.Status = v.pod.Status
	v.deploy, v.rs, v.pod = d, rs, pod
	v.svc.Spec.Selector = map[string]string{"app": "connector"}
	template, e := ConnectorAPITemplateDigest(d.Spec.Template)
	if e != nil {
		t.Fatal(e)
	}
	plan := cfg.OwnerWorkloadAdministration{Name: "owner-operation", Deployment: v.pool.Deployment, DeploymentUID: v.pool.DeploymentUID, ControlNamespace: cfg.NamespaceRef{Name: v.pool.Namespace, UID: v.pool.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}, ConfigurationProbes: []cfg.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "probe"}}}
	f.policy, f.binding, e = OwnerWorkloadAdmission(plan)
	if e != nil {
		t.Fatal(e)
	}
	pin := GuardPin{PolicyUID: ownerID(31), PolicyGeneration: 1, BindingUID: ownerID(32), BindingResourceVersion: "20"}
	f.policy.UID, f.policy.Generation, f.policy.ResourceVersion = types.UID(pin.PolicyUID), 1, "10"
	f.policy.Status.ObservedGeneration = 1
	f.policy.Status.TypeChecking = &admission.TypeChecking{}
	f.binding.UID, f.binding.ResourceVersion = types.UID(pin.BindingUID), pin.BindingResourceVersion
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	client := func(token string) *PermissionClient {
		c, e := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: roots}, BearerToken: token}, v.pool.ClusterID, plan.ControlNamespace, func() time.Time { return time.Unix(0, f.clock.Load()).UTC() })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	observer, probe := client("observer"), client("probe")
	f.guard, e = NewOwnerWorkloadProtection(observer, probe, plan, pin)
	if e != nil {
		t.Fatal(e)
	}
	f.pin = value.OwnerObservationPin{RootID: ownerID(33), SourceUID: ownerID(34), Pool: v.pool, TemplateDigest: template, ImageDigest: image, ProtectionDigest: f.guard.digest}
	f.reader, e = NewOwnerObservationOperationReader(observer, f.guard, f.pin)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *ownerOperationFixture) serve(w http.ResponseWriter, r *http.Request) {
	switch r.Header.Get("Authorization") {
	case "Bearer observer":
		f.observer.Add(1)
	case "Bearer probe":
		f.probe.Add(1)
	default:
		f.t.Error("unexpected native credential")
	}
	f.mu.Lock()
	blocked := r.URL.Path == f.blockPath
	entered, exited := f.entered, f.exited
	f.mu.Unlock()
	if blocked {
		f.blockOnce.Do(func() { close(entered) })
		<-r.Context().Done()
		close(exited)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &f.v
	if f.unknown {
		http.Error(w, "unavailable", 503)
		return
	}
	switch r.URL.Path {
	case "/api/v1/namespaces/owners":
		f.namespaceReads++
		if f.lastNamespaceExpiry && f.namespaceReads == 4 {
			f.clock.Store(f.start.Add(5 * time.Second).UnixNano())
		}
		permissionReply(w, v.ns)
	case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/owner-operation":
		permissionReply(w, f.policy)
	case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/owner-operation":
		permissionReply(w, f.binding)
	case "/apis/authentication.k8s.io/v1/selfsubjectreviews":
		permissionReply(w, auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: "probe", Groups: []string{"system:authenticated"}}}})
	case "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews":
		permissionReply(w, access.SelfSubjectAccessReview{Status: access.SubjectAccessReviewStatus{Allowed: true}})
	case "/apis/apps/v1/namespaces/owners/deployments/hub":
		if r.Method == http.MethodGet {
			permissionReply(w, v.deploy)
			return
		}
		if r.Method != http.MethodPut || r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" {
			f.t.Error("unexpected effect")
		}
		if f.accept {
			permissionReply(w, v.deploy)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(403)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy 'owner-operation' with binding 'owner-operation' denied request: " + ownerWorkloadDenial}}}})
	case "/api/v1/namespaces/owners/services/hub-owner":
		permissionReply(w, v.svc)
	case "/api/v1/namespaces/owners/serviceaccounts/hub":
		permissionReply(w, v.sa)
	case "/apis/discovery.k8s.io/v1/namespaces/owners/endpointslices":
		permissionReply(w, v.list)
	case "/api/v1/namespaces/owners/pods/hub-rs-pod":
		f.podReads++
		if f.podReadChange != nil {
			f.podReadChange(f.podReads, &v.pod)
		}
		if f.changeDuringInitial && f.podReads == 2 {
			v.pod.ResourceVersion = "104"
			v.pod.Spec.Containers[0].Args = append(v.pod.Spec.Containers[0].Args, "--changed")
		}
		permissionReply(w, v.pod)
	case "/api/v1/namespaces/owners/pods/hub-rs-other":
		permissionReply(w, f.other)
	case "/apis/apps/v1/namespaces/owners/replicasets/hub-rs":
		permissionReply(w, v.rs)
	default:
		// No release record: an installation before ADR-227 phase 2.
		if releaseRecordAbsent(w, r) {
			return
		}
		f.t.Errorf("unexpected native path %s", r.URL.Path)
		http.NotFound(w, r)
	}
}
func (f *ownerOperationFixture) begin(t *testing.T) (*OwnerObservationOperation, context.Context) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), f.start.Add(5*time.Second))
	t.Cleanup(cancel)
	r := value.OwnerObservationRequest{RootID: f.pin.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.start, NotAfter: f.start.Add(5 * time.Second)}
	op, e := f.reader.Begin(ctx, r, []value.OwnerBinding{f.v.binding})
	if e != nil {
		t.Fatal("initial actual native boundary", e)
	}
	t.Cleanup(op.Close)
	return op, ctx
}
func TestOwnerObservationOperationRealBoundaries(t *testing.T) {
	f := newOwnerOperationFixture(t)
	op, ctx := f.begin(t)
	initial, e := op.Original(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Counts include one ADR-227 release record read per native boundary.
	if f.observer.Load() != 15 || f.probe.Load() != 3 {
		t.Fatalf("first native boundary requests: %d/%d", f.observer.Load(), f.probe.Load())
	}
	initial.Peers[0].Addresses[0] = "10.9.8.7"
	again, e := op.Original(ctx)
	if e != nil || again.Peers[0].Addresses[0] == "10.9.8.7" {
		t.Fatal("returned snapshot aliases original", e)
	}
	// Constructor owns nested inputs even when the source guard's private plan
	// later changes. No callback or mutable plan is consulted after construction.
	f.guard.plan.Administrators[0].Name = "changed"
	f.guard.plan.ConfigurationProbes[0].ConfigMap = "changed"
	final, e := op.Final(ctx)
	if e != nil {
		t.Fatal("second actual native boundary", e)
	}
	if !final.Final || !final.ObservedAt.Equal(again.ObservedAt) || !final.FreshUntil.Equal(again.FreshUntil) || !sameOwnerNativePeers(final.Peers, again.Peers) {
		t.Fatal("final renewed or changed original facts")
	}
	if f.observer.Load() != 30 || f.probe.Load() != 6 {
		t.Fatalf("two native boundaries: %d/%d", f.observer.Load(), f.probe.Load())
	}
	calls := f.observer.Load()
	if _, e = op.Final(ctx); e == nil || f.observer.Load() != calls {
		t.Fatal("duplicate final read renewed operation")
	}
}
func TestOwnerObservationOperationFinalChangeIsTerminal(t *testing.T) {
	cases := map[string]func(*ownerOperationFixture){
		"namespace":     func(f *ownerOperationFixture) { f.v.ns.UID = types.UID(ownerID(90)) },
		"guard":         func(f *ownerOperationFixture) { f.policy.Spec.Validations[0].Expression = "true" },
		"guard-binding": func(f *ownerOperationFixture) { f.binding.UID = types.UID(ownerID(90)) },
		"guard-warning": func(f *ownerOperationFixture) {
			f.policy.Status.TypeChecking.ExpressionWarnings = []admission.ExpressionWarning{{FieldRef: "spec", Warning: "changed"}}
		},
		"guard-accepted":      func(f *ownerOperationFixture) { f.accept = true },
		"service":             func(f *ownerOperationFixture) { f.v.svc.UID = types.UID(ownerID(90)) },
		"service-port":        func(f *ownerOperationFixture) { f.v.svc.Spec.Ports[0].Port++ },
		"account":             func(f *ownerOperationFixture) { f.v.sa.UID = types.UID(ownerID(90)) },
		"deployment":          func(f *ownerOperationFixture) { f.v.deploy.UID = types.UID(ownerID(90)) },
		"template":            func(f *ownerOperationFixture) { f.v.deploy.Spec.Template.Spec.Containers[0].Args = []string{"changed"} },
		"replica":             func(f *ownerOperationFixture) { f.v.rs.UID = types.UID(ownerID(90)) },
		"controller":          func(f *ownerOperationFixture) { f.v.rs.OwnerReferences[0].UID = types.UID(ownerID(90)) },
		"pod":                 func(f *ownerOperationFixture) { f.v.pod.UID = types.UID(ownerID(90)) },
		"pod-spec":            func(f *ownerOperationFixture) { f.v.pod.Spec.Containers[0].Command = []string{"changed"} },
		"pod-delete":          func(f *ownerOperationFixture) { f.v.pod.DeletionTimestamp = &meta.Time{Time: f.start} },
		"ready":               func(f *ownerOperationFixture) { f.v.pod.Status.Conditions[0].Status = core.ConditionFalse },
		"endpoint":            func(f *ownerOperationFixture) { f.v.list.Items[0].Endpoints[0].Conditions.Ready = ptr.To(false) },
		"endpoint-incomplete": func(f *ownerOperationFixture) { f.v.list.Continue = "same" },
		"unknown":             func(f *ownerOperationFixture) { f.unknown = true },
		"expired":             func(f *ownerOperationFixture) { f.clock.Store(f.start.Add(5 * time.Second).UnixNano()) },
		"late-final":          func(f *ownerOperationFixture) { f.lastNamespaceExpiry = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			op, ctx := f.begin(t)
			f.mu.Lock()
			change(f)
			f.mu.Unlock()
			if _, e := op.Final(ctx); e == nil {
				t.Fatal("changed or unavailable final state accepted")
			}
			calls := f.observer.Load()
			if _, e := op.Original(ctx); e == nil {
				t.Fatal("failed operation returned retained proof")
			}
			if _, e := op.Final(ctx); e == nil || f.observer.Load() != calls {
				t.Fatal("failed operation retried native I/O")
			}
		})
	}
}
func TestOwnerObservationOperationCloseJoinsRead(t *testing.T) {
	for _, mode := range []string{"close", "caller-cancel", "original-cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			op, ctx := f.begin(t)
			f.mu.Lock()
			f.blockPath = "/api/v1/namespaces/owners/services/hub-owner"
			f.entered = make(chan struct{})
			f.exited = make(chan struct{})
			f.mu.Unlock()
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { _, e := op.Final(call); done <- e }()
			select {
			case <-f.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("read not admitted")
			}
			closed := make(chan struct{})
			go func() {
				switch mode {
				case "caller-cancel":
					cancel()
				case "original-cancel":
					op.cancel()
				}
				op.Close()
				close(closed)
			}()
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("close did not join read")
			}
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("cancelled final succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("final not joined")
			}
			select {
			case <-f.exited:
			case <-time.After(time.Second):
				t.Fatal("actual HTTPS request not cancelled")
			}
			if _, e := op.Original(ctx); e == nil {
				t.Fatal("closed state reused")
			}
		})
	}
}
func TestOwnerObservationOperationRejectsWrongOriginal(t *testing.T) {
	f := newOwnerOperationFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), f.start.Add(5*time.Second))
	defer cancel()
	valid := value.OwnerObservationRequest{RootID: f.pin.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.start, NotAfter: f.start.Add(5 * time.Second)}
	for _, mode := range []string{"no-deadline", "cancelled", "wrong-root", "expired", "overlong", "wrong-pool", "duplicate", "empty"} {
		t.Run(mode, func(t *testing.T) {
			call := ctx
			r := valid
			peers := []value.OwnerBinding{f.v.binding}
			switch mode {
			case "no-deadline":
				call = context.Background()
			case "cancelled":
				c, end := context.WithCancel(ctx)
				end()
				call = c
			case "wrong-root":
				r.RootID = ownerID(90)
			case "expired":
				r.RequestedAt = f.start.Add(-10 * time.Second)
				r.NotAfter = f.start.Add(-5 * time.Second)
			case "overlong":
				r.NotAfter = r.NotAfter.Add(time.Nanosecond)
			case "wrong-pool":
				peers[0].IssuerEpoch = ownerID(90)
			case "duplicate":
				peers = append(peers, peers[0])
			case "empty":
				peers = nil
			}
			if op, e := f.reader.Begin(call, r, peers); e == nil {
				op.Close()
				t.Fatal("invalid original accepted")
			}
		})
	}
	if f.observer.Load() != 0 || f.probe.Load() != 0 {
		t.Fatal("invalid scope caused native I/O")
	}
}
func TestOwnerObservationOperationIdenticalIDsAreIndependent(t *testing.T) {
	f := newOwnerOperationFixture(t)
	a, ctx := f.begin(t)
	b, _ := f.begin(t)
	if a == b {
		t.Fatal("same-ID operation adopted old state")
	}
	a.Close()
	if _, e := a.Final(ctx); e == nil {
		t.Fatal("old operation revived")
	}
	if _, e := b.Final(ctx); e != nil {
		t.Fatal("old cleanup closed independent operation", e)
	}
}

func TestOwnerObservationOperationTwoExactProcesses(t *testing.T) {
	for _, samePod := range []bool{false, true} {
		t.Run(map[bool]string{false: "different-pods", true: "same-pod-different-process"}[samePod], func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			first, second := f.v.binding, f.v.binding
			second.ProcessEpoch = ownerID(92)
			want := int32(30)
			if !samePod {
				want = 36
				second.PodUID = ownerID(93)
				f.other = f.v.pod.DeepCopy()
				f.other.Name = "hub-rs-other"
				f.other.UID = types.UID(second.PodUID)
				f.other.Status.PodIPs = []core.PodIP{{IP: "10.2.3.5"}}
				endpoint := f.v.list.Items[0].Endpoints[0].DeepCopy()
				endpoint.TargetRef.Name = f.other.Name
				endpoint.TargetRef.UID = f.other.UID
				endpoint.Addresses = []string{"10.2.3.5"}
				f.v.list.Items[0].Endpoints = append(f.v.list.Items[0].Endpoints, *endpoint)
			}
			ctx, cancel := context.WithDeadline(context.Background(), f.start.Add(5*time.Second))
			defer cancel()
			r := value.OwnerObservationRequest{RootID: f.pin.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.start, NotAfter: f.start.Add(5 * time.Second)}
			peers := []value.OwnerBinding{first, second}
			op, e := f.reader.Begin(ctx, r, peers)
			if e != nil {
				t.Fatal(e)
			}
			defer op.Close()
			peers[0].ProcessEpoch = ownerID(99)
			final, e := op.Final(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if len(final.Peers) != 2 || final.Peers[0].Binding != first || final.Peers[1].Binding != second || f.observer.Load() != want || f.probe.Load() != 6 {
				t.Fatalf("lost exact process/input ownership or duplicated native graph: calls %d/%d", f.observer.Load(), f.probe.Load())
			}
		})
	}
}

func TestOwnerObservationOperationInitialReadChangesDeny(t *testing.T) {
	f := newOwnerOperationFixture(t)
	f.changeDuringInitial = true
	ctx, cancel := context.WithDeadline(context.Background(), f.start.Add(5*time.Second))
	defer cancel()
	r := value.OwnerObservationRequest{RootID: f.pin.RootID, ID: ownerID(80), Challenge: ownerID(81), RequestedAt: f.start, NotAfter: f.start.Add(5 * time.Second)}
	if op, e := f.reader.Begin(ctx, r, []value.OwnerBinding{f.v.binding}); e == nil {
		op.Close()
		t.Fatal("changed Pod during initial native bracket accepted")
	}
}
func TestOwnerObservationOperationConcurrentFinalCannotReuse(t *testing.T) {
	f := newOwnerOperationFixture(t)
	op, ctx := f.begin(t)
	f.mu.Lock()
	f.blockPath = "/api/v1/namespaces/owners/services/hub-owner"
	f.entered = make(chan struct{})
	f.exited = make(chan struct{})
	f.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, e := op.Final(ctx); done <- e }()
	select {
	case <-f.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("read not admitted")
	}
	if _, e := op.Final(ctx); e == nil {
		t.Fatal("concurrent final reused original proof")
	}
	op.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("concurrent invalidation ignored")
		}
	case <-time.After(time.Second):
		t.Fatal("pending final not joined")
	}
	select {
	case <-f.exited:
	case <-time.After(time.Second):
		t.Fatal("native read not cancelled")
	}
}

func TestOwnerObservationOperationFinalCallerOnlyShortens(t *testing.T) {
	f := newOwnerOperationFixture(t)
	op, ctx := f.begin(t)
	before, e := op.Original(ctx)
	if e != nil {
		t.Fatal(e)
	}
	shorter := f.start.Add(2 * time.Second)
	call, cancel := context.WithDeadline(ctx, shorter)
	defer cancel()
	after, e := op.Final(call)
	if e != nil {
		t.Fatal(e)
	}
	if !after.ObservedAt.Equal(before.ObservedAt) || !after.FreshUntil.Equal(shorter) || !after.FreshUntil.Before(before.FreshUntil) {
		t.Fatal("current caller bound lost or original observation renewed")
	}
}
