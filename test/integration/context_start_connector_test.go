package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	execution "asservat.local/asservat/internal/domain/execution"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Independent fixture phases must not accidentally inherit a nearly spent
// proof. Wait for the previous phase's actual original end before beginning a
// different operation. No in-flight operation waits, refreshes or retries.
func waitConnectorAPIFixtureObservation(t *testing.T, ctx context.Context, until time.Time) {
	t.Helper()
	if delay := time.Until(until); delay > 0 {
		t.Logf("independent fixture phase waits for previous original observation: %s", delay)
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func qualifyConnectorAPIStart(t *testing.T, ctx context.Context, adminConfig, capacityConfig, runtimeConfig *rest.Config, client func(*rest.Config) *kube.PermissionClient, process *kube.ConnectorAPIExecutionProcess, observed execution.APIProcessObservation, control cfg.NamespaceRef, stats *contextStartAPIStats, previousUntil time.Time) time.Time {
	t.Helper()
	dc, e := dynamic.NewForConfig(adminConfig)
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile("../../charts/asservat/crds/capacityreservations.yaml")
	if e != nil {
		t.Fatal(e)
	}
	var crd unstructured.Unstructured
	if json.Unmarshal(data, &crd.Object) != nil {
		t.Fatal("shipped CRD invalid")
	}
	crds := dc.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	if _, e = crds.Create(ctx, &crd, meta.CreateOptions{}); e != nil && !apierrors.IsAlreadyExists(e) {
		t.Fatal(e)
	}
	if e = wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(c context.Context) (bool, error) {
		v, e := crds.Get(c, crd.GetName(), meta.GetOptions{})
		if e != nil {
			return false, e
		}
		conditions, _, _ := unstructured.NestedSlice(v.Object, "status", "conditions")
		for _, r := range conditions {
			m, _ := r.(map[string]any)
			if m["type"] == "Established" && m["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	}); e != nil {
		t.Fatal(e)
	}
	// Established does not mean admission already serves the new resource; the
	// chart installs this CRD long before any start. A dry-run CREATE as the
	// capacity account runs both guards and stores nothing; keep it out of the
	// timed phase and log each refusal.
	probe, e := dynamic.NewForConfig(capacityConfig)
	if e != nil {
		t.Fatal(e)
	}
	ready := time.Now()
	if e = wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 15*time.Second, true, func(c context.Context) (bool, error) {
		n := time.Now().UTC().Truncate(time.Microsecond)
		pb := execution.Binding{ExecutionClass: artifact.ContextAPIExecution, OperationID: custodyID(), CaptureID: custodyID(), ActionID: "pod-status", AttemptID: custodyID(), ClusterID: observed.Binding.ClusterID, IssuerEpoch: observed.Binding.IssuerEpoch, PodUID: custodyID(), ExecutorPodUID: observed.Binding.PodUID, ExecutorAccountUID: observed.Binding.AccountUID, CollectorEpoch: observed.Binding.ProcessEpoch, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: artifact.MaxContextBytes, NotBefore: n, NotAfter: n.Add(5 * time.Second)}
		e := connectorAPIStartCreate(c, probe, control.Name, pb, true)
		if e != nil {
			var status apierrors.APIStatus
			if errors.As(e, &status) {
				t.Logf("start readiness: dry-run CREATE refused after %s: code=%d reason=%s message=%q", time.Since(ready), status.Status().Code, status.Status().Reason, status.Status().Message)
			} else {
				t.Logf("start readiness: dry-run CREATE failed after %s: %v", time.Since(ready), e)
			}
		}
		return e == nil, nil
	}); e != nil {
		t.Fatal("capacity reservations not admitted", e)
	}
	t.Logf("start readiness: dry-run CREATE admitted after %s", time.Since(ready))
	waitConnectorAPIFixtureObservation(t, ctx, previousUntil)
	preparer, e := kube.NewConnectorAPIStartPreparer(process, client(capacityConfig))
	if e != nil {
		t.Fatal(e)
	}
	journal, e := kube.NewStartJournal(runtimeConfig, observed.Binding.ClusterID, control, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	// ADR-173 order of one work: the first process read (here a cold, complete
	// proof) is the work's observation; every start step reuses it and must
	// finish within its original interval.
	readCounts := stats.snapshot()
	n := time.Now().UTC().Truncate(time.Microsecond)
	work, e := process.ReadAPIProcess(ctx)
	stats.phase(t, "work-process-read", n, readCounts)
	if e != nil || work.Binding != observed.Binding {
		t.Fatal("work process observation", e)
	}
	// Bindings carry canonical UTC microsecond times, as SQL preparation writes them.
	n = work.CheckedAt.UTC().Truncate(time.Microsecond)
	b := execution.Binding{ExecutionClass: artifact.ContextAPIExecution, OperationID: custodyID(), CaptureID: custodyID(), ActionID: "pod-status", AttemptID: custodyID(), ClusterID: work.Binding.ClusterID, IssuerEpoch: work.Binding.IssuerEpoch, PodUID: custodyID(), ExecutorPodUID: work.Binding.PodUID, ExecutorAccountUID: work.Binding.AccountUID, CollectorEpoch: work.Binding.ProcessEpoch, ScopeDigest: artifact.Digest{1}, AuthorityDigest: artifact.Digest{2}, BudgetDigest: artifact.Digest{3}, AuditDigest: artifact.Digest{4}, NativeBytes: artifact.MaxContextBytes, NotBefore: n, NotAfter: work.ValidUntil.UTC().Truncate(time.Microsecond)}
	// Fixture-only acknowledged preparation grant. It is not a real SQL prepare.
	prepareCounts, prepareStarted := stats.snapshot(), time.Now()
	p, e := preparer.PrepareObservedStart(ctx, execution.PreparationCheck{Binding: b, CheckedAt: n, ValidUntil: b.NotAfter, MayCreate: true}, work)
	stats.phase(t, "prepare-start", prepareStarted, prepareCounts)
	if e != nil {
		connectorAPIStartDiagnostic(t, ctx, dc, control.Name, "start-"+b.AttemptID)
		connectorAPIStartReplay(t, ctx, capacityConfig, control.Name, b)
		t.Fatalf("actual capacity CREATE elapsed=%s original_remaining=%s err=%v", time.Since(n), time.Until(b.NotAfter), e)
	}
	request := execution.Request{Binding: b, ObjectUID: p.ObjectUID, CheckedAt: n, ValidUntil: b.NotAfter}
	readyCounts, readyStarted := stats.snapshot(), time.Now()
	_, e = preparer.ReadyObservedStart(ctx, request, work)
	stats.phase(t, "ready-start", readyStarted, readyCounts)
	if e != nil {
		t.Fatalf("actual capacity status Ready elapsed=%s original_remaining=%s err=%v", time.Since(n), time.Until(b.NotAfter), e)
	}
	consumeCounts, consumeStarted := stats.snapshot(), time.Now()
	got, e := journal.ConsumeStart(ctx, request)
	stats.phase(t, "consume-start", consumeStarted, consumeCounts)
	if e != nil || !got.MayStart {
		t.Fatalf("actual executor status StartCommitted elapsed=%s original_remaining=%s err=%v", time.Since(n), time.Until(b.NotAfter), e)
	}
	replay, e := journal.ConsumeStart(ctx, request)
	if e != nil || replay.MayStart {
		t.Fatal("consumed local start replay", e)
	}
	t.Logf("work process read, actual CREATE, Ready /status and one StartCommitted /status within the work observation's original interval: %s of %s", time.Since(n), work.ValidUntil.Sub(n))
	return work.ValidUntil
}

// Static operation classes only: never paths, request bodies, source identities,
// tokens, Secret contents or raw provider errors. Rate limiter waits are outside
// RoundTrip, so phase elapsed and these measured I/O totals remain distinct.
type contextStartAPIStats struct {
	mu      sync.Mutex
	counts  map[string]int
	elapsed map[string]time.Duration
}

func (s *contextStartAPIStats) wrap(next http.RoundTripper) http.RoundTripper {
	return ownerProbeRoundTripper(func(r *http.Request) (*http.Response, error) {
		class := "other"
		for _, v := range []string{"tokenreviews", "selfsubjectreviews", "validatingadmissionpolicies", "validatingadmissionpolicybindings", "capacityreservations", "deployments", "replicasets", "pods", "configmaps", "secrets", "serviceaccounts"} {
			if strings.Contains(r.URL.Path, "/"+v) {
				class = v
				break
			}
		}
		if strings.HasSuffix(r.URL.Path, "/status") {
			class += "/status"
		}
		if r.URL.Query().Get("dryRun") == "All" {
			class += "/dry-run"
		}
		class = r.Method + " " + class
		n := time.Now()
		response, e := next.RoundTrip(r)
		s.mu.Lock()
		s.counts[class]++
		s.elapsed[class] += time.Since(n)
		s.mu.Unlock()
		return response, e
	})
}

// Static per-phase deltas distinguish limiter/proof work from API round trips.
// The snapshot never includes paths, objects, credentials or response bodies.
type contextStartAPIPhase struct {
	counts  map[string]int
	elapsed map[string]time.Duration
}

func (s *contextStartAPIStats) snapshot() contextStartAPIPhase {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := contextStartAPIPhase{counts: map[string]int{}, elapsed: map[string]time.Duration{}}
	for k, v := range s.counts {
		out.counts[k] = v
	}
	for k, v := range s.elapsed {
		out.elapsed[k] = v
	}
	return out
}
func (s *contextStartAPIStats) phase(t *testing.T, name string, started time.Time, before contextStartAPIPhase) {
	t.Helper()
	after := s.snapshot()
	for k, v := range before.counts {
		after.counts[k] -= v
	}
	for k, v := range before.elapsed {
		after.elapsed[k] -= v
	}
	for k, v := range after.counts {
		if v == 0 {
			delete(after.counts, k)
			delete(after.elapsed, k)
		}
	}
	t.Logf("bounded phase=%s elapsed=%s API_counts=%v API_roundtrip=%v", name, time.Since(started), after.counts, after.elapsed)
}

// connectorAPIStartDiagnostic distinguishes a refused CREATE from a refused
// response: it reports only the stored object's shape (synthetic values).
func connectorAPIStartDiagnostic(t *testing.T, ctx context.Context, dc dynamic.Interface, namespace, name string) {
	t.Helper()
	v, e := dc.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(namespace).Get(ctx, name, meta.GetOptions{})
	if e != nil {
		t.Logf("start diagnostic: stored object absent or unreadable: %v", e)
		return
	}
	raw, _ := json.Marshal(v.Object)
	tokens := 0
	for d := json.NewDecoder(bytes.NewReader(raw)); ; tokens++ {
		if _, e := d.Token(); e != nil {
			break
		}
	}
	keys := func(m map[string]any) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		slices.Sort(out)
		return out
	}
	spec, _, _ := unstructured.NestedMap(v.Object, "spec")
	metadata, _, _ := unstructured.NestedMap(v.Object, "metadata")
	_, status := v.Object["status"]
	managed, _, _ := unstructured.NestedSlice(v.Object, "metadata", "managedFields")
	t.Logf("start diagnostic: stored bytes=%d json_tokens=%d top=%v metadata=%v spec=%v status=%t generation=%d managedFields=%d", len(raw), tokens, keys(v.Object), keys(metadata), keys(spec), status, v.GetGeneration(), len(managed))
}

// connectorAPIStartReplay repeats the refused CREATE as the capacity account to
// log the server's status. A refused request has no effect.
func connectorAPIStartReplay(t *testing.T, ctx context.Context, capacityConfig *rest.Config, namespace string, b execution.Binding) {
	t.Helper()
	dc, e := dynamic.NewForConfig(capacityConfig)
	if e != nil {
		t.Logf("start replay: client: %v", e)
		return
	}
	e = connectorAPIStartCreate(ctx, dc, namespace, b, false)
	var status apierrors.APIStatus
	if errors.As(e, &status) {
		t.Logf("start replay: code=%d reason=%s message=%q", status.Status().Code, status.Status().Reason, status.Status().Message)
		return
	}
	t.Logf("start replay: err=%v", e)
}

func connectorAPIStartCreate(ctx context.Context, dc dynamic.Interface, namespace string, b execution.Binding, dryRun bool) error {
	spec, e := kube.LocalStartSpec(b)
	if e != nil {
		return e
	}
	raw, _ := json.Marshal(spec)
	var fields map[string]any
	if e = json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "CapacityReservation", "metadata": map[string]any{"name": "start-" + b.AttemptID, "namespace": namespace}, "spec": fields}}
	options := meta.CreateOptions{}
	if dryRun {
		options.DryRun = []string{meta.DryRunAll}
	}
	_, e = dc.Resource(schema.GroupVersionResource{Group: "asservat.io", Version: "v1alpha1", Resource: "capacityreservations"}).Namespace(namespace).Create(ctx, object, options)
	return e
}

type capacityTokenWarnings struct {
	mu   sync.Mutex
	seen []string
}

func (w *capacityTokenWarnings) HandleWarningHeader(_ int, _ string, message string) {
	w.mu.Lock()
	w.seen = append(w.seen, message)
	w.mu.Unlock()
}

// capacityTokenConditionDiagnostic evaluates each condition of the ADR-175
// clause as a separate Warn-only policy on the real API server and logs the
// conditions that evaluate false for the connector's exact request.
func capacityTokenConditionDiagnostic(t *testing.T, ctx context.Context, admin kubernetes.Interface, runtime *rest.Config, namespace, connectorUID, audience string) {
	t.Helper()
	quote := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	conditions := map[string]string{
		"operation":   "request.operation == 'CREATE'",
		"group":       "(has(request.resource.group) ? request.resource.group : '') == ''",
		"resource":    "request.resource.resource == 'serviceaccounts'",
		"subresource": "(has(request.subResource) ? request.subResource : '') == 'token'",
		"name":        "request.name == 'capacity'",
		"username":    "request.userInfo.username == " + quote("system:serviceaccount:"+namespace+":connector"),
		"uid":         "request.userInfo.uid == " + quote(connectorUID),
		"pod-extra":   "has(request.userInfo.extra) && 'authentication.kubernetes.io/pod-uid' in request.userInfo.extra && size(request.userInfo.extra['authentication.kubernetes.io/pod-uid']) == 1",
		"spec":        "has(object.spec)",
		"audiences":   "has(object.spec.audiences) && object.spec.audiences == [" + quote(audience) + "]",
		"expiration":  "has(object.spec.expirationSeconds) && object.spec.expirationSeconds == 600",
		"unbound":     kube.CapacityTokenUnboundCondition,
		"sentinel":    "false",
	}
	fail, equivalent := admission.Fail, admission.Equivalent
	var names []string
	for label, expression := range conditions {
		n := "diag-capacity-" + label
		policy := &admission.ValidatingAdmissionPolicy{ObjectMeta: meta.ObjectMeta{Name: n}, Spec: admission.ValidatingAdmissionPolicySpec{FailurePolicy: &fail, MatchConstraints: &admission.MatchResources{MatchPolicy: &equivalent, ResourceRules: []admission.NamedRuleWithOperations{{RuleWithOperations: admission.RuleWithOperations{Operations: []admission.OperationType{admission.Create}, Rule: admission.Rule{APIGroups: []string{""}, APIVersions: []string{"*"}, Resources: []string{"serviceaccounts/token"}}}}}}, MatchConditions: []admission.MatchCondition{{Name: "namespace", Expression: "request.namespace == " + quote(namespace)}}, Validations: []admission.Validation{{Expression: expression, Message: "condition false: " + label, MessageExpression: "'condition false: " + label + " bound=' + (has(object.spec.boundObjectRef) ? ((has(object.spec.boundObjectRef.kind) ? object.spec.boundObjectRef.kind : '-') + '/' + (has(object.spec.boundObjectRef.name) ? object.spec.boundObjectRef.name : '-')) : 'absent')"}}}}
		if _, e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{}); e != nil {
			t.Logf("diagnostic policy %s: %v", label, e)
			continue
		}
		binding := &admission.ValidatingAdmissionPolicyBinding{ObjectMeta: meta.ObjectMeta{Name: n}, Spec: admission.ValidatingAdmissionPolicyBindingSpec{PolicyName: n, ValidationActions: []admission.ValidationAction{admission.Warn}}}
		if _, e := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{}); e != nil {
			t.Logf("diagnostic binding %s: %v", label, e)
		}
		names = append(names, n)
	}
	defer func() {
		for _, n := range names {
			_ = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(context.Background(), n, meta.DeleteOptions{})
			_ = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(context.Background(), n, meta.DeleteOptions{})
		}
	}()
	warnings := &capacityTokenWarnings{}
	c := rest.CopyConfig(runtime)
	c.WarningHandler = warnings
	api, e := kubernetes.NewForConfig(c)
	if e != nil {
		t.Logf("diagnostic client: %v", e)
		return
	}
	// Policies load asynchronously; the always-false sentinel shows they apply.
	for range 40 {
		warnings.mu.Lock()
		warnings.seen = nil
		warnings.mu.Unlock()
		_, e = api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, "capacity", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), Audiences: []string{audience}}}, meta.CreateOptions{})
		warnings.mu.Lock()
		seen := slices.Clone(warnings.seen)
		warnings.mu.Unlock()
		if slices.ContainsFunc(seen, func(m string) bool { return strings.Contains(m, "condition false: sentinel") }) {
			t.Logf("capacity TokenRequest diagnostic: request error=%v warnings=%q", e, seen)
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Log("capacity TokenRequest diagnostic: policies never applied")
}
