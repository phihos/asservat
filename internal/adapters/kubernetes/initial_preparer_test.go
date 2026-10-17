package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

func preparerTestPlan() contracts.InitialPreparationPlan {
	return contracts.InitialPreparationPlan{InstallationID: ownerID(1), RequestID: ownerID(2), ClusterID: ownerID(3), BootstrapNamespace: contracts.WorkerObjectReference{Name: "bootstrap", UID: ownerID(4)}, RootName: "prepare", ProbeName: "continuity-probe", ContinuityName: "continuity", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator"}}, Workload: contracts.InitialPreparationWorkload{Namespace: "initial-target", Name: "initial", WriterAccount: "writer", ProbeAccount: "probe", Configuration: "inputs", Credentials: "credentials", Image: "example.invalid/asservat@sha256:" + strings.Repeat("a", 64), Witness: "witness", FleetSource: "fleet", WitnessGuard: "witness-guard", FleetGuard: "fleet-guard", WorkloadGuard: "workload-guard", StagingGuard: "staging-guard", Journal: "preparation"}}
}

type preparerFixture struct {
	mu          sync.Mutex
	t           *testing.T
	plan        contracts.InitialPreparationPlan
	config      contracts.InitialPreparer
	objects     map[string]map[string]any
	posts       map[string]int
	firstBodies map[string][]byte
	pending     []byte
	fault       string
	triggered   bool
	shift       time.Duration
	serial      int
	server      *httptest.Server
	client      *rest.Config
	extra       func(http.ResponseWriter, *http.Request) bool // held under fixture lock
}

func (f *preparerFixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return time.Now().Add(f.shift)
}
func (f *preparerFixture) status(w http.ResponseWriter, n int, reason meta.StatusReason, kind, cause string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(n)
	permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: reason, Code: int32(n), Details: &meta.StatusDetails{Kind: kind, Causes: []meta.StatusCause{{Message: cause}}}})
}
func (f *preparerFixture) store(path string, b []byte) {
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		f.t.Fatal("bad synthetic body")
	}
	m := v["metadata"].(map[string]any)
	f.serial++
	m["uid"] = ownerID(100 + f.serial)
	m["resourceVersion"] = strconv.Itoa(f.serial)
	if v["kind"] == "Namespace" {
		m["labels"].(map[string]any)["kubernetes.io/metadata.name"] = m["name"]
		v["spec"] = map[string]any{"finalizers": []any{"kubernetes"}}
		v["status"] = map[string]any{"phase": "Active"}
	}
	f.objects[path] = v
}
func newPreparerFixture(t *testing.T, fault string) *preparerFixture {
	return newPreparerFixturePlan(t, fault, preparerTestPlan())
}
func newPreparerFixturePlan(t *testing.T, fault string, plan contracts.InitialPreparationPlan) *preparerFixture {
	f := &preparerFixture{t: t, plan: plan, objects: map[string]map[string]any{}, posts: map[string]int{}, firstBodies: map[string][]byte{}, fault: fault, serial: 10}
	cp, cb, e := InitialPreparationContinuityAdmission(f.plan)
	if e != nil {
		t.Fatal(e)
	}
	sp, sb, e := InitialNamespaceAdmission(preparerAdministration(f.plan))
	if e != nil {
		t.Fatal(e)
	}
	pin := func(p *admission.ValidatingAdmissionPolicy, b *admission.ValidatingAdmissionPolicyBinding, n int) contracts.OwnerDeploymentGuard {
		p.UID, p.Generation, p.ResourceVersion = types.UID(ownerID(n)), 1, "1"
		p.Status.ObservedGeneration = 1
		p.Status.TypeChecking = &admission.TypeChecking{}
		b.UID, b.ResourceVersion = types.UID(ownerID(n+1)), "2"
		return contracts.OwnerDeploymentGuard{Name: p.Name, PolicyUID: string(p.UID), PolicyGeneration: 1, BindingUID: string(b.UID), BindingResourceVersion: "2", Administrators: f.plan.Administrators}
	}
	f.config = contracts.InitialPreparer{Format: contracts.InitialPreparerFormat, Plan: f.plan, Continuity: pin(cp, cb, 5), Staging: pin(sp, sb, 7)}
	policy := map[string]any{"/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/continuity": cp, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/continuity": cb, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/staging-guard": sp, "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/staging-guard": sb}
	anchor := core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: f.plan.ProbeName, Namespace: "bootstrap", UID: types.UID(ownerID(9)), ResourceVersion: "1"}, Data: map[string]string{"probe": "public"}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.extra != nil && f.extra(w, r) {
			return
		}
		path := r.URL.Path
		if path == "/apis/authentication.k8s.io/v1/selfsubjectreviews" {
			who := "operator"
			if r.Header.Get("Authorization") == "Bearer probe" || f.fault == "wrong-admin" {
				who = "probe"
			}
			v := auth.SelfSubjectReview{}
			v.Status.UserInfo = auth.UserInfo{Username: who, Groups: []string{"system:authenticated"}}
			permissionReply(w, v)
			return
		}
		if path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			v := authz.SelfSubjectAccessReview{}
			v.Status.Allowed = true
			permissionReply(w, v)
			return
		}
		if v, ok := policy[path]; ok {
			if f.fault == "guard-lost" && strings.HasSuffix(path, "/continuity") {
				f.status(w, 404, meta.StatusReasonNotFound, "", "")
				return
			}
			permissionReply(w, v)
			return
		}
		if path == "/api/v1/namespaces/bootstrap" {
			permissionReply(w, core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "bootstrap", UID: types.UID(f.plan.BootstrapNamespace.UID), ResourceVersion: "1"}})
			return
		}
		if path == "/api/v1/namespaces/bootstrap/configmaps/continuity-probe" {
			if r.Method == "GET" {
				permissionReply(w, anchor)
				return
			}
			if r.URL.Query().Get("dryRun") != "All" {
				t.Error("probe not dry-run")
			}
			f.status(w, 403, meta.StatusReasonForbidden, "configmaps", "ValidatingAdmissionPolicy 'continuity' with binding 'continuity' denied request: "+initialContinuityDenial)
			return
		}
		if r.Method == "GET" {
			v, ok := f.objects[path]
			if !ok {
				f.status(w, 404, meta.StatusReasonNotFound, "", "")
				return
			}
			permissionReply(w, v)
			return
		}
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			return
		}
		var v map[string]any
		if json.Unmarshal(raw, &v) != nil {
			t.Error("invalid json")
			return
		}
		m := v["metadata"].(map[string]any)
		if r.Method == "POST" {
			full := path + "/" + m["name"].(string)
			f.posts[full]++
			if _, ok := f.objects[full]; ok {
				f.status(w, 409, meta.StatusReasonAlreadyExists, "", "")
				return
			}
			if old, ok := f.firstBodies[full]; ok && !reflect.DeepEqual(old, raw) {
				t.Error("retried CREATE body changed")
			}
			f.firstBodies[full] = append([]byte(nil), raw...)
			if full == "/api/v1/namespaces/initial-target" && !f.triggered && (f.fault == "lost-before-create" || f.fault == "delayed-original") {
				f.triggered = true
				f.pending = append([]byte(nil), raw...)
				f.status(w, 503, meta.StatusReasonServiceUnavailable, "", "")
				return
			}
			f.store(full, raw)
			if full == "/api/v1/namespaces/initial-target" && !f.triggered && f.fault == "lost-after-create" {
				f.triggered = true
				f.status(w, 503, meta.StatusReasonServiceUnavailable, "", "")
				return
			}
			w.WriteHeader(http.StatusCreated)
			permissionReply(w, f.objects[full])
			return
		}
		if r.Method == "PUT" {
			old, ok := f.objects[path]
			if !ok {
				f.status(w, 404, meta.StatusReasonNotFound, "", "")
				return
			}
			om := old["metadata"].(map[string]any)
			if m["uid"] != om["uid"] || m["resourceVersion"] != om["resourceVersion"] {
				f.status(w, 409, meta.StatusReasonConflict, "", "")
				return
			}
			f.serial++
			m["resourceVersion"] = strconv.Itoa(f.serial)
			f.objects[path] = v
			if f.fault == "lost-retirement-reply" && !f.triggered && strings.Contains(path, "/roles/") {
				f.triggered = true
				f.status(w, 503, meta.StatusReasonServiceUnavailable, "", "")
				return
			}
			if strings.HasSuffix(path, "/prepare") && !f.triggered && (f.fault == "lost-intent-reply" || f.fault == "expired-intent") {
				var st contracts.InitialPreparationRoot
				_ = json.Unmarshal([]byte(v["data"].(map[string]any)["root.json"].(string)), &st)
				if len(st.Creates) > 0 {
					f.triggered = true
					if f.fault == "expired-intent" {
						f.shift = 6 * time.Second
					} else {
						f.status(w, 503, meta.StatusReasonServiceUnavailable, "", "")
						return
					}
				}
			}
			permissionReply(w, v)
			return
		}
		t.Errorf("unexpected %s %s", r.Method, path)
		f.status(w, 500, meta.StatusReasonInternalError, "", "")
	}))
	t.Cleanup(f.server.Close)
	f.client = &rest.Config{Host: f.server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})}, BearerToken: "operator", RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter()}
	return f
}
func (f *preparerFixture) preparer(t *testing.T) *InitialPreparer {
	t.Helper()
	ns := cfg.NamespaceRef{Name: "bootstrap", UID: f.plan.BootstrapNamespace.UID}
	o, e := NewPermissionClient(f.client, f.plan.ClusterID, ns, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	pc := rest.CopyConfig(f.client)
	pc.BearerToken = "probe"
	p, e := NewPermissionClient(pc, f.plan.ClusterID, ns, f.clock)
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewInitialPreparer(f.client, o, p, f.config)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func TestInitialPreparerClosedInventoryAndPolicy(t *testing.T) {
	p := preparerTestPlan()
	o, e := preparerObjects(p)
	if e != nil || len(o) != 9 {
		t.Fatalf("closed inventory: %d %v", len(o), e)
	}
	for _, v := range o {
		g := v.object.GetObjectKind().GroupVersionKind()
		if g.Group == admission.GroupName || g.Kind == "Secret" || g.Kind == "Pod" || g.Kind == "ConfigMap" {
			t.Fatalf("unsafe retry kind: %s", g)
		}
	}
	policy, _, e := InitialPreparationContinuityAdmission(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range policy.Spec.MatchConditions {
		if strings.Contains(v.Expression, "variables.") {
			t.Fatal("policy variables unavailable in match conditions")
		}
	}
	expression := policy.Spec.Validations[0].Expression
	for _, want := range []string{"!has(object.aggregationRule)", "oldObject.rules ==", "oldObject.subjects ==", "object.roleRef ==", "oldObject.roleRef ==", "size(object.ownerReferences)"} {
		if want == "size(object.ownerReferences)" {
			want = "size(object.metadata.ownerReferences)"
		}
		if !strings.Contains(expression, want) {
			t.Errorf("missing exact retirement check: %s", want)
		}
	}
}
func TestInitialPreparerResumesOriginalPlanAfterUncertainty(t *testing.T) {
	for _, mode := range []string{"valid", "lost-before-create", "lost-after-create", "lost-intent-reply", "expired-intent"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparerFixture(t, mode)
			s := f.preparer(t)
			w, e := s.Declare(context.Background())
			if mode == "lost-before-create" || mode == "lost-intent-reply" || mode == "expired-intent" {
				if e == nil {
					t.Fatal("uncertain attempt reported complete")
				}
				f.mu.Lock()
				if mode == "lost-intent-reply" || mode == "expired-intent" {
					if f.posts["/api/v1/namespaces/initial-target"] != 0 {
						t.Error("effect after unknown/expired intent acknowledgement")
					}
				}
				f.shift = 0
				f.mu.Unlock()
				s = f.preparer(t)
				w, e = s.Declare(context.Background())
			}
			if e != nil || w.Phase != "declared" || len(w.Creates) != 9 {
				t.Fatalf("resume: %s %d %v", w.Phase, len(w.Creates), e)
			}
			original := w
			s = f.preparer(t)
			again, e := s.Declare(context.Background())
			if e != nil || !reflect.DeepEqual(original, again) {
				t.Fatalf("original pins changed: %v", e)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			for key, n := range f.posts {
				want := 1
				if mode == "lost-before-create" && key == "/api/v1/namespaces/initial-target" {
					want = 2
				}
				if n != want {
					t.Errorf("%s: %d CREATEs wanted %d", key, n, want)
				}
			}
		})
	}
}
func TestInitialPreparerKnownIdentityAndAuthorityLossDeny(t *testing.T) {
	for _, mode := range []string{"replacement", "deletion", "root-replacement", "guard-lost", "wrong-admin"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparerFixture(t, "")
			s := f.preparer(t)
			w, e := s.Declare(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			f.mu.Lock()
			switch mode {
			case "replacement":
				f.objects["/api/v1/namespaces/initial-target/serviceaccounts/writer"]["metadata"].(map[string]any)["uid"] = ownerID(700)
			case "deletion":
				delete(f.objects, "/api/v1/namespaces/initial-target/serviceaccounts/writer")
			case "root-replacement":
				f.objects[s.rootPath()]["metadata"].(map[string]any)["uid"] = ownerID(701)
			default:
				f.fault = mode
			}
			before := fmt.Sprint(f.posts)
			f.mu.Unlock()
			if _, e = f.preparer(t).Declare(context.Background()); e == nil {
				t.Fatal("changed identity/authority accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if before != fmt.Sprint(f.posts) {
				t.Fatal("created after known identity changed")
			}
			if w.RootUID == "" {
				t.Fatal("root UID not retained")
			}
		})
	}
}
func TestInitialPreparerRetirementNeverRecreatesOrRevivesAuthority(t *testing.T) {
	f := newPreparerFixture(t, "")
	s := f.preparer(t)
	before, e := s.Declare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	after, e := s.RetireSetupAuthority(context.Background())
	if e != nil || after.Phase != "retired" {
		t.Fatalf("retirement: %s %v", after.Phase, e)
	}
	if !reflect.DeepEqual(before.Creates, after.Creates) {
		t.Fatal("retirement rewrote original receipts")
	}
	again, e := f.preparer(t).RetireSetupAuthority(context.Background())
	if e != nil || !reflect.DeepEqual(after, again) {
		t.Fatalf("retired replay: %v", e)
	}
	if _, e = s.Declare(context.Background()); e == nil {
		t.Fatal("retired setup reopened")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for path, raw := range f.firstBodies {
		if !strings.Contains(path, "roles/") && !strings.Contains(path, "rolebindings/") {
			continue
		}
		v := f.objects[path]
		var original map[string]any
		_ = json.Unmarshal(raw, &original)
		if _, ok := original["rules"]; ok {
			if rules, ok := v["rules"].([]any); ok && len(rules) != 0 {
				t.Error("rules remain")
			}
		}
		if _, ok := original["subjects"]; ok {
			if subjects, ok := v["subjects"].([]any); ok && len(subjects) != 0 {
				t.Error("subjects remain")
			}
		}
		if f.posts[path] != 1 {
			t.Error("retirement reissued CREATE")
		}
	}
}

func TestInitialPreparerLostRetirementReplyDoesNotClaimCompletion(t *testing.T) {
	f := newPreparerFixture(t, "")
	s := f.preparer(t)
	before, e := s.Declare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.fault = "lost-retirement-reply"
	f.mu.Unlock()
	if state, e := s.RetireSetupAuthority(context.Background()); e == nil || state.Phase == "retired" {
		t.Fatal("unknown retirement reported complete")
	}
	state, e := f.preparer(t).RetireSetupAuthority(context.Background())
	if e != nil || state.Phase != "retired" || !reflect.DeepEqual(before.Creates, state.Creates) {
		t.Fatalf("retirement replay changed history: %v", e)
	}
}
func TestInitialPreparerConcurrentIntentRemainsSingleAndBounded(t *testing.T) {
	f := newPreparerFixture(t, "")
	s := f.preparer(t)
	if _, e := s.Open(context.Background()); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = s.EnsureNext(context.Background()) }()
	}
	wg.Wait()
	w, e := f.preparer(t).Declare(context.Background())
	if e != nil || len(w.Creates) != 9 {
		t.Fatalf("concurrent resume: %v", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.objects) != 10 {
		t.Fatalf("unbounded or duplicate inventory: %d", len(f.objects))
	}
}
