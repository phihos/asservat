package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	access "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

type bootstrapObserverFixture struct {
	mu                  sync.Mutex
	issues, publicReads int
	paths               []string
	blockAt             int
	entered, release    chan struct{}
	observer            *InitialBootstrapObserver
	config              contracts.InitialPreparer
	projection          contracts.InitialBootstrapObservation
	desired             contracts.InitialBootstrap
	state               contracts.InitialBootstrapState
	apiConfig           *rest.Config
	extra               func(http.ResponseWriter, *http.Request) bool
}

func newBootstrapObserverFixture(t *testing.T, ctx context.Context) *bootstrapObserverFixture {
	t.Helper()
	return newBootstrapObserverFixtureVersion(t, ctx, contracts.InitialBootstrapFormat)
}

func newBootstrapObserverFixtureVersion(t *testing.T, ctx context.Context, format string) *bootstrapObserverFixture {
	t.Helper()
	f := &bootstrapObserverFixture{entered: make(chan struct{}, 1), release: make(chan struct{})}
	d := bootstrapAdmissionFixture(t)
	d.Format = format
	_, state := bootstrapStateFixture(t)
	if contracts.InitialBootstrapHasCopyClosure(format) {
		state.Prelude.CopyMarker = &contracts.WorkerObjectReference{Name: bootstrapNames(d).copyMarker, UID: ownerID(19)}
	}
	objects := map[string]runtime.Object{}
	n := bootstrapNames(d)
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths = append(f.paths, r.URL.Path)
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/configmaps/"+n.projection) {
			f.publicReads++
			if f.blockAt == f.publicReads {
				f.mu.Unlock()
				f.entered <- struct{}{}
				select {
				case <-f.release:
				case <-r.Context().Done():
				}
				return
			}
		}
		f.mu.Unlock()
		if f.extra != nil && f.extra(w, r) {
			return
		}
		if r.Method == http.MethodGet {
			if value := objects[r.URL.Path]; value != nil {
				permissionReply(w, value)
				return
			}
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews" {
			user := auth.UserInfo{Username: "original-administrator", Groups: []string{"administrators"}}
			if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer observation-") {
				user = auth.UserInfo{Username: "system:serviceaccount:" + d.BootstrapNamespace + ":" + n.account, UID: state.Prelude.Account.UID, Groups: []string{"system:serviceaccounts"}}
			}
			permissionReply(w, auth.SelfSubjectReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "SelfSubjectReview"}, Status: auth.SelfSubjectReviewStatus{UserInfo: user}})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			permissionReply(w, access.SelfSubjectAccessReview{TypeMeta: meta.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SelfSubjectAccessReview"}, Status: access.SubjectAccessReviewStatus{Allowed: true}})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/"+d.BootstrapNamespace+"/serviceaccounts/"+n.account+"/token" {
			var request auth.TokenRequest
			if json.NewDecoder(r.Body).Decode(&request) != nil || request.Spec.BoundObjectRef == nil || string(request.Spec.BoundObjectRef.UID) != state.Prelude.TokenAnchor.UID || request.Spec.ExpirationSeconds == nil || *request.Spec.ExpirationSeconds != 600 || len(request.Spec.Audiences) != 1 || request.Spec.Audiences[0] != d.ProbeAudience {
				t.Error("unexpected observation token scope")
				http.Error(w, "invalid", 400)
				return
			}
			f.mu.Lock()
			f.issues++
			token := fmt.Sprintf("observation-%d", f.issues)
			f.mu.Unlock()
			request.Status = auth.TokenRequestStatus{Token: token, ExpirationTimestamp: meta.NewTime(time.Now().UTC().Add(600 * time.Second))}
			permissionReply(w, request)
			return
		}
		if r.Method == http.MethodPut && r.URL.Path == "/api/v1/namespaces/"+d.BootstrapNamespace+"/configmaps/"+n.marker && r.URL.Query().Get("dryRun") == "All" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Kind: "configmaps", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy '" + n.guard + "' with binding '" + n.guard + "' denied request: " + initialBootstrapDenial}}}})
			return
		}
		t.Errorf("unexpected observation API %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", 500)
	}))
	t.Cleanup(server.Close)
	d.Kubernetes = contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}
	state.DesiredDigest = bootstrapDigest(d)
	c, err := bootstrapProjectionValue(d, state)
	if err != nil {
		t.Fatal(err)
	}
	f.config = c
	f.desired, f.state = d, state
	v, err := bootstrapObservationValue(d, state, c)
	if err != nil {
		t.Fatal(err)
	}
	f.projection = v
	add := func(path string, o runtime.Object, ref contracts.WorkerObjectReference) {
		m := bootstrapObjectMetadata(o)
		m.UID = types.UID(ref.UID)
		m.ResourceVersion = "1"
		objects[path+"/"+m.Name] = o
	}
	namespace := &core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: d.BootstrapNamespace, UID: types.UID(state.Prelude.Namespace.UID), ResourceVersion: "1", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}
	objects["/api/v1/namespaces/"+d.BootstrapNamespace] = namespace
	prefix := "/api/v1/namespaces/" + d.BootstrapNamespace
	add(prefix+"/serviceaccounts", bootstrapProbeAccount(d), state.Prelude.Account)
	add(prefix+"/configmaps", bootstrapProbeMarker(d, n.marker), state.Prelude.Marker)
	add(prefix+"/configmaps", bootstrapProbeMarker(d, n.continuityMarker), state.Prelude.ContinuityMarker)
	if state.Prelude.CopyMarker != nil {
		add(prefix+"/configmaps", bootstrapProbeMarker(d, n.copyMarker), *state.Prelude.CopyMarker)
	}
	add(prefix+"/secrets", bootstrapProbeAnchor(d), state.Prelude.TokenAnchor)
	rbac := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + d.BootstrapNamespace
	add(rbac+"/roles", bootstrapProbeRole(d), state.Prelude.Role)
	add(rbac+"/rolebindings", bootstrapProbeBinding(d), state.Prelude.Binding)
	policy, binding, err := InitialBootstrapAdmission(d)
	if err != nil {
		t.Fatal(err)
	}
	policy.Generation = 1
	policy.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admission.TypeChecking{}}
	add("/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies", policy, contracts.WorkerObjectReference{UID: state.Prelude.Guard.PolicyUID})
	add("/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings", binding, contracts.WorkerObjectReference{UID: state.Prelude.Guard.BindingUID})
	projection, err := bootstrapProjectionObject(d, state, c)
	if err != nil {
		t.Fatal(err)
	}
	add(prefix+"/configmaps", projection, *state.Projection)
	// No fake unlimited rate limiter: use the production bounded client path.
	config := &rest.Config{Host: server.URL, BearerToken: "administrator", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	f.apiConfig = config
	f.observer, err = NewInitialBootstrapObserver(ctx, config, v, c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.observer.Close)
	return f
}

func TestInitialBootstrapObserverRefreshesExpiredCredentialWithoutPrivateReads(t *testing.T) {
	f := newBootstrapObserverFixture(t, context.Background())
	first, err := f.observer.ReadToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	f.observer.mu.Lock()
	f.observer.expires = time.Now().Add(-time.Second)
	f.observer.mu.Unlock()
	next, err := f.observer.ReadToken(context.Background())
	if err != nil || string(first) == string(next) {
		t.Fatal("expired credential was reused", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues != 2 {
		t.Fatal("unexpected refresh count", f.issues)
	}
	for _, path := range f.paths {
		if strings.Contains(path, "bootstrap-state") || strings.Contains(path, "sql-material") || strings.Contains(path, "provider-material") || strings.Contains(path, "private-progress") {
			t.Fatal("observer read private state", path)
		}
	}
}
func TestInitialBootstrapObserverCloseJoinsRefreshAndDeniesRetainedSource(t *testing.T) {
	f := newBootstrapObserverFixture(t, context.Background())
	f.mu.Lock()
	f.blockAt = 2
	f.mu.Unlock()
	result := make(chan error, 1)
	go func() { _, err := f.observer.ReadToken(context.Background()); result <- err }()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("final public observation not reached")
	}
	if _, err := f.observer.ReadToken(context.Background()); err == nil {
		t.Fatal("parallel refresh accepted")
	}
	f.observer.Close()
	if err := <-result; err == nil {
		t.Fatal("closed refresh disclosed token")
	}
	if _, err := f.observer.ReadToken(context.Background()); err == nil {
		t.Fatal("retained source detached from Close")
	}
}
func TestInitialBootstrapObserverFinalReadRetainsOriginalDeadline(t *testing.T) {
	f := newBootstrapObserverFixture(t, context.Background())
	f.mu.Lock()
	f.blockAt = 2
	f.mu.Unlock()
	ctx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	if token, err := f.observer.ReadToken(ctx); err == nil || len(token) != 0 {
		t.Fatal("expired original read delivered token")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issues != 1 {
		t.Fatal("deadline triggered repeated TokenRequest")
	}
}
func TestInitialBootstrapObserverProjectionCannotCarryPrivateMaterial(t *testing.T) {
	d, s := bootstrapStateFixture(t)
	c, err := bootstrapProjectionValue(d, s)
	if err != nil {
		t.Fatal(err)
	}
	v, err := bootstrapObservationValue(d, s, c)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{s.Passwords.Manager, s.Passwords.Preparation, s.Passwords.Audit, s.Passwords.Activation, s.Passwords.History, s.Material.IssuerToken, s.Material.Storage.SecretAccessKey} {
		if strings.Contains(string(b), value) {
			t.Fatal("private material in public observation projection")
		}
	}
	for _, edit := range []func(*contracts.InitialBootstrapObservation){func(v *contracts.InitialBootstrapObservation) { v.Prelude.Account.UID = ownerID(98) }, func(v *contracts.InitialBootstrapObservation) { v.InstallationID = ownerID(98) }, func(v *contracts.InitialBootstrapObservation) { v.ProjectionDigest = strings.Repeat("f", 64) }, func(v *contracts.InitialBootstrapObservation) { v.PlanDigest = strings.Repeat("f", 64) }} {
		next := v
		next.Prelude = v.Prelude
		edit(&next)
		if bootstrapObservationMatches(next, c) {
			t.Fatal("changed public identity accepted")
		}
	}
}
