package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	admission "k8s.io/api/admissionregistration/v1"
	authentication "k8s.io/api/authentication/v1"
	authorization "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

const observationMetadataRoot = "61000000-0000-4000-8000-000000000001"

type observationMetadataFixture struct {
	reader                   *ClusterObservationMetadata
	start                    time.Time
	tick                     atomic.Int64
	calls, namespaces, lists atomic.Int64
	probes                   atomic.Int64
	entered, release         chan struct{}
	releaseOnce              sync.Once
}

func (f *observationMetadataFixture) now() time.Time { return time.Unix(0, f.tick.Load()).UTC() }
func (f *observationMetadataFixture) unblock()       { f.releaseOnce.Do(func() { close(f.release) }) }

// Real client/TLS protocol tests with explicitly synthetic API objects and
// admission responses. They confer no installed or native guard authority.
func observationMetadataTestFixture(t *testing.T, mode string) *observationMetadataFixture {
	t.Helper()
	f := &observationMetadataFixture{start: time.Now().UTC().Truncate(time.Microsecond), entered: make(chan struct{}), release: make(chan struct{})}
	f.tick.Store(f.start.UnixNano())
	plan := cfg.CapacityNamespaceAdministration{Name: "metadata-guard", Administrators: []cfg.KubernetesActor{{Kind: "Group", Name: "capacity-administrators"}}, Keys: []string{"capacity.example/team"}, ProbeNamespace: permissionControl, ProbeAccount: cfg.NamespaceRef{Name: "capacity-probe", UID: "probe-uid"}}
	p, b, err := CapacityNamespaceAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	p.UID, p.Generation, p.ResourceVersion = "policy", 1, "policy-one"
	p.Status = admission.ValidatingAdmissionPolicyStatus{ObservedGeneration: 1, TypeChecking: &admission.TypeChecking{}}
	b.UID, b.ResourceVersion = "binding", "binding-one"
	var entered sync.Once
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if mode == "blocked" {
			entered.Do(func() { close(f.entered) })
			<-f.release
		}
		switch {
		case strings.Contains(r.URL.Path, "/validatingadmissionpolicies/"):
			permissionReply(w, p)
		case strings.Contains(r.URL.Path, "/validatingadmissionpolicybindings/"):
			value := b.DeepCopy()
			if mode == "changed-guard" && f.probes.Load() != 0 {
				value.UID = "replacement"
			}
			permissionReply(w, value)
		case strings.HasSuffix(r.URL.Path, "/serviceaccounts/"+plan.ProbeAccount.Name):
			permissionReply(w, core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: plan.ProbeAccount.Name, Namespace: permissionControl.Name, UID: types.UID(plan.ProbeAccount.UID)}})
		case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
			permissionReply(w, authentication.SelfSubjectReview{Status: authentication.SelfSubjectReviewStatus{UserInfo: authentication.UserInfo{Username: "system:serviceaccount:" + permissionControl.Name + ":" + plan.ProbeAccount.Name, UID: plan.ProbeAccount.UID, Groups: []string{"system:authenticated"}}}})
		case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
			permissionReply(w, authorization.SelfSubjectAccessReview{Status: authorization.SubjectAccessReviewStatus{Allowed: true}})
		case r.Method == http.MethodPut:
			if r.URL.Path != "/api/v1/namespaces/"+permissionControl.Name || r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" || r.Header.Get("Authorization") != "Bearer synthetic-probe" {
				t.Error("unexpected mutation outside exact independent dry-run probe")
			}
			var request core.Namespace
			if json.NewDecoder(r.Body).Decode(&request) != nil || string(request.UID) != permissionControl.UID || request.Labels[plan.Keys[0]] == "core" {
				t.Error("unbound namespace guard probe")
			}
			f.probes.Add(1)
			w.WriteHeader(http.StatusUnprocessableEntity)
			permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonInvalid, Code: 422, Details: &meta.StatusDetails{Kind: "namespaces", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy 'metadata-guard' with binding 'metadata-guard' denied request: " + capacityNamespaceDenial}}}})
		case r.Method != http.MethodGet:
			t.Errorf("unexpected method %s", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		case r.URL.Path == "/api/v1/namespaces/"+permissionControl.Name || r.URL.Path == "/api/v1/namespaces/payments":
			ns := permissionControl
			if strings.HasSuffix(r.URL.Path, "/payments") {
				ns = cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}
				n := f.namespaces.Add(1)
				if mode == "replaced-before" || mode == "replaced-after" && n > 1 {
					ns.UID = "replacement"
				}
				if mode == "expired-first" {
					f.tick.Store(f.start.Add(5 * time.Second).UnixNano())
				}
			}
			value := core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: ns.Name, UID: types.UID(ns.UID), ResourceVersion: "ns-one", Labels: map[string]string{plan.Keys[0]: "core", "unselected": "excluded"}}}
			if mode == "deleted-after" && f.namespaces.Load() > 1 {
				stamp := meta.NewTime(f.start)
				value.DeletionTimestamp = &stamp
			}
			permissionReply(w, value)
		case r.URL.Path == "/apis/apps/v1/namespaces/payments/deployments/api":
			if r.Header.Get("Accept") != capacityMetadataAccept {
				t.Error("exact read is not bounded metadata")
			}
			permissionReply(w, meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: "api", Namespace: "payments", UID: "workload-uid", ResourceVersion: "workload-one", Generation: 1}})
		case r.URL.Path == "/api/v1/namespaces" || r.URL.Path == "/apis/apps/v1/namespaces/payments/deployments":
			f.lists.Add(1)
			if r.Header.Get("Accept") != capacityMetadataListAccept || r.URL.Query().Get("limit") != "64" || r.URL.Query().Get("continue") != "original-cursor" {
				t.Error("changed bounded candidate selection")
			}
			if mode == "unavailable" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if mode == "expired-list" {
				f.tick.Store(f.start.Add(5 * time.Second).UnixNano())
			}
			page := meta.PartialObjectMetadataList{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadataList"}, ListMeta: meta.ListMeta{ResourceVersion: "page-rv", Continue: "next-cursor"}, Items: []meta.PartialObjectMetadata{}}
			if mode != "empty" {
				m := meta.ObjectMeta{Name: "payments", UID: "payments-uid", ResourceVersion: "ns-one"}
				if strings.HasSuffix(r.URL.Path, "/deployments") {
					m = meta.ObjectMeta{Name: "api", Namespace: "payments", UID: "workload-uid", ResourceVersion: "workload-one"}
				}
				page.Items = append(page.Items, meta.PartialObjectMetadata{ObjectMeta: m})
				if mode == "duplicate" {
					page.Items = append(page.Items, page.Items[0])
				}
				if mode == "overflow" {
					page.Items = make([]meta.PartialObjectMetadata, 65)
				}
			}
			permissionReply(w, page)
		default:
			t.Error("unexpected API path")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(f.unblock)
	config := &rest.Config{Host: srv.URL, BearerToken: "synthetic-observer", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}, RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter()}
	observer, err := NewPermissionClient(config, permissionCluster, permissionControl, f.now)
	if err != nil {
		t.Fatal(err)
	}
	config.BearerToken = "synthetic-probe"
	probe, err := NewPermissionClient(config, permissionCluster, permissionControl, f.now)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewCapacityNamespaceGuard(observer, probe, plan, GuardPin{PolicyUID: "policy", PolicyGeneration: 1, BindingUID: "binding", BindingResourceVersion: "binding-one"})
	if err != nil {
		t.Fatal(err)
	}
	f.reader, err = NewClusterObservationMetadata(observer, guard, observationMetadataRoot)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *observationMetadataFixture) request(purpose fleet.ClusterObservationPurpose) fleet.ClusterObservationRequest {
	r := fleet.ClusterObservationRequest{ID: "61000000-0000-4000-8000-000000000002", Challenge: "61000000-0000-4000-8000-000000000003", RootID: observationMetadataRoot, ClusterID: permissionCluster, Purpose: purpose, RequestedAt: f.start, NotAfter: f.start.Add(4 * time.Second)}
	switch purpose {
	case fleet.ObserveCapacityNamespaces:
		r.Continue = "original-cursor"
	case fleet.ObserveCapacityWorkloads:
		r.Namespace, r.Kind, r.Continue = cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, "Deployment", "original-cursor"
	case fleet.ObserveCapacityWorkload:
		r.Namespace, r.Workload, r.Keys = cfg.NamespaceRef{Name: "payments", UID: "payments-uid"}, cfg.WorkloadRef{Kind: "Deployment", Name: "api", UID: "workload-uid"}, []string{"capacity.example/team"}
	}
	return r
}

func TestClusterObservationMetadataFourPurposesPreserveOriginalBounds(t *testing.T) {
	for _, purpose := range []fleet.ClusterObservationPurpose{fleet.ObserveCapacityNamespaceGuard, fleet.ObserveCapacityNamespaces, fleet.ObserveCapacityWorkloads, fleet.ObserveCapacityWorkload} {
		for _, callerFirst := range []bool{false, true} {
			t.Run(string(purpose)+"/"+map[bool]string{false: "request-bound", true: "caller-bound"}[callerFirst], func(t *testing.T) {
				f := observationMetadataTestFixture(t, "valid")
				r := f.request(purpose)
				end := f.start.Add(5 * time.Second)
				want := r.NotAfter
				if callerFirst {
					end, want = f.start.Add(2*time.Second), f.start.Add(2*time.Second)
				}
				ctx, cancel := context.WithDeadline(context.Background(), end)
				defer cancel()
				out, err := f.reader.ObserveCluster(ctx, r)
				digest, _ := app.ClusterObservationRequestDigest(r)
				if err != nil || !out.Matches(r, digest, f.now()) || !out.Interval.FreshUntil.Equal(want) || !out.Interval.ObservedAt.Equal(f.start) {
					t.Fatalf("original metadata interval/correlation lost: %v", err)
				}
				switch purpose {
				case fleet.ObserveCapacityNamespaceGuard:
					if f.probes.Load() != 1 || out.Guard.Digest != f.reader.guard.guard.digest || !out.Guard.Interval.FreshUntil.Equal(want) {
						t.Fatal("independent exact guard proof not used")
					}
				case fleet.ObserveCapacityNamespaces:
					if f.calls.Load() != 1 || len(out.Namespaces.Items) != 1 || out.Namespaces.ResourceVersion != "page-rv" || out.Namespaces.Continue != "next-cursor" {
						t.Fatal("namespace page changed or reselected")
					}
				case fleet.ObserveCapacityWorkloads:
					if f.calls.Load() != 3 || f.namespaces.Load() != 2 || f.lists.Load() != 1 || len(out.Workloads.Items) != 1 || out.Workloads.ResourceVersion != "page-rv" {
						t.Fatal("exact namespace brackets or original single LIST lost")
					}
				case fleet.ObserveCapacityWorkload:
					if f.calls.Load() != 4 || f.namespaces.Load() != 2 || len(out.Workload.Labels) != 1 || out.Workload.Labels["capacity.example/team"] != "core" || !out.Workload.Interval.FreshUntil.Equal(want) || !out.Workload.NamespaceInterval.FreshUntil.Equal(want) {
						t.Fatal("exact workload reads or selected label scope lost")
					}
				}
			})
		}
	}
}

func TestClusterObservationMetadataRejectsInvalidSelectionBeforeIO(t *testing.T) {
	for _, mode := range []string{"root", "cluster", "purpose", "key", "expired", "no-deadline", "cancelled", "namespace-path"} {
		t.Run(mode, func(t *testing.T) {
			f := observationMetadataTestFixture(t, "valid")
			r := f.request(fleet.ObserveCapacityWorkload)
			ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
			defer cancel()
			switch mode {
			case "root":
				r.RootID = r.ID
			case "cluster":
				r.ClusterID = r.ID
			case "purpose":
				r.Purpose = "arbitrary-operation"
			case "key":
				r.Keys = []string{"unprotected.example/key"}
			case "expired":
				f.tick.Store(r.NotAfter.UnixNano())
			case "no-deadline":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "namespace-path":
				r = f.request(fleet.ObserveCapacityWorkloads)
				r.Namespace.Name = "../other"
			}
			if _, err := f.reader.ObserveCluster(ctx, r); err == nil || f.calls.Load() != 0 {
				t.Fatalf("invalid selection reached API: err=%v calls=%d", err, f.calls.Load())
			}
		})
	}
}

func TestClusterObservationMetadataRejectsChangedOrUnavailablePage(t *testing.T) {
	for _, mode := range []string{"replaced-before", "replaced-after", "deleted-after", "expired-first", "expired-list", "unavailable", "duplicate", "overflow", "empty"} {
		t.Run(mode, func(t *testing.T) {
			f := observationMetadataTestFixture(t, mode)
			r := f.request(fleet.ObserveCapacityWorkloads)
			ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
			defer cancel()
			out, err := f.reader.ObserveCluster(ctx, r)
			if mode == "empty" {
				digest, _ := app.ClusterObservationRequestDigest(r)
				if err != nil || !out.Matches(r, digest, f.now()) || out.Workloads.Items == nil || len(out.Workloads.Items) != 0 || f.calls.Load() != 3 {
					t.Fatal("acknowledged empty page became unavailable or missing")
				}
			} else if err == nil || out.Workloads != nil {
				t.Fatal("changed, expired or unknown page reported success")
			}
			if (mode == "replaced-before" || mode == "expired-first") && f.calls.Load() != 1 {
				t.Fatal("failed first namespace check allowed a subsequent LIST")
			}
			if mode == "expired-list" && f.calls.Load() != 2 {
				t.Fatal("expiry after LIST allowed a subsequent API read")
			}
		})
	}
}

func TestClusterObservationMetadataGuardChangeAndCancellation(t *testing.T) {
	t.Run("guard-change", func(t *testing.T) {
		f := observationMetadataTestFixture(t, "changed-guard")
		r := f.request(fleet.ObserveCapacityNamespaceGuard)
		ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
		defer cancel()
		if out, err := f.reader.ObserveCluster(ctx, r); err == nil || out.Guard != nil || f.probes.Load() != 1 {
			t.Fatal("changed guard returned a current metadata proof")
		}
	})
	t.Run("cancel-blocked-read", func(t *testing.T) {
		f := observationMetadataTestFixture(t, "blocked")
		r := f.request(fleet.ObserveCapacityNamespaces)
		ctx, cancel := context.WithDeadline(context.Background(), r.NotAfter)
		defer cancel()
		joined := make(chan error, 1)
		go func() { _, err := f.reader.ObserveCluster(ctx, r); joined <- err }()
		select {
		case <-f.entered:
		case <-time.After(time.Second):
			t.Fatal("native read never started")
		}
		cancel()
		select {
		case err := <-joined:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("original caller cancellation lost: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("caller cancellation did not join metadata read")
		}
		f.unblock()
		if f.calls.Load() != 1 {
			t.Fatal("cancelled read retried")
		}
	})
}

func TestClusterObservationMetadataConstructorRequiresExactClients(t *testing.T) {
	f := observationMetadataTestFixture(t, "valid")
	for _, input := range []struct {
		client *PermissionClient
		guard  *CapacityNamespaceGuard
		root   string
	}{{nil, f.reader.guard, observationMetadataRoot}, {f.reader.client, nil, observationMetadataRoot}, {f.reader.guard.guard.probe, f.reader.guard, observationMetadataRoot}, {f.reader.client, &CapacityNamespaceGuard{}, observationMetadataRoot}, {f.reader.client, f.reader.guard, "invalid"}} {
		if _, err := NewClusterObservationMetadata(input.client, input.guard, input.root); err == nil {
			t.Fatal("unbound regional metadata constructor accepted")
		}
	}
	if f.calls.Load() != 0 {
		t.Fatal("constructor performed native effects")
	}
}
