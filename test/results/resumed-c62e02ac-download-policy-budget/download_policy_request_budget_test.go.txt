package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type downloadPolicyBudgetFixture struct {
	source                  *DownloadEnvironmentSource
	observer, probe, denied atomic.Int32
	mu                      sync.Mutex
	before                  func(http.ResponseWriter, *http.Request) bool
}

// Reuse the existing TLS API model and its unchanged default 20/20 clients.
// Only the processing document and its exact guard/probe response are added.
// Native admission, identity, SQL and installed concurrency are not simulated
// by a successful policy observation in this test.
func newDownloadPolicyBudgetFixture(t *testing.T) *downloadPolicyBudgetFixture {
	t.Helper()
	api := newConfigurationSourcePathFixture(t)
	observer, probe := api.source.client, api.source.protection.probe
	if observer.api.GetRateLimiter().QPS() != 20 || probe.api.GetRateLimiter().QPS() != 20 || observer.SharesLimiter(probe) {
		t.Fatal("fixture changed the installed default independent client limits")
	}
	plan := cfg.ConfigMapAdministration{Name: "download-policy", SourceName: "processing", ControlNamespace: observer.control, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "installer"}}}
	pin := GuardPin{PolicyUID: ownerID(19000), PolicyGeneration: 1, BindingUID: ownerID(19001), BindingResourceVersion: "1"}
	policy, binding, err := DownloadEnvironmentAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	policy.UID, policy.Generation, policy.ResourceVersion = types.UID(pin.PolicyUID), 1, "1"
	policy.Status.ObservedGeneration, policy.Status.TypeChecking = 1, &admission.TypeChecking{}
	binding.UID, binding.ResourceVersion = types.UID(pin.BindingUID), pin.BindingResourceVersion
	root, installation, sourceUID := ownerID(19002), api.source.input.InstallationID, ownerID(19003)
	revision := identity.Revision{UID: ownerID(19004), Generation: 1, Digest: artifact.Digest{1}}
	path := privacy.DownloadPath{ID: ownerID(19005), TargetClusterID: observer.clusterID, StoreID: ownerID(19006), StorageRegion: "storage", AcquisitionClusterID: observer.clusterID, AcquisitionRegion: "hub", ConnectorClusterID: observer.clusterID, ConnectorRegion: "hub", HubClusterID: observer.clusterID, HubRegion: "hub", WorkerConfiguration: revision, HubConfiguration: revision}
	wireRevision := contracts.DownloadEnvironmentRevision{UID: revision.UID, Generation: revision.Generation, SHA256: hex.EncodeToString(revision.Digest[:])}
	wire := contracts.DownloadEnvironmentSettings{
		Format: contracts.DownloadEnvironmentFormat, RootID: root, InstallationID: installation, RecoveryEpoch: ownerID(19007), Revision: 1,
		PermittedRegions: []string{"storage", "hub"},
		Paths:            []contracts.DownloadEnvironmentPath{{ID: path.ID, TargetClusterID: path.TargetClusterID, StoreID: path.StoreID, StorageRegion: path.StorageRegion, AcquisitionClusterID: path.AcquisitionClusterID, AcquisitionRegion: path.AcquisitionRegion, ConnectorClusterID: path.ConnectorClusterID, ConnectorRegion: path.ConnectorRegion, HubClusterID: path.HubClusterID, HubRegion: path.HubRegion, WorkerConfiguration: wireRevision, HubConfiguration: wireRevision}},
		Clients:          []contracts.DownloadEnvironmentClient{{Issuer: "https://id.example.test", ID: "console", Kind: "human", DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, Purposes: []string{"diagnostics"}, PathIDs: []string{path.ID}}},
		Operators:        []contracts.ProcessingOperator{{Issuer: "https://id.example.test", ClientID: "console", Kind: "Group", ID: "privacy"}},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	object := &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: plan.SourceName, Namespace: plan.ControlNamespace.Name, UID: types.UID(sourceUID), ResourceVersion: "1"}, Data: map[string]string{contracts.DownloadEnvironmentFile: string(encoded)}}
	objectPath := "/api/v1/namespaces/" + plan.ControlNamespace.Name + "/configmaps/" + plan.SourceName
	f := &downloadPolicyBudgetFixture{}
	api.extraHandler = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") == "Bearer administrator" {
			f.observer.Add(1)
		} else {
			f.probe.Add(1)
		}
		f.mu.Lock()
		before := f.before
		f.mu.Unlock()
		if before != nil && before(w, r) {
			return true
		}
		switch r.URL.Path {
		case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + plan.Name:
			permissionReply(w, policy)
		case "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + plan.Name:
			permissionReply(w, binding)
		case objectPath:
			if r.Method == http.MethodGet {
				permissionReply(w, object)
				return true
			}
			var submitted core.ConfigMap
			if r.Method != http.MethodPut || r.Header.Get("Authorization") != "Bearer probe" || r.URL.Query().Get("dryRun") != "All" || r.URL.Query().Get("fieldValidation") != "Strict" || json.NewDecoder(r.Body).Decode(&submitted) != nil || !reflect.DeepEqual(submitted, *object) {
				t.Error("processing proof changed its original object or attempted a persistent write")
				http.Error(w, "invalid probe", http.StatusForbidden)
				return true
			}
			f.denied.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Kind: "configmaps", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy '" + plan.Name + "' with binding '" + plan.Name + "' denied request: " + downloadEnvironmentDenial}}}})
		default:
			return false
		}
		return true
	}
	guard, err := NewDownloadEnvironmentProtection(observer, probe, plan, pin)
	if err != nil {
		t.Fatal(err)
	}
	f.source, err = NewDownloadEnvironmentSource(observer, guard, plan.SourceName, sourceUID, root, installation, []privacy.DownloadPath{path})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDownloadPolicyRequestBudgetOriginalParent(t *testing.T) {
	f := newDownloadPolicyBudgetFixture(t)
	start := time.Now()
	originalUntil := start.Add(5 * time.Second)
	call, end := context.WithDeadline(t.Context(), originalUntil)
	defer end()
	// CurrentDownloadEnvironment reads the policy twice in every full authority
	// check. Measure both actual source reads, without replacing their clients,
	// advancing clocks or deriving a fresh deadline for the second read.
	for n := int32(1); n <= 2; n++ {
		readStart := time.Now()
		p, err := f.source.DownloadPolicy(call)
		elapsed := time.Since(readStart)
		t.Logf("policy_read=%d elapsed=%s total_elapsed=%s observer=%d probe=%d denied=%d", n, elapsed, time.Since(start), f.observer.Load(), f.probe.Load(), f.denied.Load())
		if err != nil || !p.Valid(time.Now()) || p.ObservedAt.Before(readStart) || !p.FreshUntil.Equal(originalUntil) || call.Err() != nil {
			t.Fatal("policy lost the original parent interval", err)
		}
		if f.observer.Load() != 14*n || f.probe.Load() != 3*n || f.denied.Load() != n {
			t.Fatal("actual guarded policy request graph changed", f.observer.Load(), f.probe.Load(), f.denied.Load())
		}
	}
}

func TestDownloadPolicyRequestBudgetOriginalSourceInterval(t *testing.T) {
	f := newDownloadPolicyBudgetFixture(t)
	call, end := context.WithTimeout(t.Context(), 10*time.Second)
	defer end()
	p, err := f.source.DownloadPolicy(call)
	if err != nil || !p.Valid(time.Now()) || !p.FreshUntil.Equal(p.ObservedAt.Add(5*time.Second)) {
		t.Fatal("final guard renewed the initial source observation", err)
	}
	if f.observer.Load() != 14 || f.probe.Load() != 3 || f.denied.Load() != 1 {
		t.Fatal("source interval omitted protected reads")
	}
}

func TestDownloadPolicyRequestBudgetStopsAtOriginalBoundary(t *testing.T) {
	for _, mode := range []string{"deadline", "cancellation"} {
		t.Run(mode, func(t *testing.T) {
			f := newDownloadPolicyBudgetFixture(t)
			call, end := context.WithTimeout(t.Context(), time.Second)
			defer end()
			joined := make(chan struct{})
			f.mu.Lock()
			f.before = func(_ http.ResponseWriter, r *http.Request) bool {
				if f.observer.Load() != 14 || r.Header.Get("Authorization") != "Bearer administrator" {
					return false
				}
				if mode == "cancellation" {
					end()
				}
				<-r.Context().Done()
				close(joined)
				return true
			}
			f.mu.Unlock()
			p, err := f.source.DownloadPolicy(call)
			if err == nil || !reflect.DeepEqual(p, privacy.DownloadPolicy{}) {
				t.Fatal("unfinished final guard supplied policy authority")
			}
			want := context.DeadlineExceeded
			if mode == "cancellation" {
				want = context.Canceled
			}
			if !errors.Is(call.Err(), want) {
				t.Fatal("original caller boundary changed", call.Err())
			}
			select {
			case <-joined:
			case <-time.After(time.Second):
				t.Fatal("final guard HTTP request did not observe caller cancellation")
			}
			if f.observer.Load() != 14 || f.probe.Load() != 3 || f.denied.Load() != 1 {
				t.Fatal("boundary caused an implicit retry or skipped the actual guard", f.observer.Load(), f.probe.Load(), f.denied.Load())
			}
		})
	}
}
