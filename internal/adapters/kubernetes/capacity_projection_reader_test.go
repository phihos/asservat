package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	apps "k8s.io/api/apps/v1"
	auth "k8s.io/api/authentication/v1"
	authz "k8s.io/api/authorization/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
	"k8s.io/utils/ptr"
)

// The loopback API models current admission/objects. It does not claim native
// admission, SQL setup, original CREATE completion or installed Pod execution.
type capacityReaderFixture struct {
	reader              *InstalledWorkerProjectionReader
	mu                  sync.Mutex
	state               contracts.InitialRuntimeResourceState
	journalUID          string
	worker              *apps.Deployment
	metadata            meta.PartialObjectMetadata
	metadataReads       atomic.Int32
	wrongIdentity       atomic.Bool
	blockJournal        chan struct{}
	journalEntered      chan struct{}
	clock               atomic.Int64
	advanceAfterJournal atomic.Bool
}

func newCapacityReaderFixture(t *testing.T) *capacityReaderFixture {
	t.Helper()
	s, state := installedWorkerResourceFixture(t)
	_, model, _ := capacityProjectionStateFixture()
	p := *model.CapacityProjection
	p.Setup.InstallationID = s.initial.InstallationID
	p.Setup.ClaimedAt = state.CreatedAt.Add(time.Second)
	p.Setup.Until = p.Setup.ClaimedAt.Add(5 * time.Second)
	p.ClaimedAt = state.CreatedAt.Add(10 * time.Second)
	p.Until = p.ClaimedAt.Add(5 * time.Second)
	p.Receipt = &contracts.CapacityRuntimeProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.CapacityRuntimeProjectionName(s.initial.InstallationID), UID: ownerID(2100)}, ResourceVersion: "50", ObservedAt: p.ClaimedAt.Add(time.Second)}
	state.CapacityProjection = &p
	in, err := s.inventory(state)
	if err != nil {
		t.Fatal(err)
	}
	f := &capacityReaderFixture{state: state, journalUID: ownerID(2101)}
	activation, err := BuildHubWorkerActivation(s.initial.InstallationID, contracts.InitialRuntimeResourceSnapshot{State: state, UID: f.journalUID}, in)
	if err != nil {
		t.Fatal(err)
	}
	input := contracts.HubWorkerDeployment{InstallationID: s.initial.InstallationID, ClusterID: s.initial.ClusterID, Namespace: in.Namespace, FleetSource: in.FleetSource, FleetGuard: s.initial.FleetGuard, OwnerSource: in.OwnerSource, OwnerGuard: in.OwnerSourceGuard, LeaderLease: in.LeaderLease, Activation: activation}
	plan := capacityActivationAdministration(input)
	policy, binding, err := OwnerWorkloadAdmission(plan)
	if err != nil {
		t.Fatal(err)
	}
	policy.UID = types.UID(activation.WorkloadGuard.PolicyUID)
	policy.Generation = activation.WorkloadGuard.PolicyGeneration
	policy.ResourceVersion = "40"
	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.TypeChecking = &admission.TypeChecking{}
	binding.UID = types.UID(activation.WorkloadGuard.BindingUID)
	binding.ResourceVersion = activation.WorkloadGuard.BindingResourceVersion
	objects := map[string]runtime.Object{}
	for _, i := range []int{1, 10, 11, 13} {
		o, e := s.object(state, i)
		if e != nil {
			t.Fatal(e)
		}
		object := o.object.(interface {
			runtime.Object
			meta.Object
		})
		object.SetUID(types.UID(state.Objects[i].Receipt.UID))
		object.SetResourceVersion("60")
		object.SetGeneration(state.Objects[i].Receipt.Generation)
		object.SetAnnotations(map[string]string{initialRuntimeResourceMarker: state.Objects[i].OperationID})
		objects[o.collection+"/"+object.GetName()] = object
		if i == 11 {
			f.worker = object.(*apps.Deployment)
			f.worker.Spec.Replicas = ptr.To(int32(1))
			f.worker.Generation++
			f.worker.Annotations[configurationLaunchAnnotation] = ownerID(2102)
			f.worker.Annotations["deployment.kubernetes.io/revision"] = "1"
		}
	}
	f.metadata = meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Namespace: input.Namespace.Name, Name: p.Receipt.Secret.Name, UID: types.UID(p.Receipt.Secret.UID), ResourceVersion: p.Receipt.ResourceVersion, Annotations: capacityProjectionAnnotations(f.journalUID, state.SetupID, &p)}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/secrets/"+activation.Resources.Name) && f.blockJournal != nil {
			select {
			case f.journalEntered <- struct{}{}:
			default:
			}
			select {
			case <-f.blockJournal:
			case <-r.Context().Done():
				return
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/namespaces/"+input.Namespace.Name:
			permissionReply(w, permissionNamespace(input.Namespace.Name, input.Namespace.UID))
		case strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies/"+plan.Name):
			permissionReply(w, policy)
		case strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings/"+plan.Name):
			permissionReply(w, binding)
		case strings.HasSuffix(r.URL.Path, "/selfsubjectreviews"):
			name := "probe"
			if r.Header.Get("Authorization") == "Bearer observer" {
				name = "system:serviceaccount:" + input.Namespace.Name + ":" + activation.ServiceAccount.Name
			}
			if f.wrongIdentity.Load() {
				name = "another-runtime"
			}
			permissionReply(w, auth.SelfSubjectReview{Status: auth.SelfSubjectReviewStatus{UserInfo: auth.UserInfo{Username: name, Groups: []string{"system:authenticated"}}}})
		case strings.HasSuffix(r.URL.Path, "/selfsubjectaccessreviews"):
			permissionReply(w, authz.SelfSubjectAccessReview{Status: authz.SubjectAccessReviewStatus{Allowed: true}})
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/deployments/"+activation.OwnerDeployment.Name):
			if r.URL.Query().Get("dryRun") != "All" {
				t.Error("persistent projection proof mutation")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			permissionReply(w, meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonForbidden, Code: 403, Details: &meta.StatusDetails{Group: "apps", Kind: "deployments", Causes: []meta.StatusCause{{Message: "ValidatingAdmissionPolicy '" + plan.Name + "' with binding '" + plan.Name + "' denied request: " + ownerWorkloadDenial}}}})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/"+activation.Resources.Name):
			body, e := json.Marshal(f.state)
			if e != nil {
				t.Error(e)
				return
			}
			permissionReply(w, core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: activation.Resources.Name, Namespace: input.Namespace.Name, UID: types.UID(f.journalUID), ResourceVersion: "70"}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}})
			if f.advanceAfterJournal.Load() {
				f.clock.Add(int64(6 * time.Second))
			}
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets/"+f.metadata.Name):
			if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
				t.Error("projection payload requested by runtime observation")
			}
			f.metadataReads.Add(1)
			permissionReply(w, f.metadata)
		case r.Method == http.MethodGet && objects[r.URL.Path] != nil:
			permissionReply(w, objects[r.URL.Path])
		default:
			t.Error("unexpected API access; private role journals are forbidden", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := func(token string) *PermissionClient {
		c, e := NewPermissionClient(&rest.Config{Host: server.URL, BearerToken: token, RateLimiter: flowcontrol.NewFakeAlwaysRateLimiter(), TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, input.ClusterID, cfg.NamespaceRef{Name: input.Namespace.Name, UID: input.Namespace.UID}, func() time.Time { return time.Now().Add(time.Duration(f.clock.Load())) })
		if e != nil {
			t.Fatal(e)
		}
		return c
	}
	f.reader, err = NewInstalledWorkerProjectionReader(client("observer"), client("probe"), input)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCapacityProjectionCurrentReaderRequiresExactPositiveReceipt(t *testing.T) {
	for _, mode := range []string{"ready", "pending", "secret-before-receipt", "historical-complete", "expired-pending", "wrong-secret-uid", "wrong-secret-rv", "replaced-journal", "changed-worker", "wrong-account", "late-read"} {
		t.Run(mode, func(t *testing.T) {
			f := newCapacityReaderFixture(t)
			f.mu.Lock()
			switch mode {
			case "pending":
				f.state.CapacityProjection = nil
			case "secret-before-receipt":
				f.state.CapacityProjection.Receipt = nil
			case "historical-complete", "expired-pending":
				// Model an original input from an hour ago without moving the
				// current observation clock or creating a fresh setup interval.
				f.state.CreatedAt = f.state.CreatedAt.Add(-time.Hour)
				f.state.Until = f.state.Until.Add(-time.Hour)
				f.reader.input.Activation.CreatedAt = f.state.CreatedAt
				f.reader.input.Activation.Until = f.state.Until
				for i := range f.state.Objects {
					f.state.Objects[i].ClaimedAt = f.state.Objects[i].ClaimedAt.Add(-time.Hour)
					f.state.Objects[i].Until = f.state.Objects[i].Until.Add(-time.Hour)
				}
				p := f.state.CapacityProjection
				p.ClaimedAt, p.Until = p.ClaimedAt.Add(-time.Hour), p.Until.Add(-time.Hour)
				p.Setup.ClaimedAt, p.Setup.Until = p.Setup.ClaimedAt.Add(-time.Hour), p.Setup.Until.Add(-time.Hour)
				p.Setup.PostmasterAt = p.Setup.PostmasterAt.Add(-time.Hour)
				p.Receipt.ObservedAt = p.Receipt.ObservedAt.Add(-time.Hour)
				if mode == "expired-pending" {
					f.state.CapacityProjection.Receipt = nil
				}
			case "wrong-secret-uid":
				f.metadata.UID = types.UID(ownerID(2120))
			case "wrong-secret-rv":
				f.metadata.ResourceVersion = "other"
			case "replaced-journal":
				f.journalUID = ownerID(2121)
			case "changed-worker":
				f.worker.Spec.Template.Spec.Containers[0].Image = "other"
			case "wrong-account":
				f.wrongIdentity.Store(true)
			case "late-read":
				f.advanceAfterJournal.Store(true)
			}
			f.mu.Unlock()
			got, ready, until, err := f.reader.ReadCapacity(t.Context())
			valid := mode == "ready" || mode == "pending" || mode == "secret-before-receipt" || mode == "historical-complete"
			if (err == nil) != valid {
				t.Fatalf("mode=%s ready=%t error=%v", mode, ready, err)
			}
			if valid && (ready != (mode == "ready" || mode == "historical-complete") || !f.reader.client.now().Before(until)) {
				t.Fatal("receipt status or original interval changed")
			}
			if ready && got.Receipt.Secret.UID != ownerID(2100) {
				t.Fatal("replacement accepted")
			}
			if (mode == "pending" || mode == "secret-before-receipt") && f.metadataReads.Load() != 0 {
				t.Fatal("unacknowledged projection inspected")
			}
		})
	}
}

func TestCapacityProjectionCurrentReaderCancellationDoesNotReturnReceipt(t *testing.T) {
	f := newCapacityReaderFixture(t)
	f.blockJournal = make(chan struct{})
	f.journalEntered = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, ready, _, err := f.reader.ReadCapacity(ctx)
		if ready || err == nil {
			done <- cfg.ErrInvalid
		} else {
			done <- nil
		}
	}()
	select {
	case <-f.journalEntered:
	case <-time.After(time.Second):
		t.Fatal("journal read not reached")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("cancelled observation returned authority")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled read did not join")
	}
	close(f.blockJournal)
}
