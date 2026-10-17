package kubernetes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

type preparationBindingFixture struct {
	f               *preparerFixture
	config          contracts.InitialInstaller
	input, material contracts.WorkerObjectReference
	password        contracts.InitialSQLMaterial
}

func newPreparationBindingFixture(t *testing.T) *preparationBindingFixture {
	t.Helper()
	f, p := activationPreparerFixture(t)
	return preparationBindingFixtureFrom(t, f, p)
}
func preparationBindingFixtureFrom(t *testing.T, f *preparerFixture, p *InitialPreparer) *preparationBindingFixture {
	t.Helper()
	root, e := p.PrepareGatedPod(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	ref := func(kind, name string) contracts.WorkerObjectReference {
		for _, x := range root.Creates {
			if x.Kind == kind && x.Name == name {
				return contracts.WorkerObjectReference{Name: name, UID: x.Receipt.UID}
			}
		}
		t.Fatal("missing fixture receipt")
		return contracts.WorkerObjectReference{}
	}
	c := contracts.InitialInstaller{Format: contracts.InitialInstallerFormat, InstallationID: f.plan.InstallationID, IssuerEpoch: ownerID(50), ClusterID: f.plan.ClusterID, Namespace: ref("Namespace", f.plan.Workload.Namespace), WriterAccount: ref("ServiceAccount", f.plan.Workload.WriterAccount), ProbeAccount: ref("ServiceAccount", f.plan.Workload.ProbeAccount), Pod: contracts.WorkerObjectReference{Name: f.plan.Workload.Name, UID: root.Activation.Pod.Receipt.UID}, PodSpecDigest: root.Activation.Pod.SpecDigest, Configuration: f.plan.Workload.Configuration, Witness: contracts.WorkerObjectReference{Name: f.plan.Workload.Witness, UID: ownerID(51)}, FleetSource: contracts.WorkerObjectReference{Name: f.plan.Workload.FleetSource, UID: ownerID(52)}}
	wp := cfg.InitialWorkloadAdministration{Name: f.plan.Workload.WorkloadGuard, Configuration: c.Configuration, Witness: c.Witness.Name, FleetSource: c.FleetSource.Name, ControlNamespace: cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID}, PodName: c.Pod.Name, PodUID: c.Pod.UID, WriterAccount: c.WriterAccount.Name, WriterAccountUID: c.WriterAccount.UID, ProbeAccount: c.ProbeAccount.Name, ProbeAccountUID: c.ProbeAccount.UID, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: "operator"}}}
	d, _ := hex.DecodeString(c.PodSpecDigest)
	copy(wp.PodSpecDigest[:], d)
	policy, binding, e := InitialWorkloadAdmission(wp)
	if e != nil {
		t.Fatal(e)
	}
	policy.TypeMeta = meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicy"}
	policy.UID = types.UID(ownerID(53))
	policy.Generation = 1
	policy.ResourceVersion = "1"
	policy.Status.ObservedGeneration = 1
	policy.Status.TypeChecking = &admission.TypeChecking{}
	binding.TypeMeta = meta.TypeMeta{APIVersion: "admissionregistration.k8s.io/v1", Kind: "ValidatingAdmissionPolicyBinding"}
	binding.UID = types.UID(ownerID(54))
	binding.ResourceVersion = "2"
	c.WorkloadGuard = contracts.OwnerDeploymentGuard{Name: wp.Name, PolicyUID: string(policy.UID), PolicyGeneration: 1, BindingUID: string(binding.UID), BindingResourceVersion: "2", Administrators: f.plan.Administrators}
	c.FleetGuard = contracts.OwnerDeploymentGuard{Name: f.plan.Workload.FleetGuard, Administrators: f.plan.Administrators}
	c.WitnessGuard = contracts.OwnerDeploymentGuard{Name: f.plan.Workload.WitnessGuard}
	raw, _ := json.Marshal(c)
	input := core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: c.Configuration, Namespace: c.Namespace.Name}, Immutable: ptr.To(true), Data: map[string]string{"deployment.json": string(raw)}}
	inputRaw, _ := json.Marshal(input)
	inputPath := "/api/v1/namespaces/" + c.Namespace.Name + "/configmaps/" + c.Configuration
	password := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(v, 32))) }
	material := contracts.InitialSQLMaterial{Format: contracts.InitialSQLMaterialFormat, InstallationID: c.InstallationID, RequestID: f.plan.RequestID, PreparationPassword: password("a"), AuditPassword: password("b"), ActivationPassword: password("c")}
	private, _ := json.Marshal(material)
	defer clear(private)
	secret := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: "initial-material", Namespace: f.plan.BootstrapNamespace.Name}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"material.json": private}}
	secretRaw, _ := json.Marshal(secret)
	defer clear(secretRaw)
	secretPath := "/api/v1/namespaces/bootstrap/secrets/initial-material"
	f.mu.Lock()
	f.store(inputPath, inputRaw)
	f.store(secretPath, secretRaw)
	out := &preparationBindingFixture{f: f, config: c, password: material, input: contracts.WorkerObjectReference{Name: c.Configuration, UID: f.objects[inputPath]["metadata"].(map[string]any)["uid"].(string)}, material: contracts.WorkerObjectReference{Name: secret.Name, UID: f.objects[secretPath]["metadata"].(map[string]any)["uid"].(string)}}
	prior := f.extra
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews" && r.Header.Get("Authorization") == "Bearer target-probe" {
			who := auth.SelfSubjectReview{}
			who.Status.UserInfo = auth.UserInfo{Username: "system:serviceaccount:" + c.Namespace.Name + ":" + c.ProbeAccount.Name, UID: c.ProbeAccount.UID, Groups: []string{"system:authenticated"}}
			permissionReply(w, who)
			return true
		}
		if r.URL.Path == "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/"+wp.Name {
			permissionReply(w, policy)
			return true
		}
		if r.URL.Path == "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/"+wp.Name {
			permissionReply(w, binding)
			return true
		}
		if r.URL.Path == inputPath && r.Method == "PUT" && r.URL.Query().Get("dryRun") == "All" {
			f.status(w, 403, meta.StatusReasonForbidden, "configmaps", "ValidatingAdmissionPolicy '"+wp.Name+"' with binding '"+wp.Name+"' denied request: "+initialWorkloadDenial)
			return true
		}
		if prior != nil {
			return prior(w, r)
		}
		return false
	}
	f.mu.Unlock()
	return out
}
func (f *preparationBindingFixture) binder(t *testing.T) *InitialPreparationCredentialBinder {
	t.Helper()
	p := f.f.preparer(t)
	ns := cfg.NamespaceRef{Name: f.config.Namespace.Name, UID: f.config.Namespace.UID}
	admin, e := NewPermissionClient(f.f.client, f.config.ClusterID, ns, f.f.clock)
	if e != nil {
		t.Fatal(e)
	}
	pc := rest.CopyConfig(f.f.client)
	pc.BearerToken = "target-probe"
	probe, e := NewPermissionClient(pc, f.config.ClusterID, ns, f.f.clock)
	if e != nil {
		t.Fatal(e)
	}
	b, e := NewInitialPreparationCredentialBinder(p, admin, probe, f.config, f.input.UID, f.material)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestInitialPreparationCredentialBindingKeepsOriginalInterval(t *testing.T) {
	for _, mode := range []string{"replay-after-expiry", "wrong-interval", "replacement-material", "different-material-pin", "different-startup"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparationBindingFixture(t)
			b := f.binder(t)
			m, original, until, e := b.Bind(context.Background())
			if e != nil || m != f.password || !time.Now().Before(until) || original.Material != f.material || original.NotAfter.Sub(original.NotBefore) != 15*time.Minute {
				t.Fatal("first original interval", e)
			}
			f.f.mu.Lock()
			switch mode {
			case "replay-after-expiry":
				f.f.shift = time.Hour
			case "wrong-interval":
				cm := f.f.objects["/api/v1/namespaces/bootstrap/configmaps/prepare"]
				var root contracts.InitialPreparationRoot
				_ = json.Unmarshal([]byte(cm["data"].(map[string]any)["root.json"].(string)), &root)
				root.Activation.Credentials.NotAfter = root.Activation.Credentials.NotAfter.Add(time.Second)
				v, _ := json.Marshal(root)
				cm["data"].(map[string]any)["root.json"] = string(v)
			case "replacement-material":
				f.f.objects["/api/v1/namespaces/bootstrap/secrets/initial-material"]["metadata"].(map[string]any)["uid"] = ownerID(70)
			case "different-material-pin":
				f.material.UID = ownerID(70)
			case "different-startup":
				f.config.IssuerEpoch = ownerID(70)
			}
			f.f.mu.Unlock()
			b = f.binder(t)
			m, replay, _, e := b.Bind(context.Background())
			if mode == "replay-after-expiry" {
				if e != nil || replay != original || m != f.password {
					t.Fatal("original binding renewed or unavailable for cleanup", e)
				}
			} else if e == nil || m.PreparationPassword != "" || !replay.NotBefore.IsZero() {
				t.Fatal("wrong original binding/material accepted")
			}
		})
	}
}
func TestInitialPreparationCredentialBindingLostReplyAndCASLoser(t *testing.T) {
	for _, mode := range []string{"lost-reply", "concurrent-CAS"} {
		t.Run(mode, func(t *testing.T) {
			f := newPreparationBindingFixture(t)
			var writes atomic.Int32
			ready := make(chan struct{})
			f.f.client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
				return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
					effect := r.Method == "PUT" && r.URL.Path == "/api/v1/namespaces/bootstrap/configmaps/prepare"
					if effect {
						raw, _ := io.ReadAll(r.Body)
						r.Body = io.NopCloser(bytes.NewReader(raw))
						var cm core.ConfigMap
						_ = json.Unmarshal(raw, &cm)
						var root contracts.InitialPreparationRoot
						_ = json.Unmarshal([]byte(cm.Data["root.json"]), &root)
						effect = root.Activation != nil && root.Activation.Credentials != nil
					}
					if effect && mode == "concurrent-CAS" {
						if writes.Add(1) == 2 {
							close(ready)
						}
						select {
						case <-ready:
						case <-r.Context().Done():
							return nil, r.Context().Err()
						}
					}
					response, e := next.RoundTrip(r)
					if effect && mode == "lost-reply" && writes.Add(1) == 1 && e == nil {
						response.Body.Close()
						raw, _ := json.Marshal(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonServiceUnavailable, Code: 503})
						response.StatusCode = 503
						response.Body = io.NopCloser(bytes.NewReader(raw))
						response.ContentLength = int64(len(raw))
					}
					return response, e
				})
			}
			if mode == "lost-reply" {
				if m, _, _, e := f.binder(t).Bind(context.Background()); e == nil || m.PreparationPassword != "" {
					t.Fatal("lost binding acknowledgement supplied material/effect authority")
				}
			} else {
				var group sync.WaitGroup
				errors := make(chan error, 2)
				first, second := f.binder(t), f.binder(t)
				for _, b := range []*InitialPreparationCredentialBinder{first, second} {
					group.Add(1)
					go func() { defer group.Done(); _, _, _, e := b.Bind(context.Background()); errors <- e }()
				}
				group.Wait()
				close(errors)
				winners := 0
				for e := range errors {
					if e == nil {
						winners++
					}
				}
				if winners != 1 || writes.Load() != 2 {
					t.Fatal("expected exactly one root CAS winner", winners, writes.Load())
				}
			}
			_, root, e := f.f.preparer(t).read(context.Background())
			if e != nil || root.Activation.Credentials == nil {
				t.Fatal("original accepted binding missing", e)
			}
			original := *root.Activation.Credentials
			f.f.mu.Lock()
			f.f.shift = 2 * time.Minute
			f.f.mu.Unlock()
			m, replay, _, e := f.binder(t).Bind(context.Background())
			if e != nil || m != f.password || replay != original {
				t.Fatal("retry renewed dates or replaced private pin", e)
			}
		})
	}
}
