package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
