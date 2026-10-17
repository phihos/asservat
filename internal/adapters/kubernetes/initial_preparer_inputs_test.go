package kubernetes

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

func finalInputFixture(t *testing.T, mode string) (*preparerFixture, *InitialPreparer) {
	t.Helper()
	f, p := activationPreparerFixture(t)
	if _, e := p.PrepareGatedPod(context.Background()); e != nil {
		t.Fatal(e)
	}
	var fleet contracts.FleetSettings
	raw, e := os.ReadFile("../../../examples/fleet-settings.json")
	if e != nil || json.Unmarshal(raw, &fleet) != nil {
		t.Fatal("synthetic fleet", e)
	}
	fleet.InstallationID = f.plan.InstallationID
	services := contracts.InitialPreparationServices{Format: contracts.InitialPreparationServicesFormat, Fleet: fleet, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: f.server.URL, Roots: [][]byte{f.server.Certificate().Raw}}, Postgres: contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", Roots: [][]byte{f.server.Certificate().Raw}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Roots: [][]byte{f.server.Certificate().Raw}, Region: "test", Bucket: "audit"}, KeyService: contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", Roots: [][]byte{f.server.Certificate().Raw}, AuditMount: "transit", AuditKey: "audit"}}
	fleetRaw, _ := json.Marshal(services.Fleet)
	var parsed contracts.FleetSettings
	if _, e := decodePermissionSpec(fleetRaw, p.protection.observer.validator.fleetSchema, &parsed); e != nil {
		t.Fatal("synthetic fleet rejected", e)
	}
	if _, e := p.checkedServices(services); e != nil {
		t.Fatalf("synthetic public services rejected: endpoint=%s API=%s enabled=%v err=%v", services.Kubernetes.Endpoint, p.creator.api.Get().URL().String(), p.ActivationPreparationEnabled(), e)
	}
	f.config.Services = &services
	f.mu.Lock()
	f.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "POST" {
			return false
		}
		if !strings.HasSuffix(r.URL.Path, "/configmaps") && !strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicies") && !strings.HasSuffix(r.URL.Path, "/validatingadmissionpolicybindings") {
			return false
		}
		raw, e := io.ReadAll(r.Body)
		if e != nil {
			t.Error(e)
			return true
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			t.Error("synthetic body")
			return true
		}
		name := value["metadata"].(map[string]any)["name"].(string)
		full := r.URL.Path + "/" + name
		f.posts[full]++
		if mode == "lost-before" && name == f.plan.Workload.Witness {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"ServiceUnavailable","code":503}`))
			return true
		}
		f.store(full, raw)
		if value["kind"] == "ValidatingAdmissionPolicy" {
			f.objects[full]["metadata"].(map[string]any)["generation"] = float64(1)
			if mode != "policy-pending" {
				f.objects[full]["status"] = map[string]any{"observedGeneration": float64(1), "typeChecking": map[string]any{}}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if mode == "lost-after" && name == f.plan.Workload.Witness {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Status","status":"Failure","reason":"ServiceUnavailable","code":503}`))
			return true
		}
		w.WriteHeader(201)
		permissionReply(w, f.objects[full])
		return true
	}
	f.mu.Unlock()
	p = f.preparer(t)
	t.Cleanup(p.Close)
	return f, p
}
func TestInitialPreparationFinalInputsUseActualOriginalIdentities(t *testing.T) {
	for _, mode := range []string{"healthy", "lost-after"} {
		t.Run(mode, func(t *testing.T) {
			f, p := finalInputFixture(t, mode)
			root, e := p.PrepareFinalInputs(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if len(root.Activation.Inputs.Creates) != 9 {
				t.Fatal("public inventory not complete")
			}
			raw, e := p.creator.raw(context.Background(), "/api/v1/namespaces/"+f.plan.Workload.Namespace+"/configmaps/"+f.plan.Workload.Configuration, nil)
			if e != nil {
				t.Fatal(e)
			}
			var cm core.ConfigMap
			if json.Unmarshal(raw, &cm) != nil {
				t.Fatal("final inputs")
			}
			c, e := contracts.DecodeInitialInstaller(strings.NewReader(cm.Data["deployment.json"]))
			if e != nil || c.Pod.UID != root.Activation.Pod.Receipt.UID || c.PodSpecDigest != root.Activation.Pod.SpecDigest || c.Witness.UID != root.Activation.Inputs.Creates[0].Receipt.UID || c.FleetSource.UID != root.Activation.Inputs.Creates[1].Receipt.UID || c.WorkloadGuard.PolicyUID != root.Activation.Inputs.Creates[2].Receipt.UID || c.WorkloadGuard.BindingUID != root.Activation.Inputs.Creates[3].Receipt.UID || c.WorkloadGuard.BindingResourceVersion != root.Activation.Inputs.Creates[3].Receipt.ResourceVersion {
				t.Fatal("startup did not retain actual original identities", e)
			}
			before := map[string]int{}
			f.mu.Lock()
			for k, v := range f.posts {
				before[k] = v
			}
			f.mu.Unlock()
			replay, e := f.preparer(t).PrepareFinalInputs(context.Background())
			if e != nil || !equalJSON(root, replay) {
				t.Fatal("public-input replay changed original state", e)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if !equalJSON(before, f.posts) {
				t.Fatal("replay issued another CREATE")
			}
		})
	}
}
func TestInitialPreparationPublicInputUnknownDoesNotRepeat(t *testing.T) {
	f, p := finalInputFixture(t, "lost-before")
	if _, e := p.PrepareFinalInputs(context.Background()); e == nil {
		t.Fatal("unknown missing public effect reported complete")
	}
	if _, e := f.preparer(t).PrepareFinalInputs(context.Background()); e == nil {
		t.Fatal("pending public effect retried")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts["/api/v1/namespaces/"+f.plan.Workload.Namespace+"/configmaps/"+f.plan.Workload.Witness] != 1 {
		t.Fatal("unknown witness CREATE was repeated")
	}
}
func TestInitialPreparationPublicInputChangedServiceIntentDenied(t *testing.T) {
	f, p := finalInputFixture(t, "healthy")
	root, e := p.PrepareFinalInputs(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	f.config.Services.Fleet.IssuerEpoch = ownerID(901)
	if _, e = f.preparer(t).PrepareFinalInputs(context.Background()); e == nil {
		t.Fatal("accepted replacement service intent")
	}
	_, after, e := p.read(context.Background())
	if e != nil || !equalJSON(root, after) {
		t.Fatal("changed intent rewrote root", e)
	}
}

func TestInitialPreparationPendingPolicyDoesNotAdmitBinding(t *testing.T) {
	f, p := finalInputFixture(t, "policy-pending")
	if _, e := p.PrepareFinalInputs(context.Background()); e == nil {
		t.Fatal("uncompiled policy advanced")
	}
	policyPath := "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/" + f.plan.Workload.WorkloadGuard
	bindingPath := "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + f.plan.Workload.WorkloadGuard
	f.mu.Lock()
	if f.posts[policyPath] != 1 || f.posts[bindingPath] != 0 {
		t.Error("binding admitted before exact policy compilation")
	}
	f.objects[policyPath]["status"] = map[string]any{"observedGeneration": float64(1), "typeChecking": map[string]any{}}
	f.mu.Unlock()
	// One bounded next call resolves only that existing policy receipt. It does
	// not repeat the original CREATE or assume the later policies are ready.
	root, e := p.EnsureNextPublicInput(context.Background())
	if e != nil || len(root.Activation.Inputs.Creates) != 3 || root.Activation.Inputs.Creates[2].Receipt == nil {
		t.Fatal("compiled original policy not recovered", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts[policyPath] != 1 || f.posts[bindingPath] != 0 {
		t.Fatal("observation manufactured another policy or binding request")
	}
}

func TestInitialPreparationPublicInputReplayRejectsChangedNativeIdentity(t *testing.T) {
	for _, mode := range []string{"missing", "replacement", "binding-version"} {
		t.Run(mode, func(t *testing.T) {
			f, p := finalInputFixture(t, "healthy")
			if _, e := p.PrepareFinalInputs(context.Background()); e != nil {
				t.Fatal(e)
			}
			f.mu.Lock()
			var path string
			if mode == "binding-version" {
				path = "/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/" + f.plan.Workload.WorkloadGuard
			} else {
				path = "/api/v1/namespaces/" + f.plan.Workload.Namespace + "/configmaps/" + f.plan.Workload.Witness
			}
			switch mode {
			case "missing":
				delete(f.objects, path)
			case "replacement":
				f.objects[path]["metadata"].(map[string]any)["uid"] = "33333333-3333-4333-8333-333333333333"
			case "binding-version":
				f.objects[path]["metadata"].(map[string]any)["resourceVersion"] = "98765"
			}
			before := map[string]int{}
			for k, v := range f.posts {
				before[k] = v
			}
			f.mu.Unlock()
			replay := f.preparer(t)
			defer replay.Close()
			if _, e := replay.PrepareFinalInputs(context.Background()); e == nil {
				t.Fatal("changed known input accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if !equalJSON(before, f.posts) {
				t.Fatal("changed known input caused another CREATE")
			}
		})
	}
}

func TestInitialPreparationRejectsStaticProviderErrorsBeforeEffects(t *testing.T) {
	for _, mode := range []string{"sql-port", "sql-host", "sql-pool", "sql-roots", "audit-roots", "audit-path", "key-mount", "key-roots", "invalid-root", "pem-root", "expired-root", "duplicate-root", "endpoint-port"} {
		t.Run(mode, func(t *testing.T) {
			f, p := finalInputFixture(t, "healthy")
			raw, _ := json.Marshal(f.config)
			var c contracts.InitialPreparer
			if json.Unmarshal(raw, &c) != nil {
				t.Fatal("fixture copy")
			}
			switch mode {
			case "sql-port":
				c.Services.Postgres.Port = 0
			case "sql-host":
				c.Services.Postgres.Host = "db..invalid"
			case "sql-pool":
				c.Services.Postgres.MaxConnections = 5
			case "sql-roots":
				c.Services.Postgres.Roots = nil
			case "audit-roots":
				c.Services.AuditStore.Roots = nil
			case "audit-path":
				c.Services.AuditStore.Endpoint = "https://audit.example.test/private"
			case "key-mount":
				c.Services.KeyService.AuditMount = "../root"
			case "key-roots":
				c.Services.KeyService.Roots = nil
			case "invalid-root":
				c.Services.Kubernetes.Roots = [][]byte{[]byte("not a certificate")}
			case "pem-root":
				c.Services.Kubernetes.Roots = [][]byte{f.client.CAData}
			case "expired-root":
				c.Services.Kubernetes.Roots = [][]byte{ownerConfigurationTestRoot(t, time.Now().Add(-2*time.Hour))}
			case "duplicate-root":
				c.Services.Kubernetes.Roots = append(c.Services.Kubernetes.Roots, c.Services.Kubernetes.Roots[0])
			case "endpoint-port":
				c.Services.AuditStore.Endpoint = "https://audit.example.test:99999"
			}
			f.mu.Lock()
			before := map[string]int{}
			for k, v := range f.posts {
				before[k] = v
			}
			f.mu.Unlock()
			bad, e := NewInitialPreparer(f.client, p.protection.observer, p.protection.probe, c)
			if e == nil {
				bad.Close()
				t.Fatal("invalid public provider input consumed preparation")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if !equalJSON(before, f.posts) {
				t.Fatal("provider typo caused an irreversible effect")
			}
		})
	}
}
