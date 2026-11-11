package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

// Read the operator example itself on each use. This intentionally supplies no
// native endpoint, identity, credential or generated installation identifier.
type helmContextTrialSettings struct {
	Fleet  contracts.InitialBootstrapFleet
	Public *contracts.InstallerPublicSettings
}

func helmContextTrialProfile(t *testing.T) helmContextTrialSettings {
	t.Helper()
	raw, err := os.ReadFile("../../examples/helm/context-trial-profile.yaml")
	if err != nil {
		t.Fatal("canonical context trial profile", err)
	}
	var document struct {
		Bootstrap struct {
			Fleet        contracts.InitialBootstrapFleet `json:"fleet"`
			Continuation contracts.InstallerContinuation `json:"continuation"`
		} `json:"bootstrap"`
	}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal("decode canonical context trial profile", err)
	}
	p := document.Bootstrap.Continuation.Public
	if p == nil || p.Capacity == nil || p.Capacity.PoolSpec == nil || p.Capacity.PolicySpec == nil || p.Federation == nil || p.RetentionBaseline == nil {
		t.Fatal("canonical context trial lacks its complete declared profile")
	}
	return helmContextTrialSettings{Fleet: document.Bootstrap.Fleet, Public: p}
}

// The old fixture's exact budget choices, supplied before generated identities
// exist. The product fills the original hub cluster ID and creates the sources.
func installerDeclaredCapacitySpecs() (*wire.EvidenceStoragePoolSpec, *wire.EvidenceBudgetPolicySpec) {
	amount := func(b, o int64) wire.CapacityAmount { return wire.CapacityAmount{Bytes: b, Objects: o} }
	systemObjects, burstObjects := installedCapacityObjectPartitions()
	pool := &wire.EvidenceStoragePoolSpec{StorageProfileRef: "dedicated", Capacity: amount(137438953472, installedPoolCapacityObjects()),
		SafetyHeadroom: amount(17179869184, 10000), SystemReserve: amount(8589934592, systemObjects), SharedBurst: amount(42949672960, burstObjects),
		ProtectedAllocations: []wire.CapacityProtectedAllocation{{BudgetPolicyRef: "applications", WorkloadSlots: 4, ProtectedPerWorkload: amount(17179869184, 10000)}},
		Upload:               wire.CapacityUpload{BytesPerSecond: 134217728, BurstBytes: 16777216}, MaxUploadRequestsPerSecond: 100, CapacityAssurance: "qualifiedReservedBackend"}
	policy := &wire.EvidenceBudgetPolicySpec{PoolRef: "capacity", Scope: wire.CapacityPolicyScope{NamespaceSelector: wire.Selector{MatchLabels: map[string]string{"team": "applications"}}},
		NamespaceEnvelope: wire.CapacityNamespaceEnvelope{MaxWorkloadAccounts: 4, MaxStoredBytes: 111669149696, MaxObjects: 80000},
		Workload: wire.CapacityWorkloadLimits{Protected: amount(17179869184, 10000), HardLimit: amount(34359738368, 20000), ContextReserve: amount(1073741824, 1000),
			Dump:                   wire.CapacityDumpLimits{Burst: 1, MinimumIntervalSeconds: 900, MaxStartsPerRollingHour: 2, MaxInputBytesPerRollingHour: 4294967296},
			MaxConcurrentExpensive: 1, MaxQueuedExpensive: 1, MaxQueueAgeSeconds: 30, Upload: wire.CapacityUpload{BytesPerSecond: 33554432, BurstBytes: 4194304},
			MaxUploadRequestsPerSecond: 20, MaxSpoolBytes: 2147483648, OnFull: "RejectNewExpensive"},
		Node: wire.CapacityNodeLimits{MaxConcurrentExpensive: 2, MaxQueuedExpensive: 10, Upload: wire.CapacityUpload{BytesPerSecond: 67108864, BurstBytes: 8388608},
			MaxSpoolBytes: 4294967296, ImpactProfileRef: "standard-node", UnhealthySamples: 3, SampleIntervalSeconds: 5, RecoveryHealthySeconds: 60}}
	return pool, policy
}

func installerContinuationOperatorConfig(original *rest.Config, desired contracts.InitialBootstrap) *rest.Config {
	if os.Getenv("ASSERVAT_HELM_CONTEXT_NATIVE") == "1" {
		return rest.CopyConfig(original)
	}
	return installedUnifiedRunnerConfig(original, desired)
}

// Synthetic certificate generation represents the external operator's input.
// This writes only local private files; the actual provider CLI/inbox and
// continuation create the target serving Secrets under product guards.
func installerOperatorServingTLSArgs(t *testing.T, directory string, plan contracts.InstallerServingTLSPlan) (args []string, federationCA, keyServiceCA []byte) {
	t.Helper()
	for i, selection := range []struct{ prefix, host string }{{"federation", plan.FederationServerName}, {"key-service", plan.KeyServiceServerName}} {
		if selection.host == "" {
			continue
		}
		ca, cert, key := syntheticServingPair(t, selection.host)
		for _, file := range []struct {
			flag string
			data []byte
		}{{"certificate", cert}, {"key", key}, {"ca", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})}} {
			path := filepath.Join(directory, selection.prefix+"-tls-"+file.flag+".pem")
			if err := os.WriteFile(path, file.data, 0600); err != nil {
				t.Fatal("operator serving input", err)
			}
			args = append(args, "--"+selection.prefix+"-tls-"+file.flag, path)
		}
		clear(key)
		if i == 0 {
			federationCA = ca
		} else {
			keyServiceCA = ca
		}
	}
	return
}

func TestInstallerHelmManagementRetainsOriginalOperator(t *testing.T) {
	t.Setenv("ASSERVAT_HELM_CONTEXT_NATIVE", "1")
	original := &rest.Config{Host: "https://owned.example.test", BearerToken: "synthetic-original-operator"}
	got := installerContinuationOperatorConfig(original, contracts.InitialBootstrap{BootstrapNamespace: "trusted-bootstrap", Name: "install"})
	if got == original || got.Host != original.Host || got.BearerToken != original.BearerToken || got.Impersonate.UserName != "" || len(got.Impersonate.Groups) != 0 {
		t.Fatal("Helm management substituted the original operator")
	}
}

func TestInstallerOperatorTLSFilesMatchProductionValidator(t *testing.T) {
	plan := contracts.InstallerServingTLSPlan{FederationServerName: "federation.synthetic.invalid", KeyServiceServerName: "127.0.0.1"}
	args, federationCA, keyCA := installerOperatorServingTLSArgs(t, t.TempDir(), plan)
	if len(args) != 12 {
		t.Fatal("operator CLI bundle flags", len(args))
	}
	for offset, host := range []string{plan.FederationServerName, plan.KeyServiceServerName} {
		base := offset * 6
		cert, e1 := os.ReadFile(args[base+1])
		key, e2 := os.ReadFile(args[base+3])
		ca, e3 := os.ReadFile(args[base+5])
		if e1 != nil || e2 != nil || e3 != nil {
			t.Fatal(e1, e2, e3)
		}
		roots, err := kube.ValidateInstallerServingTLS(cert, key, ca, host, time.Now())
		clear(key)
		want := federationCA
		if offset == 1 {
			want = keyCA
		}
		if err != nil || len(roots) != 1 || !bytes.Equal(roots[0], want) {
			t.Fatal("operator bundle differs from expected root", err)
		}
		if stat, err := os.Stat(args[base+3]); err != nil || stat.Mode().Perm() != 0600 {
			t.Fatal("operator key permissions", err)
		}
	}
}

func TestInstallerDeclaredCapacityPassesProductPreflight(t *testing.T) {
	// Returning an unavailable first namespace read proves that the complete
	// native profile passed the product's schema/budget/backend/scope checks;
	// this synthetic endpoint supplies no namespace or accepted authority.
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/hub" {
			t.Error("preflight reached an unexpected effect", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	config := &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	profile := nativeCapacityProfile()
	err := kube.EnsureInstallerCapacityObjects(context.Background(), config, cfg.NamespaceRef{Name: "hub", UID: custodyID()}, custodyID(), custodyID(), *profile)
	if !errors.Is(err, cfg.ErrUnavailable) || calls != 1 || profile.PolicySpec.Scope.ClusterID != "" {
		t.Fatal("declared native profile failed before its actual current-source check", err, calls)
	}
}

func TestInstallerHelmRegionalPolicyUsesDeclaredCapacity(t *testing.T) {
	t.Setenv("ASSERVAT_HELM_CONTEXT_NATIVE", "1")
	profile := helmContextTrialProfile(t).Public.Capacity
	cluster := custodyID()
	expected := *profile.PolicySpec
	expected.Scope.ClusterID = cluster
	expected.NamespaceEnvelope = wire.CapacityNamespaceEnvelope{MaxWorkloadAccounts: 1, MaxStoredBytes: expected.Workload.HardLimit.Bytes, MaxObjects: expected.Workload.HardLimit.Objects}
	expectedPool := *profile.PoolSpec
	expectedPool.ProtectedAllocations = append(append([]wire.CapacityProtectedAllocation{}, expectedPool.ProtectedAllocations...), wire.CapacityProtectedAllocation{BudgetPolicyRef: "trial-region", WorkloadSlots: 1, ProtectedPerWorkload: expected.Workload.Protected})
	base := "/apis/asservat.io/v1alpha1/namespaces/hub/"
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base+"evidencebudgetpolicies":
			var got struct {
				Metadata struct{ Name string }         `json:"metadata"`
				Spec     wire.EvidenceBudgetPolicySpec `json:"spec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got.Metadata.Name != "trial-region" || !reflect.DeepEqual(got.Spec, expected) {
				t.Error("operator regional policy replaced declared scope, reserve or limits", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{}`))
		case r.Method == http.MethodGet && r.URL.Path == base+"evidencestoragepools/"+profile.Pool:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "asservat.io/v1alpha1", "kind": "EvidenceStoragePool", "metadata": map[string]string{"name": profile.Pool, "resourceVersion": "7"}, "spec": profile.PoolSpec})
		case r.Method == http.MethodPut && r.URL.Path == base+"evidencestoragepools/"+profile.Pool:
			var got struct {
				Metadata struct{ ResourceVersion string } `json:"metadata"`
				Spec     wire.EvidenceStoragePoolSpec     `json:"spec"`
			}
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got.Metadata.ResourceVersion != "7" || !reflect.DeepEqual(got.Spec, expectedPool) {
				t.Error("regional slot changed declared backing or lost original CAS", err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Error("unexpected regional operator request", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	api, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}})
	if err != nil {
		t.Fatal(err)
	}
	newRegionalBudget(t, context.Background(), api, "hub", "https://issuer.example.test", cluster, 1).addPolicy()
	if calls != 3 {
		t.Fatal("regional declared policy/slot did not use its three bounded operator calls", calls)
	}
}
