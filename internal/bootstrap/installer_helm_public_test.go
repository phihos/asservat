package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	wire "asservat.local/asservat/api/v1alpha1"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Actual Helm output reaches the actual closed installer decoder and capacity
// compilers. All source identities/footprints are explicitly synthetic; this
// proves packaging compatibility, not native authority or backend capacity.
func TestHelmContextContinuationUsesActualInstallerDTO(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("Helm is required for the chart producer/consumer check")
	}
	raw, err := os.ReadFile("testdata/helm_context_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]any
	if json.Unmarshal(raw, &public) != nil {
		t.Fatal("invalid public test input")
	}
	var expected contracts.InstallerPublicSettings
	if json.Unmarshal(raw, &expected) != nil {
		t.Fatal("test input differs from actual installer DTO")
	}
	public["origin"], public["issuer"], public["clientID"] = "https://asservat.example", "https://id.example/realms/org", "console"
	public["clients"] = []map[string]string{{"id": "console", "kind": "human"}}
	public["eligibleGroups"] = []string{"stable-group-id"}
	values := map[string]any{"bootstrap": map[string]any{
		"administrators": []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator@example.org"}},
		"enabled":        true, "image": "registry.example/asservat@sha256:" + strings.Repeat("a", 64), "targetNamespace": "asservat-runtime",
		"secrets":      map[string]string{"producer": "operator-producer", "schema": "operator-schema", "retirement": "operator-retirement"},
		"postgres":     map[string]string{"host": "postgres.example", "rootsPEM": "PUBLIC-CA"},
		"auditStore":   map[string]string{"endpoint": "https://store.example", "region": "region-a", "bucket": "audit", "rootsPEM": "PUBLIC-CA"},
		"keyService":   map[string]string{"endpoint": "https://bao.example", "rootsPEM": "PUBLIC-CA"},
		"fleet":        map[string]any{"issuer": "https://id.example/realms/org", "clients": []string{"console"}, "subjects": []map[string]string{{"id": "installer", "kind": "human"}}},
		"continuation": map[string]any{"enabled": true, "workerProvider": map[string]string{"authMount": "worker-k8s", "authMountAccessor": "auth_kubernetes_1"}, "ownerProvider": map[string]string{"authMount": "owner-k8s", "authMountAccessor": "auth_kubernetes_2"}, "ownerIssuerRootsPEM": "-----BEGIN CERTIFICATE-----\nPUBLIC\n-----END CERTIFICATE-----\n", "public": public},
	}}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "public-values.json")
	if os.WriteFile(file, encoded, 0600) != nil {
		t.Fatal("write public values")
	}
	ctx, end := context.WithTimeout(t.Context(), 30*time.Second)
	defer end()
	output, err := exec.CommandContext(ctx, helm, "template", "asservat", "../../charts/asservat", "--namespace", "trusted-bootstrap", "--kube-version", "1.37.0", "-f", file).CombinedOutput()
	if err != nil {
		t.Fatalf("actual chart render: %v\n%s", err, output)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	var projection []byte
	var initial []byte
	for {
		var resource struct {
			Kind string
			Data map[string]string
		}
		if err := decoder.Decode(&resource); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if body := resource.Data["bootstrap.json"]; body != "" {
			initial = []byte(body)
		}
		if body := resource.Data[contracts.InstallerContinuationFile]; body != "" {
			if projection != nil {
				t.Fatal("duplicate continuation producer")
			}
			projection = []byte(body)
		}
	}
	initialInput, err := contracts.DecodeInitialBootstrapInput(bytes.NewReader(initial))
	if err != nil {
		t.Fatal("rendered initial bootstrap rejected by actual decoder", err)
	}
	if !reflect.DeepEqual(initialInput.Administrators, []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator@example.org"}}) {
		t.Fatal("chart dropped explicit existing guard administrator")
	}
	got, err := contracts.DecodeInstallerContinuation(bytes.NewReader(projection))
	if err != nil || got.Public == nil {
		t.Fatal("rendered continuation rejected by actual decoder", err)
	}
	p := got.Public
	if !reflect.DeepEqual(p.Capacity, expected.Capacity) || !reflect.DeepEqual(p.Federation, expected.Federation) || !reflect.DeepEqual(p.Promotion, expected.Promotion) || !reflect.DeepEqual(p.RetentionBaseline, expected.RetentionBaseline) || !reflect.DeepEqual(p.ProcessingOperators, expected.ProcessingOperators) {
		t.Fatal("chart changed or omitted a typed public context input")
	}
	d := capacityDerivedFixture()
	if _, err := buildCapacityQualification(*p.Capacity, d, sequentialIDs()); err != nil {
		t.Fatal("rendered capacity rejected by actual consumer", err)
	}
	if _, err := buildConnectorBacking(p.Federation.Connector, p.Capacity.Backup, d.Root, d.Installation, d.AccountVersion, d.Root, time.Now()); err != nil {
		t.Fatal("rendered connector backing rejected by actual consumer", err)
	}
}

// Exact proposed reference profile, tested through complete root/connector
// arithmetic. It is a configured envelope, never measured backend authority.
func TestHelmContextTrialReferenceProfile(t *testing.T) {
	path := "../../examples/helm/context-trial-profile.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]any
	if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096).Decode(&values); err != nil {
		t.Fatal(err)
	}
	var expected struct {
		Bootstrap struct {
			Continuation struct {
				Public contracts.InstallerPublicSettings `json:"public"`
			} `json:"continuation"`
		} `json:"bootstrap"`
	}
	if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096).Decode(&expected); err != nil {
		t.Fatal(err)
	}
	// Site values supply real syntactically valid roots and stable identities.
	// No limit, footprint, envelope or connector choice is overridden here.
	_, _, roots := serverCertificate(t)
	b := values["bootstrap"].(map[string]any)
	b["administrators"] = []contracts.OwnerDeploymentActor{{Kind: "User", Name: "operator@example.org"}}
	b["image"] = "registry.example/asservat@sha256:" + strings.Repeat("a", 64)
	b["kubernetes"] = map[string]any{"endpoint": "https://kubernetes.default.svc", "rootsPEM": roots}
	postgres := b["postgres"].(map[string]any)
	postgres["host"], postgres["rootsPEM"] = "postgres.example", roots
	b["auditStore"] = map[string]any{"endpoint": "https://store.example", "region": "region-a", "bucket": "audit", "rootsPEM": roots}
	key := b["keyService"].(map[string]any)
	key["endpoint"], key["rootsPEM"] = "https://bao.example", roots
	fleet := b["fleet"].(map[string]any)
	fleet["issuer"], fleet["clients"], fleet["groups"] = "https://id.example/realms/org", []string{"console"}, []string{"stable-group-id"}
	c := b["continuation"].(map[string]any)
	c["workerProvider"], c["ownerProvider"] = map[string]string{"authMount": "worker-k8s", "authMountAccessor": "worker-accessor"}, map[string]string{"authMount": "owner-k8s", "authMountAccessor": "owner-accessor"}
	c["ownerIssuerRootsPEM"] = roots
	public := c["public"].(map[string]any)
	public["origin"], public["issuer"], public["clientID"] = "https://asservat.example", "https://id.example/realms/org", "console"
	public["clients"] = []map[string]string{{"id": "console", "kind": "human"}}
	public["eligibleGroups"] = []string{"stable-group-id"}
	public["processingOperators"] = []contracts.ProcessingOperator{{ClientID: "console", Issuer: "https://id.example/realms/org", Kind: "Group", ID: "stable-group-id"}}
	f := public["federation"].(map[string]any)
	f["connectorPKIMount"], f["connectorIssuerRootsPEM"] = "connector-pki", roots
	f["endpoint"], f["serverName"] = "https://federation.example:31446", "federation.example"
	f["ownerAddress"], f["ownerOperationAddress"], f["keyServiceEndpoint"] = "owner.example:31447", "owner.example:31449", "https://keys.example:31448"
	f["evidenceStore"] = map[string]any{"endpoint": "https://store.example", "region": "region-a", "bucket": "evidence", "rootsPEM": roots}
	promotion := public["promotion"].(map[string]any)
	promotion["browserAudience"], promotion["providerRootsPEM"] = "asservat-api", roots
	got := renderReferenceContinuation(t, values)
	p := got.Public
	if p == nil || p.Capacity == nil || p.Federation == nil || p.Capacity.PoolSpec == nil || p.Capacity.PolicySpec == nil {
		t.Fatal("reference profile omits declared capacity/connector")
	}
	if !reflect.DeepEqual(p.Capacity, expected.Bootstrap.Continuation.Public.Capacity) || p.Federation.Connector != expected.Bootstrap.Continuation.Public.Federation.Connector {
		t.Fatal("actual Helm changed exact reference profile capacity or connector")
	}
	d := capacityDerivedFixture()
	d.SharedQueries = true
	d.NamespaceGuards[0].Keys = append([]string{}, p.Capacity.NamespaceKeys...)
	q, err := buildCapacityQualification(*p.Capacity, d, sequentialIDs())
	if err != nil {
		t.Fatal("exact reference promoted capacity qualification (shared queries enabled)", err)
	}
	amount := func(v wire.CapacityAmount) capacityapp.BudgetAmount {
		return capacityapp.BudgetAmount{Bytes: v.Bytes, Objects: v.Objects}
	}
	pool, policy := p.Capacity.PoolSpec, p.Capacity.PolicySpec
	poolBudget := capacityapp.PoolBudgetInput{Name: p.Capacity.Pool, Capacity: amount(pool.Capacity), Safety: amount(pool.SafetyHeadroom), System: amount(pool.SystemReserve), Burst: amount(pool.SharedBurst)}
	for _, allocation := range pool.ProtectedAllocations {
		poolBudget.Slots = append(poolBudget.Slots, capacityapp.ProtectedSlotInput{Policy: allocation.BudgetPolicyRef, Workloads: allocation.WorkloadSlots, Protected: amount(allocation.ProtectedPerWorkload)})
	}
	policyBudget := capacityapp.PolicyBudgetInput{Name: p.Capacity.Policy, Pool: policy.PoolRef, Cluster: d.NamespaceGuards[0].ClusterID, Protected: amount(policy.Workload.Protected), Hard: amount(policy.Workload.HardLimit), Context: amount(policy.Workload.ContextReserve), NamespaceMaximum: capacityapp.BudgetAmount{Bytes: policy.NamespaceEnvelope.MaxStoredBytes, Objects: policy.NamespaceEnvelope.MaxObjects}, NamespaceAccounts: policy.NamespaceEnvelope.MaxWorkloadAccounts}
	budget, err := capacityapp.CompileProtectedPool(poolBudget, []capacityapp.PolicyBudgetInput{policyBudget})
	if err != nil || budget.AccountSlots() != p.Capacity.Accounts {
		t.Fatal("exact reference pool/policy conservation", err)
	}
	plan, err := capacityapp.CompileQualifiedRootBacking(q, capacityapp.ProtectedPoolPlan{Format: capacityapp.ProtectedPoolPlanFormat, UID: d.SystemPoolUID, StorageProfile: pool.StorageProfileRef, Capacity: amount(pool.Capacity), System: amount(pool.SystemReserve)})
	if err != nil {
		t.Fatal("exact reference complete root/backend envelope", err)
	}
	connector, err := buildConnectorBacking(p.Federation.Connector, p.Capacity.Backup, d.Root, d.Installation, d.AccountVersion, d.Root, d.Now)
	if err != nil {
		t.Fatal("exact reference connector backing", err)
	}
	if p.Capacity.Lanes.Normal.Accounts != 4 || p.Capacity.Lanes.Normal.Records != 128 {
		t.Fatal("reference lowered per-request normal headroom")
	}
	t.Logf("configured reference root totals: %+v; connector source backup=%d WAL=%d processrun=%ds", plan.Totals(), connector.SourceBackupReservedBytes, connector.SourceWALReservedBytes, connector.ProcessRunSeconds())
}

func renderReferenceContinuation(t *testing.T, values map[string]any) contracts.InstallerContinuation {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("Helm required for actual reference producer/consumer")
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "reference-values.json")
	if err := os.WriteFile(file, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, end := context.WithTimeout(t.Context(), 30*time.Second)
	defer end()
	output, err := exec.CommandContext(ctx, "helm", "template", "asservat", "../../charts/asservat", "--namespace", "trusted-bootstrap", "--kube-version", "1.37.0", "-f", file).CombinedOutput()
	if err != nil {
		t.Fatalf("exact reference actual Helm render: %v\n%s", err, output)
	}
	decoder := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	var got *contracts.InstallerContinuation
	var initial *contracts.InitialBootstrapInput
	for {
		var resource struct {
			Kind string
			Data map[string]string
		}
		if err := decoder.Decode(&resource); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if body := resource.Data["bootstrap.json"]; body != "" {
			decoded, err := contracts.DecodeInitialBootstrapInput(strings.NewReader(body))
			if err != nil || initial != nil {
				t.Fatal("reference initial closed input", err)
			}
			initial = &decoded
		}
		if body := resource.Data[contracts.InstallerContinuationFile]; body != "" {
			decoded, err := contracts.DecodeInstallerContinuation(strings.NewReader(body))
			if err != nil || got != nil {
				t.Fatal("reference continuation closed input", err)
			}
			got = &decoded
		}
	}
	if initial == nil || got == nil {
		t.Fatal("reference chart omitted actual installer inputs")
	}
	return *got
}
