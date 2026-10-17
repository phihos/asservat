package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type ownerProjectionNoEffects struct{ calls int }

func (v *ownerProjectionNoEffects) VerifyOwnerIdentityRoles(context.Context) (contracts.OwnerIdentityRoleSnapshot, error) {
	v.calls++
	return contracts.OwnerIdentityRoleSnapshot{}, cfg.ErrUnavailable
}

// Only static original input comparisons are exercised here. These synthetic
// structs cannot supply the concrete root's native/SQL proofs or run an effect.
func ownerProjectionOriginalInputFixture(t *testing.T) (*OwnerIdentityRoleRoot, contracts.OwnerDeployment, contracts.InitialRuntimeResourceState) {
	t.Helper()
	resources, state, in, a := ownerIdentityActivationFixture(t)
	inventory, e := resources.inventory(state)
	if e != nil {
		t.Fatal(e)
	}
	roots := [][]byte{ownerConfigurationTestRoot(t, time.Now())}
	original := &resources.initial
	original.Kubernetes = contracts.OwnerProviderEndpoint{Endpoint: "https://api.example.test", Roots: roots}
	original.Postgres = contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 2}
	original.AuditStore = contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Roots: roots, Region: "test", Bucket: "audit"}
	original.KeyService = contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", Roots: roots, AuditMount: "transit", AuditKey: "audit"}
	plan := inventory.BridgeAdministration.Owner
	// Include each optional guard arm explicitly; removing any one must fail.
	plan.APIContextStarts = &cfg.OwnerAPIContextStarts{CapacityAccount: "capacity", CapacityAccountUID: ownerID(7100), ExecutionAccount: "execution", ExecutionAccountUID: ownerID(7101)}
	plan.CapacityProbe = &cfg.OwnerCapacityProbe{ServiceAccount: inventory.WorkerAccount.Name, ServiceAccountUID: inventory.WorkerAccount.UID}
	guard := &OwnerWorkloadProtection{plan: plan, pin: GuardPin{PolicyUID: in.WorkloadGuard.PolicyUID, PolicyGeneration: in.WorkloadGuard.PolicyGeneration, BindingUID: in.WorkloadGuard.BindingUID, BindingResourceVersion: in.WorkloadGuard.BindingResourceVersion}, digest: artifact.Digest{1}}
	root := &OwnerIdentityRoleRoot{resources: resources, input: a.Input, bridge: &InitialRuntimeBridge{administration: cfg.InitialRuntimeBridgeAdministration{Owner: plan}, source: &ConfigurationRoleSource{protection: guard}}}
	in.PermissionRootID = ownerID(7110)
	in.Kubernetes, in.Postgres, in.AuditStore = original.Kubernetes, original.Postgres, original.AuditStore
	in.Postgres.MaxConnections = 1
	in.KeyService = contracts.OwnerKeyService{Endpoint: original.KeyService.Endpoint, Roots: roots, AuditMount: original.KeyService.AuditMount, AuditKey: original.KeyService.AuditKey, PKIMount: "owner-pki", ServerRole: "owner-server", ClientRole: "owner-client"}
	for _, p := range plan.Administrators {
		in.WorkloadGuard.Administrators = append(in.WorkloadGuard.Administrators, contracts.OwnerDeploymentActor{Kind: string(p.Kind), Name: p.Name})
	}
	in.ConfigurationProbes = []contracts.OwnerConfigurationProbe{}
	for _, p := range plan.ConfigurationProbes {
		in.ConfigurationProbes = append(in.ConfigurationProbes, contracts.OwnerConfigurationProbe{ConfigMap: p.ConfigMap, ServiceAccount: p.ServiceAccount})
	}
	in.SchedulingLeases = []contracts.OwnerSchedulingLease{}
	for _, p := range plan.SchedulingLeases {
		in.SchedulingLeases = append(in.SchedulingLeases, contracts.OwnerSchedulingLease{Lease: p.Lease, ServiceAccount: p.ServiceAccount})
	}
	p := plan.InitialHistoryProbe
	in.InitialHistoryProbe = &contracts.OwnerInitialHistoryProbe{Namespace: contracts.WorkerObjectReference{Name: p.Namespace.Name, UID: p.Namespace.UID}, ServiceAccount: contracts.WorkerObjectReference{Name: p.ServiceAccount, UID: p.ServiceAccountUID}, Configuration: p.Configuration}
	in.APIContextStarts = &contracts.OwnerDeploymentAPIContextStarts{CapacityAccount: contracts.WorkerObjectReference{Name: plan.APIContextStarts.CapacityAccount, UID: plan.APIContextStarts.CapacityAccountUID}, ExecutionAccount: contracts.WorkerObjectReference{Name: plan.APIContextStarts.ExecutionAccount, UID: plan.APIContextStarts.ExecutionAccountUID}}
	in.CapacityProbe = &contracts.OwnerDeploymentCapacityProbe{ServiceAccount: inventory.WorkerAccount}
	in.Connections, in.Concurrency = 4, 2
	in.Observation = &contracts.OwnerObservationBootstrap{Format: contracts.OwnerObservationFormat, TemplateDigest: strings.Repeat("1", 64), ImageDigest: strings.Repeat("2", 64), ProtectionDigest: hex.EncodeToString(guard.digest[:]), Peers: []contracts.OwnerObservationPeer{{InstallationID: original.InstallationID, ClusterID: original.ClusterID, IssuerEpoch: original.IssuerEpoch, PeerID: ownerID(7111), Roots: roots}}}
	return root, in, state
}

func TestOwnerIdentityProjectionRejectsChangedOriginalInputsBeforeEffects(t *testing.T) {
	root, original, _ := ownerProjectionOriginalInputFixture(t)
	verifier := &ownerProjectionNoEffects{}
	if _, e := NewOwnerIdentityProjection(root, verifier, original, OwnerIdentityProviderMaterial{}); e != nil {
		t.Fatal("original fixed input rejected", e)
	}
	for name, mutate := range map[string]func(*contracts.OwnerDeployment){
		"api-endpoint":          func(v *contracts.OwnerDeployment) { v.Kubernetes.Endpoint = "https://other-api.example.test" },
		"api-roots":             func(v *contracts.OwnerDeployment) { v.Kubernetes.Roots = nil },
		"sql-host":              func(v *contracts.OwnerDeployment) { v.Postgres.Host = "other-sql.example.test" },
		"sql-port":              func(v *contracts.OwnerDeployment) { v.Postgres.Port++ },
		"sql-database":          func(v *contracts.OwnerDeployment) { v.Postgres.Database = "other" },
		"sql-roots":             func(v *contracts.OwnerDeployment) { v.Postgres.Roots = nil },
		"sql-pool":              func(v *contracts.OwnerDeployment) { v.Postgres.MaxConnections = 2 },
		"audit-endpoint":        func(v *contracts.OwnerDeployment) { v.AuditStore.Endpoint = "https://other-audit.example.test" },
		"audit-region":          func(v *contracts.OwnerDeployment) { v.AuditStore.Region = "other" },
		"audit-bucket":          func(v *contracts.OwnerDeployment) { v.AuditStore.Bucket = "other" },
		"audit-roots":           func(v *contracts.OwnerDeployment) { v.AuditStore.Roots = nil },
		"key-endpoint":          func(v *contracts.OwnerDeployment) { v.KeyService.Endpoint = "https://other-keys.example.test" },
		"key-roots":             func(v *contracts.OwnerDeployment) { v.KeyService.Roots = nil },
		"audit-mount":           func(v *contracts.OwnerDeployment) { v.KeyService.AuditMount = "different" },
		"audit-key":             func(v *contracts.OwnerDeployment) { v.KeyService.AuditKey = "different" },
		"pki-role":              func(v *contracts.OwnerDeployment) { v.KeyService.ServerRole = v.KeyService.ClientRole },
		"guard-policy":          func(v *contracts.OwnerDeployment) { v.WorkloadGuard.PolicyUID = ownerID(7190) },
		"guard-generation":      func(v *contracts.OwnerDeployment) { v.WorkloadGuard.PolicyGeneration++ },
		"guard-binding":         func(v *contracts.OwnerDeployment) { v.WorkloadGuard.BindingUID = ownerID(7190) },
		"guard-binding-version": func(v *contracts.OwnerDeployment) { v.WorkloadGuard.BindingResourceVersion = "2" },
		"administrator":         func(v *contracts.OwnerDeployment) { v.WorkloadGuard.Administrators[0].Name = "different" },
		"source-probe":          func(v *contracts.OwnerDeployment) { v.ConfigurationProbes = v.ConfigurationProbes[:1] },
		"source-probe-account":  func(v *contracts.OwnerDeployment) { v.ConfigurationProbes[0].ServiceAccount = "different" },
		"lease":                 func(v *contracts.OwnerDeployment) { v.SchedulingLeases = nil },
		"history":               func(v *contracts.OwnerDeployment) { v.InitialHistoryProbe = nil },
		"history-uid":           func(v *contracts.OwnerDeployment) { v.InitialHistoryProbe.ServiceAccount.UID = ownerID(7190) },
		"api-start":             func(v *contracts.OwnerDeployment) { v.APIContextStarts = nil },
		"api-start-uid":         func(v *contracts.OwnerDeployment) { v.APIContextStarts.ExecutionAccount.UID = ownerID(7190) },
		"capacity-probe":        func(v *contracts.OwnerDeployment) { v.CapacityProbe = nil },
		"capacity-probe-uid":    func(v *contracts.OwnerDeployment) { v.CapacityProbe.ServiceAccount.UID = ownerID(7190) },
		"protection-digest":     func(v *contracts.OwnerDeployment) { v.Observation.ProtectionDigest = strings.Repeat("9", 64) },
		"template-zero":         func(v *contracts.OwnerDeployment) { v.Observation.TemplateDigest = strings.Repeat("0", 64) },
		"image-zero":            func(v *contracts.OwnerDeployment) { v.Observation.ImageDigest = strings.Repeat("0", 64) },
		"peer-epoch":            func(v *contracts.OwnerDeployment) { v.Observation.Peers[0].IssuerEpoch = ownerID(7190) },
		"peer-installation":     func(v *contracts.OwnerDeployment) { v.Observation.Peers[0].InstallationID = ownerID(7190) },
		"duplicate-peer": func(v *contracts.OwnerDeployment) {
			v.Observation.Peers = append(v.Observation.Peers, v.Observation.Peers[0])
		},
		"missing-peer":      func(v *contracts.OwnerDeployment) { v.Observation.Peers = nil },
		"connection-bound":  func(v *contracts.OwnerDeployment) { v.Connections = 65 },
		"concurrency-bound": func(v *contracts.OwnerDeployment) { v.Concurrency = v.Connections + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(original)
			var input contracts.OwnerDeployment
			if e := json.Unmarshal(raw, &input); e != nil {
				t.Fatal(e)
			}
			mutate(&input)
			if _, e := NewOwnerIdentityProjection(root, verifier, input, OwnerIdentityProviderMaterial{}); e == nil {
				t.Fatal("changed original input admitted to immutable projection")
			}
		})
	}
	if verifier.calls != 0 {
		t.Fatal("static validation performed SQL effects")
	}
}
