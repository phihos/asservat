package bootstrap

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Pure generated-document inputs only. These synthetic references never stand
// in for the native journals, current guard or actual provider qualification.
func configurationDocumentsProbeFixture(t *testing.T, capacity bool) (contracts.InitialInstaller, kube.InitialRuntimeResourceInventory, contracts.ConfigurationRoleInstaller) {
	t.Helper()
	_, input := configurationRoleInstallerFixture(t)
	input.InitialHistoryProbe = &contracts.OwnerInitialHistoryProbe{
		Namespace:      contracts.WorkerObjectReference{Name: "bootstrap", UID: "10000000-0000-4000-8000-000000000020"},
		ServiceAccount: contracts.WorkerObjectReference{Name: "history", UID: "10000000-0000-4000-8000-000000000021"},
		Configuration:  "original-installer",
	}
	input.ConfigurationProbes = []contracts.OwnerConfigurationProbe{
		{ConfigMap: input.Roles.FleetSource.Name, ServiceAccount: input.Roles.ServiceAccount.Name},
		{ConfigMap: input.Roles.OwnerSource.Name, ServiceAccount: input.Roles.ServiceAccount.Name},
	}
	lease := contracts.WorkerObjectReference{Name: "configuration-lease", UID: "10000000-0000-4000-8000-000000000022"}
	input.SchedulingLeases = []contracts.OwnerSchedulingLease{{Lease: lease.Name, ServiceAccount: input.Roles.ServiceAccount.Name}}
	if capacity {
		input.CapacityProbe = &contracts.OwnerDeploymentCapacityProbe{ServiceAccount: input.Roles.ServiceAccount}
		input.ConfigurationProbes = append(input.ConfigurationProbes, contracts.OwnerConfigurationProbe{ConfigMap: "processing-source", ServiceAccount: input.Roles.ServiceAccount.Name})
	}
	owner, _, err := configurationRoleInstallerPlan(input)
	if err != nil {
		t.Fatal("complete synthetic original owner guard", err)
	}
	original := contracts.InitialInstaller{
		Format: contracts.InitialInstallerFormat, InstallationID: input.Roles.InstallationID,
		ClusterID: input.Roles.ClusterID, Namespace: input.Roles.Namespace,
		Configuration: input.InitialHistoryProbe.Configuration,
		FleetSource:   input.Roles.FleetSource, FleetGuard: input.FleetGuard,
		Kubernetes: input.Kubernetes, Postgres: input.Postgres,
		AuditStore: contracts.OwnerAuditStore{Endpoint: "https://store.invalid", Roots: input.Kubernetes.Roots, Region: "test-region", Bucket: "audit"},
		KeyService: contracts.ConfigurationKeyService{Endpoint: "https://keys.invalid", Roots: input.Kubernetes.Roots, AuditMount: "audit", AuditKey: "records"},
	}
	inventory := kube.InitialRuntimeResourceInventory{
		Namespace: input.Roles.Namespace, FleetSource: input.Roles.FleetSource, OwnerSource: input.Roles.OwnerSource,
		OwnerDeployment: input.OwnerDeployment, WorkerDeployment: input.Roles.Deployment, WorkerAccount: input.Roles.ServiceAccount,
		LeaderLease: lease, FleetGuard: input.FleetGuard, OwnerSourceGuard: input.OwnerGuard, WorkloadGuard: input.WorkloadGuard,
		BridgeAdministration: cfg.InitialRuntimeBridgeAdministration{Owner: owner},
	}
	return original, inventory, input
}

func TestInitialConfigurationDocumentsPreserveCompleteOriginalOwnerGuard(t *testing.T) {
	for _, capacity := range []bool{false, true} {
		name := "legacy-omission"
		if capacity {
			name = "installed-capacity-probe"
		}
		t.Run(name, func(t *testing.T) {
			original, inventory, expected := configurationDocumentsProbeFixture(t, capacity)
			documents, err := BuildInitialConfigurationDocuments(original, inventory, expected.Roles.InitialClaimID)
			if err != nil {
				t.Fatal("generate original configuration documents", err)
			}
			decoded, err := contracts.DecodeConfigurationRoleInstaller(bytes.NewReader(documents.Roles))
			if err != nil {
				t.Fatal(err)
			}
			actual, pin, err := configurationRoleInstallerPlan(decoded)
			if err != nil || !reflect.DeepEqual(actual, inventory.BridgeAdministration.Owner) {
				t.Fatal("generated configuration installer changed the complete original owner guard", err)
			}
			g := inventory.WorkloadGuard
			if pin != (kube.GuardPin{PolicyUID: g.PolicyUID, PolicyGeneration: g.PolicyGeneration, BindingUID: g.BindingUID, BindingResourceVersion: g.BindingResourceVersion}) {
				t.Fatal("generated guard replaced its original policy/binding pin")
			}
			wantPolicy, wantBinding, err := kube.OwnerWorkloadAdmission(inventory.BridgeAdministration.Owner)
			if err != nil {
				t.Fatal(err)
			}
			gotPolicy, gotBinding, err := kube.OwnerWorkloadAdmission(actual)
			if err != nil || !reflect.DeepEqual(gotPolicy, wantPolicy) || !reflect.DeepEqual(gotBinding, wantBinding) {
				t.Fatal("generated input reconstructed another admission policy", err)
			}
			want, err := json.Marshal(expected)
			if err != nil || !bytes.Equal(documents.Roles, want) {
				t.Fatal("generated role document changed original fields or omission bytes", err)
			}
			if !capacity && strings.Contains(string(documents.Roles), "capacityProbe") {
				t.Fatal("legacy document gained a capacity field")
			}
		})
	}
}

func TestInitialConfigurationDocumentsRejectUnsupportedOriginalStartGuard(t *testing.T) {
	original, inventory, input := configurationDocumentsProbeFixture(t, true)
	inventory.BridgeAdministration.Owner.APIContextStarts = &cfg.OwnerAPIContextStarts{
		CapacityAccount: "capacity-start", CapacityAccountUID: "10000000-0000-4000-8000-000000000030",
		ExecutionAccount: "execution", ExecutionAccountUID: "10000000-0000-4000-8000-000000000031",
	}
	if !inventory.BridgeAdministration.Owner.Valid() {
		t.Fatal("negative test did not supply a valid unsupported original guard")
	}
	got, err := BuildInitialConfigurationDocuments(original, inventory, input.Roles.InitialClaimID)
	if err != configurationRoleInputInvalid || len(got.Worker) != 0 || len(got.Roles) != 0 {
		t.Fatal("unsupported original start branch silently changed the generated guard", err)
	}
}
