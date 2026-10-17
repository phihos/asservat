package bootstrap

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func configurationRoleInputPair(t *testing.T) (contracts.ConfigurationRoleInstaller, contracts.OwnerDeployment, contracts.HubWorkerDeployment) {
	t.Helper()
	_, original := configurationRoleInstallerFixture(t)
	account := original.Roles.ServiceAccount.Name
	owner := contracts.OwnerDeployment{
		Format:         contracts.OwnerDeploymentFormat,
		InstallationID: original.Roles.InstallationID, ClusterID: original.Roles.ClusterID,
		Namespace: original.Roles.Namespace, ConfigurationUID: original.Roles.OwnerSource.UID,
		WorkloadGuard: original.WorkloadGuard, Kubernetes: original.Kubernetes, Postgres: original.Postgres,
		ConfigurationProbes: []contracts.OwnerConfigurationProbe{
			{ConfigMap: original.Roles.FleetSource.Name, ServiceAccount: account},
			{ConfigMap: original.Roles.OwnerSource.Name, ServiceAccount: account},
		},
		SchedulingLeases: []contracts.OwnerSchedulingLease{{Lease: "configuration-scheduling", ServiceAccount: account}},
	}
	worker := contracts.HubWorkerDeployment{
		Format:         contracts.HubWorkerDeploymentFormat,
		InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, Namespace: owner.Namespace,
		FleetSource: original.Roles.FleetSource, OwnerSource: original.Roles.OwnerSource,
		FleetGuard: original.FleetGuard, OwnerGuard: original.OwnerGuard,
		LeaderLease: contracts.WorkerObjectReference{Name: "configuration-scheduling", UID: "10000000-0000-4000-8000-000000000099"},
		Kubernetes:  original.Kubernetes, Postgres: original.Postgres,
		AuditStore: contracts.OwnerAuditStore{Endpoint: "https://store.invalid", Roots: original.Kubernetes.Roots, Region: "test", Bucket: "configuration-audit"},
		KeyService: contracts.ConfigurationKeyService{Endpoint: "https://keys.invalid", Roots: original.Kubernetes.Roots, AuditMount: "audit", AuditKey: "configuration"},
	}
	return original, owner, worker
}

func TestConfigurationInstallerGeneratedInputKeepsExistingPins(t *testing.T) {
	for _, mode := range []string{"valid", "installation", "cluster", "namespace", "source", "api", "database", "roots", "probe", "lease", "activation"} {
		t.Run(mode, func(t *testing.T) {
			original, owner, worker := configurationRoleInputPair(t)
			claim := original.Roles.InitialClaimID
			switch mode {
			case "installation":
				owner.InstallationID = "10000000-0000-4000-8000-000000000090"
			case "cluster":
				owner.ClusterID = "10000000-0000-4000-8000-000000000090"
			case "namespace":
				owner.Namespace.Name = "other"
			case "source":
				owner.ConfigurationUID = "10000000-0000-4000-8000-000000000090"
			case "api":
				owner.Kubernetes.Endpoint = "https://other.invalid"
			case "database":
				owner.Postgres.Database = "other"
			case "roots":
				owner.Postgres.Roots = nil
			case "probe":
				owner.ConfigurationProbes = owner.ConfigurationProbes[:1]
			case "lease":
				owner.SchedulingLeases = nil
			case "activation":
				claim = ""
			}
			b, err := BuildConfigurationRoleInstallerInput(owner, worker, original.OwnerDeployment, original.Roles.Deployment, original.Roles.ServiceAccount, claim)
			if mode != "valid" {
				if err == nil || len(b) != 0 {
					t.Fatal("inconsistent installed inputs generated a continuation")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := contracts.DecodeConfigurationRoleInstaller(bytes.NewReader(b))
			if err != nil || got.Roles != original.Roles || got.OwnerDeployment != original.OwnerDeployment || !reflect.DeepEqual(got.WorkloadGuard, owner.WorkloadGuard) || !reflect.DeepEqual(got.FleetGuard, worker.FleetGuard) || !reflect.DeepEqual(got.OwnerGuard, worker.OwnerGuard) || got.Postgres.MaxConnections != 1 {
				t.Fatal("generated input replaced an original identity or fixed pool bound", err)
			}
			for _, forbidden := range []string{"password", "token", "grants", "sqlFile", "freshUntil", "activatedAt"} {
				if strings.Contains(string(b), forbidden) {
					t.Fatal("generated public input contains credentials or fabricated current authority")
				}
			}
		})
	}
}
