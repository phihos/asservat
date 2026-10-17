package bootstrap

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestHubWorkerProjectionPinsAndProviderIsolation(t *testing.T) {
	for _, mode := range []string{"valid", "shared-source", "shared-guard", "bad-lease", "nil-roots", "http-provider", "unbounded-pool", "role-in-document"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, owner := ownerInputFixture(t)
			c := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, Namespace: owner.Namespace, FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: runtimeID}, OwnerSource: contracts.WorkerObjectReference{Name: "owner", UID: runtimeID}, FleetGuard: owner.WorkloadGuard, OwnerGuard: owner.WorkloadGuard, LeaderLease: contracts.WorkerObjectReference{Name: "reconcile", UID: runtimeID}, Kubernetes: owner.Kubernetes, Postgres: owner.Postgres, AuditStore: owner.AuditStore, KeyService: contracts.ConfigurationKeyService{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, AuditMount: owner.KeyService.AuditMount, AuditKey: owner.KeyService.AuditKey}}
			c.OwnerGuard.Name = "owner-configuration"
			switch mode {
			case "shared-source":
				c.OwnerSource = c.FleetSource
			case "shared-guard":
				c.OwnerGuard = c.FleetGuard
			case "bad-lease":
				c.LeaderLease.UID = "caller-selected"
			case "nil-roots":
				c.Postgres.Roots = nil
			case "http-provider":
				c.Kubernetes.Endpoint = "http://api.invalid"
			case "unbounded-pool":
				c.Postgres.MaxConnections = 20
			}
			if mode == "role-in-document" {
				writeOwnerJSON(t, dir, "deployment.json", map[string]any{"format": c.Format, "sqlRole": "admin"})
			} else {
				writeOwnerJSON(t, dir, "deployment.json", c)
			}
			_, got, err := readHubWorkerInputs(context.Background(), in.files)
			if mode == "valid" {
				if err != nil || got.InstallationID != c.InstallationID {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("invalid protected deployment accepted")
			}
		})
	}
}
