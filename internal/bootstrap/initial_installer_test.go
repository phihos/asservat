package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func initialInputFixture(t *testing.T) (*ownerInputs, string, contracts.InitialInstaller) {
	t.Helper()
	in, dir, o := ownerInputFixture(t)
	c := contracts.InitialInstaller{Format: contracts.InitialInstallerFormat, InstallationID: o.InstallationID, IssuerEpoch: o.InstallationID, ClusterID: o.ClusterID, Namespace: o.Namespace, Witness: contracts.WorkerObjectReference{Name: "witness", UID: runtimeID}, FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: runtimeID}, WriterAccount: contracts.WorkerObjectReference{Name: "writer", UID: runtimeID}, ProbeAccount: contracts.WorkerObjectReference{Name: "probe", UID: "22222222-2222-4222-8222-222222222222"}, Pod: contracts.WorkerObjectReference{Name: "install", UID: runtimeID}, PodSpecDigest: strings.Repeat("01", 32), Configuration: "install-inputs", WitnessGuard: o.WorkloadGuard, FleetGuard: o.WorkloadGuard, WorkloadGuard: o.WorkloadGuard, Kubernetes: o.Kubernetes, Postgres: o.Postgres, AuditStore: o.AuditStore, KeyService: contracts.ConfigurationKeyService{Endpoint: o.KeyService.Endpoint, Roots: o.KeyService.Roots, AuditMount: o.KeyService.AuditMount, AuditKey: o.KeyService.AuditKey}}
	c.WitnessGuard.Name, c.FleetGuard.Name, c.WorkloadGuard.Name = "witness-guard", "fleet-guard", "installer-guard"
	return in, dir, c
}

func TestInitialInstallerClosedInputsAndPlan(t *testing.T) {
	in, dir, c := initialInputFixture(t)
	writeOwnerJSON(t, dir, "deployment.json", c)
	first, err := readInitialInputs(context.Background(), in.files)
	if err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(c, "", "  ")
	if err = os.WriteFile(filepath.Join(dir, "deployment.json"), pretty, 0600); err != nil {
		t.Fatal(err)
	}
	again, err := readInitialInputs(context.Background(), in.files)
	if err != nil || first.plan != again.plan {
		t.Fatal("formatting changed immutable plan", err)
	}
	c.Postgres.Host = "other.synthetic.invalid"
	writeOwnerJSON(t, dir, "deployment.json", c)
	changed, err := readInitialInputs(context.Background(), in.files)
	if err != nil || changed.plan == first.plan {
		t.Fatal("endpoint change did not bind plan", err)
	}
	for _, mode := range []string{"same-principal", "same-uid", "shared-map", "shared-guard", "invalid-uid", "zero-spec", "upper-spec", "missing-ca", "http", "sql-pool", "unknown", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := initialInputFixture(t)
			switch mode {
			case "same-principal":
				c.ProbeAccount.Name = c.WriterAccount.Name
			case "same-uid":
				c.ProbeAccount.UID = c.WriterAccount.UID
			case "shared-map":
				c.Configuration = c.Witness.Name
			case "shared-guard":
				c.FleetGuard = c.WitnessGuard
			case "invalid-uid":
				c.Pod.UID = "caller"
			case "zero-spec":
				c.PodSpecDigest = strings.Repeat("00", 32)
			case "upper-spec":
				c.PodSpecDigest = strings.Repeat("AB", 32)
			case "missing-ca":
				c.KeyService.Roots = nil
			case "http":
				c.AuditStore.Endpoint = "http://store.invalid"
			case "sql-pool":
				c.Postgres.MaxConnections = 500
			}
			b, _ := json.Marshal(c)
			if mode == "unknown" {
				b = append([]byte(`{"activate":true,`), b[1:]...)
			}
			if mode == "duplicate" {
				b = append([]byte(`{"format":"asservat-initial-installer/v1",`), b[1:]...)
			}
			if err := os.WriteFile(filepath.Join(dir, "deployment.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readInitialInputs(context.Background(), in.files); err == nil {
				t.Fatal("unsafe initial configuration accepted")
			}
		})
	}
}
