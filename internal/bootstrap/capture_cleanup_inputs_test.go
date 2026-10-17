package bootstrap

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

// The fixture supplies historical public receipts only. It performs no SQL,
// Kubernetes guard, provider provisioning or runtime activation.
func captureCleanupInputFixture(t *testing.T) (*providerInputs, string, contracts.HubWorkerDeployment, contracts.CaptureCleanupDeployment, contracts.CaptureCleanupCredentialManifest, contracts.CaptureCleanupProjectionClaim) {
	t.Helper()
	in, dir, owner := ownerInputFixture(t)
	id := func(n int) string { return fmt.Sprintf("90000000-0000-4000-8000-%012d", n) }
	at := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	prefix := "asservat-" + strings.ReplaceAll(owner.InstallationID, "-", "")
	ref := func(suffix string, n int) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: prefix + suffix, UID: id(n)}
	}
	guard := func(suffix string, n int) contracts.OwnerDeploymentGuard {
		g := owner.WorkloadGuard
		g.Name, g.PolicyUID, g.BindingUID = prefix+suffix, id(n), id(n+1)
		return g
	}
	worker := contracts.HubWorkerDeployment{
		Format: contracts.HubWorkerDeploymentFormat, InstallationID: owner.InstallationID, ClusterID: owner.ClusterID, Namespace: owner.Namespace,
		FleetSource: ref("-fleet", 1), OwnerSource: ref("-owner-source", 2), LeaderLease: ref("-leader", 3),
		FleetGuard: guard("-fleet-guard", 4), OwnerGuard: guard("-owner-source-guard", 6),
		Kubernetes: owner.Kubernetes, Postgres: owner.Postgres, AuditStore: owner.AuditStore,
		KeyService: contracts.ConfigurationKeyService{Endpoint: owner.KeyService.Endpoint, Roots: owner.KeyService.Roots, AuditMount: owner.KeyService.AuditMount, AuditKey: owner.KeyService.AuditKey},
	}
	a := &contracts.HubWorkerRuntimeActivation{
		Resources: contracts.WorkerObjectReference{Name: "asservat-runtime-resources-" + strings.ReplaceAll(owner.InstallationID, "-", ""), UID: id(8)},
		SetupID:   id(9), BindingDigest: strings.Repeat("d", 64), WorkerLayout: contracts.HubWorkerInstalledLayout, CreatedAt: at, Until: at.Add(30 * time.Minute),
		Deployment: ref("-worker", 10), ServiceAccount: ref("-worker", 11), OwnerDeployment: ref("-owner", 12), WorkloadGuard: guard("-workload-guard", 13),
		ConfigurationProbes: []contracts.OwnerConfigurationProbe{{ConfigMap: worker.FleetSource.Name, ServiceAccount: prefix + "-worker"}, {ConfigMap: worker.OwnerSource.Name, ServiceAccount: prefix + "-worker"}},
		SchedulingLeases:    []contracts.OwnerSchedulingLease{{Lease: worker.LeaderLease.Name, ServiceAccount: prefix + "-worker"}},
		InitialHistoryProbe: &contracts.OwnerInitialHistoryProbe{Namespace: contracts.WorkerObjectReference{Name: "original-bootstrap", UID: id(15)}, ServiceAccount: contracts.WorkerObjectReference{Name: "original-bootstrap", UID: id(16)}, Configuration: "original-plan"},
	}
	worker.Activation = a
	if err := validateHubWorkerInputs(worker); err != nil {
		t.Fatal("synthetic worker input invalid", err)
	}
	m := contracts.CaptureCleanupCredentialManifest{Format: contracts.CaptureCleanupManifestFormat, RootUID: id(20), SetupID: id(21), Input: contracts.PublicRuntimeRoles{
		Format: contracts.PublicRuntimeRolesFormat, InstallationID: worker.InstallationID, InitialClaimID: id(22), ClusterID: worker.ClusterID, Namespace: worker.Namespace, OwnerConfigurationUID: worker.OwnerSource.UID, LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest(),
		Worker: contracts.PublicRuntimeWorkerBinding{Resources: a.Resources, ResourceSetupID: a.SetupID, ResourceBinding: a.BindingDigest, WorkerLayout: a.WorkerLayout, Deployment: contracts.PublicRuntimeWorkerObject{Reference: a.Deployment}, Account: contracts.PublicRuntimeWorkerObject{Reference: a.ServiceAccount}, Lease: contracts.PublicRuntimeWorkerObject{Reference: worker.LeaderLease}},
	}}
	m.CaptureSetup = contracts.CapacityRootSetupReceipt{Format: contracts.CapacityRootSetupFormat, OperationID: id(23), InstallationID: worker.InstallationID, InitialClaimID: m.Input.InitialClaimID, PermissionRootID: id(24), RoleRootUID: m.RootUID, RoleSetupID: m.SetupID, InputDigest: strings.Repeat("b", 64), DatabaseOID: 234, PostmasterAt: at.Add(-time.Hour), ClaimedAt: at.Add(time.Minute), Until: at.Add(time.Minute + 5*time.Second)}
	for n, purpose := range contracts.PublicRuntimeCaptureCleanupPurposes() {
		name, known := postgres.PublicRuntimeRoleName(worker.InstallationID, purpose)
		if !known {
			t.Fatal("unknown fixed purpose")
		}
		m.Roles = append(m.Roles, contracts.PublicRuntimeCredentialProof{Purpose: purpose, Claim: contracts.PublicRuntimeRoleClaim{OperationID: id(30 + n), DatabaseOID: m.CaptureSetup.DatabaseOID, PostmasterAt: m.CaptureSetup.PostmasterAt, ClaimedAt: at, Until: at.Add(5 * time.Second)}, Receipt: contracts.PublicRuntimeRoleReceipt{RoleName: name, RoleOID: uint32(243 + n), LayoutDigest: m.Input.LayoutDigest}})
	}
	c := contracts.CaptureCleanupDeployment{Format: contracts.CaptureCleanupDeploymentFormat, InstallationID: worker.InstallationID, RootID: m.CaptureSetup.PermissionRootID, StoreID: id(40), RoleRootUID: m.RootUID, RoleSetupID: m.SetupID, Postgres: owner.Postgres, AuditStore: owner.AuditStore, KeyService: worker.KeyService,
		Signing: contracts.CaptureCleanupSigning{Mount: "transit", Name: "retirement", Version: 1, KeyID: "original-retirement", PublicKeys: map[string][]byte{"original-retirement": make([]byte, ed25519.PublicKeySize)}},
	}
	c.Postgres.MaxConnections = 1
	digest, err := contracts.CaptureCleanupProjectionDigest(c, m)
	if err != nil {
		t.Fatal(err)
	}
	claim := contracts.CaptureCleanupProjectionClaim{OperationID: id(41), PublicDigest: digest, Setup: m.CaptureSetup, ClaimedAt: at.Add(2 * time.Minute), Until: at.Add(2*time.Minute + 5*time.Second), Receipt: &contracts.CaptureCleanupProjectionReceipt{Secret: contracts.WorkerObjectReference{Name: contracts.HubWorkerCleanupProjectionName(worker.InstallationID), UID: id(42)}, ResourceVersion: "44", ObservedAt: at.Add(2*time.Minute + time.Second)}}
	return &providerInputs{files: in.files, postgresEndpoint: c.Postgres}, dir, worker, c, m, claim
}

func TestCaptureCleanupInputsRequireMatchingOriginalWorkerAndPositiveReceipt(t *testing.T) {
	for _, mode := range []string{"historical-positive", "unknown-receipt", "no-activation", "other-worker", "other-account", "other-lease", "other-resource-journal", "other-owner-source", "other-setup", "changed-store-without-receipt", "expanded-pool", "wrong-key-size", "canceled", "expired"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, worker, c, m, claim := captureCleanupInputFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "unknown-receipt":
				claim.Receipt = nil
			case "no-activation":
				worker.Activation = nil
			case "other-worker":
				m.Input.Worker.Deployment.Reference.UID = m.RootUID
			case "other-account":
				m.Input.Worker.Account.Reference.UID = m.RootUID
			case "other-lease":
				m.Input.Worker.Lease.Reference.UID = m.RootUID
			case "other-resource-journal":
				m.Input.Worker.Resources.UID = m.RootUID
			case "other-owner-source":
				m.Input.OwnerConfigurationUID = m.RootUID
			case "other-setup":
				m.CaptureSetup.RoleSetupID = m.RootUID
			case "changed-store-without-receipt":
				c.StoreID = m.RootUID
			case "expanded-pool":
				c.Postgres.MaxConnections = 2
			case "wrong-key-size":
				c.Signing.PublicKeys[c.Signing.KeyID] = []byte("wrong")
			case "canceled":
				cancel()
			case "expired":
				var end context.CancelFunc
				ctx, end = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer end()
			}
			// Even a self-consistent replacement public digest cannot substitute
			// another worker/cohort for the exact installed input.
			if mode != "changed-store-without-receipt" {
				claim.PublicDigest, _ = contracts.CaptureCleanupProjectionDigest(c, m)
			}
			writeOwnerJSON(t, dir, contracts.HubWorkerCleanupDeploymentFile, c)
			writeOwnerJSON(t, dir, contracts.HubWorkerCleanupManifestFile, m)
			got, manifest, err := readCaptureCleanupInputs(ctx, in.files, worker, claim)
			if mode == "historical-positive" {
				if err != nil || !reflect.DeepEqual(got, c) || !reflect.DeepEqual(manifest, m) {
					t.Fatal("original completed provenance was not readable", err)
				}
			} else if err == nil || got.Format != "" || manifest.Format != "" {
				t.Fatal("inconsistent or unavailable projection was accepted")
			}
		})
	}
}

func TestCaptureCleanupStorageCredentialsRemainSeparateAndDoNotFallback(t *testing.T) {
	in, dir, _, _, _, _ := captureCleanupInputFixture(t)
	writeOwnerJSON(t, dir, "cleanup-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "cleanup-original", SecretAccessKey: "cleanup-secret"})
	writeOwnerJSON(t, dir, "verify-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "verify-original", SecretAccessKey: "verify-secret"})
	cleanup, verify := captureCleanupStorage{inputs: in}, captureCleanupStorage{inputs: in, verifier: true}
	for _, source := range []struct {
		reader captureCleanupStorage
		want   string
	}{{cleanup, "cleanup-original"}, {verify, "verify-original"}} {
		got, err := source.reader.Retrieve(context.Background())
		if err != nil || got.AccessKeyID != source.want {
			t.Fatal("credential compartments crossed", err)
		}
	}
	if err := os.Remove(filepath.Join(dir, "verify-storage.json")); err != nil {
		t.Fatal(err)
	}
	if got, err := verify.Retrieve(context.Background()); err == nil || got.AccessKeyID != "" {
		t.Fatal("missing verifier credential used cached or cleanup material")
	}
	writeOwnerJSON(t, dir, "verify-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "verify-rotated", SecretAccessKey: "new-secret"})
	if got, err := verify.Retrieve(context.Background()); err != nil || got.AccessKeyID != "verify-rotated" {
		t.Fatal("fresh projected credential was not read", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cleanup.Retrieve(ctx); err == nil {
		t.Fatal("canceled credential read accepted")
	}
}
