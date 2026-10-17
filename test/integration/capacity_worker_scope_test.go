package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	coordination "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This SQL-only matrix substitutes the Kubernetes root. These original worker
// journals/observations are synthetic; they are never passed as current native
// guard proof. The three pinned worker templates use the real inert builder,
// and the binding uses the same production translation as the installer. SQL
// role claims, passwords and receipts are produced separately by the real SQL
// adapter. None of the synthetic configuration-role OIDs below enter SQL54.
func capacityNativeWorkerScope(t *testing.T, in contracts.PublicRuntimeRoles) contracts.PublicRuntimeWorkerBinding {
	t.Helper()
	prefix := "asservat-" + strings.ReplaceAll(in.InstallationID, "-", "")
	ref := func(name string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: custodyID()}
	}
	inventory := kubernetes.InitialRuntimeResourceInventory{
		Namespace: in.Namespace, FleetSource: ref(prefix + "-fleet-source"),
		OwnerSource:      contracts.WorkerObjectReference{Name: prefix + "-owner-source", UID: in.OwnerConfigurationUID},
		WorkerDeployment: ref(prefix + "-worker"), WorkerAccount: ref(prefix + "-worker"), LeaderLease: ref(prefix + "-leader"),
		FleetGuard: contracts.OwnerDeploymentGuard{Name: prefix + "-fleet-guard"},
	}
	worker, err := kubernetes.BuildInstalledHubWorkerWorkload(kubernetes.HubWorkerWorkloadPlan{
		Namespace: in.Namespace.Name, Name: inventory.WorkerDeployment.Name, ServiceAccount: inventory.WorkerAccount.Name,
		Configuration: prefix + "-worker-inputs", Credentials: prefix + "-worker-providers",
		Image:       "registry.invalid/synthetic-asservat@sha256:" + strings.Repeat("9", 64),
		FleetSource: inventory.FleetSource.Name, OwnerSource: inventory.OwnerSource.Name,
		FleetGuard: inventory.FleetGuard.Name, OwnerGuard: prefix + "-owner-source-guard", LeaderLease: inventory.LeaderLease.Name,
	}, in.InstallationID)
	if err != nil {
		t.Fatal("fixed synthetic worker template", err)
	}
	lease := &coordination.Lease{TypeMeta: metav1.TypeMeta{APIVersion: "coordination.k8s.io/v1", Kind: "Lease"}, ObjectMeta: metav1.ObjectMeta{Name: inventory.LeaderLease.Name, Namespace: in.Namespace.Name}}
	start := time.Now().UTC().Truncate(time.Microsecond).Add(-30 * time.Second)
	until := start.Add(5 * time.Second)
	resources := contracts.InitialRuntimeResourceState{Format: contracts.InitialRuntimeResourcesFormat, WorkerLayout: contracts.HubWorkerInstalledLayout, SetupID: custodyID(), BindingDigest: strings.Repeat("6", 64), CreatedAt: start, Until: start.Add(30 * time.Minute)}
	items := []string{"owner-account", "worker-account", "owner-role", "owner-binding", "owner-cluster-role", "owner-cluster-binding", "worker-role", "worker-binding", "worker-cluster-role", "worker-cluster-binding", "owner-deployment", "worker-deployment", "owner-service", "worker-lease", "owner-source", "owner-source-policy", "owner-source-binding", "owner-workload-policy", "owner-workload-binding"}
	if len(items) != contracts.InitialRuntimeResourceCount {
		t.Fatal("synthetic resource recipe no longer matches fixed inventory")
	}
	for _, item := range items {
		// Non-worker entries are explicitly synthetic historical placeholders;
		// this SQL test does not qualify complete native journal validation.
		resources.Objects = append(resources.Objects, contracts.InitialRuntimeResourceClaim{Item: item, OperationID: custodyID(), TemplateDigest: capacityNativeDigest(t, item), ClaimedAt: start, Until: until, Receipt: &contracts.InitialRuntimeResourceReceipt{UID: custodyID(), ResourceVersion: "1", Generation: 1}})
	}
	for _, entry := range []struct {
		index int
		ref   contracts.WorkerObjectReference
		value any
	}{{1, inventory.WorkerAccount, worker.Account}, {11, inventory.WorkerDeployment, worker.Deployment}, {13, inventory.LeaderLease, lease}} {
		resources.Objects[entry.index].Receipt.UID = entry.ref.UID
		resources.Objects[entry.index].TemplateDigest = capacityNativeDigest(t, entry.value)
	}
	configuration := contracts.ConfigurationRuntimeRoles{Format: contracts.ConfigurationRuntimeRolesFormat, InstallationID: in.InstallationID, InitialClaimID: in.InitialClaimID, ClusterID: in.ClusterID, Namespace: in.Namespace, Deployment: inventory.WorkerDeployment, ServiceAccount: inventory.WorkerAccount, FleetSource: inventory.FleetSource, OwnerSource: inventory.OwnerSource, LayoutDigest: postgres.ConfigurationRuntimeRoleLayoutDigest()}
	sources := contracts.ConfigurationRoleObservation{InstallationID: in.InstallationID, ClusterID: in.ClusterID, IssuerEpoch: custodyID(), NamespaceUID: in.Namespace.UID, DeploymentUID: inventory.WorkerDeployment.UID, AccountUID: inventory.WorkerAccount.UID, WorkloadDigest: capacityNativeDigest(t, worker.Deployment.Spec), GuardDigest: strings.Repeat("2", 64), ObservedAt: start, FreshUntil: until,
		Fleet: contracts.ConfigurationRoleSourceRevision{UID: inventory.FleetSource.UID, Generation: 1, Digest: strings.Repeat("3", 64), ObservedAt: start, FreshUntil: until}, Owner: contracts.ConfigurationRoleSourceRevision{UID: inventory.OwnerSource.UID, Generation: 1, Digest: strings.Repeat("4", 64), ObservedAt: start, FreshUntil: until}}
	state := contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: configuration, OperationID: custodyID(), CreatedAt: start, Until: start.Add(30 * time.Minute), Projection: &contracts.PublicRuntimeProjectionClaim{OperationID: custodyID(), ClaimedAt: start, Until: until, SecretUID: custodyID()}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		state.Roles = append(state.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Password: base64.RawURLEncoding.EncodeToString(key), Claim: &contracts.ConfigurationRuntimeRoleClaim{OperationID: custodyID(), ClaimedAt: start, Until: until, DatabaseOID: 42, PostmasterAt: start.Add(-time.Hour), Sources: sources}, Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: "as_" + strings.ReplaceAll(in.InstallationID, "-", "") + fmt.Sprintf("_cfg_%02d", i), RoleOID: uint32(300 + i), LayoutDigest: configuration.LayoutDigest}})
	}
	*worker.Deployment.Spec.Replicas = 1
	state.Launch = &contracts.ConfigurationRuntimeLaunch{OperationID: custodyID(), ClaimedAt: start.Add(time.Second), Until: until, Sources: sources, InertResourceVersion: "1", RunningDigest: capacityNativeDigest(t, worker.Deployment.Spec), ProjectionUID: state.Projection.SecretUID, Configuration: ref(prefix + "-worker-inputs"), Providers: ref(prefix + "-worker-providers"), Receipt: &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: "2", ObservedAt: start.Add(2 * time.Second)}}
	out, err := kubernetes.BuildPublicRuntimeWorkerBinding(contracts.InitialRuntimeResourceSnapshot{State: resources, UID: custodyID()}, inventory, contracts.ConfigurationRuntimeRoleSnapshot{State: state, UID: custodyID()})
	if err != nil {
		t.Fatal("synthetic original worker receipt translation", err)
	}
	return out
}

func capacityNativeDigest(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}
