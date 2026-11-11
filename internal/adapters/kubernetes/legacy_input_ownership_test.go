package kubernetes

import (
	"context"
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

// These tests exercise caller ownership, not native authorization. Existing
// synthetic fixtures never confer installation, provider or SQL authority.
func TestLegacyInputOwnershipBootstrapConstructor(t *testing.T) {
	f := newBootstrapObserverFixture(t, context.Background())
	desired := f.desired
	s, err := NewInitialBootstrap(context.Background(), f.apiConfig, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	want := preparationDigest(s.desired)
	desired.Administrators[0].Name = "replaced-administrator"
	desired.Kubernetes.Roots[0][0] ^= 1
	if preparationDigest(s.desired) != want {
		t.Fatal("caller changed retained bootstrap input")
	}
}

func TestLegacyInputOwnershipBootstrapObserver(t *testing.T) {
	f := newBootstrapObserverFixture(t, context.Background())
	wantProjection, wantConfiguration := preparationDigest(f.observer.projection), preparationDigest(f.observer.configuration)
	f.projection.Desired.Administrators[0].Name = "replaced-administrator"
	f.projection.Desired.Kubernetes.Roots[0][0] ^= 1
	f.config.Plan.HistoryProbe.UID = ownerID(15100)
	if preparationDigest(f.observer.projection) != wantProjection || preparationDigest(f.observer.configuration) != wantConfiguration {
		t.Fatal("caller changed retained observer input")
	}
}

func TestLegacyInputOwnershipBootstrapState(t *testing.T) {
	desired := bootstrapAdmissionFixture(t)
	_, original := bootstrapStateFixture(t)
	desired.Format = contracts.InitialBootstrapCopyClosureFormat
	prelude := original.Prelude
	prelude.CopyMarker = &contracts.WorkerObjectReference{Name: bootstrapNames(desired).copyMarker, UID: ownerID(15101)}
	state, err := newBootstrapState(desired, prelude, *original.Material)
	if err != nil {
		t.Fatal(err)
	}
	// Never render the generated private state or its bytes in failure output.
	before, err := json.Marshal(state)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	defer clear(before)
	prelude.Guard.Administrators[0].Name = "replaced-administrator"
	prelude.CopyMarker.UID = ownerID(15102)
	after, err := json.Marshal(state)
	if err != nil {
		t.Fatal("fixture encoding failed")
	}
	defer clear(after)
	if string(before) != string(after) {
		t.Fatal("caller changed retained bootstrap state")
	}
}

func TestLegacyInputOwnershipCleanupConstructor(t *testing.T) {
	resources, state, _, _ := ownerIdentityActivationFixture(t)
	input, _ := publicWorkerProofFixture(t, contracts.PublicRuntimeRoles{InstallationID: resources.initial.InstallationID, InitialClaimID: ownerID(1500), ClusterID: resources.initial.ClusterID, Namespace: resources.initial.Namespace, OwnerConfigurationUID: state.Objects[14].Receipt.UID})
	roles := &PublicRuntimeRoleRoot{input: input}
	bridge := &InitialRuntimeBridge{preparer: resources.preparer, rootUID: resources.rootUID, initial: resources.initial}
	deployment := contracts.CaptureCleanupDeployment{Format: contracts.CaptureCleanupDeploymentFormat, InstallationID: resources.initial.InstallationID,
		Postgres: contracts.OwnerPostgresEndpoint{Roots: [][]byte{{1, 2, 3}}},
		Signing:  contracts.CaptureCleanupSigning{PublicKeys: map[string][]byte{"original": make([]byte, 32)}},
	}
	resources.workerLayout, resources.ownerLayout = contracts.HubWorkerProviderInstalledLayout, contracts.OwnerProviderInstalledLayout
	names := runtimeResourceNames(resources.initial.InstallationID)
	resources.workerProvider = &contracts.ConfigurationProviderSelection{AuthMount: "configuration", AuthMountAccessor: "auth_configuration", AuditCredentials: contracts.WorkerObjectReference{Name: names.WorkerProviders, UID: ownerID(14931)}}
	resources.ownerProvider = &contracts.OwnerProviderSelection{AuthMount: "owner", AuthMountAccessor: "auth_owner", AuditCredentials: contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(resources.initial.InstallationID), UID: ownerID(14932)}}
	resources.initial.KeyService = contracts.ConfigurationKeyService{AuditMount: "audit", AuditKey: "original", Roots: [][]byte{{1, 2, 3}}}
	bridge.initial = resources.initial
	deployment.AuditStore, deployment.KeyService = resources.initial.AuditStore, resources.initial.KeyService
	resources.workerProvider.CleanupAudit = contracts.OwnerPublicTransit{Mount: deployment.KeyService.AuditMount, Key: deployment.KeyService.AuditKey}
	resources.workerProvider.ContextDeletionSigning = contracts.OwnerPublicTransit{Mount: deployment.KeyService.AuditMount, Key: contracts.ContextDeletionSigningKeyName(resources.initial.InstallationID)}
	deployment.Signing.Mount, deployment.Signing.Name = deployment.KeyService.AuditMount, contracts.ContextDeletionSigningKeyName(resources.initial.InstallationID)
	s, err := NewCaptureCleanupProjection(bridge, resources, roles, deployment, CaptureCleanupProviderMaterial{})
	if err != nil {
		t.Fatal(err)
	}
	want := preparationDigest(s.deployment)
	deployment.Postgres.Roots[0][0] ^= 1
	deployment.Signing.PublicKeys["original"][0] ^= 1
	deployment.Signing.PublicKeys["added"] = make([]byte, 32)
	if preparationDigest(s.deployment) != want {
		t.Fatal("caller changed retained cleanup input")
	}
}
