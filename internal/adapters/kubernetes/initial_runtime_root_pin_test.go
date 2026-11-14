package kubernetes

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
)

// The protected API/root facts and SQL receipt in this fixture are synthetic.
// It exercises the actual constructors and original handover read graph, not
// native admission or independent database activation.
type rootPinEffectFixture struct {
	record  audit.InitialInstallation
	receipt audit.Receipt
	effects int
}

func (s *rootPinEffectFixture) InitialRuntimeBridgeRecord() (audit.InitialInstallation, audit.Receipt) {
	return s.record, s.receipt
}
func (s *rootPinEffectFixture) WithInitialRuntimeBridge(ctx context.Context, run func(context.Context) error) error {
	s.effects++
	return run(ctx)
}

func (s *rootPinEffectFixture) WithInitialRuntimeOwnerBridge(ctx context.Context, a fleet.Administration, run func(context.Context) error) error {
	if ctx.Err() != nil || !a.Valid(time.Now()) || a.Suspended {
		return cfg.ErrUnavailable
	}
	return s.WithInitialRuntimeBridge(ctx, run)
}

func rootPinSource(t *testing.T, resources *InitialRuntimeResources, effects *rootPinEffectFixture) (*ConfigurationRoleSource, cfg.InitialRuntimeBridgeAdministration) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	v := contracts.InitialRuntimeResourceState{Format: contracts.InitialRuntimeResourcesFormat, BindingDigest: resources.binding, SetupID: ownerID(972), CreatedAt: now, Until: now.Add(30 * time.Minute), Objects: []contracts.InitialRuntimeResourceClaim{}}
	for i, item := range initialRuntimeResourceItems {
		obj, err := resources.object(v, i)
		if err != nil {
			t.Fatal(err)
		}
		v.Objects = append(v.Objects, contracts.InitialRuntimeResourceClaim{Item: item, OperationID: ownerID(1000 + i), TemplateDigest: preparationDigest(obj.object), ClaimedAt: now, Until: now.Add(5 * time.Second), Receipt: &contracts.InitialRuntimeResourceReceipt{UID: ownerID(1100 + i), ResourceVersion: "1", Generation: 1}})
	}
	in, err := resources.inventory(v)
	if err != nil {
		t.Fatal(err)
	}
	a := in.BridgeAdministration
	// No source effect is called by these constructor/root-mismatch tests.
	// Current source enforcement is qualified by the separate native matrix.
	s := &ConfigurationRoleSource{client: &PermissionClient{control: a.Initial.ControlNamespace, now: time.Now}, protection: &OwnerWorkloadProtection{plan: a.Owner}, fleet: &ProtectedFleetSettings{settings: &FleetSettingsClient{}, protection: &FleetConfigurationProtection{configMapProtection: &configMapProtection{}}}, owner: &OwnerConfigurationSource{protection: &OwnerConfigurationProtection{configMapProtection: &configMapProtection{}}}, input: contracts.ConfigurationRuntimeRoles{InstallationID: effects.record.Scope.InstallationID, InitialClaimID: effects.record.Claim.ID, ClusterID: resources.initial.ClusterID, Namespace: in.Namespace, FleetSource: in.FleetSource, OwnerSource: in.OwnerSource}}
	return s, a
}
