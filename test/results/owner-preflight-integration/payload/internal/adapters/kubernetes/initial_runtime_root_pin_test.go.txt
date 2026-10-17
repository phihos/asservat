package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
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

func rootPinEffects(t *testing.T, p *InitialPreparer, root contracts.InitialPreparationRoot) *rootPinEffectFixture {
	t.Helper()
	c, err := p.inputConfiguration(root)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := audit.InitialInstallation{Scope: initialPreparationWitnessScope(c), Claim: fleet.InitialActivationClaim{
		ID: ownerID(971), Database: fleet.DatabaseIncarnation{StartedAt: now.Add(-time.Hour), DatabaseOID: 1, SchemaVersion: 53},
		FleetSource: identity.Revision{UID: c.FleetSource.UID, Generation: 1, Digest: artifact.Digest{1}},
		PlanDigest:  sha256.Sum256(raw), NotBefore: now.Add(-time.Minute), NotAfter: now,
	}}
	receipt := audit.Receipt{Key: audit.InitialInstallationKey(record.Scope.InstallationID, record.Claim.ID), Version: "original-version", ETag: "original", Bytes: 1, SHA256: artifact.Digest{2}}
	if !record.Valid() || !receipt.ValidInitialInstallation(record.Scope.InstallationID, record.Claim.ID) {
		t.Fatal("invalid synthetic original record")
	}
	return &rootPinEffectFixture{record: record, receipt: receipt}
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

func TestInitialRuntimeRootPinOriginalCreationInputAndReplacement(t *testing.T) {
	f, preparer, original := handoverConflictFixture(t)
	if preparer.rootUID != "" || original.RootUID == "" {
		t.Fatal("fixture must preserve original creation input and acknowledged UID")
	}
	effects := rootPinEffects(t, preparer, original)
	roots := [][]byte{ownerConfigurationTestRoot(t, time.Now())}
	resources, err := NewInitialRuntimeResources(context.Background(), preparer, effects, roots)
	if err != nil {
		t.Fatal("completed original creation input rejected", err)
	}
	defer resources.Close()
	if preparer.rootUID != "" || effects.effects != 0 {
		t.Fatal("constructor changed shared preparer or entered SQL effects")
	}
	if _, err = resources.current(context.Background()); err != nil {
		t.Fatal("current original acknowledged root rejected", err)
	}
	source, administration := rootPinSource(t, resources, effects)
	bridge, err := NewInitialRuntimeBridge(context.Background(), preparer, source, effects, administration)
	if err != nil {
		t.Fatal("bridge rejected original unpinned creation input", err)
	}
	defer bridge.Close()
	if preparer.rootUID != "" {
		t.Fatal("bridge changed shared preparer")
	}

	// Explicitly pinned reopens and original creation inputs must derive the
	// same durable binding. Root pinning is not a new attempt or new authority.
	f.config.RootUID = original.RootUID
	pinned := f.preparer(t)
	defer pinned.Close()
	again, err := NewInitialRuntimeResources(context.Background(), pinned, effects, roots)
	if err != nil {
		t.Fatal("exact pinned reopen", err)
	}
	defer again.Close()
	b2, err := NewInitialRuntimeBridge(context.Background(), pinned, source, effects, administration)
	if err != nil {
		t.Fatal("exact pinned bridge reopen", err)
	}
	defer b2.Close()
	if again.binding != resources.binding || b2.binding != bridge.binding {
		t.Fatal("same actual original root changed durable binding")
	}
	f.config.RootUID = ownerID(1200)
	wrong := f.preparer(t)
	defer wrong.Close()
	if value, e := NewInitialRuntimeResources(context.Background(), wrong, effects, roots); e == nil {
		value.Close()
		t.Fatal("explicit contrary root pin ignored")
	}

	// A self-consistent replacement cannot become the current root for an
	// already-constructed component even though the shared original input is
	// still empty. This deliberately changes both the metadata and self pin.
	replacement := original
	replacement.RootUID = ownerID(1201)
	setSyntheticHandoverRoot(t, f, preparer, replacement)
	f.mu.Lock()
	f.objects[preparer.rootPath()]["metadata"].(map[string]any)["uid"] = replacement.RootUID
	f.mu.Unlock()
	if _, e := resources.current(context.Background()); !errors.Is(e, cfg.ErrChanged) {
		t.Fatal("resource component adopted changed root", e)
	}
	ctx, end := context.WithTimeout(context.Background(), 5*time.Second)
	defer end()
	if _, _, _, e := bridge.current(ctx, contracts.InitialRuntimeBridgeState{}); !errors.Is(e, cfg.ErrChanged) {
		t.Fatal("bridge component adopted changed root", e)
	}
	if _, e := bridge.CreateInitialRuntimeBridge(context.Background()); !errors.Is(e, cfg.ErrChanged) {
		t.Fatal("bridge CREATE adopted changed root", e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for path, count := range f.posts {
		if strings.HasSuffix(path, "/secrets/"+bridge.name()) && count != 0 {
			t.Fatal("changed-root bridge journal was created")
		}
	}
}
