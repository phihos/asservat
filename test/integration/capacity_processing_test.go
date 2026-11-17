package integration

import (
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	capacityapp "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/audit"
)

// capacityAuditProfiles caches provisioned profiles per permission root.
var capacityAuditProfiles sync.Map

// readAuditProfiles provisions the normal and resolution audit pools that
// capacity no longer creates (ADR-330 D6) and returns their profiles. Only
// tests that still compose the encrypted operation auditor use it; remove it
// with that auditor.
func (f *capacitySQLFixture) readAuditProfiles(t *testing.T) audit.AcceptedCapacityAuditProfiles {
	t.Helper()
	if v, ok := capacityAuditProfiles.Load(f.input.PermissionRootID); ok {
		return v.(audit.AcceptedCapacityAuditProfiles)
	}
	ledger, err := postgres.New(f.ctx, f.fixturePool("operation_audit_config_runtime", "synthetic-operation-config"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Hour)
	out := audit.AcceptedCapacityAuditProfiles{Format: audit.CapacityAuditProfilesFormat, RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID,
		QualificationID: f.qualification.ID, AccountVersion: f.input.AccountVersion, QualificationDigest: f.qualification.Digest, PlanDigest: f.qualification.Digest,
		ConfigurationRevision: 1, SourceRevision: 1, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	root := f.qualification.RootBacking
	for _, lane := range []struct {
		name string
		dst  *audit.CapacityAuditProfile
		src  capacityapp.RootAuditBacking
	}{{"normal", &out.Normal, root.Normal}, {"resolution", &out.Resolution, root.Resolution}} {
		p := lane.src.Policy
		p.BackingRevision, p.ValidUntil = 1, until
		if err = ledger.ProvisionOperationAuditPool(f.ctx, auditapp.OperationAuditPool{RootID: f.input.PermissionRootID, Lane: lane.name, AccountVersion: f.input.AccountVersion,
			Accounts: lane.src.Accounts, RecordsPerAccount: lane.src.RecordsPerAccount, RetainedSeconds: lane.src.RetainedSeconds, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), ValidUntil: until}); err != nil {
			t.Fatal("provision fixture audit pool", lane.name, err)
		}
		*lane.dst = audit.CapacityAuditProfile{Policy: p, RetainedSeconds: lane.src.RetainedSeconds}
	}
	capacityAuditProfiles.Store(f.input.PermissionRootID, out)
	return out
}
