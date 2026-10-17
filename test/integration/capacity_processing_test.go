package integration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/capacity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// Capacity only prepays processing state. The distinct privacy operator must
// still perform actual independently audited initialization. This helper does
// not create or replace processing/normal audit backing as older fixtures do.
func (f *capacitySQLFixture) initializeManagedProcessing(t *testing.T, root app.RootConfiguration) {
	t.Helper()
	f.fresh(t)
	guard, err := postgres.NewRecoveryTransactionGuard(f.input.PermissionRootID, f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := postgres.NewRecoveryReader(f.ctx, f.fixturePool("peer_read_runtime", "synthetic-peer-read"), f.input.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	accepted := f.readAuditProfiles(t)
	policy := accepted.Normal.Policy
	if policy.BackingRevision != root.Revision || !policy.ValidUntil.Equal(root.PlannedUntil) {
		t.Fatal("normal profile differs from original Ready root")
	}
	journal, err := postgres.NewHealthyOperationJournal(f.ctx, f.fixturePool("operation_audit_runtime", "synthetic-operation-journal"), policy, guard)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := postgres.NewOperationAcknowledgements(f.ctx, f.fixturePool("operation_audit_ack_runtime", "synthetic-operation-ack"), policy.RootID, "normal", guard)
	if err != nil {
		t.Fatal(err)
	}
	lifecycle, err := postgres.NewOperationLifecycles(f.ctx, f.fixturePool("operation_audit_runtime", "synthetic-operation-journal"), policy.RootID, "normal", guard)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := objectstore.NewClosedOperationAuditObjects(f.store, policy.StoreID, f.keys, f.keys)
	if err != nil {
		t.Fatal(err)
	}
	auditor, err := auditapp.NewHealthyOperationAuditor(policy, journal, ack, &objectstore.OperationAuditObjects{Store: f.store, Seal: f.keys, Open: f.keys}, objects, lifecycle, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	material := f.root.value.State.MAC
	mac, err := auditapp.NewOperationMAC(material.InputVersion, material.InputKey, material.AccountVersion, material.AccountKey)
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	decisions, err := postgres.NewProcessingDecisions(f.ctx, f.fixturePool("processing_decision_runtime", "synthetic-processing-decision"), f.input.PermissionRootID, guard)
	if err != nil {
		t.Fatal(err)
	}
	actor := processingTestIdentity{value: identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.test", Subject: "capacity-privacy-operator", ClientID: "console", Kind: identity.Human}, Groups: []string{"operators"}, Scopes: []string{"evidence:privacy"}, Policy: identity.Revision{UID: "synthetic-privacy-identity", Generation: 1, Digest: artifact.Digest{28}}}}
	service := privacyapp.ProcessingChanges{RootID: f.input.PermissionRootID, InstallationID: f.input.InstallationID, Policies: processingTestPolicy{value: f.processingPolicy}, Recovery: recovery, Decisions: decisions, Audit: auditor, MAC: mac, AuditPolicy: policy, RetainedSeconds: accepted.Normal.RetainedSeconds, Now: time.Now}
	if _, err = service.Change(f.ctx, actor, privacy.ProcessingChange{RequestID: custodyID(), Action: "initialize_processing"}); err != nil {
		t.Fatal("independent managed processing initialization", err)
	}
}

func (f *capacitySQLFixture) readAuditProfiles(t *testing.T) audit.AcceptedCapacityAuditProfiles {
	t.Helper()
	r, err := postgres.NewCapacityAuditProfiles(f.ctx, f.roles["capacity-profile-read"], f.input.PermissionRootID, f.input.InstallationID, f.qualification.ID, f.qualification.Digest, f.input.AccountVersion)
	if err != nil {
		t.Fatal("scoped profile constructor", err)
	}
	value, err := r.ReadCapacityAuditProfiles(f.ctx)
	if err != nil {
		t.Fatal("current exact scoped profiles", err)
	}
	return value
}
