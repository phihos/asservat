package presentation

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"testing"
	"time"
)

// This fixture deliberately refuses admission. The real healthy binding must
// reach its journal before any business effect or evidence result can occur.
// Embedded unused ports cannot supply storage or writer-completion authority.
type healthyPresentationJournal struct {
	auditapp.OperationJournal
	auditapp.OperationAcknowledgements
	auditapp.OperationObjects
	auditapp.ClosedOperationObjects
	auditapp.OperationCompletions
	intents []audit.OperationIntent
}

func (j *healthyPresentationJournal) ReserveOperation(_ context.Context, in audit.OperationIntent) (audit.OperationSnapshot, error) {
	j.intents = append(j.intents, in)
	return audit.OperationSnapshot{}, auditapp.ErrUnavailable
}

func TestHealthyAuditPresentationBindsEachLaneBeforeBusinessEffects(t *testing.T) {
	base, identity, _ := auditedFixture(t)
	c := base.config
	c.NormalConcurrency, c.ResolutionConcurrency = 1, 1
	normal, resolution := &healthyPresentationJournal{}, &healthyPresentationJournal{}
	create := func(lane string, j *healthyPresentationJournal) *auditapp.HealthyOperationAuditor {
		t.Helper()
		p := audit.OperationLifecyclePolicy{
			RootID: c.RootID, Lane: lane,
			InstallationID:  "00000000-0000-4000-8000-000000000001",
			StoreID:         "00000000-0000-4000-8000-000000000002",
			PolicyID:        "00000000-0000-4000-8000-000000000003",
			BackupProfileID: "00000000-0000-4000-8000-000000000004",
			PolicyDigest:    artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2},
			BackingRevision: 1, MetadataSlots: 1, MaxPurgeLeases: 2,
			CleanupBudgetSeconds: 1, ProofWindowSeconds: 1,
			ValidUntil: c.Now().Add(time.Hour),
		}
		p.History = &audit.OperationHistoryQualification{ID: p.RootID, Digest: artifact.Digest{4}, Layout: audit.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}
		p.BackupReservedBytes, p.WALReservedBytes = p.History.SlotBacking(p.MaxPurgeLeases)
		a, err := auditapp.NewHealthyOperationAuditor(p, j, j, j, j, j, c.Now)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	n, r := create("normal", normal), create("resolution", resolution)
	inner := base.inner.(*InvestigationOperations)
	s, err := NewHealthyAuditedOperations(c, inner, n, r, base.mac)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"request_capture", "resolve_capture_request"} {
		reply, err := s.Call(context.Background(), identity, operation, []byte(wireRequest))
		if err == nil || len(reply.Body) != 0 || identity.requests != 0 || identity.resolutions != 0 {
			t.Fatalf("%s escaped failed healthy admission: %v", operation, err)
		}
	}
	for lane, j := range map[string]*healthyPresentationJournal{"normal": normal, "resolution": resolution} {
		if len(j.intents) != 1 || j.intents[0].Lifecycle == nil || j.intents[0].Lifecycle.Policy.Lane != lane || !j.intents[0].Lifecycle.Valid(j.intents[0]) {
			t.Fatalf("%s did not receive its frozen healthy lifecycle", lane)
		}
	}
	for _, invalid := range []*auditapp.HealthyOperationAuditor{nil, {}} {
		if _, err = NewHealthyAuditedOperations(c, inner, invalid, r, base.mac); err == nil {
			t.Fatal("invalid normal auditor accepted")
		}
		if _, err = NewHealthyAuditedOperations(c, inner, n, invalid, base.mac); err == nil {
			t.Fatal("invalid resolution auditor accepted")
		}
	}
}
