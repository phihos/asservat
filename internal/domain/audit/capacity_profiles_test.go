package audit

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func capacityAuditProfilesFixture() AcceptedCapacityAuditProfiles {
	id := "40000000-0000-4000-8000-000000000001"
	n := time.Date(2026, 10, 12, 12, 0, 0, 123456000, time.UTC)
	lane := func(name string) CapacityAuditProfile {
		q := OperationHistoryQualification{ID: id, Digest: artifact.Digest{1}, Layout: OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}
		b, w := q.SlotBacking(2)
		return CapacityAuditProfile{Policy: OperationLifecyclePolicy{RootID: id, Lane: name, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{2}, BackupProfileDigest: artifact.Digest{3}, BackingRevision: 2, MetadataSlots: 4, BackupReservedBytes: 4 * b, WALReservedBytes: 4 * w, BackupHorizonSeconds: 0, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), MaxPurgeLeases: 2, History: &q, OverdueTerminal: OperationOverdueTerminal}, RetainedSeconds: 60}
	}
	return AcceptedCapacityAuditProfiles{Format: CapacityAuditProfilesFormat, RootID: id, InstallationID: id, QualificationID: id, AccountVersion: "original-account-v1", QualificationDigest: artifact.Digest{4}, PlanDigest: artifact.Digest{5}, ConfigurationRevision: 2, SourceRevision: 8, Normal: lane("normal"), Resolution: lane("resolution"), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
}

func TestCapacityAuditProfilesPreserveExactLaneAndOriginalInterval(t *testing.T) {
	for _, name := range []string{"valid", "normal-is-resolution", "legacy-layout", "other-root", "unbacked", "wrong-revision", "not-verifier-backed", "no-overdue", "invalid-retention", "earlier-policy", "future-observation", "expired", "renewed-interval", "submicro", "wrong-store", "no-plan", "no-account"} {
		t.Run(name, func(t *testing.T) {
			v := capacityAuditProfilesFixture()
			now := v.ObservedAt.Add(time.Second)
			switch name {
			case "normal-is-resolution":
				v.Normal.Policy.Lane = "resolution"
			case "legacy-layout":
				v.Normal.Policy.History.Layout = OperationHistoryLayout
			case "other-root":
				v.Normal.Policy.RootID = "40000000-0000-4000-8000-000000000002"
			case "unbacked":
				v.Resolution.Policy.MetadataSlots++
			case "wrong-revision":
				v.Resolution.Policy.BackingRevision++
			case "not-verifier-backed":
				v.Normal.Policy.History = nil
			case "no-overdue":
				v.Normal.Policy.OverdueTerminal = ""
			case "invalid-retention":
				v.Normal.RetainedSeconds = 34
			case "earlier-policy":
				v.Normal.Policy.ValidUntil = now.Add(time.Second)
			case "future-observation":
				now = v.ObservedAt.Add(-time.Microsecond)
			case "expired":
				now = v.FreshUntil
			case "renewed-interval":
				v.FreshUntil = v.FreshUntil.Add(time.Microsecond)
			case "submicro":
				v.ObservedAt = v.ObservedAt.Add(time.Nanosecond)
			case "wrong-store":
				v.Resolution.Policy.StoreID = "40000000-0000-4000-8000-000000000002"
			case "no-plan":
				v.PlanDigest = artifact.Digest{}
			case "no-account":
				v.AccountVersion = ""
			}
			if v.Valid(now) != (name == "valid") {
				t.Fatal("profile validity differs from original accepted lane/interval")
			}
		})
	}
}
