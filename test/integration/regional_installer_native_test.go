package integration

import (
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/google/uuid"
)

// syntheticConnectorBacking is a valid prepaid-retirement backing for root.
func syntheticConnectorBacking(t *testing.T, root, installation string) app.ConnectorIdentityBacking {
	t.Helper()
	q := audit.OperationHistoryQualification{ID: uuid.NewString(), Digest: artifact.Digest{2}, Layout: audit.ConnectorRetirementHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	b := app.ConnectorIdentityBacking{AccountVersion: "account-v1", AccountLimit: 2, RecordsPerAccount: 256, RetainedSeconds: 3600, ProfileLimit: 2, SourceTransitionLimit: 64,
		Policy: audit.OperationLifecyclePolicy{RootID: root, Lane: "identity", InstallationID: installation, StoreID: uuid.NewString(), PolicyID: uuid.NewString(), BackupProfileID: uuid.NewString(), PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4},
			BackingRevision: 1, MetadataSlots: 512, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), History: &q, OverdueTerminal: audit.OperationOverdueTerminal}}
	bb, ww := q.SlotBacking(b.Policy.MaxPurgeLeases)
	b.Policy.BackupReservedBytes, b.Policy.WALReservedBytes = bb*b.Policy.MetadataSlots, ww*b.Policy.MetadataSlots
	rows := 1 + b.ProfileLimit + b.ProfileLimit*(b.SourceTransitionLimit+1)
	b.SourceBackupReservedBytes = rows * 2 * q.MaximumRowFootprintBytes * q.BackupCopies
	b.SourceWALReservedBytes = (2*b.SourceTransitionLimit + app.ConnectorRetirementTicketTransitions*b.ProfileLimit*(b.SourceTransitionLimit+1)) * q.MaximumTransitionWALBytes * q.WALCopies
	if !b.Valid() {
		t.Fatal("synthetic backing invalid")
	}
	return b
}
