package integration

import (
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/privacy"
)

// This attempts the provisional S02 envelope; a compiled test is not evidence
// that its original five-second SQL transaction bound is feasible.
const capacityNativeAccounts = 16

// Fixed synthetic physical-history qualification is an explicit test input.
// It is not SQLHistoryCoverage, provider settlement, or permission to reuse a
// configuration window. No stored SQL timestamps are backdated by this helper.
func capacityNativeHistory(root, installation string) app.ContextBackingHistory {
	id := root
	return app.ContextBackingHistory{
		Capture: audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{1}, Layout: audit.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3}, CapturePurgeLeases: 4,
		Native: authorization.NativeHistoryQualification{ID: id, Digest: artifact.Digest{2}, RowBytes: 64 << 10, TransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 3},
	}
}

func capacityNativeBacking(root, installation, accountVersion string) app.RootBackingInput {
	h := capacityNativeHistory(root, installation)
	n := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	lane := func(name, layout string, accounts, records int64) app.RootAuditBacking {
		q := h.Capture
		q.Layout = layout
		b, w := q.SlotBacking(h.CapturePurgeLeases)
		return app.RootAuditBacking{Accounts: accounts, RecordsPerAccount: records, RetainedSeconds: 10000, Policy: audit.OperationLifecyclePolicy{
			RootID: root, Lane: name, InstallationID: installation, StoreID: root, PolicyID: root, BackupProfileID: root, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2},
			BackingRevision: 1, MetadataSlots: accounts * records, BackupReservedBytes: accounts * records * b, WALReservedBytes: accounts * records * w, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60,
			ValidUntil: n, MaxPurgeLeases: h.CapturePurgeLeases, History: &q, OverdueTerminal: audit.OperationOverdueTerminal,
		}}
	}
	in := app.RootBackingInput{Format: app.RootBackingFormat, RootID: root, InstallationID: installation, QualificationID: root, QualificationDigest: artifact.Digest{5}, SystemPoolUID: "system-pool", AccountVersion: accountVersion, Accounts: capacityNativeAccounts, RecordsPerAccount: 3,
		AdmissionSeconds: 60, ProcessingEpoch: root, ProcessingSourceUID: root, ProcessingProtectionDigest: artifact.Digest{1},
		Capture: lane("capture", audit.CaptureOperationHistoryLayout, capacityNativeAccounts, 3), Normal: lane("normal", audit.OperationVerificationHistoryLayout, 4, 7), Resolution: lane("resolution", audit.OperationVerificationHistoryLayout, 4, 2), Processing: lane("processing", audit.ProcessingReleaseHistoryLayout, 2, 16),
		ContextHistory: h, Metadata: app.RootMetadataQualification{ID: root, Layout: app.RootMetadataLayout, Digest: artifact.Digest{9}, FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, BackupCopies: 2, WALCopies: 2, ConfigurationTransitions: 100},
		Envelope: app.RootBackingEnvelope{SystemObjects: app.BudgetAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
	}
	in.ProcessingState = privacy.ProcessingBacking{RootID: root, InstallationID: installation, PolicyID: root, BackupIdentity: root, PolicyDigest: artifact.Digest{8}, BackupDigest: artifact.Digest{7}, History: privacy.ProcessingHistoryQualification{Format: privacy.ProcessingHistoryFormat, ID: root, Digest: artifact.Digest{6}, RowBytes: 16 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: capacityNativeAccounts * 3, MaxRules: 2, MaxRootTransitions: 8, BackupHorizonSeconds: 3600, CleanupSeconds: 60, ValidUntil: n, RetireBy: n.Add(7260 * time.Second)}
	in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	return in
}

func capacityNativeQualification(t *testing.T, root, installation, cluster, accountVersion string) app.CapacityQualification {
	t.Helper()
	in := capacityNativeBacking(root, installation, accountVersion)
	in.SystemPoolUID = custodyID()
	q := app.CapacityQualification{ID: in.QualificationID, Digest: in.QualificationDigest, RootBacking: in, NamespaceGuards: []app.CapacityNamespaceQualification{{ClusterID: cluster, Digest: artifact.Digest{12}, Keys: []string{"team"}}}, Backends: []app.CapacityBackendQualification{{Layout: app.CapacityBackendLayout, ID: custodyID(), Digest: artifact.Digest{13}, PoolUID: in.SystemPoolUID, StorageProfile: "synthetic-dedicated", CapacityID: custodyID(), PoolID: custodyID(), EvidenceStoreID: custodyID(), AuditStoreID: in.Capture.Policy.StoreID, Usable: app.BudgetAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
	if !q.Valid() || !app.ValidateRootBackingInput(in) {
		t.Fatal("synthetic complete backing invalid")
	}
	return q
}

// capacityNativeValues are the fixture's Helm capacity values: 16 workload
// shares of 1 MiB with a 4 MiB burst limit.
func capacityNativeValues() app.CapacityValues {
	return app.CapacityValues{EvidenceBytes: 17 << 20, ReserveBytes: 1 << 20, ShareBytes: 1 << 20, LimitBytes: 4 << 20, MaxConcurrentExpensive: 1, OnFull: "RejectNewExpensive"}
}
