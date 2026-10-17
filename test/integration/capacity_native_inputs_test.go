package integration

import (
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/privacy"
	"testing"
	"time"
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
		Stop:   audit.DownloadStopLifecyclePolicy{RootID: id, InstallationID: installation, StoreID: id, PolicyID: id, BackupProfileID: id, QualificationID: id, PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4}, QualificationDigest: artifact.Digest{5}, Layout: audit.DownloadStopHistoryLayout, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3, MaxPurgeLeases: 4},
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
		ContextHistory: h, StopRetainedSeconds: 10000, Metadata: app.RootMetadataQualification{ID: root, Layout: app.RootMetadataLayout, Digest: artifact.Digest{9}, FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, BackupCopies: 2, WALCopies: 2, ConfigurationTransitions: 100},
		Envelope: app.RootBackingEnvelope{SystemObjects: app.BudgetAmount{Bytes: 1 << 50, Objects: 1 << 50}, SQLBytes: 1 << 50, BackupBytes: 1 << 50, WALBytes: 1 << 50, KeyAttempts: 1 << 50},
	}
	in.ProcessingState = privacy.ProcessingBacking{RootID: root, InstallationID: installation, PolicyID: root, BackupIdentity: root, PolicyDigest: artifact.Digest{8}, BackupDigest: artifact.Digest{7}, History: privacy.ProcessingHistoryQualification{Format: privacy.ProcessingHistoryFormat, ID: root, Digest: artifact.Digest{6}, RowBytes: 16 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: capacityNativeAccounts * 3, MaxRules: 2, MaxRootTransitions: 8, BackupHorizonSeconds: 3600, CleanupSeconds: 60, ValidUntil: n, RetireBy: n.Add(7260 * time.Second)}
	in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	return in
}

func capacityNativeQualification(t *testing.T, root, installation, cluster, controlUID, accountVersion string) (app.CapacityQualification, app.CapacitySnapshot) {
	t.Helper()
	in := capacityNativeBacking(root, installation, accountVersion)
	in.SystemPoolUID = custodyID()
	unit := (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes()
	protected := app.BudgetAmount{Bytes: 3 * unit, Objects: 12}
	policy := app.PolicyBudgetInput{Name: "applications", Pool: "capacity", Cluster: cluster, Protected: protected, Hard: protected, Context: protected, NamespaceMaximum: app.BudgetAmount{Bytes: capacityNativeAccounts * protected.Bytes, Objects: capacityNativeAccounts * protected.Objects}, NamespaceAccounts: capacityNativeAccounts}
	pool := app.PoolBudgetInput{Name: "capacity", Capacity: app.BudgetAmount{Bytes: 1 << 50, Objects: 1000000000}, Safety: app.BudgetAmount{Bytes: 1 << 20, Objects: 16}, System: app.BudgetAmount{Bytes: 1 << 40, Objects: 1000000}, Burst: app.BudgetAmount{Bytes: unit, Objects: 4}, Slots: []app.ProtectedSlotInput{{Policy: policy.Name, Workloads: capacityNativeAccounts, Protected: protected}}}
	n := time.Now().UTC().Truncate(time.Microsecond)
	ref := func(kind, name, uid string) cfg.Resource {
		return cfg.Resource{ClusterID: cluster, Namespace: "control", NamespaceUID: controlUID, Kind: kind, Name: name, UID: uid, Generation: 1, ResourceVersion: "synthetic-1", SpecDigest: artifact.Digest{11}}
	}
	source := app.CapacitySnapshot{ClusterID: cluster, ControlNamespace: cfg.NamespaceRef{Name: "control", UID: controlUID}, PoolResourceVersion: "synthetic-pool-1", PolicyResourceVersion: "synthetic-policy-1", ObservedAt: n, FreshUntil: n.Add(5 * time.Second), Pools: []app.PoolObservation{{Resource: ref("EvidenceStoragePool", pool.Name, in.SystemPoolUID), StorageProfile: "synthetic-dedicated", Assurance: "qualifiedReservedBackend", Budget: &pool}}, Policies: []app.BudgetPolicyObservation{{Resource: ref("EvidenceBudgetPolicy", policy.Name, custodyID()), Pool: pool.Name, Scope: &app.BudgetScope{ClusterID: cluster, NamespaceLabels: map[string]string{"team": "synthetic"}}, Budget: &policy}}}
	q := app.CapacityQualification{ID: in.QualificationID, Digest: in.QualificationDigest, RootBacking: in, NamespaceGuards: []app.CapacityNamespaceQualification{{ClusterID: cluster, Digest: artifact.Digest{12}, Keys: []string{"team"}}}, Backends: []app.CapacityBackendQualification{{Layout: app.CapacityBackendLayout, ID: custodyID(), Digest: artifact.Digest{13}, PoolUID: in.SystemPoolUID, StorageProfile: "synthetic-dedicated", CapacityID: custodyID(), PoolID: custodyID(), EvidenceStoreID: custodyID(), AuditStoreID: in.Capture.Policy.StoreID, Usable: pool.Capacity}}}
	compiled, err := app.CompileProtectedPoolPlan(source, pool.Name)
	if err != nil {
		t.Fatal("synthetic exact source plan invalid", err)
	}
	if _, err = app.CompileQualifiedRootBacking(q, compiled); err != nil {
		t.Fatal("synthetic complete backing invalid", err)
	}
	return q, source
}

func capacityNativeSource(t *testing.T, template app.CapacitySnapshot, n, until time.Time) app.CapacitySourceObservation {
	t.Helper()
	template.ObservedAt, template.FreshUntil = n, until
	versions := make([]app.CapacitySourceVersion, 0, len(template.Pools)+len(template.Policies))
	add := func(r cfg.Resource) {
		versions = append(versions, app.CapacitySourceVersion{Kind: r.Kind, Name: r.Name, UID: r.UID, Generation: r.Generation, Deleting: r.Deleting, Spec: r.SpecDigest})
	}
	for _, p := range template.Pools {
		add(p.Resource)
	}
	for _, p := range template.Policies {
		add(p.Resource)
	}
	digest, err := app.CapacitySourceDigest(template, versions)
	if err != nil {
		t.Fatal("synthetic current source invalid", err)
	}
	return app.CapacitySourceObservation{Snapshot: template, Versions: versions, Digest: digest}
}
