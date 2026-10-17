package capacity

import (
	"bytes"
	"math"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/privacy"
)

func capacityRootBackingFixture() (RootBackingInput, ProtectedPoolPlan) {
	h := contextBackingHistoryFixture()
	root := h.Stop.RootID
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	lane := func(name, layout string, accounts, records int64) RootAuditBacking {
		q := h.Capture
		q.Layout = layout
		b, w := q.SlotBacking(h.CapturePurgeLeases)
		return RootAuditBacking{Accounts: accounts, RecordsPerAccount: records, RetainedSeconds: 10000, Policy: audit.OperationLifecyclePolicy{
			RootID: root, Lane: name, InstallationID: root, StoreID: root, PolicyID: root, BackupProfileID: root, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2},
			BackingRevision: 1, MetadataSlots: accounts * records, BackupReservedBytes: accounts * records * b, WALReservedBytes: accounts * records * w, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60,
			ValidUntil: n, MaxPurgeLeases: h.CapturePurgeLeases, History: &q, OverdueTerminal: audit.OperationOverdueTerminal,
		}}
	}
	in := RootBackingInput{Format: RootBackingFormat, RootID: root, InstallationID: root, QualificationID: root, QualificationDigest: artifact.Digest{5}, SystemPoolUID: "system-pool", AccountVersion: "account-v1", Accounts: 2, RecordsPerAccount: 3,
		AdmissionSeconds: 3600, ProcessingEpoch: root, ProcessingSourceUID: root, ProcessingProtectionDigest: artifact.Digest{1},
		Capture: lane("capture", audit.CaptureOperationHistoryLayout, 2, 3), Normal: lane("normal", audit.OperationVerificationHistoryLayout, 4, 7), Resolution: lane("resolution", audit.OperationVerificationHistoryLayout, 4, 2), Processing: lane("processing", audit.ProcessingReleaseHistoryLayout, 2, 16),
		ContextHistory: h, StopRetainedSeconds: 10000, Metadata: RootMetadataQualification{ID: root, Layout: RootMetadataLayout, Digest: artifact.Digest{9}, FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, BackupCopies: 2, WALCopies: 2, ConfigurationTransitions: 100},
		Envelope: RootBackingEnvelope{SystemObjects: BudgetAmount{math.MaxInt64, math.MaxInt64}, SQLBytes: math.MaxInt64, BackupBytes: math.MaxInt64, WALBytes: math.MaxInt64, KeyAttempts: math.MaxInt64},
	}
	in.ProcessingState = privacy.ProcessingBacking{RootID: root, InstallationID: root, PolicyID: root, BackupIdentity: root, PolicyDigest: artifact.Digest{8}, BackupDigest: artifact.Digest{7}, History: privacy.ProcessingHistoryQualification{Format: privacy.ProcessingHistoryFormat, ID: root, Digest: artifact.Digest{6}, RowBytes: 16 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: 6, MaxRules: 2, MaxRootTransitions: 8, BackupHorizonSeconds: 3600, CleanupSeconds: 60, ValidUntil: n, RetireBy: n.Add(7260 * time.Second)}
	in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	pool := ProtectedPoolPlan{Format: ProtectedPoolPlanFormat, UID: in.SystemPoolUID, System: BudgetAmount{math.MaxInt64, math.MaxInt64}}
	return in, pool
}

func TestCapacityRootBackingPaysSharedLanesAndFullAccountCeilingOnce(t *testing.T) {
	in, pool := capacityRootBackingFixture()
	p, e := CompileRootBacking(in, pool)
	if e != nil {
		t.Fatal(e)
	}
	totals := p.Totals()
	work, e := CompileContextProtocolBacking(BudgetAmount{3 * (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes(), 12}, in.ContextHistory)
	if e != nil {
		t.Fatal(e)
	}
	rootSlots := in.Normal.Policy.MetadataSlots + in.Resolution.Policy.MetadataSlots + in.Processing.Policy.MetadataSlots
	expected, _ := work.ProtocolSystemObjects.multiply(2)
	shared, _ := (BudgetAmount{2 * audit.OperationCipherLimit, 2}).multiply(rootSlots)
	expected, _ = expected.add(shared)
	if totals.Records != 6 || totals.SystemObjects != expected || totals.ConfigurationTransitions != 100 {
		t.Fatalf("fixed prepaid root differs: %+v", totals)
	}
	// A third workload cannot enlarge this value; the same original plan is
	// returned regardless of how many source workloads have been discovered.
	second, e := CompileRootBacking(in, pool)
	a, ad := p.Canonical()
	b, bd := second.Canonical()
	if e != nil || ad != bd || !bytes.Equal(a, b) {
		t.Fatal("root plan changed without changed protected input")
	}
	a[0] = 'x'
	again, _ := p.Canonical()
	if bytes.Equal(a, again) {
		t.Fatal("caller mutated retained plan")
	}
	if totals.SQLBytes <= in.Metadata.FixedRowBytes || totals.BackupBytes <= totals.SQLBytes || totals.WALBytes <= in.Metadata.RecordWALBytes*totals.Records || totals.KeyAttempts <= totals.Records*16 {
		t.Fatal("fixed/history/protocol dimensions were omitted")
	}
}

func TestCapacityRootBackingEveryDimensionMustBeIndependentlyFunded(t *testing.T) {
	in, pool := capacityRootBackingFixture()
	p, e := CompileRootBacking(in, pool)
	if e != nil {
		t.Fatal(e)
	}
	need := p.Totals()
	for _, name := range []string{"system-bytes", "system-objects", "pool-bytes", "pool-objects", "sql", "backup", "wal", "keys"} {
		t.Run(name, func(t *testing.T) {
			input, source := capacityRootBackingFixture()
			switch name {
			case "system-bytes":
				input.Envelope.SystemObjects.Bytes = need.SystemObjects.Bytes - 1
			case "system-objects":
				input.Envelope.SystemObjects.Objects = need.SystemObjects.Objects - 1
			case "pool-bytes":
				source.System.Bytes = need.SystemObjects.Bytes - 1
			case "pool-objects":
				source.System.Objects = need.SystemObjects.Objects - 1
			case "sql":
				input.Envelope.SQLBytes = need.SQLBytes - 1
			case "backup":
				input.Envelope.BackupBytes = need.BackupBytes - 1
			case "wal":
				input.Envelope.WALBytes = need.WALBytes - 1
			case "keys":
				input.Envelope.KeyAttempts = need.KeyAttempts - 1
			}
			if _, e := CompileRootBacking(input, source); e != ErrBudgetFull {
				t.Fatalf("underfunded %s accepted: %v", name, e)
			}
		})
	}
	in.Envelope = RootBackingEnvelope{SystemObjects: need.SystemObjects, SQLBytes: need.SQLBytes, BackupBytes: need.BackupBytes, WALBytes: need.WALBytes, KeyAttempts: need.KeyAttempts}
	pool.System = need.SystemObjects
	if _, e := CompileRootBacking(in, pool); e != nil {
		t.Fatal("exact complete envelope rejected", e)
	}
}

func TestCapacityRootBackingRejectsIdentityLayoutAndFiniteBoundChanges(t *testing.T) {
	for _, name := range []string{"seventeenth-account", "zero-records", "session-arithmetic-cap", "wrong-pool", "capture-accounts", "capture-layout", "normal-layout", "normal-history", "overdue", "root", "revision", "slot-count", "retention", "metadata-layout", "metadata-zero", "unfunded-initial-phases", "overflow"} {
		t.Run(name, func(t *testing.T) {
			in, pool := capacityRootBackingFixture()
			switch name {
			case "seventeenth-account":
				in.Accounts = 17
			case "zero-records":
				in.RecordsPerAccount = 0
			case "session-arithmetic-cap":
				in.RecordsPerAccount = 513
			case "wrong-pool":
				pool.UID = "other"
			case "capture-accounts":
				in.Capture.Accounts++
			case "capture-layout":
				in.Capture.Policy.History.Layout = audit.OperationVerificationHistoryLayout
			case "normal-layout":
				in.Normal.Policy.History.Layout = audit.ProcessingReleaseHistoryLayout
			case "normal-history":
				in.Normal.Policy.BackupProfileDigest = artifact.Digest{}
			case "overdue":
				in.Normal.Policy.OverdueTerminal = ""
			case "root":
				in.Normal.Policy.RootID = "30000000-0000-4000-8000-000000000002"
			case "revision":
				in.Normal.Policy.BackingRevision = 2
			case "slot-count":
				in.Normal.Policy.MetadataSlots++
			case "retention":
				in.StopRetainedSeconds = 2*in.ContextHistory.Stop.BackupHorizonSeconds + 3*in.ContextHistory.Stop.CleanupBudgetSeconds + in.ContextHistory.Stop.ProofWindowSeconds + 30
			case "metadata-layout":
				in.Metadata.Layout = "unqualified/v1"
			case "metadata-zero":
				in.Metadata.Digest = artifact.Digest{}
			case "unfunded-initial-phases":
				in.Metadata.ConfigurationTransitions = 3
			case "overflow":
				in.Normal.Accounts = 1000000
				in.Normal.RecordsPerAccount = 1000000
				in.Normal.Policy.MetadataSlots = 1000000000000
				in.Normal.Policy.BackupReservedBytes = math.MaxInt64
				in.Normal.Policy.WALReservedBytes = math.MaxInt64
				in.Resolution.Policy.WALReservedBytes = math.MaxInt64
			}
			if _, e := CompileRootBacking(in, pool); e == nil {
				t.Fatal("invalid root qualification accepted")
			}
		})
	}
}
