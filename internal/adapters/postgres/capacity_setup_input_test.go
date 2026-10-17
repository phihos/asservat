package postgres

import (
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// Synthetic static qualification only; these quantities are not a measured
// provider profile and cannot make a real source, role or SQL root current.
func capacitySetupHistoryFixture() app.ContextBackingHistory {
	id := "30000000-0000-4000-8000-000000000001"
	return app.ContextBackingHistory{
		Capture: audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{1}, Layout: audit.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3}, CapturePurgeLeases: 4,
		Native: authorization.NativeHistoryQualification{ID: id, Digest: artifact.Digest{2}, RowBytes: 64 << 10, TransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 3},
		Stop:   audit.DownloadStopLifecyclePolicy{RootID: id, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, QualificationID: id, PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4}, QualificationDigest: artifact.Digest{5}, Layout: audit.DownloadStopHistoryLayout, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3, MaxPurgeLeases: 4},
	}
}

func capacitySetupBackingFixture() (app.RootBackingInput, app.ProtectedPoolPlan) {
	h := capacitySetupHistoryFixture()
	root := h.Stop.RootID
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	lane := func(name, layout string, accounts, records int64) app.RootAuditBacking {
		q := h.Capture
		q.Layout = layout
		b, w := q.SlotBacking(h.CapturePurgeLeases)
		return app.RootAuditBacking{Accounts: accounts, RecordsPerAccount: records, RetainedSeconds: 10000, Policy: audit.OperationLifecyclePolicy{
			RootID: root, Lane: name, InstallationID: root, StoreID: root, PolicyID: root, BackupProfileID: root, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2},
			BackingRevision: 1, MetadataSlots: accounts * records, BackupReservedBytes: accounts * records * b, WALReservedBytes: accounts * records * w, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60,
			ValidUntil: n, MaxPurgeLeases: h.CapturePurgeLeases, History: &q, OverdueTerminal: audit.OperationOverdueTerminal,
		}}
	}
	in := app.RootBackingInput{Format: app.RootBackingFormat, RootID: root, InstallationID: root, QualificationID: root, QualificationDigest: artifact.Digest{5}, SystemPoolUID: "system-pool", AccountVersion: "account-v1", Accounts: 2, RecordsPerAccount: 3,
		AdmissionSeconds: 3600, ProcessingEpoch: root, ProcessingSourceUID: root, ProcessingProtectionDigest: artifact.Digest{1},
		Capture: lane("capture", audit.CaptureOperationHistoryLayout, 2, 3), Normal: lane("normal", audit.OperationVerificationHistoryLayout, 4, 7), Resolution: lane("resolution", audit.OperationVerificationHistoryLayout, 4, 2), Processing: lane("processing", audit.ProcessingReleaseHistoryLayout, 2, 16),
		ContextHistory: h, StopRetainedSeconds: 10000, Metadata: app.RootMetadataQualification{ID: root, Layout: app.RootMetadataLayout, Digest: artifact.Digest{9}, FixedRowBytes: 1 << 20, AccountRowBytes: 256 << 10, RecordRowBytes: 128 << 10, RecordWALBytes: 8 << 20, RecordKeyAttempts: 16, TransitionWALBytes: 1 << 20, BackupCopies: 2, WALCopies: 2, ConfigurationTransitions: 100},
		Envelope: app.RootBackingEnvelope{SystemObjects: app.BudgetAmount{Bytes: math.MaxInt64, Objects: math.MaxInt64}, SQLBytes: math.MaxInt64, BackupBytes: math.MaxInt64, WALBytes: math.MaxInt64, KeyAttempts: math.MaxInt64},
	}
	in.ProcessingState = privacy.ProcessingBacking{RootID: root, InstallationID: root, PolicyID: root, BackupIdentity: root, PolicyDigest: artifact.Digest{8}, BackupDigest: artifact.Digest{7}, History: privacy.ProcessingHistoryQualification{Format: privacy.ProcessingHistoryFormat, ID: root, Digest: artifact.Digest{6}, RowBytes: 16 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 2, WALCopies: 2}, MaxCaptures: 6, MaxRules: 2, MaxRootTransitions: 8, BackupHorizonSeconds: 3600, CleanupSeconds: 60, ValidUntil: n, RetireBy: n.Add(7260 * time.Second)}
	in.ProcessingState.BackupBytes, in.ProcessingState.WALBytes, _ = in.ProcessingState.RequiredBytes()
	pool := app.ProtectedPoolPlan{Format: app.ProtectedPoolPlanFormat, UID: in.SystemPoolUID, System: app.BudgetAmount{Bytes: math.MaxInt64, Objects: math.MaxInt64}}
	return in, pool
}

func capacitySetupInputFixture(t *testing.T) (contracts.CapacityRootSetup, contracts.PublicRuntimeRoles) {
	t.Helper()
	r, _ := capacitySetupBackingFixture()
	q := app.CapacityQualification{ID: r.QualificationID, Digest: r.QualificationDigest, RootBacking: r,
		NamespaceGuards: []app.CapacityNamespaceQualification{{ClusterID: r.RootID, Digest: artifact.Digest{1}, Keys: []string{"team"}}},
		Backends:        []app.CapacityBackendQualification{{Layout: app.CapacityBackendLayout, ID: r.RootID, Digest: artifact.Digest{4}, PoolUID: r.SystemPoolUID, StorageProfile: "test", CapacityID: r.RootID, PoolID: r.RootID, EvidenceStoreID: r.RootID, AuditStoreID: r.Capture.Policy.StoreID, Usable: app.BudgetAmount{Bytes: 1 << 50, Objects: 1000000000}}}}
	raw, e := json.Marshal(q)
	if e != nil {
		t.Fatal(e)
	}
	input := contracts.CapacityRootSetup{Format: contracts.CapacityRootSetupFormat, InstallationID: r.InstallationID, InitialClaimID: r.RootID, PermissionRootID: r.RootID, RoleRootUID: r.RootID, RoleSetupID: r.RootID, ControlClusterID: r.RootID, ControlNamespaceUID: "namespace-uid", SourceGuardDigest: strings.Repeat("1", 64), AccountVersion: r.AccountVersion, Qualification: raw}
	original := contracts.PublicRuntimeRoles{InstallationID: input.InstallationID, InitialClaimID: input.InitialClaimID}
	return input, original
}

func TestCapacitySetupInputChecksCompleteBackingBeforeClaim(t *testing.T) {
	for _, name := range []string{"valid", "underfunded-wal", "wrong-native-history", "wrong-root", "zero-guard", "unknown-top", "unknown-nested", "duplicate", "missing", "case", "null"} {
		t.Run(name, func(t *testing.T) {
			in, original := capacitySetupInputFixture(t)
			switch name {
			case "underfunded-wal", "wrong-native-history":
				var q app.CapacityQualification
				if e := json.Unmarshal(in.Qualification, &q); e != nil {
					t.Fatal(e)
				}
				if name == "underfunded-wal" {
					q.RootBacking.Envelope.WALBytes = 1
				} else {
					q.RootBacking.ContextHistory.Native.Digest = artifact.Digest{}
				}
				in.Qualification, _ = json.Marshal(q)
			case "wrong-root":
				in.PermissionRootID = "20000000-0000-4000-8000-000000000002"
			case "zero-guard":
				in.SourceGuardDigest = strings.Repeat("0", 64)
			case "unknown-top":
				in.Qualification = append(in.Qualification[:len(in.Qualification)-1], []byte(`,"Authority":true}`)...)
			case "unknown-nested":
				in.Qualification = bytes.Replace(in.Qualification, []byte(`"RootBacking":{`), []byte(`"RootBacking":{"Authority":true,`), 1)
			case "duplicate":
				in.Qualification = append(in.Qualification[:len(in.Qualification)-1], []byte(`,"ID":"30000000-0000-4000-8000-000000000001"}`)...)
			case "missing":
				in.Qualification = bytes.Replace(in.Qualification, []byte(`"ConfigurationTransitions":100`), []byte(`"configurationTransitions":100`), 1)
			case "case":
				in.Qualification = bytes.Replace(in.Qualification, []byte(`"NamespaceGuards":`), []byte(`"namespaceGuards":`), 1)
			case "null":
				in.Qualification = bytes.Replace(in.Qualification, []byte(`"Digest":[5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]`), []byte(`"Digest":null`), 1)
			}
			got, e := decodeCapacitySetupInput(in, original)
			if name != "valid" {
				if e == nil {
					t.Fatal("unsafe setup reached irreversible claim boundary")
				}
				return
			}
			if e != nil || len(got.digest) != 64 {
				t.Fatalf("closed static input unavailable: %v", e)
			}
			in.Qualification[0] = 'x'
			if got.bytes[0] != '{' || !json.Valid(got.value.Qualification) {
				t.Fatal("caller mutated retained setup input")
			}
		})
	}
}
