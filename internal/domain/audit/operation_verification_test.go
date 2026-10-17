package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestOperationVerificationQualificationIsVersionedAndPrepaid(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	p := OperationLifecyclePolicy{RootID: id, Lane: "normal", InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 3, MaxPurgeLeases: 2, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)}
	if !p.Valid() || p.CertificateVerificationBacked() {
		t.Fatal("historical H=0 binding changed authority")
	}
	q := OperationHistoryQualification{ID: id, Digest: artifact.Digest{3}, Layout: OperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	p.History = &q
	p.BackupHorizonSeconds = 1
	for _, layout := range []string{OperationHistoryLayout, OperationOverdueHistoryLayout, OperationVerificationHistoryLayout} {
		q.Layout = layout
		p.OverdueTerminal = ""
		fixed := int64(16)
		if layout == OperationOverdueHistoryLayout {
			p.OverdueTerminal = OperationOverdueTerminal
			fixed = 19
		}
		if layout == OperationVerificationHistoryLayout {
			fixed = 21
		}
		b, w := q.SlotBacking(p.MaxPurgeLeases)
		if w != 2*q.MaximumTransitionWALBytes*q.WALCopies*(fixed+3*p.MaxPurgeLeases) {
			t.Fatal("incorrect transition accounting", layout, w)
		}
		p.BackupReservedBytes, p.WALReservedBytes = b*p.MetadataSlots, w*p.MetadataSlots
		if !p.Valid() || p.CertificateVerificationBacked() != (layout == OperationVerificationHistoryLayout) {
			t.Fatal("layout authority mismatch", layout)
		}
	}
	p.BackupHorizonSeconds = 0
	if !p.CertificateVerificationBacked() {
		t.Fatal("qualified zero-history admission rejected")
	}
	p.WALReservedBytes--
	if p.Valid() {
		t.Fatal("under-backed verifier transitions accepted")
	}
	p.WALReservedBytes++
	q.Layout = "operation-audit-history/v4"
	if p.Valid() {
		t.Fatal("future/unsupported profile guessed")
	}
}
