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
	q.Layout = "operation-audit-history/v5"
	if p.Valid() {
		t.Fatal("future/unsupported profile guessed")
	}
}

func TestSharingRequiresItsOwnPrepaidLayoutAndLane(t *testing.T) {
	id := "00000000-0000-4000-8000-000000000001"
	for _, tc := range []struct{ lane, old, next string }{
		{"normal", OperationVerificationHistoryLayout, ShareOperationHistoryLayout},
		{"resolution", OperationVerificationHistoryLayout, ShareOperationHistoryLayout},
		{"capture", CaptureOperationHistoryLayout, ShareCaptureOperationHistoryLayout},
	} {
		t.Run(tc.lane, func(t *testing.T) {
			q := OperationHistoryQualification{ID: id, Digest: artifact.Digest{3}, Layout: tc.old, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
			b, w := q.SlotBacking(2)
			p := OperationLifecyclePolicy{RootID: id, Lane: tc.lane, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 3, MaxPurgeLeases: 2, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), History: &q, OverdueTerminal: OperationOverdueTerminal, BackupReservedBytes: 3 * b, WALReservedBytes: 3 * w}
			if !p.CertificateVerificationBacked() || p.SharingBacked() {
				t.Fatal("historical verification qualification promoted to share backing")
			}
			q.Layout = tc.next
			if p.Valid() {
				t.Fatal("new share transitions accepted with the old WAL budget")
			}
			b, w = q.SlotBacking(2)
			p.BackupReservedBytes, p.WALReservedBytes = 3*b, 3*w
			if !p.SharingBacked() {
				t.Fatal("fully prepaid share layout rejected")
			}
			if tc.next == ShareOperationHistoryLayout {
				business := p.MetadataSlots * 2 * q.WALCopies * ShareOperationBusinessWALBytes
				p.WALReservedBytes -= business
				if p.Valid() {
					t.Fatal("audit protocol backing accepted without the business allowance")
				}
				p.WALReservedBytes += business
			}
			p.WALReservedBytes--
			if p.SharingBacked() {
				t.Fatal("one-byte short backing accepted")
			}
			p.WALReservedBytes++
			for _, forbidden := range []string{"identity", "processing"} {
				p.Lane = forbidden
				if p.Valid() {
					t.Fatal("share qualification crossed into another compartment", forbidden)
				}
			}
		})
	}
}

func TestShareBusinessWALIsPrepaidPerGenerationAndCopy(t *testing.T) {
	q := OperationHistoryQualification{Layout: ShareOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3}
	b, w := q.SlotBacking(4)
	if b != 512<<10 || w != 102<<20 {
		t.Fatalf("share slot backup/WAL = %d/%d, want 512KiB/102MiB", b, w)
	}
	for _, tc := range []struct {
		layout string
		fixed  int64
	}{
		{OperationHistoryLayout, 16}, {OperationOverdueHistoryLayout, 19}, {OperationVerificationHistoryLayout, 21},
		{CaptureOperationHistoryLayout, 32}, {ShareCaptureOperationHistoryLayout, 34}, {ProcessingReleaseHistoryLayout, 32},
		{ConnectorOperationHistoryLayout, 32}, {ConnectorRetirementHistoryLayout, 40},
	} {
		q.Layout = tc.layout
		_, got := q.SlotBacking(4)
		if want := 2 * q.WALCopies * q.MaximumTransitionWALBytes * (tc.fixed + 12); got != want {
			t.Fatalf("historical/nonbusiness layout %s WAL=%d want %d", tc.layout, got, want)
		}
	}
}
