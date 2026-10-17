package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
	"time"
)

func TestProcessingReleaseHistoryCannotBorrowPublicOrConnectorBacking(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	q := OperationHistoryQualification{ID: id, Digest: artifact.Digest{3}, Layout: ProcessingReleaseHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	p := OperationLifecyclePolicy{RootID: id, InstallationID: id, Lane: "processing", StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 16, MaxPurgeLeases: 2, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), History: &q}
	b, w := q.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes = b * p.MetadataSlots
	p.WALReservedBytes = w * p.MetadataSlots
	if !p.CertificateVerificationBacked() || w != 2*q.MaximumTransitionWALBytes*q.WALCopies*(32+3*p.MaxPurgeLeases) {
		t.Fatal("processing release allowance is not fully prepaid")
	}
	for _, lane := range []string{"normal", "resolution", "identity", "unknown"} {
		copy := p
		copy.Lane = lane
		if copy.Valid() {
			t.Fatalf("processing backing authorized %s", lane)
		}
	}
	for _, layout := range []string{OperationHistoryLayout, OperationOverdueHistoryLayout, OperationVerificationHistoryLayout, ConnectorOperationHistoryLayout, "processing-release-history/v2"} {
		copy := p
		other := q
		other.Layout = layout
		other.MaximumRowFootprintBytes = 1 << 20
		copy.History = &other
		if copy.Valid() {
			t.Fatalf("release borrowed %s", layout)
		}
	}
	p.WALReservedBytes--
	if p.Valid() {
		t.Fatal("missing prepaid transition accepted")
	}
	p.WALReservedBytes++
	p.BackupReservedBytes--
	if p.Valid() {
		t.Fatal("missing retained copy backing accepted")
	}
	for name, want := range map[string]string{"initialize_processing": "normal", "restrict_processing": "normal", "release_processing": "processing", "cancel_artifact_download": ""} {
		if OperationLane(name) != want {
			t.Fatalf("wrong lane for %s", name)
		}
	}
}
