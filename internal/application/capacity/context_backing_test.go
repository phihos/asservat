package capacity

import (
	"math"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

func contextBackingHistoryFixture() ContextBackingHistory {
	id := "30000000-0000-4000-8000-000000000001"
	return ContextBackingHistory{
		Capture: audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{1}, Layout: audit.CaptureOperationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3}, CapturePurgeLeases: 4,
		Native: authorization.NativeHistoryQualification{ID: id, Digest: artifact.Digest{2}, RowBytes: 64 << 10, TransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 3},
		Stop:   audit.DownloadStopLifecyclePolicy{RootID: id, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, QualificationID: id, PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4}, QualificationDigest: artifact.Digest{5}, Layout: audit.DownloadStopHistoryLayout, BackupHorizonSeconds: 3600, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 256 << 10, BackupCopies: 2, WALCopies: 3, MaxPurgeLeases: 4},
	}
}

func TestCapacityContextBackingUsesActualArtifactAndNativeProtocols(t *testing.T) {
	h := contextBackingHistoryFixture()
	r := artifact.Registration{NativeLimit: artifact.MaxContextBytes}
	slice := BudgetAmount{Bytes: r.ReservedBytes() * 3, Objects: 12}
	p, e := CompileContextProtocolBacking(slice, h)
	if e != nil {
		t.Fatal(e)
	}
	if p.Records != 3 || p.Evidence != slice || p.Evidence.Bytes <= p.Records*artifact.MaxContextBytes || p.ReplayRecords != 3 || p.Sessions != 3 || p.Responses != 6 || p.Windows != 6 || p.WindowObjects != (BudgetAmount{Bytes: 12 * artifact.DownloadWindowAuditBytes, Objects: 12}) {
		t.Fatalf("actual complete protocol quantities not reserved: %+v", p)
	}
	id := h.Stop.RootID
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	native := authorization.NativeBacking{AllocationID: id, RootID: id, PolicyID: id, PolicyDigest: artifact.Digest{9}, Rows: p.NativeRows, Keys: p.NativeKeys, TransitionsPerRow: p.NativeTransitionsPerRow, BackupBytes: p.NativeBackupBytes, WALBytes: p.NativeWALBytes, BackupHorizonSeconds: 3600, CleanupSeconds: 60, ValidUntil: n, RetireBy: n.Add(7260 * time.Second), History: h.Native}
	if !native.Valid() {
		t.Fatal("compiled quantities cannot fund the existing native allocation")
	}
	native.WALBytes--
	if native.Valid() {
		t.Fatal("native WAL was not the exact original formula")
	}
	native.WALBytes++
	native.BackupBytes--
	if native.Valid() {
		t.Fatal("native residual generations were not exactly funded")
	}
	if p.CaptureKeyAttempts != 39 || p.StopKeyAttempts != 36 || p.PreparationUnwraps != 9 || p.ContentUnwraps != 18 || p.ArtifactWraps != 9 {
		t.Fatal("purpose-specific bounded key work lost")
	}
	if p.CaptureBackupBytes != 3*2*h.Capture.MaximumRowFootprintBytes*h.Capture.BackupCopies || p.CaptureWALBytes != 3*2*h.Capture.MaximumTransitionWALBytes*h.Capture.WALCopies*(32+3*h.CapturePurgeLeases) {
		t.Fatal("capture history backing differs from the accepted capture layout")
	}
}

// The installed approval-required recording fixture reserves four recording
// ciphertext obligations and sixteen objects. The metadata record ceiling must
// stay four, while its custody child must retain those authored evidence bytes.
func TestCapacityContextBackingFundsAuthoredPacketEvidence(t *testing.T) {
	recordingBytes := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	slice := BudgetAmount{Bytes: 4 * recordingBytes, Objects: 16}
	p, err := CompileContextProtocolBacking(slice, contextBackingHistoryFixture())
	if err != nil {
		t.Fatal(err)
	}
	if p.Records != 4 || p.ReplayRecords != 4 || p.Sessions != 4 || p.Evidence != slice {
		t.Fatalf("authored recording reserve lost in custody backing: source=%+v compiled=%+v", slice, p)
	}
}

func TestCapacityContextBackingRetainsResidualAndCapsPacketFunding(t *testing.T) {
	unit := (artifact.Registration{NativeLimit: artifact.MaxContextBytes}).ReservedBytes()
	packet := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	for _, tc := range []struct {
		name           string
		slice          BudgetAmount
		bytes, records int64
	}{
		{"exact-pod", BudgetAmount{unit, 4}, unit, 1},
		{"authored-residual", BudgetAmount{unit + 7, 4}, unit + 7, 1},
		{"partial-packet", BudgetAmount{packet - 1, 4}, packet - 1, 1},
		{"objects-bind-packet-cap", BudgetAmount{10 * packet, 7}, packet, 1},
		{"maximum-source-packet-cap", BudgetAmount{math.MaxInt64, math.MaxInt64}, 512 * packet, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := CompileContextProtocolBacking(tc.slice, contextBackingHistoryFixture())
			if err != nil || p.Records != tc.records || p.Evidence != (BudgetAmount{tc.bytes, 4 * tc.records}) {
				t.Fatalf("funding bound: source=%+v evidence=%+v records=%d err=%v", tc.slice, p.Evidence, p.Records, err)
			}
		})
	}
}

func TestCapacityContextBackingNeverRoundsUpOrBorrows(t *testing.T) {
	unit := artifact.Registration{NativeLimit: artifact.MaxContextBytes}.ReservedBytes()
	for _, tc := range []struct {
		name    string
		slice   BudgetAmount
		records int64
	}{
		{"native-bytes-only", BudgetAmount{artifact.MaxContextBytes, 4}, 0},
		{"missing-one-cipher-byte", BudgetAmount{unit - 1, 4}, 0},
		{"missing-one-object", BudgetAmount{unit, 3}, 0},
		{"exact", BudgetAmount{unit, 4}, 1},
		{"objects-bind", BudgetAmount{10 * unit, 7}, 1},
		{"bytes-bind", BudgetAmount{2*unit - 1, 40}, 1},
		{"response-cap", BudgetAmount{math.MaxInt64, math.MaxInt64}, 512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, e := CompileContextProtocolBacking(tc.slice, contextBackingHistoryFixture())
			if tc.records == 0 {
				if e == nil {
					t.Fatal("unbacked context admitted")
				}
				return
			}
			if e != nil || p.Records != tc.records || !tc.slice.contains(p.Evidence) {
				t.Fatalf("bounded compile: records=%d err=%v", p.Records, e)
			}
		})
	}
}

func TestCapacityContextBackingRejectsOtherLayoutsAndUnqualifiedHistory(t *testing.T) {
	for _, kind := range []string{"capture-layout", "capture-digest", "capture-leases", "native-digest", "native-copies", "stop-layout", "stop-digest"} {
		t.Run(kind, func(t *testing.T) {
			h := contextBackingHistoryFixture()
			switch kind {
			case "capture-layout":
				h.Capture.Layout = audit.OperationVerificationHistoryLayout
			case "capture-digest":
				h.Capture.Digest = artifact.Digest{}
			case "capture-leases":
				h.CapturePurgeLeases = 33
			case "native-digest":
				h.Native.Digest = artifact.Digest{}
			case "native-copies":
				h.Native.BackupCopies = 0
			case "stop-layout":
				h.Stop.Layout = audit.CaptureOperationHistoryLayout
			case "stop-digest":
				h.Stop.QualificationDigest = artifact.Digest{}
			}
			if _, e := CompileContextProtocolBacking(BudgetAmount{1 << 30, 1000}, h); e == nil {
				t.Fatal("unqualified/mixed history accepted")
			}
		})
	}
}

func TestCapacityBackingProductRejectsOverflow(t *testing.T) {
	if _, ok := capacityProduct(math.MaxInt64, 2); ok {
		t.Fatal("overflow wrapped into backing")
	}
	if _, ok := capacityProduct(1, -1); ok {
		t.Fatal("negative quantity became credit")
	}
	if n, ok := capacityProduct(math.MaxInt64, 1); !ok || n != math.MaxInt64 {
		t.Fatal("exact finite boundary rejected")
	}
}
