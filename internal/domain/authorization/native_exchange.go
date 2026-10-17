package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"math"
	"time"
)

type NativeOperationKind string

const (
	NativePrepare  NativeOperationKind = "prepare-context"
	NativeObserve  NativeOperationKind = "observe-prepared-context"
	NativeResponse NativeOperationKind = "read-context-response"
)

// NativeReference is a locator, not a capability. In particular neither the
// certificate enrollment locator nor an arbitrary UUID grants native access.
type NativeReference struct {
	InstallationID, SessionID, WorkerID, OperationID string
	Fence                                            int64
}

func (r NativeReference) Valid() bool {
	return UUID(r.InstallationID) && UUID(r.SessionID) && UUID(r.WorkerID) && UUID(r.OperationID) && r.Fence > 0 && r.Fence <= 1<<60
}

type NativeOperation struct {
	Path                           artifact.DownloadPath            `json:",omitzero"`
	Processing                     artifact.DownloadProcessingProof `json:",omitzero"`
	Reference                      NativeReference
	Kind                           NativeOperationKind
	HubPodUID, HubProcessEpoch     string
	WorkerPodUID                   string
	WorkerPublicKey, SourceVersion artifact.Digest
	ParentID                       string
	Generation                     int64
	StartedAt, Until               time.Time
}

func (o NativeOperation) Valid() bool {
	if !o.Reference.Valid() || !UUID(o.HubPodUID) || !UUID(o.HubProcessEpoch) || !UUID(o.WorkerPodUID) || o.WorkerPublicKey == (artifact.Digest{}) || o.SourceVersion == (artifact.Digest{}) || !UUID(o.ParentID) || o.Generation < 1 || o.StartedAt.IsZero() || !o.Until.After(o.StartedAt) {
		return false
	}
	switch o.Kind {
	case NativePrepare, NativeObserve:
		return !o.Until.After(o.StartedAt.Add(5 * time.Second))
	case NativeResponse:
		return !o.Until.After(o.StartedAt.Add(8 * time.Hour))
	default:
		return false
	}
}

// NativeLease is a current SQL/peer observation. Consumers must additionally
// retain the live request/stream owner and current callback; wire decoding never
// constructs that owner. Restrictive changes only shorten this observation.
type NativeLease struct {
	Operation         NativeOperation
	Certificate       artifact.Digest
	Sequence          int64
	ObservedAt, Until time.Time
}

func (l NativeLease) Valid(now time.Time) bool {
	return l.Operation.Valid() && l.Certificate != (artifact.Digest{}) && l.Sequence > 0 && l.Sequence <= 1<<60 && identity.Fresh(l.ObservedAt, l.Until, now, 5*time.Second) && !l.Until.After(l.Operation.Until)
}

// Accepted qualification/backing is supplied by protected installation input,
// never estimated by a runtime or inferred from available SQL disk space.
// Exact bounds cover heap/TOAST/index and full transaction/rollback WAL within
// the finite transition envelope. Admission does not certify those measurements.
type NativeHistoryQualification struct {
	ID                                                    string
	Digest                                                artifact.Digest
	RowBytes, TransitionWALBytes, BackupCopies, WALCopies int64
}

func (q NativeHistoryQualification) Valid() bool {
	return UUID(q.ID) && q.Digest != (artifact.Digest{}) && q.RowBytes >= 64<<10 && q.RowBytes <= 16<<20 && q.TransitionWALBytes >= 64<<10 && q.TransitionWALBytes <= 64<<20 && q.BackupCopies >= 1 && q.BackupCopies <= 64 && q.WALCopies >= 1 && q.WALCopies <= 64
}

type NativeBacking struct {
	AllocationID, RootID, PolicyID       string
	PolicyDigest                         artifact.Digest
	Rows, Keys, TransitionsPerRow        int64
	BackupBytes, WALBytes                int64
	BackupHorizonSeconds, CleanupSeconds int64
	ValidUntil, RetireBy                 time.Time
	History                              NativeHistoryQualification
}

func (b NativeBacking) Valid() bool {
	if !UUID(b.AllocationID) || !UUID(b.RootID) || !UUID(b.PolicyID) || b.PolicyDigest == (artifact.Digest{}) || b.Rows < 1 || b.Rows > 100000 || b.Keys < 1 || b.Keys > artifact.MaxDownloadWindows || b.TransitionsPerRow < 8 || b.TransitionsPerRow > 65536 || !b.History.Valid() || b.BackupHorizonSeconds < 0 || b.BackupHorizonSeconds > 316224000 || b.CleanupSeconds < 1 || b.CleanupSeconds > 86400 || b.ValidUntil.IsZero() || !b.RetireBy.Equal(b.ValidUntil.Add(time.Duration(2*b.BackupHorizonSeconds+b.CleanupSeconds)*time.Second)) {
		return false
	}
	// Reserve both live and residual history before a slot can be consumed.
	backup, ok := nativeMultiply(2*b.History.RowBytes*b.History.BackupCopies, b.Rows+b.Keys)
	if !ok {
		return false
	}
	transitions := (b.TransitionsPerRow+4)*b.Rows + 8*b.Keys
	wal, ok := nativeMultiply(b.History.TransitionWALBytes*b.History.WALCopies, transitions)
	return ok && b.BackupBytes >= backup && b.WALBytes >= wal
}
func nativeMultiply(a, b int64) (int64, bool) {
	if a < 0 || b < 0 || a != 0 && b > math.MaxInt64/a {
		return 0, false
	}
	return a * b, true
}

func (o NativeOperation) Equal(other NativeOperation) bool {
	dates := o.StartedAt.Equal(other.StartedAt) && o.Until.Equal(other.Until) && o.Processing.ObservedAt.Equal(other.Processing.ObservedAt) && o.Processing.ValidUntil.Equal(other.Processing.ValidUntil)
	o.Processing.ObservedAt, other.Processing.ObservedAt = time.Time{}, time.Time{}
	o.Processing.ValidUntil, other.Processing.ValidUntil = time.Time{}, time.Time{}
	o.StartedAt, other.StartedAt = time.Time{}, time.Time{}
	o.Until, other.Until = time.Time{}, time.Time{}
	return dates && o == other
}

// CurrentValid is required by live native admission. Historical absence remains
// decodable for audit and zero-byte terminal closure, never data or key I/O.
func (o NativeOperation) CurrentValid(now time.Time) bool {
	return o.Valid() && o.Path.Valid() && o.Processing.Valid(now) && o.Path.TargetClusterID == o.Processing.Location.ClusterID && !o.Until.After(o.Processing.ValidUntil)
}
