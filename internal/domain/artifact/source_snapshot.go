package artifact

import "time"

// SourceSnapshotRequest is the immutable window of one admitted save from an
// existing source. It is not source observation authority and cannot arm one.
// Target, executor, audience and source definition remain in the enclosing
// accepted expectation. A producer's completion cannot change these bounds.
type SourceSnapshotRequest struct {
	RequireApproval                        bool `json:",omitempty"`
	SourceBindingDigest                    Digest
	SourceID, Fence, SnapshotID            string
	SourceStartedAt, SourceHardUntil       time.Time
	T0, IssuedAt, StartBy, ProcessingUntil time.Time
	Before, After                          time.Duration
	MaxBytes                               int64
}

// Valid imposes the structural maximum. Ordinary producers select five
// seconds; only the protected grouped-admission path selects a longer bound.
// Exact accepted dates, source hard ends and current caller bounds still apply.
func (s SourceSnapshotRequest) Valid() bool {
	if !uuid(s.SourceID) || !uuid(s.Fence) || !uuid(s.SnapshotID) ||
		!lifecycleTime(s.SourceStartedAt) || !lifecycleTime(s.SourceHardUntil) ||
		s.SourceBindingDigest == (Digest{}) || !lifecycleTime(s.IssuedAt) || !lifecycleTime(s.T0) || !lifecycleTime(s.StartBy) || !lifecycleTime(s.ProcessingUntil) ||
		!s.SourceStartedAt.Before(s.SourceHardUntil) ||
		s.T0.After(s.IssuedAt) || !s.IssuedAt.Before(s.StartBy) || !s.StartBy.Before(s.ProcessingUntil) ||
		s.StartBy.After(s.IssuedAt.Add(15*time.Second)) || s.StartBy.After(s.SourceHardUntil) || !s.IssuedAt.Before(s.SourceHardUntil) || !s.T0.Before(s.SourceHardUntil) ||
		s.MaxBytes < minRecordingBytes || s.MaxBytes > RecordingNativeLimit {
		return false
	}
	return s.Before >= 0 && s.Before <= MaxLifecycleWindow && s.After >= 0 && s.After <= MaxLifecycleWindow &&
		s.Before%time.Millisecond == 0 && s.After%time.Millisecond == 0 && s.Before+s.After > 0 &&
		s.T0.Add(s.After).Before(s.ProcessingUntil)
}

func (s SourceSnapshotRequest) Clone() *SourceSnapshotRequest { out := s; return &out }

// SourceSnapshotAnchor conservatively retains the earliest possible included
// acquisition, rather than resetting retention at the save or upload.
func SourceSnapshotAnchor(s SourceSnapshotRequest) time.Time {
	start := s.T0.Add(-s.Before)
	if start.Before(s.SourceStartedAt) {
		return s.SourceStartedAt
	}
	return start
}

// Equal compares original clock instants, independent of SQL scan location or
// transport UTC normalization. It does not renew or round any bound.
func (s SourceSnapshotRequest) Equal(other SourceSnapshotRequest) bool {
	if !s.SourceStartedAt.Equal(other.SourceStartedAt) || !s.SourceHardUntil.Equal(other.SourceHardUntil) || !s.T0.Equal(other.T0) || !s.IssuedAt.Equal(other.IssuedAt) || !s.StartBy.Equal(other.StartBy) || !s.ProcessingUntil.Equal(other.ProcessingUntil) {
		return false
	}
	s.SourceStartedAt, s.SourceHardUntil, s.T0, s.IssuedAt, s.StartBy, s.ProcessingUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}
	other.SourceStartedAt, other.SourceHardUntil, other.T0, other.IssuedAt, other.StartBy, other.ProcessingUntil = time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}, time.Time{}
	return s == other
}
