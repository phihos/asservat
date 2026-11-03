package collector

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"time"
)

// RecordingStop restricts one accepted finite argument attempt in its original regional writer.
// It contains no replacement source, new acquisition interval or refund.
type RecordingStop struct {
	RootID, ClusterID, CaptureID, AttemptID, WriterPodUID, WriterEpoch string
	ExpectationDigest                                                  artifact.Digest
	WriteUntil                                                         time.Time
}

func (s RecordingStop) Valid() bool {
	for _, id := range []string{s.RootID, s.ClusterID, s.CaptureID, s.AttemptID, s.WriterPodUID, s.WriterEpoch} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return s.ExpectationDigest != (artifact.Digest{}) && !s.WriteUntil.IsZero()
}

func (s RecordingStop) Equal(other RecordingStop) bool {
	if !s.WriteUntil.Equal(other.WriteUntil) {
		return false
	}
	s.WriteUntil, other.WriteUntil = time.Time{}, time.Time{}
	return s == other
}
