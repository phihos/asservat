package artifact

import "time"

// SourceSnapshotCancellation records joined ownership, not observation or an
// artifact. It never refunds ambiguous acquisition or storage spend.
type SourceSnapshotCancellation struct {
	CaptureID, AttemptID      string
	Request                   SourceSnapshotRequest
	AcceptedExpectationDigest Digest
	JoinedAt                  time.Time
}

func (c SourceSnapshotCancellation) Valid() bool {
	return uuid(c.CaptureID) && uuid(c.AttemptID) && c.Request.Valid() && c.AcceptedExpectationDigest != (Digest{}) && lifecycleTime(c.JoinedAt)
}
