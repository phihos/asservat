package artifact

import "time"

// ProcessCancellation retains positive runtime/proc-reader and artifact-writer join
// without a stored result. It does not erase partial encrypted objects or spend.
type ProcessCancellation struct {
	CaptureID, AttemptID, WriterPodUID, WriterEpoch string
	ExpectationDigest                               Digest
	JoinedAt                                        time.Time
}

func (p ProcessCancellation) Valid() bool {
	return uuid(p.CaptureID) && uuid(p.AttemptID) && uuid(p.WriterPodUID) && uuid(p.WriterEpoch) && p.ExpectationDigest != (Digest{}) && !p.JoinedAt.IsZero()
}
