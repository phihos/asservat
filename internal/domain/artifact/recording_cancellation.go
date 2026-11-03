package artifact

import "time"

// RecordingCancellation proves the finite argument engine returned and the
// regional writer joined without a stored result. It does not claim that the
// node has already released the upload buffer after sending this result.
type RecordingCancellation struct {
	CaptureID, AttemptID, WriterPodUID, WriterEpoch string
	ExpectationDigest                               Digest
	JoinedAt                                        time.Time
}

func (p RecordingCancellation) Valid() bool {
	return uuid(p.CaptureID) && uuid(p.AttemptID) && uuid(p.WriterPodUID) && uuid(p.WriterEpoch) && p.ExpectationDigest != (Digest{}) && !p.JoinedAt.IsZero()
}
