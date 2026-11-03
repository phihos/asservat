package artifact

import "time"

// ProfileCancellation proves that Asservat's acquisition and regional writer
// joined without a stored result. MayHaveStarted preserves uncertainty about
// the application's profiler; HTTP cancellation is not a remote stop proof.
type ProfileCancellation struct {
	CaptureID, AttemptID, WriterPodUID, WriterEpoch string
	ExpectationDigest                               Digest
	JoinedAt                                        time.Time
	MayHaveStarted                                  bool
}

func (p ProfileCancellation) Valid() bool {
	return uuid(p.CaptureID) && uuid(p.AttemptID) && uuid(p.WriterPodUID) && uuid(p.WriterEpoch) && p.ExpectationDigest != (Digest{}) && !p.JoinedAt.IsZero()
}
