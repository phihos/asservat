package artifact

import "time"

// AcquisitionWindow is verified display metadata about endpoint HTTP acquisition,
// not a sample-history interval, measured clock offset or serving-process proof.
// Values use UTC microseconds; sealed manifest/native precision is unchanged.
type AcquisitionWindow struct {
	StartedAt, CompletedAt time.Time
}

func (w AcquisitionWindow) Valid() bool {
	return !w.StartedAt.IsZero() && !w.CompletedAt.IsZero() && !w.CompletedAt.Before(w.StartedAt) && w.StartedAt.Location() == time.UTC && w.CompletedAt.Location() == time.UTC && w.StartedAt.Nanosecond()%1000 == 0 && w.CompletedAt.Nanosecond()%1000 == 0
}

func (w AcquisitionWindow) Equal(o AcquisitionWindow) bool {
	return w.StartedAt.Equal(o.StartedAt) && w.CompletedAt.Equal(o.CompletedAt)
}

func (w *AcquisitionWindow) Clone() *AcquisitionWindow {
	if w == nil {
		return nil
	}
	out := *w
	return &out
}

// ContextVerificationResult exists only after the complete native, manifest,
// framing/index/hash and semantic checks have succeeded. An error returns zero.
// Only currently supported Go profiles carry acquisition timing (ADR-297).
type ContextVerificationResult struct {
	NativeBytes int64
	Acquisition *AcquisitionWindow
}

func (r ContextVerificationResult) Valid(e ContextExpectation) bool {
	if r.NativeBytes < 0 || r.NativeBytes > e.Registration.NativeLimit {
		return false
	}
	profile := e.Profile != nil && (e.NativeType == PprofArtifact || e.NativeType == GoTraceArtifact)
	if !profile {
		return r.Acquisition == nil
	}
	return r.Acquisition != nil && r.Acquisition.Valid()
}

func (r ContextVerificationResult) Clone() ContextVerificationResult {
	r.Acquisition = r.Acquisition.Clone()
	return r
}
