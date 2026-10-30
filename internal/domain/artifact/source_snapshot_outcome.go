package artifact

import "time"

// SourceSnapshotOutcome is an authenticated producer observation, separately
// retained from the immutable admission. NativeSHA256 must also match the bytes
// consumed by the connector; it is not an output supplied by an API caller.
type SourceSnapshotOutcome struct {
	SourceSnapshotCoverage
	NativeSHA256 Digest
}

// SourceSnapshotCoverage is bounded authenticated metadata; native hashes remain
// in the producer outcome and encrypted evidence, outside SQL.
type SourceSnapshotCoverage struct {
	Request                                                                    SourceSnapshotRequest
	AcceptedExpectationDigest                                                  Digest
	NativeBytes                                                                int64
	Retained, OutputFull                                                       uint64
	AvailableFrom, ObservedUntil, SourceStoppedAt, SourceClosedAt, CompletedAt time.Time
	HistoryComplete, WindowComplete, HistoryEvicted, InputUnknown              bool
}

// ProjectSourceSnapshot checks actual coverage against immutable requested
// bounds. The caller supplies the independently retained admission digest and
// authenticated producer result; this function never treats a manifest as a
// source of expected facts. Unknown continuity remains unknown/partial.
func ProjectSourceSnapshot(e ContextExpectation, acceptedDigest Digest, o SourceSnapshotOutcome) (ContextExpectation, error) {
	if o.NativeSHA256 == (Digest{}) {
		return ContextExpectation{}, ErrInvalid
	}
	return ProjectSourceSnapshotCoverage(e, acceptedDigest, o.SourceSnapshotCoverage)
}

func ProjectSourceSnapshotCoverage(e ContextExpectation, acceptedDigest Digest, o SourceSnapshotCoverage) (ContextExpectation, error) {
	if e.Snapshot == nil || !e.Snapshot.Equal(o.Request) || !o.Request.Valid() || e.Lifecycle == nil ||
		!e.TriggeredAt.Equal(o.Request.T0) || e.Lifecycle.SourceSessionID != o.Request.SourceID || e.Lifecycle.SnapshotID != o.Request.SnapshotID || !e.Lifecycle.SourceStartedAt.Equal(o.Request.SourceStartedAt) || e.Lifecycle.RequestedBefore != o.Request.Before || e.Lifecycle.After != o.Request.After ||
		acceptedDigest == (Digest{}) || o.AcceptedExpectationDigest != acceptedDigest ||
		o.NativeBytes <= 0 || o.NativeBytes > o.Request.MaxBytes || o.CompletedAt.IsZero() ||
		!o.CompletedAt.Before(o.Request.ProcessingUntil) || o.CompletedAt.Before(o.Request.IssuedAt) {
		return ContextExpectation{}, ErrInvalid
	}
	s := o.Request
	start, end := s.T0.Add(-s.Before), s.T0.Add(s.After)
	if !o.SourceClosedAt.IsZero() && (o.SourceClosedAt.Before(s.SourceStartedAt) || o.SourceClosedAt.After(o.CompletedAt)) ||
		!o.SourceStoppedAt.IsZero() && (o.SourceStoppedAt.Before(s.SourceStartedAt) || o.SourceStoppedAt.After(o.CompletedAt)) ||
		!o.AvailableFrom.IsZero() && o.AvailableFrom.Before(s.SourceStartedAt) ||
		!o.ObservedUntil.IsZero() && (o.ObservedUntil.After(o.CompletedAt) || o.ObservedUntil.After(s.SourceHardUntil)) ||
		o.HistoryComplete && (o.AvailableFrom.IsZero() || o.AvailableFrom.After(start) || o.ObservedUntil.Before(s.T0) || o.InputUnknown || o.HistoryEvicted) ||
		o.WindowComplete && (!o.SourceClosedAt.IsZero() && o.SourceClosedAt.Before(end) || !o.HistoryComplete || o.ObservedUntil.Before(end) || o.CompletedAt.Before(end) || o.OutputFull > 0 || !o.SourceStoppedAt.IsZero() && o.SourceStoppedAt.Before(end)) ||
		o.Retained == 0 && !o.WindowComplete {
		return ContextExpectation{}, ErrInvalid
	}
	l := e.Lifecycle.Clone()
	l.HistoryCoverage, l.WindowCoverage = "partial", "partial"
	l.GapReasons = nil
	if o.HistoryComplete {
		l.HistoryCoverage = "full"
	}
	if o.WindowComplete {
		l.WindowCoverage = "full"
	}
	if s.SourceStartedAt.After(start) {
		l.GapReasons = append(l.GapReasons, "warming")
	}
	if o.HistoryEvicted {
		l.GapReasons = append(l.GapReasons, "historyEvicted")
	}
	if o.InputUnknown || !o.SourceClosedAt.IsZero() && o.SourceClosedAt.Before(end) || !o.HistoryComplete && !o.HistoryEvicted && !s.SourceStartedAt.After(start) {
		l.GapReasons = append(l.GapReasons, "unknownLoss")
	}
	if o.OutputFull > 0 {
		l.GapReasons = append(l.GapReasons, "capacityLimited")
	}
	if !o.SourceStoppedAt.IsZero() && o.SourceStoppedAt.Before(end) {
		l.GapReasons = append(l.GapReasons, "targetGone")
	}
	if !o.WindowComplete && len(l.GapReasons) == 0 {
		l.GapReasons = append(l.GapReasons, "unknownLoss")
	}
	l.SourceStoppedAt = o.SourceStoppedAt
	l.SourceClosedAt = o.SourceClosedAt
	if l.Validate(s.T0) != nil {
		return ContextExpectation{}, ErrInvalid
	}
	e.Lifecycle = l
	e.Snapshot = e.Snapshot.Clone()
	e.SourceSnapshotManifest = e.SourceSnapshotManifest.Clone()
	return e, nil
}
