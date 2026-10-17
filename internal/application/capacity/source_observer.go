package capacity

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

type CapacityRecoveryReader interface {
	RecoveryState(context.Context) (artifact.RecoveryProof, error)
}

// CapacitySourceObserver performs one bounded source reconciliation. Scheduling
// belongs to the existing installed reconciliation owner. It creates no goroutine,
// retry queue, recovery authority, workload observation or allocation by itself.
type CapacitySourceObserver struct {
	RootID, InstallationID, QualificationID string
	QualificationDigest                     artifact.Digest
	Source                                  CapacitySourceReader
	Protection                              CapacitySourceProtectionReader
	Recovery                                CapacityRecoveryReader
	Journal                                 CapacitySourceJournal
	Now                                     func() time.Time
}

func (s *CapacitySourceObserver) Observe(ctx context.Context) (AcceptedCapacitySource, error) {
	var zero AcceptedCapacitySource
	if s == nil || ctx == nil || ctx.Err() != nil || s.Now == nil || s.Source == nil || s.Protection == nil || s.Recovery == nil || s.Journal == nil || !authorization.UUID(s.RootID) || !authorization.UUID(s.InstallationID) || !authorization.UUID(s.QualificationID) || s.QualificationDigest == (artifact.Digest{}) {
		return zero, cfg.ErrUnavailable
	}
	started := s.Now()
	until := started.Add(CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	live, cancel := context.WithDeadline(ctx, until)
	defer func() { cancel() }()
	// Every independently returned bound narrows both the next call's context
	// and the final check. No later observation renews a previous phase.
	narrow := func(d time.Time) bool {
		if d.Before(until) {
			until = d
			next, end := context.WithDeadline(live, until)
			prior := cancel
			cancel = func() { end(); prior() }
			live = next
		}
		return live.Err() == nil && s.Now().Before(until)
	}
	r, e := s.Recovery.RecoveryState(live)
	if e != nil || !r.Valid(s.Now()) || r.InstallationID != s.InstallationID || !narrow(r.FreshUntil) {
		return zero, cfg.ErrUnavailable
	}
	revision, e := s.Journal.ReadCapacitySourceRevision(live, r)
	if e != nil || revision < 0 || revision >= 1<<60 || !narrow(until) {
		return zero, cfg.ErrUnavailable
	}
	// Failure can only fence the observed CAS sequence, within this invocation's
	// original interval. Losing that CAS never suppresses a later accepted read.
	failed := func() (AcceptedCapacitySource, error) {
		if live.Err() == nil && r.Valid(s.Now()) && s.Now().Before(until) {
			at := started
			if at.Nanosecond()%1000 != 0 {
				at = at.Truncate(time.Microsecond).Add(time.Microsecond)
			}
			end := until.Truncate(time.Microsecond)
			if !at.After(s.Now()) && end.After(at) {
				_ = s.Journal.InvalidateCapacitySource(live, s.RootID, revision, r, at, end)
			}
		}
		return zero, cfg.ErrUnavailable
	}
	protection, e := s.Protection.CapacityProtection(live)
	if e != nil || !protection.Valid(s.Now()) || !narrow(protection.FreshUntil) {
		return failed()
	}
	observation, e := s.Source.ReadCapacitySource(live)
	if e != nil || !observation.Valid(s.Now()) || !narrow(observation.Snapshot.FreshUntil) {
		return failed()
	}
	input := CapacitySourceAcceptance{RootID: s.RootID, InstallationID: s.InstallationID, QualificationID: s.QualificationID, QualificationDigest: s.QualificationDigest, ExpectedRevision: revision, Observation: observation, Protection: protection, Recovery: r}
	if !input.Valid(s.Now()) || live.Err() != nil {
		return failed()
	}
	out, e := s.Journal.AcceptCapacitySource(live, input)
	if e != nil {
		return zero, cfg.ErrUnavailable
	} // unknown commit remains lookup/CAS-only
	if !out.Valid(s.Now()) || out.RootID != s.RootID || out.InstallationID != s.InstallationID || out.QualificationID != s.QualificationID || out.QualificationDigest != s.QualificationDigest || out.ProtectionDigest != protection.Digest || out.Observation.Digest != observation.Digest || out.Revision < revision || out.Revision > revision+1 || out.FreshUntil.After(until) || out.ObservedAt.Before(protection.ObservedAt) || out.ObservedAt.Before(r.ObservedAt) || !narrow(out.FreshUntil) {
		return zero, cfg.ErrUnavailable
	}
	return out, nil
}
