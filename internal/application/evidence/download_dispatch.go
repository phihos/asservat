package evidence

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"errors"
	"time"
)

type DownloadWorkerLedger interface {
	ReserveDownloadWorker(context.Context, string, string, artifact.DownloadAuthority, value.DownloadWorkerProfile) (value.DownloadWorkerIntent, error)
	ReadDownloadWorkerIntentReceipt(context.Context, value.DownloadWorkerIntent) (audit.Receipt, bool, error)
	ClaimDownloadWorker(context.Context, value.DownloadWorkerIntent, artifact.DownloadAuthority) (value.DownloadWorkerLaunch, error)
	RecordDownloadWorkerJob(context.Context, value.DownloadWorkerIntent, value.DownloadWorkerJob) error
	BindDownloadWorker(context.Context, value.DownloadWorker, artifact.DownloadAuthority) error
	ReadDownloadWorker(context.Context, string, artifact.DownloadAuthority) (value.DownloadWorker, error)
	ReadDownloadWorkerTermination(context.Context, value.DownloadWorker) (value.DownloadWorkerTermination, bool, error)
	ConfirmDownloadWorkerTermination(context.Context, value.DownloadWorkerTermination) (value.DownloadWorkerTermination, error)
	RetireDownloadWorker(context.Context, value.DownloadWorkerRetirement) error
}
type DownloadWorkerBindings interface {
	ReadDownloadWorkerIdentity(context.Context, string, value.KeyPeer) (value.DownloadWorkerIdentity, error)
}
type DownloadWorkerJobs interface {
	CreateDownloadWorker(context.Context, value.DownloadWorkerLaunch) (value.DownloadWorkerJob, error)
	FindDownloadWorkerJob(context.Context, value.DownloadWorkerIntent) (value.DownloadWorkerJob, error)
	ObserveDownloadWorker(context.Context, value.DownloadWorkerIntent, value.DownloadWorkerJob) (value.DownloadWorker, error)
	ObserveDownloadWorkerTermination(context.Context, value.DownloadWorker) (value.DownloadWorkerTermination, error)
	RetireDownloadWorker(context.Context, value.DownloadWorkerTermination) (value.DownloadWorkerRetirement, error)
}

func (s *DownloadDispatcher) Retire(ctx context.Context, w value.DownloadWorker) error {
	if s == nil || ctx == nil || s.Jobs == nil || s.Ledger == nil || s.Now == nil || !w.Valid() {
		return artifact.ErrInvalid
	}
	termination, ok, e := s.Ledger.ReadDownloadWorkerTermination(ctx, w)
	if e != nil {
		return e
	}
	if !ok {
		termination, e = s.Jobs.ObserveDownloadWorkerTermination(ctx, w)
		if e != nil {
			return e
		}
		if !termination.Valid(s.Now()) || termination.Worker != w {
			return artifact.ErrIntegrity
		}
		termination, e = s.Ledger.ConfirmDownloadWorkerTermination(ctx, termination)
		if e != nil {
			return e
		}
	}
	p, e := s.Jobs.RetireDownloadWorker(ctx, termination)
	if e != nil {
		return e
	}
	if !p.Valid(s.Now()) || p.Termination.Worker != w {
		return artifact.ErrIntegrity
	}
	return s.Ledger.RetireDownloadWorker(ctx, p)
}

// Ensure creates at most one Job per admitted intent. A lost create reply is
// reconciled by exact lookup; it never causes another create call. Waiting for
// scheduling uses later current authority, not an extended effect lease.
type DownloadDispatcher struct {
	Ledger           DownloadWorkerLedger
	Jobs             DownloadWorkerJobs
	Audit            auditapp.DownloadWorkerWriter
	Acknowledgements auditapp.DownloadWorkerAcknowledgements
	Authority        DownloadAuthorityGate
	CurrentAuthority CurrentDownloadAuthority
	Profile          value.DownloadWorkerProfile
	Now              func() time.Time
}

func (s *DownloadDispatcher) Ensure(ctx context.Context, credential, session, intentID string, scope artifact.DownloadScope) (value.DownloadWorker, error) {
	if s == nil || s.Authority == nil {
		return value.DownloadWorker{}, artifact.ErrInvalid
	}
	return s.ensureChecked(ctx, session, intentID, scope, func(c context.Context) (artifact.DownloadAuthority, error) {
		return s.Authority.CheckDownload(c, credential, scope)
	}, nil)
}

// EnsureCurrent uses the browser/MCP request's current identity without exposing
// provider credentials. It preserves one original interval through all effects.
func (s *DownloadDispatcher) EnsureCurrent(ctx context.Context, source identities.CurrentIdentity, session, intentID string, scope artifact.DownloadScope) (value.DownloadWorker, error) {
	if s == nil {
		return value.DownloadWorker{}, artifact.ErrInvalid
	}
	check, err := newWorkerCurrentCheck(ctx, source, s.CurrentAuthority, scope, s.Now)
	if err != nil {
		return value.DownloadWorker{}, err
	}
	call, cancel := context.WithDeadline(ctx, check.Deadline())
	defer cancel()
	return s.ensureChecked(call, session, intentID, scope, check.Check, check.Deadline)
}
func (s *DownloadDispatcher) ensureChecked(ctx context.Context, session, intentID string, scope artifact.DownloadScope, check contextDownloadCheck, bound func() time.Time) (value.DownloadWorker, error) {
	var zero value.DownloadWorker
	if s == nil || ctx == nil || ctx.Err() != nil || s.Ledger == nil || s.Jobs == nil || s.Audit == nil || s.Acknowledgements == nil || check == nil || s.Now == nil || !s.Profile.Valid() || !value.UUID(session) || !value.UUID(intentID) || !scope.Valid() {
		return zero, artifact.ErrInvalid
	}
	shorten, finish := workerEffectContext(&ctx, bound)
	defer finish()
	current := func() (artifact.DownloadAuthority, error) {
		a, e := check(ctx)
		if e != nil || !a.Valid(s.Now()) || a.Scope != scope || ctx.Err() != nil {
			return a, artifact.ErrDownloadExpired
		}
		shorten()
		return a, nil
	}
	a, e := current()
	if e != nil {
		return zero, e
	}
	i, e := s.Ledger.ReserveDownloadWorker(ctx, session, intentID, a, s.Profile)
	if e != nil {
		return zero, e
	}
	if !i.Valid() || i.SessionID != session || i.Profile != s.Profile || i.Authority.Scope != scope {
		return zero, artifact.ErrIntegrity
	}
	r, acknowledged, e := s.Ledger.ReadDownloadWorkerIntentReceipt(ctx, i)
	if e != nil {
		return zero, e
	}
	if acknowledged {
		if !r.ValidDownloadWorker(i) {
			return zero, artifact.ErrIntegrity
		}
	} else {
		if _, e = current(); e != nil {
			return zero, e
		}
		r, e = s.Audit.WriteDownloadWorkerIntent(ctx, i)
		if e != nil {
			return zero, e
		}
		if !r.ValidDownloadWorker(i) {
			return zero, artifact.ErrIntegrity
		}
		if _, e = current(); e != nil {
			return zero, e
		}
		if e = s.Acknowledgements.AcknowledgeDownloadWorkerIntent(ctx, i, r); e != nil {
			return zero, e
		}
	}
	a, e = current()
	if e != nil {
		return zero, e
	}
	l, e := s.Ledger.ClaimDownloadWorker(ctx, i, a)
	if e != nil {
		return zero, e
	}
	if !l.Valid(s.Now()) || l.Intent != i {
		return zero, artifact.ErrIntegrity
	}
	if _, e = current(); e != nil {
		return zero, e
	}
	var job value.DownloadWorkerJob
	if l.MayCreate {
		launch, end := context.WithDeadline(ctx, l.Until)
		job, e = s.Jobs.CreateDownloadWorker(launch, l)
		end()
	} else {
		job, e = s.Jobs.FindDownloadWorkerJob(ctx, i)
	}
	if e != nil {
		return zero, e
	}
	if !job.Valid(i) {
		return zero, artifact.ErrIntegrity
	}
	// An observed effect may be recorded after its launch permit expires. That
	// record cannot authorize a replacement, start work or extend the session.
	if _, e = current(); e != nil {
		return zero, e
	}
	if e = s.Ledger.RecordDownloadWorkerJob(ctx, i, job); e != nil {
		return zero, e
	}
	w, e := s.Jobs.ObserveDownloadWorker(ctx, i, job)
	if e != nil {
		var pending *DownloadWorkerPending
		if errors.As(e, &pending) {
			if !pending.Valid(s.Now()) || pending.Intent != i || pending.Job != job {
				return zero, artifact.ErrIntegrity
			}
			latest, err := current()
			if err != nil {
				return zero, err
			}
			observed := *pending
			observed.ValidUntil = identity.Earlier(observed.ValidUntil, latest.ValidUntil)
			if deadline, ok := ctx.Deadline(); ok {
				observed.ValidUntil = identity.Earlier(observed.ValidUntil, deadline)
			}
			if !observed.Valid(s.Now()) || ctx.Err() != nil {
				return zero, artifact.ErrDownloadExpired
			}
			return zero, &observed
		}
		return zero, e
	}
	if !w.Valid() || w.Intent != i || w.Job != job {
		return zero, artifact.ErrIntegrity
	}
	a, e = current()
	if e != nil {
		return zero, e
	}
	if e = s.Ledger.BindDownloadWorker(ctx, w, a); e != nil {
		return zero, e
	}
	out, e := s.Ledger.ReadDownloadWorker(ctx, session, a)
	if e != nil {
		return zero, e
	}
	if _, e = current(); e != nil {
		return zero, e
	}
	if out != w {
		return zero, artifact.ErrIntegrity
	}
	return out, nil
}
