package capture

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

type ContextIntentPublication interface {
	AcknowledgedCaptureIntent(context.Context, string) (audit.CaptureIntent, error)
}
type ContextAcceptedStart interface {
	StartContext(context.Context, identities.CurrentIdentity, string) error
}

// ContextSubmission owns no queued identity or detached execution. Request
// starts only on first admission; Continue is a separate explicit accepted-only
// action. Both retain the actual caller and their original current interval.
// Downstream failures return the accepted receipt plus an error. That receipt
// never authorizes disclosure after MetadataValidUntil.
type ContextSubmission struct {
	ContextInvestigation
	Intents ContextIntentPublication
	Start   ContextAcceptedStart
}

func (s ContextSubmission) Request(ctx context.Context, current identities.CurrentIdentity, preview, key string) (value.Accepted, error) {
	return s.submit(ctx, current, preview, key, false)
}

// Continue never admits work or restores a preview. It can reach the original
// runner only for the same accepted actor/client and request key. Durable
// execution/start state alone decides whether the original attempt may start.
func (s ContextSubmission) Continue(ctx context.Context, current identities.CurrentIdentity, preview, key string) (value.Accepted, error) {
	return s.submit(ctx, current, preview, key, true)
}

func (s ContextSubmission) submit(ctx context.Context, current identities.CurrentIdentity, preview, key string, continuation bool) (value.Accepted, error) {
	var zero value.Accepted
	if ctx == nil || ctx.Err() != nil || current == nil || s.Intents == nil || s.Start == nil || !s.ContextInvestigation.configured() {
		return zero, value.ErrUnavailable
	}
	if !authorization.UUID(preview) || !identity.Text(key, 128) {
		return zero, value.ErrInvalid
	}
	started := s.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	if continuation && !slices.Contains(i.Scopes, "evidence:capture") {
		return zero, value.ErrDenied
	}
	until := identity.Earlier(i.ValidUntil, started.Add(5*time.Second))
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, stop := context.WithDeadline(ctx, until)
	stops := []context.CancelFunc{stop}
	defer func() {
		for j := len(stops) - 1; j >= 0; j-- {
			stops[j]()
		}
	}()
	// Every known shorter source bound constrains subsequent blocking work. A
	// later observation cannot widen this invocation or the accepted operation.
	narrow := func(bound time.Time) error {
		if bound.IsZero() {
			return value.ErrUnavailable
		}
		next := identity.Earlier(until, bound)
		if next.Before(until) {
			var cancel context.CancelFunc
			call, cancel = context.WithDeadline(call, next)
			stops = append(stops, cancel)
			until = next
		}
		if call.Err() != nil || s.Now().Before(started) || !s.Now().Before(until) {
			return value.ErrDenied
		}
		return nil
	}
	check := func() error {
		last, e := current.ResolveIdentity(call)
		if e != nil || !last.Valid(s.Now()) || last.Principal != i.Principal || last.Policy != i.Policy {
			return value.ErrDenied
		}
		// The request-owned handle additionally fixes the original groups/scopes.
		return narrow(last.ValidUntil)
	}
	var a value.Accepted
	if continuation {
		recovery, e := s.currentRecovery(call)
		if e != nil {
			return zero, e
		}
		if e = narrow(recovery.FreshUntil); e != nil {
			return zero, e
		}
		digest := ContextRequestDigest(preview)
		var found bool
		a, found, err = s.Replay.LookupContextAdmission(call, value.ReplayQuery{RootID: s.RootID, PreviewID: preview, IdempotencyKey: key, SubmissionDigest: digest, Identity: i, Recovery: recovery})
		if err != nil {
			return zero, err
		}
		if !found || !acceptedContext(a, digest) {
			return zero, value.ErrUnavailable
		}
		if !recovery.Valid(s.Now()) {
			return zero, value.ErrDenied
		}
		a.Replay = true
	} else {
		a, err = s.ContextInvestigation.Request(call, current, preview, key)
		if err != nil {
			return a, err
		}
	}
	if err = narrow(a.MetadataValidUntil); err != nil {
		return a, err
	}
	if err = check(); err != nil {
		return a, err
	}
	// Ordinary accepted replay remains passive regardless of a lost earlier
	// response. Only the explicit Continue action can reach this effect path.
	if a.Replay && !continuation {
		a.MetadataValidUntil = until
		return a, nil
	}
	if !s.Now().Before(a.Deadline) || !s.Now().Before(a.Expectation.Registration.WriteUntil) {
		return a, value.ErrAcquisitionClosed
	}
	if err = narrow(identity.Earlier(a.Deadline, a.Expectation.Registration.WriteUntil)); err != nil {
		return a, err
	}
	intentStarted := time.Now()
	r, err := s.Intents.AcknowledgedCaptureIntent(call, a.CaptureID)
	auditapp.MarkStep(call, "s-intent", intentStarted)
	b, encodeErr := json.Marshal(a.Expectation)
	if err != nil {
		if s.ReportPreviewFailure != nil {
			s.ReportPreviewFailure("request/intent/" + auditapp.CaptureOperationFailureStage(err))
		}
		return a, value.ErrUnavailable
	}
	if encodeErr != nil || !r.Valid() || r.RootID != s.RootID || r.CaptureID != a.CaptureID || r.Actor != i.Principal || r.ScopeDigest != a.ScopeDigest || r.SubmissionDigest != a.SubmissionDigest || r.ExpectationDigest != artifact.Digest(sha256.Sum256(b)) || !r.Deadline.Equal(a.Deadline) {
		if s.ReportPreviewFailure != nil {
			s.ReportPreviewFailure("request/intent/record")
		}
		return a, value.ErrUnavailable
	}
	if err = check(); err != nil {
		return a, err
	}
	startStarted := time.Now()
	err = s.Start.StartContext(call, current, a.CaptureID)
	auditapp.MarkStep(call, "s-start", startStarted)
	if err != nil {
		return a, err
	}
	if err = check(); err != nil {
		return a, err
	}
	a.MetadataValidUntil = until
	return a, nil
}
