package capture

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sync"
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
type ContextHistoryPersistence interface {
	Persist(context.Context, value.Accepted, identity.Identity, value.HistoryParameters, *value.HistoryLineage) error
}

type ContextSubmission struct {
	History ContextHistoryPersistence
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

func (s ContextSubmission) submit(ctx context.Context, current identities.CurrentIdentity, preview, key string, continuation bool) (result value.Accepted, failure error) {
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
	until := identity.Earlier(i.ValidUntil, started.Add(identity.RecordingSaveRequestWindow))
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
	// Every known shorter authority bound constrains subsequent blocking work.
	// Response-only metadata is consumed separately; it is not start authority.
	// A later observation cannot widen this invocation or the accepted operation.
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
		if !recovery.Valid(s.Now()) {
			return zero, value.ErrDenied
		}
		digest := ContextRequestDigest(preview)
		var found bool
		observed, endRead := context.WithDeadline(call, recovery.FreshUntil)
		a, found, err = s.Replay.LookupContextAdmission(observed, value.ReplayQuery{RootID: s.RootID, PreviewID: preview, IdempotencyKey: key, SubmissionDigest: digest, Identity: i, Recovery: recovery})
		readErr := observed.Err()
		endRead()
		if err == nil && readErr != nil {
			err = value.ErrDenied
		}
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
	// Retain one advisory attempt on early failure. Group starts take priority;
	// advisory history uses only the remaining original request interval.
	// Replay never writes history and no history outcome changes admission.
	historyAttempted := false
	persistHistory := func() {
		if a.Replay || historyAttempted {
			return
		}
		historyAttempted = true
		if a.HistoryParameters == nil {
			return
		}
		began := time.Now()
		e := value.ErrHistoryUnavailable
		if s.History != nil {
			e = s.History.Persist(call, a, i, *a.HistoryParameters, a.HistorySource)
		}
		auditapp.MarkStep(call, "s-history", began)
		a.HistoryUnavailable, a.HistoryRecorded = e != nil, e == nil
	}
	defer func() {
		persistHistory()
		result.HistoryUnavailable, result.HistoryRecorded = a.HistoryUnavailable, a.HistoryRecorded
		result.HistoryParameters, result.HistorySource = nil, nil
	}()
	if err = check(); err != nil {
		return a, err
	}
	// Consume the exact accepted identity while its admission/replay observation
	// is current. Start obtains its own authority; the metadata read's cutoff
	// must not become that later phase's deadline.
	a.MetadataValidUntil = identity.Earlier(a.MetadataValidUntil, until)
	if !s.Now().Before(a.MetadataValidUntil) {
		return a, value.ErrDenied
	}
	// Ordinary accepted replay remains passive regardless of a lost earlier
	// response. Only the explicit Continue action can reach this effect path.
	if a.Replay && !continuation {
		return a, nil
	}
	if a.Group != nil {
		if !s.RecordingSaveEnabled {
			return a, value.ErrUnavailable
		}
		err = s.dispatchRecordingSaveGroup(call, current, i, a, until, func() (context.Context, time.Time, error) { e := check(); return call, until, e })
		persistHistory()
		fresh, readErr := s.refreshGroupMetadata(i, a, preview, key, func() (context.Context, time.Time, error) { e := check(); return call, until, e })
		return fresh, errors.Join(err, readErr)
	}
	if err = narrow(started.Add(5 * time.Second)); err != nil {
		return a, err
	}
	if e := a.Expectation; e.Snapshot != nil && e.Lifecycle != nil && e.Lifecycle.TriggerKind == "recordingSave" && !s.RecordingSaveEnabled {
		return a, value.ErrUnavailable
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
	if encodeErr != nil || !r.Valid() || r.RootID != s.RootID || r.CaptureID != a.CaptureID || r.Requester() != i.Principal || r.ScopeDigest != a.ScopeDigest || r.SubmissionDigest != a.SubmissionDigest || r.ExpectationDigest != artifact.Digest(sha256.Sum256(b)) || !r.Deadline.Equal(a.Deadline) {
		if s.ReportPreviewFailure != nil {
			s.ReportPreviewFailure("request/intent/record")
		}
		return a, value.ErrUnavailable
	}
	if err = check(); err != nil {
		return a, err
	}
	persistHistory()
	// History can block, so consume current identity again before dispatch;
	// neither its completion nor a fresh identity extends the original bound.
	if err = check(); err != nil {
		return a, err
	}
	executionCurrent := current
	if r.Initiator != nil {
		if s.PolicyAccepted == nil || a.Expectation.Snapshot == nil || a.Expectation.Lifecycle == nil || a.Expectation.Lifecycle.Origin == nil {
			return a, value.ErrUnavailable
		}
		_, policyUID, isPolicy := authorization.PolicyExecutor(r.Actor)
		if !isPolicy {
			return a, value.ErrDenied
		}
		accepted, e := s.PolicyAccepted.AcceptedPolicyAuthority(call, policyUID)
		if e != nil || accepted.Authority.Executor != r.Actor || accepted.Authority.ScopeDigest != a.Expectation.Lifecycle.Origin.PolicyExecutionDigest {
			return a, value.ErrDenied
		}
		liveUntil := identity.Earlier(until, accepted.SourceUntil)
		executionCurrent = recordingSaveIdentity{policy: newPolicyIdentity(call, s.PolicyAccepted, accepted.Authority, liveUntil, s.Now), initiator: current, original: i, until: liveUntil}
	}
	startStarted := time.Now()
	err = s.Start.StartContext(call, executionCurrent, a.CaptureID)
	auditapp.MarkStep(call, "s-start", startStarted)
	if err != nil {
		return a, err
	}
	if err = check(); err != nil {
		return a, err
	}
	a.MetadataValidUntil = identity.Earlier(a.MetadataValidUntil, until)
	if s.Now().Before(a.MetadataValidUntil) {
		return a, nil
	}
	// The start may have completed after its admission metadata expired. Obtain
	// one current read-only response for that same accepted operation, never a
	// new admission, audit write or execution attempt. No stale receipt is renewed.
	recovery, err := s.currentRecovery(call)
	if err != nil {
		return a, err
	}
	observed, endRead := context.WithDeadline(call, recovery.FreshUntil)
	defer endRead()
	fresh, found, err := s.Replay.LookupContextAdmission(observed, value.ReplayQuery{RootID: s.RootID, PreviewID: preview, IdempotencyKey: key, SubmissionDigest: a.SubmissionDigest, Identity: i, Recovery: recovery})
	if err != nil {
		return a, err
	}
	encoded, encodeErr := json.Marshal(fresh.Expectation)
	if !found || !acceptedContext(fresh, a.SubmissionDigest) || fresh.CaptureID != a.CaptureID || fresh.ScopeDigest != a.ScopeDigest || fresh.Pin != a.Pin || !fresh.CreatedAt.Equal(a.CreatedAt) || !fresh.Deadline.Equal(a.Deadline) || encodeErr != nil || !bytes.Equal(encoded, b) {
		return a, value.ErrUnavailable
	}
	err = check()
	if err != nil {
		return a, err
	}
	fresh.MetadataValidUntil = identity.Earlier(fresh.MetadataValidUntil, identity.Earlier(until, recovery.FreshUntil))
	if observed.Err() != nil || !recovery.Valid(s.Now()) || !s.Now().Before(fresh.MetadataValidUntil) {
		return a, value.ErrDenied
	}
	fresh.Replay = a.Replay
	return fresh, nil
}

// The parent owns navigation and admission only. Each real child consumes its
// own acknowledged intent and accepted deadlines; sibling outcomes are separate.
func (s ContextSubmission) dispatchRecordingSaveGroup(ctx context.Context, current identities.CurrentIdentity, i identity.Identity, a value.Accepted, until time.Time, check func() (context.Context, time.Time, error)) error {
	if a.Group == nil || !acceptedContext(a, a.SubmissionDigest) || s.PolicyAccepted == nil {
		return value.ErrUnavailable
	}
	// Only intent acknowledgement is parallel. The request owner performs all
	// identity narrowing and actual starts serially, respecting Router capacity.
	type acknowledgement struct {
		index  int
		intent audit.CaptureIntent
		err    error
	}
	results := make(chan acknowledgement, len(a.Group.Children))
	audits, cancelAudits := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() { cancelAudits(); workers.Wait() }()
	for n, child := range a.Group.Children {
		workers.Add(1)
		go func() {
			defer workers.Done()
			end := identity.Earlier(until, child.Expectation.Snapshot.StartBy)
			call, cancel := context.WithDeadline(audits, end)
			defer cancel()
			if call.Err() != nil {
				results <- acknowledgement{index: n, err: value.ErrAcquisitionClosed}
				return
			}
			r, err := s.Intents.AcknowledgedCaptureIntent(call, child.CaptureID)
			results <- acknowledgement{n, r, err}
		}()
	}
	var failures []error
	for range a.Group.Children {
		// A start can observe a shorter caller interval. Reconsume it before
		// waiting again, and wait on that narrowed context rather than the
		// original owner. Expiry then cancels and joins the remaining audits.
		call, currentUntil, err := check()
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		var result acknowledgement
		select {
		case <-call.Done():
			return errors.Join(append(failures, call.Err())...)
		case result = <-results:
		}
		n := result.index
		child, r := a.Group.Children[n], result.intent
		end := identity.Earlier(currentUntil, identity.Earlier(child.Expectation.Snapshot.StartBy, identity.Earlier(child.Deadline, child.Expectation.Registration.WriteUntil)))
		if !s.Now().Before(end) {
			failures = append(failures, value.ErrAcquisitionClosed)
			continue
		}
		raw, encodeErr := json.Marshal(child.Expectation)
		if result.err != nil || encodeErr != nil || !r.Valid() || r.RootID != s.RootID || r.CaptureID != child.CaptureID || r.Requester() != i.Principal || r.ScopeDigest != child.ScopeDigest || r.SubmissionDigest != child.SubmissionDigest || r.ExpectationDigest != artifact.Digest(sha256.Sum256(raw)) || !r.Deadline.Equal(child.Deadline) || r.Group == nil || r.Group.ParentCaptureID != a.CaptureID || r.Group.ChildIndex != n || r.Group.ChildCount != len(a.Group.Children) || r.Group.SelectionDigest != a.ScopeDigest {
			failures = append(failures, value.ErrUnavailable)
			continue
		}
		_, uid, ok := authorization.PolicyExecutor(r.Actor)
		if !ok || r.Initiator == nil || child.Expectation.Lifecycle == nil || child.Expectation.Lifecycle.Origin == nil {
			failures = append(failures, value.ErrDenied)
			continue
		}
		policy, err := s.PolicyAccepted.AcceptedPolicyAuthority(call, uid)
		if err != nil || policy.Authority.Executor != r.Actor || policy.Authority.ScopeDigest != child.Expectation.Lifecycle.Origin.PolicyExecutionDigest {
			failures = append(failures, value.ErrDenied)
			continue
		}
		end = identity.Earlier(end, policy.SourceUntil)
		// The policy read can block. Reconsume current caller authority before effect.
		call, currentUntil, err = check()
		if err != nil {
			return errors.Join(append(failures, err)...)
		}
		end = identity.Earlier(end, currentUntil)
		if !s.Now().Before(end) {
			failures = append(failures, value.ErrAcquisitionClosed)
			continue
		}
		live := recordingSaveIdentity{policy: newPolicyIdentity(call, s.PolicyAccepted, policy.Authority, end, s.Now), initiator: current, original: i, until: end}
		childCall, cancel := context.WithDeadline(call, end)
		err = s.Start.StartContext(childCall, live, child.CaptureID)
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	if _, _, err := check(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

// Refresh only response metadata for the exact accepted parent and every real
// child. This read never admits, acknowledges or starts work.
func (s ContextSubmission) refreshGroupMetadata(i identity.Identity, a value.Accepted, preview, key string, check func() (context.Context, time.Time, error)) (value.Accepted, error) {
	ctx, until, err := check()
	if err != nil {
		return a, err
	}
	if s.Now().Before(a.MetadataValidUntil) {
		return a, nil
	}
	recovery, err := s.currentRecovery(ctx)
	if err != nil {
		return a, err
	}
	observed, cancel := context.WithDeadline(ctx, recovery.FreshUntil)
	defer cancel()
	fresh, found, err := s.Replay.LookupContextAdmission(observed, value.ReplayQuery{RootID: s.RootID, PreviewID: preview, IdempotencyKey: key, SubmissionDigest: a.SubmissionDigest, Identity: i, Recovery: recovery})
	if err != nil {
		return a, err
	}
	if !found || !acceptedContext(fresh, a.SubmissionDigest) || !sameAcceptedGroup(a, fresh) {
		return a, value.ErrUnavailable
	}
	ctx, until, err = check()
	if err != nil {
		return a, err
	}
	fresh.MetadataValidUntil = identity.Earlier(fresh.MetadataValidUntil, identity.Earlier(until, recovery.FreshUntil))
	if observed.Err() != nil || !recovery.Valid(s.Now()) || !s.Now().Before(fresh.MetadataValidUntil) {
		return a, value.ErrDenied
	}
	fresh.Replay = a.Replay
	return fresh, nil
}

func sameAcceptedGroup(a, b value.Accepted) bool {
	if a.CaptureID != b.CaptureID || a.ScopeDigest != b.ScopeDigest || a.SubmissionDigest != b.SubmissionDigest || a.Pin != b.Pin || !a.CreatedAt.Equal(b.CreatedAt) || !a.Deadline.Equal(b.Deadline) || a.Group == nil || b.Group == nil || a.Group.CaseID != b.Group.CaseID || len(a.Group.Children) != len(b.Group.Children) {
		return false
	}
	for n, x := range a.Group.Children {
		y := b.Group.Children[n]
		xb, xe := json.Marshal(x.Expectation)
		yb, ye := json.Marshal(y.Expectation)
		if xe != nil || ye != nil || !bytes.Equal(xb, yb) || x.CaptureID != y.CaptureID || x.ScopeDigest != y.ScopeDigest || x.SubmissionDigest != y.SubmissionDigest || x.Pin != y.Pin || !x.CreatedAt.Equal(y.CreatedAt) || !x.Deadline.Equal(y.Deadline) {
			return false
		}
	}
	return true
}
