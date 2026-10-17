package execution

import (
	"context"
	"reflect"
	"slices"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	fleetport "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type ContextWorkResolver interface {
	ResolveContextWork(context.Context, fleet.AuthenticatedAction, fleet.Receiver) (value.ContextStart, error)
}
type ContextCollector interface {
	Capture(context.Context, artifact.PinnedPod) ([]byte, error)
}

type ContextResult struct {
	State  string // AlreadyStarted, Indeterminate, or StoredPendingVerification.
	Copies artifact.Copies
}
type ContextExecutor struct {
	Work      fleetport.RunActionVerifier
	Resolve   ContextWorkResolver
	Starts    StartJournal
	Output    evidence.ContextProducer
	Collector ContextCollector
	Now       func() time.Time
}

// Execute is purpose-specific: it cannot dispatch commands, dumps or recorders.
// Unknown starts stay spent. Stored output still needs independent full-context
// verification, durable outcome audit and catalog publication authority.
func (s ContextExecutor) Execute(ctx context.Context, signed []byte, receiver fleet.Receiver) (ContextResult, error) {
	var out ContextResult
	if s.Work == nil || s.Resolve == nil || s.Starts == nil || s.Output == nil || s.Collector == nil || s.Now == nil {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	action, err := s.Work.VerifyRunAction(ctx, signed, receiver)
	if err != nil {
		return out, err
	}
	resolved, err := s.Resolve.ResolveContextWork(ctx, action, receiver)
	if err != nil {
		return out, err
	}
	action.Work.RequiredCapabilities = slices.Clone(action.Work.RequiredCapabilities)
	resolved.Expectation.Audience = slices.Clone(resolved.Expectation.Audience)
	resolved.Expectation.RetentionRules = slices.Clone(resolved.Expectation.RetentionRules)
	if !resolved.Valid(action, receiver, s.Now()) {
		return out, value.ErrDenied
	}
	existing, err := s.Starts.LookupStart(ctx, resolved.Start)
	if err != nil {
		return out, err
	}
	if existing.ObjectUID != resolved.Start.ObjectUID || existing.MayStart {
		return out, value.ErrDenied
	}
	if existing.Phase == value.StartCommitted {
		return ContextResult{State: "AlreadyStarted"}, nil
	}
	if existing.Phase != value.Ready {
		return out, value.ErrDenied
	}
	prepared, err := s.Output.PrepareContext(ctx, resolved.Expectation)
	if err != nil {
		return out, err
	}
	if prepared == nil {
		return out, value.ErrUnavailable
	}
	defer prepared.Close()
	// Key preparation may block. Repeat signature/trust and current reference
	// checks, preserving all immutable scope, capacity and effect identities.
	current, err := s.Work.VerifyRunAction(ctx, signed, receiver)
	if err != nil {
		return out, err
	}
	fresh, err := s.Resolve.ResolveContextWork(ctx, current, receiver)
	if err != nil {
		return out, err
	}
	if !fresh.Valid(current, receiver, s.Now()) || !reflect.DeepEqual(action.Work, current.Work) || current.KeyID != action.KeyID || current.TrustRevision != action.TrustRevision || fresh.Start.Binding != resolved.Start.Binding || fresh.Start.ObjectUID != resolved.Start.ObjectUID || fresh.Pin != resolved.Pin || !reflect.DeepEqual(fresh.Expectation, resolved.Expectation) {
		return out, value.ErrConflict
	}
	disposition, err := s.Starts.ConsumeStart(ctx, fresh.Start)
	if err != nil {
		return ContextResult{State: "Indeterminate"}, err
	}
	if disposition.ObjectUID != fresh.Start.ObjectUID || disposition.Phase != value.StartCommitted {
		return ContextResult{State: "Indeterminate"}, value.ErrDenied
	}
	if !disposition.MayStart {
		return ContextResult{State: "AlreadyStarted"}, nil
	}
	out.State = "Indeterminate"
	now := s.Now().UTC()
	if disposition.CommittedAt.IsZero() || disposition.CommittedAt.Before(fresh.Start.Binding.NotBefore) || disposition.CommittedAt.After(now) || !fresh.Valid(current, receiver, now) || !now.Before(disposition.ValidUntil) || disposition.ValidUntil.After(fresh.Start.ValidUntil) {
		return out, value.ErrExpired
	}
	deadline := identity.Earlier(disposition.ValidUntil, now.Add(5*time.Second))
	captureCtx, stop := context.WithDeadline(ctx, deadline)
	native, err := s.Collector.Capture(captureCtx, fresh.Pin)
	completed := s.Now().UTC()
	captureErr := captureCtx.Err()
	stop()
	defer clear(native)
	if err != nil {
		return out, err
	}
	if captureErr != nil {
		return out, captureErr
	}
	if !completed.Before(deadline) {
		return out, value.ErrExpired
	}
	if len(native) == 0 || len(native) > artifact.MaxContextBytes {
		return out, value.ErrInvalid
	}
	copies, err := prepared.StoreContext(ctx, native, now, completed)
	if err != nil {
		return out, err
	}
	if copies.Validate(fresh.Expectation.Registration) != nil {
		return out, value.ErrDenied
	}
	return ContextResult{State: "StoredPendingVerification", Copies: copies}, nil
}
