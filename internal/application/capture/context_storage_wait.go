package capture

import (
	"context"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

type contextStorageDemand uint8

const (
	storageDemandUnused contextStorageDemand = iota
	storageDemandAcknowledged
	storageDemandFailed
)

// One owner transfers from a non-authoritative hint to authoritative
// consumption only after the hint joins. Its original authority bound and
// single demand attempt survive that transfer; no second hint is started.
type contextStorageWait struct {
	done      chan struct{}
	cancel    context.CancelFunc
	until     time.Time
	selection value.ContextStorageSelection
	bound     string               // closed private label for the original enclosing cutoff
	demand    contextStorageDemand // read only after done is closed
}

func (s ContextInvestigation) beginStorageWait(ctx context.Context, target targets.PodResolution, until time.Time, selection value.ContextStorageSelection) *contextStorageWait {
	call, cancel := context.WithDeadline(ctx, until)
	w := &contextStorageWait{done: make(chan struct{}), cancel: cancel, until: until, selection: selection, bound: "request"}
	started := time.Now()
	if s.Refresh == nil || s.Storage == nil {
		auditapp.MarkStep(ctx, "p-await-storage", started)
		close(w.done)
		return w
	}
	go func() {
		defer close(w.done)
		defer auditapp.MarkStep(ctx, "p-await-storage", started)
		if !storageCallCurrent(call, until, s.Now()) {
			return
		}
		w.demand = s.awaitStorage(call, target)
	}()
	return w
}

func (w *contextStorageWait) close() {
	w.cancel()
	<-w.done
}

// The early hint keeps ADR-200's cold-start behavior: a missing/stale read can
// demand refresh and poll. It grants no authority and retains no observation.
func (s ContextInvestigation) awaitStorage(ctx context.Context, target targets.PodResolution) contextStorageDemand {
	if s.Refresh == nil || s.Storage == nil {
		return storageDemandUnused
	}
	ready := func() bool {
		v, err := s.Storage.ContextStorage(ctx, target.Target())
		return err == nil && !v.Binding.FreshUntil.Before(s.Now().Add(storageMargin))
	}
	if ready() {
		return storageDemandUnused
	}
	if s.Refresh.DemandCapacityRefresh(ctx, target.Request) != nil {
		return storageDemandFailed
	}
	for !ready() {
		t := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return storageDemandAcknowledged
		case <-t.C:
		}
	}
	return storageDemandAcknowledged
}

type contextStorageSelectionChange struct{}

func (contextStorageSelectionChange) Error() string { return "context storage selection changed" }
func (contextStorageSelectionChange) Unwrap() error { return value.ErrChanged }

// storageCallCurrent checks the actual context deadline even if its timer
// callback has not run, separately from the injected authority clock.
func storageCallCurrent(ctx context.Context, until, now time.Time) bool {
	if ctx.Err() != nil || !now.Before(until) {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Before(deadline)
}

func (s ContextInvestigation) consumeStorage(ctx context.Context, f contextFacts, intent value.ContextIntent, w *contextStorageWait) (ContextStorageObservation, error) {
	var zero ContextStorageObservation
	until, boundName := w.until, w.bound
	if boundName == "" {
		boundName = "request"
	}
	for _, bound := range []struct {
		at   time.Time
		name string
	}{
		{f.target.FreshUntil, "target"}, {f.eligibility.ValidUntil, "eligibility"}, {f.eligibility.VerifiedIdentity.ValidUntil, "identity"},
		{f.capability.FreshUntil, "capability"}, {f.retention.Proof.ValidUntil, "retention-proof"}, {f.retention.ValidUntil, "retention"}, {f.retention.ExpiresAt, "retention-expiry"},
	} {
		if bound.at.Before(until) {
			until, boundName = bound.at, bound.name
		}
	}
	if intent.Reason != nil && intent.Reason.ExpiresAt.Before(until) {
		until, boundName = intent.Reason.ExpiresAt, "reason"
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	current := func() bool {
		now := s.Now()
		return storageCallCurrent(call, until, now) && s.nonStorageFactsCurrent(f, now)
	}
	expired := func() error {
		reason := boundName
		if s.Now().Before(until) {
			if why := s.nonStorageFactsFailure(f, s.Now()); why != "" {
				reason = why
			}
		}
		// Context timers use the real clock independently from injected
		// authority clocks; never substitute one clock's time into the other.
		if deadline, ok := ctx.Deadline(); ctx.Err() != nil || ok && !time.Now().Before(deadline) {
			reason = "operation"
		}
		if err := call.Err(); err != nil {
			return previewFailure("facts/current/"+reason, err)
		}
		return previewFailure("facts/current/"+reason, value.ErrChanged)
	}
	if !current() {
		w.close()
		return zero, expired()
	}
	select {
	case <-w.done:
	case <-call.Done():
		w.close()
		return zero, expired()
	}
	// The old hint no longer owns I/O. No background operation is restarted.
	for {
		if !current() {
			return zero, expired()
		}
		v, err := s.Storage.ContextStorage(call, f.target.Target())
		if err != nil {
			return zero, previewFailure("facts/storage", err)
		}
		if !current() {
			return zero, expired()
		}
		if !s.storageCurrent(v, f.target.Target(), s.Now()) {
			return zero, previewFailure("facts/current/storage", value.ErrChanged)
		}
		if w.selection == (value.ContextStorageSelection{}) {
			w.selection = v.Selection
		} else if w.selection != v.Selection {
			return zero, previewFailure("facts/storage", contextStorageSelectionChange{})
		}
		if !v.Binding.FreshUntil.Before(s.Now().Add(storageMargin)) {
			return v, nil
		}
		// A valid but thin observation supplies no admission authority. Only
		// another independent protected read may replace it. Other facts,
		// selection and original deadlines cannot be replaced or extended.
		if s.Refresh == nil || w.demand == storageDemandFailed {
			return zero, previewFailure("facts/storage", contextStorageMarginRefusal{})
		}
		if w.demand == storageDemandUnused {
			if !current() {
				return zero, expired()
			}
			w.demand = storageDemandFailed
			if err := s.Refresh.DemandCapacityRefresh(call, f.target.Request); err != nil {
				return zero, previewFailure("facts/storage/refresh", err)
			}
			w.demand = storageDemandAcknowledged
		}
		if !current() {
			return zero, expired()
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-call.Done():
			timer.Stop()
			return zero, expired()
		case <-timer.C:
		}
	}
}
