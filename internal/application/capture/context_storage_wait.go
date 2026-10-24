package capture

import (
	"context"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
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
	demand    contextStorageDemand // read only after done is closed
}

func (s ContextInvestigation) beginStorageWait(ctx context.Context, target targets.PodResolution, until time.Time, selection value.ContextStorageSelection) *contextStorageWait {
	call, cancel := context.WithDeadline(ctx, until)
	w := &contextStorageWait{done: make(chan struct{}), cancel: cancel, until: until, selection: selection}
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
	until := w.until
	for _, bound := range []time.Time{
		f.target.FreshUntil, f.eligibility.ValidUntil, f.eligibility.VerifiedIdentity.ValidUntil,
		f.capability.FreshUntil, f.retention.ValidUntil, f.retention.Proof.ValidUntil, f.retention.ExpiresAt,
	} {
		until = identity.Earlier(until, bound)
	}
	if intent.Reason != nil {
		until = identity.Earlier(until, intent.Reason.ExpiresAt)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	current := func() bool {
		now := s.Now()
		return storageCallCurrent(call, until, now) && s.nonStorageFactsCurrent(f, now)
	}
	expired := func() error {
		if err := call.Err(); err != nil {
			return previewFailure("facts/current", err)
		}
		return previewFailure("facts/current", value.ErrChanged)
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
		if !current() || !s.storageCurrent(v, f.target.Target(), s.Now()) {
			return zero, expired()
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
