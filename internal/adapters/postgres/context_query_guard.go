package postgres

import (
	"context"
	"sync"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
)

// queryGuarded requires one synchronous completed callback. It seals the entry
// before returning, joins an already-running callback under cancellation, and
// notices repeated calls even if a faulty guard swallows their error. Callback
// work is bounded SQL; it performs no external provider I/O.
func queryGuarded(ctx context.Context, invoke func(context.Context, func(context.Context) error) error, effect func(context.Context) error) error {
	if ctx == nil || ctx.Err() != nil || invoke == nil || effect == nil {
		return value.ErrUnavailable
	}
	owned, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var calls int
	var running, sealed bool
	var callbackError error
	var callbackUntil time.Time
	done := make(chan struct{})
	e := invoke(owned, func(child context.Context) (result error) {
		mu.Lock()
		if sealed {
			mu.Unlock()
			return value.ErrUnavailable
		}
		calls++
		if calls != 1 {
			mu.Unlock()
			return value.ErrUnavailable
		}
		running = true
		mu.Unlock()
		defer func() { mu.Lock(); running = false; callbackError = result; close(done); mu.Unlock() }()
		if child == nil || child.Err() != nil || owned.Err() != nil {
			return value.ErrUnavailable
		}
		callback, stop := context.WithCancel(owned)
		if until, ok := child.Deadline(); ok {
			stop()
			callback, stop = context.WithDeadline(owned, until)
			mu.Lock()
			callbackUntil = until
			mu.Unlock()
		}
		defer stop()
		unlink := context.AfterFunc(child, stop)
		defer unlink()
		if err := effect(callback); err != nil {
			return err
		}
		if child.Err() != nil || callback.Err() != nil {
			return value.ErrUnavailable
		}
		return nil
	})
	mu.Lock()
	sealed = true
	active := running
	valid := calls == 1 && !active && callbackError == nil && (callbackUntil.IsZero() || time.Now().Before(callbackUntil))
	mu.Unlock()
	if active {
		cancel()
		<-done
	}
	if e != nil || !valid || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}
