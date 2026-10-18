package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
)

func TestContextQueryGuardRejectsMissingRepeatedAndSwallowedFailure(t *testing.T) {
	failure := errors.New("synthetic failure")
	for _, tc := range []struct {
		name        string
		invoke      func(context.Context, func(context.Context) error) error
		effectError error
	}{
		{"missing", func(context.Context, func(context.Context) error) error { return nil }, nil},
		{"repeated", func(c context.Context, f func(context.Context) error) error { _ = f(c); _ = f(c); return nil }, nil},
		{"swallowed-effect-error", func(c context.Context, f func(context.Context) error) error { _ = f(c); return nil }, failure},
		{"postcommit-guard-error", func(c context.Context, f func(context.Context) error) error {
			if e := f(c); e != nil {
				return e
			}
			return failure
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			e := queryGuarded(context.Background(), tc.invoke, func(context.Context) error { calls++; return tc.effectError })
			if !errors.Is(e, value.ErrUnavailable) || calls > 1 {
				t.Fatalf("err=%v effects=%d", e, calls)
			}
		})
	}
}
func TestContextQueryGuardSealsLateCallbackAndJoinsCancellation(t *testing.T) {
	var later func(context.Context) error
	var calls atomic.Int32
	if e := queryGuarded(context.Background(), func(_ context.Context, f func(context.Context) error) error { later = f; return nil }, func(context.Context) error { calls.Add(1); return nil }); !errors.Is(e, value.ErrUnavailable) {
		t.Fatal(e)
	}
	if e := later(context.Background()); !errors.Is(e, value.ErrUnavailable) || calls.Load() != 0 {
		t.Fatal("late callback ran", e)
	}
	entered := make(chan struct{})
	finished := make(chan struct{})
	e := queryGuarded(context.Background(), func(c context.Context, f func(context.Context) error) error {
		go func() { _ = f(c) }()
		<-entered
		return nil
	}, func(c context.Context) error { close(entered); <-c.Done(); close(finished); return c.Err() })
	if !errors.Is(e, value.ErrUnavailable) {
		t.Fatal(e)
	}
	select {
	case <-finished:
	default:
		t.Fatal("returned without joining cancelled SQL callback")
	}
}
func TestContextQueryGuardPreservesOriginalCancellationAndDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := queryGuarded(ctx, func(c context.Context, f func(context.Context) error) error { return f(context.Background()) }, func(c context.Context) error { cancel(); <-c.Done(); return c.Err() })
	if !errors.Is(e, value.ErrUnavailable) {
		t.Fatal(e)
	}
	until := time.Now().Add(time.Second)
	bounded, stop := context.WithDeadline(context.Background(), until)
	defer stop()
	e = queryGuarded(bounded, func(_ context.Context, f func(context.Context) error) error { return f(context.Background()) }, func(c context.Context) error {
		got, ok := c.Deadline()
		if !ok || !got.Equal(until) {
			t.Fatal("guard replaced original deadline")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestContextQueryGuardPreservesEarlierGuardDeadline(t *testing.T) {
	original, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()
	earlier := time.Now().Add(time.Second)
	err := queryGuarded(original, func(c context.Context, callback func(context.Context) error) error {
		child, stop := context.WithDeadline(c, earlier)
		defer stop()
		return callback(child)
	}, func(c context.Context) error {
		got, ok := c.Deadline()
		if !ok || !got.Equal(earlier) {
			t.Fatalf("SQL callback lost original guard deadline: got %v want %v", got, earlier)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestContextQueryGuardRejectsChildExpiryBeforeGuardReturns(t *testing.T) {
	err := queryGuarded(context.Background(), func(c context.Context, callback func(context.Context) error) error {
		child, stop := context.WithTimeout(c, 20*time.Millisecond)
		defer stop()
		if err := callback(child); err != nil {
			return err
		}
		<-child.Done()
		return nil
	}, func(context.Context) error { return nil })
	if !errors.Is(err, value.ErrUnavailable) {
		t.Fatal("expired guard returned Fresh eligibility", err)
	}
}
