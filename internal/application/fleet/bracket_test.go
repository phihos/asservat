package fleet

import (
	"context"
	"errors"
	"testing"
	"time"
)

type bracketClock struct{ t time.Time }

func (c *bracketClock) now() time.Time { return c.t }

// bracketRun applies pending steps of cost each under a lease of lease.
func bracketRun(t *testing.T, clock *bracketClock, lease, cost time.Duration, pending *int, closeErr error) (int, int, error) {
	t.Helper()
	opens := 0
	b := Bracket{
		Now:     clock.now,
		Reserve: 2 * time.Second,
		Open: func(context.Context) (time.Time, error) {
			opens++
			return clock.t.Add(lease), nil
		},
		Close: func(context.Context) error { return closeErr },
	}
	n, err := b.Run(context.Background(), func(ctx context.Context) (bool, error) {
		if *pending == 0 {
			return false, nil
		}
		if d, ok := ctx.Deadline(); !ok || d.After(clock.t.Add(lease)) {
			t.Fatal("step deadline exceeds the opening proof")
		}
		clock.t = clock.t.Add(cost)
		*pending--
		return true, nil
	})
	return n, opens, err
}

func TestBracketStopsAtReserveAndResumes(t *testing.T) {
	clock := &bracketClock{t: time.Unix(1_800_000_000, 0)}
	pending := 19
	// A short lease: 3 s minus a 2 s reserve leaves room for a few steps only.
	n, opens, err := bracketRun(t, clock, 3*time.Second, 300*time.Millisecond, &pending, nil)
	if err != nil || opens != 1 || n != 4 || pending != 15 {
		t.Fatalf("short lease: n=%d opens=%d pending=%d err=%v", n, opens, pending, err)
	}
	brackets := 1
	for pending > 0 {
		if _, _, err = bracketRun(t, clock, 5*time.Second, 300*time.Millisecond, &pending, nil); err != nil {
			t.Fatal(err)
		}
		brackets++
	}
	if brackets > 5 {
		t.Fatalf("resume needed %d brackets for 19 steps", brackets)
	}
	// A completed sequence opens once more, runs nothing and closes nothing.
	n, opens, err = bracketRun(t, clock, 5*time.Second, 0, &pending, errors.New("closing proof must not run"))
	if err != nil || n != 0 || opens != 1 {
		t.Fatal("completed sequence", n, opens, err)
	}
}

func TestBracketFirstStepRunsBelowReserve(t *testing.T) {
	clock := &bracketClock{t: time.Unix(1_800_000_000, 0)}
	pending := 3
	n, _, err := bracketRun(t, clock, time.Second, 100*time.Millisecond, &pending, nil)
	if err != nil || n != 1 || pending != 2 {
		t.Fatal("one step per bracket below the reserve", n, pending, err)
	}
}

func TestBracketLostClosingProofFails(t *testing.T) {
	clock := &bracketClock{t: time.Unix(1_800_000_000, 0)}
	pending := 2
	lost := errors.New("closing proof lost")
	n, _, err := bracketRun(t, clock, 5*time.Second, 100*time.Millisecond, &pending, lost)
	if !errors.Is(err, lost) || n != 2 || pending != 0 {
		t.Fatal("closing proof failure must fail the bracket after its steps", n, err)
	}
}

func TestBracketStepFailureSkipsClosingProof(t *testing.T) {
	clock := &bracketClock{t: time.Unix(1_800_000_000, 0)}
	failed := errors.New("uncertain step")
	closed := false
	b := Bracket{Now: clock.now, Reserve: time.Second,
		Open:  func(context.Context) (time.Time, error) { return clock.t.Add(5 * time.Second), nil },
		Close: func(context.Context) error { closed = true; return nil }}
	n, err := b.Run(context.Background(), func(context.Context) (bool, error) { return false, failed })
	if !errors.Is(err, failed) || n != 0 || closed {
		t.Fatal("step failure", n, err, closed)
	}
}

func TestBracketRejectsExpiredOpeningProof(t *testing.T) {
	clock := &bracketClock{t: time.Unix(1_800_000_000, 0)}
	ran := false
	b := Bracket{Now: clock.now, Reserve: time.Second,
		Open:  func(context.Context) (time.Time, error) { return clock.t, nil },
		Close: func(context.Context) error { return nil }}
	if _, err := b.Run(context.Background(), func(context.Context) (bool, error) { ran = true; return true, nil }); !errors.Is(err, ErrBracketProof) || ran {
		t.Fatal("expired opening proof ran a step", err)
	}
}
