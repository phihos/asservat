package identity

import (
	"context"
	"errors"
	"time"
)

// ErrBracketProof reports an opening proof that returned no future deadline.
var ErrBracketProof = errors.New("bracket proof has no future deadline")

// Bracket runs a sequence of installer steps under one opening proof
// (ADR-316, generalizing ADR-315). The opening proof's original deadline
// bounds every step; it is never renewed. Another step starts only while at
// least Reserve of it remains, and a bracket that ran a step ends with one
// closing proof. Each step keeps its own effect checks and deadlines.
type Bracket struct {
	Now     func() time.Time
	Reserve time.Duration
	// Open returns the opening proof's deadline.
	Open func(context.Context) (time.Time, error)
	// Close is the closing proof, run after at least one step.
	Close func(context.Context) error
}

// Run calls step until it reports no further work, the remaining lease is
// below Reserve or a step fails. The first step always runs, as one step
// did under the former per-step proof. It returns the number of steps that
// did work. A step error is returned without a closing proof: the step's
// own uncertain-result rules apply and the caller resumes with a new bracket.
func (b Bracket) Run(ctx context.Context, step func(context.Context) (bool, error)) (int, error) {
	if ctx == nil || b.Now == nil || b.Open == nil || b.Close == nil || step == nil || b.Reserve <= 0 {
		return 0, errors.New("incomplete bracket")
	}
	until, err := b.Open(ctx)
	if err != nil {
		return 0, err
	}
	if !b.Now().Before(until) {
		return 0, ErrBracketProof
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	n := 0
	for n == 0 || until.Sub(b.Now()) >= b.Reserve {
		if err = ctx.Err(); err != nil {
			return n, err
		}
		more, err := step(ctx)
		if err != nil {
			return n, err
		}
		if !more {
			break
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	if err = b.Close(ctx); err != nil {
		return n, err
	}
	return n, ctx.Err()
}
