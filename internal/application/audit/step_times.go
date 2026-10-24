package audit

import (
	"context"
	"strings"
	"sync"
	"time"
)

// StepTimes collects fixed audit step names with duration buckets for one
// call's diagnostics. It carries no record, identity or error text and never
// changes a result; absence of a recorder changes nothing.
type StepTimes struct {
	mu    sync.Mutex
	marks []string
}
type stepTimesKey struct{}

func WithStepTimes(ctx context.Context) (context.Context, *StepTimes) {
	t := &StepTimes{}
	return context.WithValue(ctx, stepTimesKey{}, t), t
}

// StepTimesFrom returns the call's recorder, or nil when none is installed.
func StepTimesFrom(ctx context.Context) *StepTimes {
	if ctx == nil {
		return nil
	}
	t, _ := ctx.Value(stepTimesKey{}).(*StepTimes)
	return t
}

// MarkStep records step with the bucketed time since start, at most 64 marks.
func MarkStep(ctx context.Context, step string, start time.Time) {
	MarkDuration(ctx, step, time.Since(start))
}

// MarkDuration records step with the bucketed duration d, at most 64 marks.
func MarkDuration(ctx context.Context, step string, d time.Duration) {
	if t := StepTimesFrom(ctx); t != nil {
		t.mu.Lock()
		if len(t.marks) < 64 {
			t.marks = append(t.marks, step+DurationBucket(d))
		}
		t.mu.Unlock()
	}
}

func (t *StepTimes) String() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.marks, " ")
}

// DurationBucket keeps timing diagnostics in a finite vocabulary.
func DurationBucket(d time.Duration) string {
	switch {
	case d < 100*time.Millisecond:
		return "@<100ms"
	case d < 250*time.Millisecond:
		return "@<250ms"
	case d < 500*time.Millisecond:
		return "@<500ms"
	case d < time.Second:
		return "@<1s"
	case d < 2*time.Second:
		return "@<2s"
	case d < 3*time.Second:
		return "@<3s"
	default:
		return "@>=3s"
	}
}
