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

// MarkStep records step with the bucketed time since start, at most 16 marks.
func MarkStep(ctx context.Context, step string, start time.Time) {
	if ctx == nil {
		return
	}
	if t, ok := ctx.Value(stepTimesKey{}).(*StepTimes); ok && t != nil {
		t.mu.Lock()
		if len(t.marks) < 16 {
			t.marks = append(t.marks, step+DurationBucket(time.Since(start)))
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
