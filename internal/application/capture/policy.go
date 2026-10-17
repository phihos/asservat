package capture

import (
	value "asservat.local/asservat/internal/domain/capture"
	"context"
	"time"
)

// Private roles use separate credentials. A source observation or an acceptance
// receipt grants no right to acquire, disclose, approve or dispatch evidence.
type PolicySourceWriter interface {
	ObservePolicy(context.Context, value.PolicySource) error
}

// A reader is pinned to a concrete Kubernetes object and never reads its
// status as execution authority. Compilation/acceptance remain independent.
type PolicySourceReader interface {
	PolicySource(context.Context) (value.PolicySource, error)
}

type PolicySourceObserver struct {
	Source PolicySourceReader
	Writer PolicySourceWriter
	Now    func() time.Time
}

func (s PolicySourceObserver) Reconcile(ctx context.Context) error {
	if s.Source == nil || s.Writer == nil || s.Now == nil {
		return value.ErrUnavailable
	}
	started := s.Now().UTC().Truncate(time.Microsecond)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	source, e := s.Source.PolicySource(ctx)
	if e != nil || !source.Valid(s.Now()) || source.ObservedAt.Before(started) || s.Now().Before(started) {
		return value.ErrUnavailable
	}
	// Failure never freshens the previous SQL observation. Its original lease
	// remains the bound, including NotFound before a UID tombstone is recorded.
	return s.Writer.ObservePolicy(ctx, source)
}

type PolicyAcceptor interface {
	AcceptPolicy(context.Context, value.PolicyAdmission) (value.AcceptedPolicy, error)
}
