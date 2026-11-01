package evidence

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// A prepaid response window can outlive its first short observation. Each
// later frame still needs a fresh complete check, and neither the original
// operation deadline nor a revocation can be renewed by that observation.
func TestNativeResponseGateRechecksBeyondInitialObservation(t *testing.T) {
	base := nativeLeaseFixture()
	start := base.Operation.StartedAt
	base.Operation.Kind = value.NativeResponse
	base.Operation.Until = start.Add(identity.EvidenceReadRequestWindow)
	base.Operation.Processing.ValidUntil = base.Operation.Until
	var elapsed atomic.Int64
	now := func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	var revoked atomic.Bool
	var checks atomic.Int32
	observe := func(context.Context) (value.NativeLease, error) {
		checks.Add(1)
		if revoked.Load() {
			return value.NativeLease{}, artifact.ErrDownloadUnavailable
		}
		l := base
		l.ObservedAt = now()
		l.Until = identity.Earlier(now().Add(5*time.Second), base.Operation.Until)
		return l, nil
	}
	g, err := NewNativeFrameGate(context.Background(), observe, now)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	elapsed.Store(int64(12 * time.Second))
	l, err := g.Check(context.Background())
	if err != nil {
		t.Fatalf("fresh response check after the first observation expired: %v (checks=%d)", err, checks.Load())
	}
	if checks.Load() != 2 || !l.Valid(now()) || l.Until.After(now().Add(5*time.Second)) {
		t.Fatal("response reused an expired observation or widened the new one", l, checks.Load())
	}
	revoked.Store(true)
	if _, err := g.Check(context.Background()); err == nil {
		t.Fatal("revoked response continued")
	}
	if g.Context().Err() == nil {
		t.Fatal("revocation did not close the response")
	}
}

func TestNativeResponseGateCannotRenewOriginalOperation(t *testing.T) {
	base := nativeLeaseFixture()
	start := base.Operation.StartedAt
	base.Operation.Kind = value.NativeResponse
	base.Operation.Until = start.Add(identity.EvidenceReadRequestWindow)
	base.Operation.Processing.ValidUntil = base.Operation.Until
	var elapsed atomic.Int64
	now := func() time.Time { return start.Add(time.Duration(elapsed.Load())) }
	var checks atomic.Int32
	g, err := NewNativeFrameGate(context.Background(), func(context.Context) (value.NativeLease, error) {
		checks.Add(1)
		l := base
		l.ObservedAt, l.Until = now(), now().Add(5*time.Second)
		return l, nil
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	elapsed.Store(int64(identity.EvidenceReadRequestWindow))
	if _, err := g.Check(context.Background()); err == nil || checks.Load() != 1 {
		t.Fatal("expired original operation consulted a new observation", err, checks.Load())
	}
}
