package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type runtimeCredentialFixture struct {
	target        value.WorkerCredentialTarget
	now           *time.Time
	peer          value.KeyPeer
	calls, closed int
	fail          bool
}

func (f *runtimeCredentialFixture) Enroll(ctx context.Context) error {
	f.calls++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if f.fail {
		return artifact.ErrDownloadUnavailable
	}
	_, until, err := f.target.CertificateEpoch(*f.now)
	if err != nil {
		return err
	}
	f.peer = value.KeyPeer{InstallationID: f.target.InstallationID, Role: "acquisition", PeerID: f.target.PodUID, Certificate: artifact.Digest{byte(f.calls)}, NotBefore: f.now.Add(-time.Second), NotAfter: until}
	return nil
}
func (f *runtimeCredentialFixture) Peer() (value.KeyPeer, error) {
	if !f.peer.Valid(*f.now) {
		return value.KeyPeer{}, artifact.ErrDownloadExpired
	}
	return f.peer, nil
}
func (f *runtimeCredentialFixture) Close() { f.closed++ }
func runtimeFixture(t *testing.T, d time.Duration) (WorkerCredentialSupervisor, *runtimeCredentialFixture) {
	t.Helper()
	now := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	id := "10000000-0000-4000-8000-000000000001"
	target := value.WorkerCredentialTarget{InstallationID: id, SessionID: id, WorkerID: id, PodUID: id, CreatedAt: now, RunUntil: now.Add(d)}
	f := &runtimeCredentialFixture{target: target, now: &now}
	return WorkerCredentialSupervisor{Client: f, Target: target, Now: func() time.Time { return now }, Wait: func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d <= 0 {
			t.Fatal("busy/negative wait")
		}
		now = now.Add(d)
		return nil
	}, Jitter: func() time.Duration { return 0 }, IdentityReady: nil}, f
}
func TestWorkerRuntimeOriginalPeriodsAndShortDeadline(t *testing.T) {
	for _, duration := range []time.Duration{time.Second, 30 * time.Second, 21 * time.Minute, 8 * time.Hour} {
		t.Run(duration.String(), func(t *testing.T) {
			s, f := runtimeFixture(t, duration)
			ready := make(chan value.KeyPeer, 24)
			s.IdentityReady = ready
			if err := s.Run(context.Background()); !errors.Is(err, artifact.ErrDownloadExpired) {
				t.Fatal(err)
			}
			count := len(ready)
			close(ready)
			for p := range ready {
				if p.NotAfter.After(s.Target.RunUntil) {
					t.Fatal("extended worker")
				}
			}
			want := int((duration + 20*time.Minute - 1) / (20 * time.Minute))
			if f.calls != want || count != want || f.closed != 1 || s.Now().After(s.Target.RunUntil) {
				t.Fatal("renewal changed original periods", f.calls, count, f.closed, s.Now())
			}
		})
	}
}
func TestWorkerRuntimeFailureAndCancellationAreFinite(t *testing.T) {
	s, f := runtimeFixture(t, time.Hour)
	f.fail = true
	if err := s.Run(context.Background()); err == nil || f.calls > 8 || f.closed != 1 || s.Now().Sub(s.Target.CreatedAt) > 30*time.Second {
		t.Fatal("unbounded bootstrap", err, f.calls)
	}
	s, f = runtimeFixture(t, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	s.Wait = func(context.Context, time.Duration) error { cancel(); return ctx.Err() }
	if err := s.Run(ctx); err == nil || f.closed != 1 || f.calls != 1 {
		t.Fatal("cancellation did not close credential", err)
	}
	s, f = runtimeFixture(t, time.Hour)
	f.fail = true
	s.Jitter = func() time.Duration { return time.Hour }
	if err := s.Run(context.Background()); !errors.Is(err, artifact.ErrInvalid) || f.closed != 1 {
		t.Fatal("unbounded jitter accepted", err)
	}
}

func TestWorkerRuntimeBlockedObserverCannotDelayExpiry(t *testing.T) {
	s, f := runtimeFixture(t, time.Hour)
	s.IdentityReady = make(chan value.KeyPeer) // No receiver, including at shutdown.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	s.Wait = func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case err := <-done:
		if err == nil || f.closed != 1 || f.calls != 1 {
			t.Fatal("observer bypassed shutdown", err)
		}
	case <-time.After(time.Second):
		t.Fatal("observer blocked credential shutdown")
	}
}
