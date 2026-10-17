package fleet

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

type ownerRuntimeFixture struct {
	now           *time.Time
	binding       value.OwnerBinding
	usage         string
	certificate   value.OwnerCertificate
	calls, closed int
	fail, stale   bool
}

func (f *ownerRuntimeFixture) Enroll(ctx context.Context) error {
	f.calls++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if f.fail {
		return value.ErrUnavailable
	}
	if f.stale && f.certificate.Valid(*f.now) {
		return nil
	}
	_, until, err := value.OwnerCertificateWindow(*f.now)
	if err != nil {
		return err
	}
	f.certificate = value.OwnerCertificate{Binding: f.binding, Usage: f.usage, Digest: artifact.Digest{byte(f.calls)}, NotBefore: f.now.Add(-time.Second), NotAfter: until}
	return nil
}
func (f *ownerRuntimeFixture) Certificate() (value.OwnerCertificate, error) {
	if !f.certificate.Valid(*f.now) {
		return value.OwnerCertificate{}, value.ErrUnavailable
	}
	return f.certificate, nil
}
func (f *ownerRuntimeFixture) Close() { f.closed++ }
func ownerRuntimeTest(t *testing.T) (OwnerCredentialSupervisor, *ownerRuntimeFixture, *ownerRuntimeFixture) {
	t.Helper()
	now := time.Now().Add(time.Hour).UTC().Truncate(value.OwnerCertificatePeriod).Add(2 * time.Minute)
	id := "11111111-1111-4111-8111-111111111111"
	b := value.OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	s := &ownerRuntimeFixture{now: &now, binding: b, usage: "server"}
	c := &ownerRuntimeFixture{now: &now, binding: b, usage: "client"}
	r := OwnerCredentialSupervisor{Server: s, Client: c, Binding: b, Now: func() time.Time { return now }, Wait: func(ctx context.Context, d time.Duration) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d <= 0 {
			t.Fatal("busy wait")
		}
		now = now.Add(d)
		return nil
	}, Jitter: func() time.Duration { return 0 }}
	return r, s, c
}
func TestOwnerRuntimeRenewsBothPurposesUntilCancellation(t *testing.T) {
	r, s, c := ownerRuntimeTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	end := r.Now().Add(8 * time.Hour)
	wait := r.Wait
	r.Wait = func(ctx context.Context, d time.Duration) error {
		if !r.Now().Add(d).Before(end) {
			cancel()
			return ctx.Err()
		}
		return wait(ctx, d)
	}
	r.IdentityReady = make(chan OwnerCredentialStatus) // unread notification cannot block
	if err := r.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.calls < 24 || s.calls != c.calls || s.closed != 1 || c.closed != 1 {
		t.Fatal("renewal/shutdown", s.calls, c.calls, s.closed, c.closed)
	}
}
func TestOwnerRuntimeFailurePreservesOriginalBound(t *testing.T) {
	for _, mode := range []string{"initial", "renewal", "stale", "wrong-purpose", "wrong-process", "jitter"} {
		t.Run(mode, func(t *testing.T) {
			r, s, c := ownerRuntimeTest(t)
			start := r.Now()
			_, until, _ := value.OwnerCertificateWindow(start)
			switch mode {
			case "initial":
				c.fail = true
			case "renewal":
				wait := r.Wait
				r.Wait = func(ctx context.Context, d time.Duration) error { c.fail = true; return wait(ctx, d) }
			case "stale":
				c.stale = true
			case "wrong-purpose":
				c.usage = "server"
			case "wrong-process":
				c.binding.ProcessEpoch = "22222222-2222-4222-8222-222222222222"
			case "jitter":
				c.fail = true
				r.Jitter = func() time.Duration { return time.Hour }
			}
			if err := r.Run(context.Background()); err == nil {
				t.Fatal("unsafe supervisor success")
			}
			if s.closed != 1 || c.closed != 1 || r.Now().After(until) || s.calls > 9 || c.calls > 9 {
				t.Fatal("unbounded retry or leaked key", s.calls, c.calls, r.Now())
			}
			if mode == "initial" && r.Now().After(start.Add(90*time.Second)) {
				t.Fatal("unbounded initial enrollment")
			}
		})
	}
}
