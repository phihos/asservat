package evidence

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

type WorkerCredentialClient interface {
	Enroll(context.Context) error
	Peer() (value.KeyPeer, error)
	Close()
}

// WorkerCredentialSupervisor owns only the credential phase of A-ACQUIRE.
// Identity readiness is not task readiness, evidence access or delivery success.
// Native work/connection supervision must be composed separately before enabling
// the public download workflow; this loop never substitutes a no-op transfer.
type WorkerCredentialSupervisor struct {
	Client WorkerCredentialClient
	Target value.WorkerCredentialTarget
	Now    func() time.Time
	Wait   func(context.Context, time.Duration) error
	Jitter func() time.Duration
	// Advisory, nonblocking notifications. Readiness never grants evidence access.
	IdentityReady chan<- value.KeyPeer
}

func (s WorkerCredentialSupervisor) enroll(ctx context.Context, until time.Time) error {
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		if ctx.Err() != nil || !s.Now().Before(until) {
			return artifact.ErrDownloadExpired
		}
		if err := s.Client.Enroll(ctx); err == nil {
			p, e := s.Client.Peer()
			if e == nil && p.Valid(s.Now()) && p.InstallationID == s.Target.InstallationID && p.PeerID == s.Target.PodUID && p.Role == "acquisition" && !p.NotAfter.After(s.Target.RunUntil) && ctx.Err() == nil {
				return nil
			}
		}
		if attempt == 7 {
			break
		}
		jitter := s.Jitter()
		if jitter < 0 || jitter > 500*time.Millisecond {
			return artifact.ErrInvalid
		}
		delay := time.Duration(1<<min(attempt, 3))*time.Second + jitter
		if left := until.Sub(s.Now()); left < delay {
			delay = left
		}
		if delay <= 0 || s.Wait(ctx, delay) != nil {
			return artifact.ErrDownloadExpired
		}
	}
	return artifact.ErrDownloadUnavailable
}

func (s WorkerCredentialSupervisor) Run(ctx context.Context) error {
	if ctx == nil || s.Client == nil || !s.Target.Valid() || s.Now == nil || s.Wait == nil || s.Jitter == nil {
		return artifact.ErrInvalid
	}
	defer s.Client.Close()
	ctx, cancel := context.WithDeadline(ctx, s.Target.RunUntil)
	defer cancel()
	if _, _, e := s.Target.CertificateEpoch(s.Now()); e != nil {
		return e
	}
	first := s.Now().Add(30 * time.Second)
	if s.Target.RunUntil.Before(first) {
		first = s.Target.RunUntil
	}
	if err := s.enroll(ctx, first); err != nil {
		return err
	}
	for {
		if ctx.Err() != nil || !s.Now().Before(s.Target.RunUntil) {
			return artifact.ErrDownloadExpired
		}
		p, err := s.Client.Peer()
		if err != nil || !p.Valid(s.Now()) {
			return artifact.ErrDownloadExpired
		}
		select {
		case s.IdentityReady <- p:
		default:
		}
		// The final (possibly shortened) certificate cannot be renewed past the
		// worker's original deadline. Wait once rather than polling it forever.
		end := s.Target.RunUntil.UTC().Truncate(time.Second)
		if p.NotAfter.Equal(end) {
			if err = s.Wait(ctx, p.NotAfter.Sub(s.Now())); err != nil {
				return err
			}
			return artifact.ErrDownloadExpired
		}
		wake := p.NotAfter.Add(-value.WorkerCertificateRenewBefore)
		if delay := wake.Sub(s.Now()); delay > 0 {
			if err = s.Wait(ctx, delay); err != nil {
				return err
			}
		}
		if err = s.enroll(ctx, p.NotAfter); err != nil {
			return err
		}
		renewed, err := s.Client.Peer()
		if err != nil || !renewed.NotAfter.After(p.NotAfter) {
			return artifact.ErrDownloadUnavailable
		}
	}
}
