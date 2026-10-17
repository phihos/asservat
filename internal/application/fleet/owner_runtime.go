package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerCredentialStatus is a non-authoritative process-local notification.
// Runtime readiness additionally requires protected bootstrap and routing;
// forwarding still performs current peer and exact request authorization.
type OwnerCredentialStatus struct{ Server, Client value.OwnerCertificate }

type OwnerCredentialSupervisor struct {
	Server, Client OwnerCredentialClient
	Binding        value.OwnerBinding
	Now            func() time.Time
	Wait           func(context.Context, time.Duration) error
	Jitter         func() time.Duration
	IdentityReady  chan<- OwnerCredentialStatus
}

func (s OwnerCredentialSupervisor) current() (OwnerCredentialStatus, error) {
	server, e1 := s.Server.Certificate()
	client, e2 := s.Client.Certificate()
	now := s.Now()
	if e1 != nil || e2 != nil || !server.Valid(now) || !client.Valid(now) || server.Binding != s.Binding || client.Binding != s.Binding || server.Usage != "server" || client.Usage != "client" {
		return OwnerCredentialStatus{}, value.ErrUnavailable
	}
	return OwnerCredentialStatus{Server: server, Client: client}, nil
}

func (s OwnerCredentialSupervisor) enroll(ctx context.Context, until, previousExpiry time.Time) (OwnerCredentialStatus, error) {
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	for attempt := 0; attempt < 8; attempt++ {
		if ctx.Err() != nil {
			return OwnerCredentialStatus{}, ctx.Err()
		}
		if !s.Now().Before(until) {
			return OwnerCredentialStatus{}, value.ErrUnavailable
		}
		e1 := s.Server.Enroll(ctx)
		// Do not start the second operation after the original pair deadline.
		if ctx.Err() != nil {
			return OwnerCredentialStatus{}, ctx.Err()
		}
		if !s.Now().Before(until) {
			return OwnerCredentialStatus{}, value.ErrUnavailable
		}
		e2 := s.Client.Enroll(ctx)
		current, err := s.current()
		if e1 == nil && e2 == nil && err == nil && ctx.Err() == nil && s.Now().Before(until) && current.Server.NotAfter.After(previousExpiry) && current.Client.NotAfter.After(previousExpiry) {
			return current, nil
		}
		if attempt == 7 {
			break
		}
		jitter := s.Jitter()
		if jitter < 0 || jitter > 500*time.Millisecond {
			return OwnerCredentialStatus{}, value.ErrInvalid
		}
		delay := min(time.Duration(1<<min(attempt, 5))*time.Second, 30*time.Second) + jitter
		if left := until.Sub(s.Now()); left < delay {
			delay = left
		}
		if delay <= 0 {
			return OwnerCredentialStatus{}, value.ErrUnavailable
		}
		if err = s.Wait(ctx, delay); err != nil {
			return OwnerCredentialStatus{}, err
		}
	}
	return OwnerCredentialStatus{}, value.ErrUnavailable
}

// Run supervises both independently keyed purposes for this process lifetime.
// Initial enrollment lasts at most 90 seconds; renewal cannot outlive the
// earlier original leaf. A partial success never extends the pair deadline.
func (s OwnerCredentialSupervisor) Run(ctx context.Context) error {
	if ctx == nil || s.Server == nil || s.Client == nil || !s.Binding.Valid() || s.Now == nil || s.Wait == nil || s.Jitter == nil {
		return value.ErrInvalid
	}
	defer s.Server.Close()
	defer s.Client.Close()
	current, err := s.enroll(ctx, s.Now().Add(90*time.Second), time.Time{})
	if err != nil {
		return err
	}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !current.Server.Valid(s.Now()) || !current.Client.Valid(s.Now()) {
			return value.ErrUnavailable
		}
		select {
		case s.IdentityReady <- current:
		default:
		}
		until := current.Server.NotAfter
		if current.Client.NotAfter.Before(until) {
			until = current.Client.NotAfter
		}
		if delay := until.Add(-value.OwnerCertificateRenewBefore).Sub(s.Now()); delay > 0 {
			if err = s.Wait(ctx, delay); err != nil {
				return err
			}
		}
		current, err = s.enroll(ctx, until, until)
		if err != nil {
			return err
		}
	}
}
