package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

// Only a private adapter over an actual verified TLS connection implements this
// port. Public certificate strings/JSON cannot instantiate peer authentication.
type OwnerPeerConnection interface {
	OwnerCertificate() (value.OwnerCertificate, error)
	VerifyCurrentOwner(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)
}

// OwnerServingIdentity is the process-owned server key, not a fabricated TLS
// peer. Local serving eligibility and actual remote peer authentication share
// current registry/protection/route checks, but have distinct entry points.
type OwnerServingIdentity interface {
	ServingCertificate() (value.OwnerCertificate, error)
	VerifyServingCertificate(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)
}
type OwnerClientIdentity interface {
	ClientCertificate() (value.OwnerCertificate, error)
	VerifyClientCertificate(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)
}
type OwnerProtectionReader interface {
	ReadOwnerProtection(context.Context, value.OwnerPool) (value.OwnerProtection, error)
}
type OwnerAuthenticator struct {
	Registry   OwnerCertificateRegistry
	Routes     OwnerRouteReader
	Protection OwnerProtectionReader
	Now        func() time.Time
}

func (s *OwnerAuthenticator) AuthenticateOwner(ctx context.Context, connection OwnerPeerConnection) (value.AuthenticatedOwner, error) {
	if connection == nil {
		return value.AuthenticatedOwner{}, value.ErrInvalid
	}
	return s.authenticate(ctx, connection.OwnerCertificate, connection.VerifyCurrentOwner)
}

func (s *OwnerAuthenticator) CheckOwnerServing(ctx context.Context, server OwnerServingIdentity) (time.Time, error) {
	if server == nil {
		return time.Time{}, value.ErrInvalid
	}
	return s.checkLocal(ctx, "server", server.ServingCertificate, server.VerifyServingCertificate)
}

func (s *OwnerAuthenticator) CheckOwnerClient(ctx context.Context, client OwnerClientIdentity) (time.Time, error) {
	if client == nil {
		return time.Time{}, value.ErrInvalid
	}
	return s.checkLocal(ctx, "client", client.ClientCertificate, client.VerifyClientCertificate)
}

func (s *OwnerAuthenticator) checkLocal(ctx context.Context, usage string, get func() (value.OwnerCertificate, error), verify func(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)) (time.Time, error) {
	certificate, err := get()
	if err != nil || certificate.Usage != usage {
		return time.Time{}, value.ErrDenied
	}
	out, err := s.authenticate(ctx, func() (value.OwnerCertificate, error) { return certificate, nil }, verify)
	if err != nil {
		return time.Time{}, err
	}
	return out.ValidUntil, nil
}

type refusalStepKey struct{}

// WithRefusalSteps carries a diagnostic sink for fixed authentication step
// names. It carries no request data and changes no result.
func WithRefusalSteps(ctx context.Context, report func(string)) context.Context {
	return context.WithValue(ctx, refusalStepKey{}, report)
}

func refusalStep(ctx context.Context, step string) {
	if ctx == nil {
		return
	}
	if report, ok := ctx.Value(refusalStepKey{}).(func(string)); ok && report != nil {
		report(step + RemainingBucket(ctx, time.Now()))
	}
}

// RemainingBucket coarsely names the time left on ctx for diagnostics.
func RemainingBucket(ctx context.Context, now time.Time) string {
	d, ok := ctx.Deadline()
	switch left := d.Sub(now); {
	case !ok:
		return "@none"
	case left <= 0:
		return "@0"
	case left < 500*time.Millisecond:
		return "@<0.5s"
	case left < time.Second:
		return "@<1s"
	case left < 2*time.Second:
		return "@<2s"
	}
	return "@>=2s"
}

func (s *OwnerAuthenticator) authenticate(ctx context.Context, certificateFrom func() (value.OwnerCertificate, error), verify func(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)) (value.AuthenticatedOwner, error) {
	var zero value.AuthenticatedOwner
	if s == nil || ctx == nil || s.Registry == nil || s.Routes == nil || s.Protection == nil || s.Now == nil {
		refusalStep(ctx, "invalid")
		return zero, value.ErrInvalid
	}
	start := s.Now()
	ctx, end := context.WithDeadline(ctx, start.Add(5*time.Second))
	defer end()
	certificate, err := certificateFrom()
	if err != nil || !certificate.Valid(s.Now()) || ctx.Err() != nil {
		refusalStep(ctx, "certificate")
		return zero, value.ErrDenied
	}
	first, err := s.Registry.ReadOwnerRegistration(ctx, certificate)
	if err != nil || !first.Valid(s.Now()) || first.Certificate != certificate {
		refusalStep(ctx, "registration-first")
		return zero, value.ErrUnavailable
	}
	first.Configuration.Configuration = first.Configuration.Configuration.Clone()
	current, err := verify(first.Configuration)
	if err != nil || current != certificate {
		refusalStep(ctx, "verify-first")
		return zero, value.ErrDenied
	}
	pool := first.Enrollment.Pool
	before, err := s.Protection.ReadOwnerProtection(ctx, pool)
	if err != nil || !before.Valid(s.Now()) || before.Pool != pool {
		refusalStep(ctx, "protection-before")
		return zero, value.ErrUnavailable
	}
	route, err := s.Routes.CurrentOwnerRoute(ctx, certificate.Binding)
	if err != nil || !route.Valid(s.Now()) || route.Endpoint.Binding != certificate.Binding || route.Endpoint.Pool != pool || route.Endpoint.Pod != first.Enrollment.Pod || route.Endpoint.ReplicaSetUID != first.Enrollment.ReplicaSetUID || !route.Configuration.Configuration.Equal(first.Configuration.Configuration) {
		refusalStep(ctx, "route")
		return zero, value.ErrUnavailable
	}
	route.Configuration.Configuration = route.Configuration.Configuration.Clone()
	after, err := s.Protection.ReadOwnerProtection(ctx, pool)
	if err != nil || !after.Valid(s.Now()) || after.Pool != pool || after.Digest != before.Digest {
		refusalStep(ctx, "protection-after")
		return zero, value.ErrUnavailable
	}
	last, err := s.Registry.ReadOwnerRegistration(ctx, certificate)
	if err != nil || !last.Valid(s.Now()) || last.Certificate != certificate || last.Enrollment != first.Enrollment || !last.Configuration.Configuration.Equal(first.Configuration.Configuration) {
		refusalStep(ctx, "registration-last")
		return zero, value.ErrUnavailable
	}
	current, err = verify(last.Configuration)
	if err != nil || current != certificate {
		refusalStep(ctx, "verify-last")
		return zero, value.ErrDenied
	}
	now := s.Now()
	if ctx.Err() != nil || !first.Valid(now) || !last.Valid(now) || !before.Valid(now) || !after.Valid(now) || !route.Valid(now) || !certificate.Valid(now) {
		refusalStep(ctx, "expired")
		return zero, value.ErrUnavailable
	}
	until := start.Add(5 * time.Second)
	for _, deadline := range []time.Time{first.FreshUntil, last.FreshUntil, route.FreshUntil, before.FreshUntil, after.FreshUntil, certificate.NotAfter} {
		until = identity.Earlier(until, deadline)
	}
	out := value.AuthenticatedOwner{Certificate: certificate, EnrollmentID: first.Enrollment.ID, Pool: pool, Pod: route.Endpoint.Pod, ReplicaSetUID: route.Endpoint.ReplicaSetUID, ConfigurationRevision: first.Configuration.Configuration.Revision, ProtectionDigest: before.Digest, VerifiedAt: start, ValidUntil: until}
	if !out.Valid(s.Now()) {
		refusalStep(ctx, "result")
		return zero, value.ErrUnavailable
	}
	return out, nil
}

// ObserveOwnerServing returns the same independently current local server
// observation used by serving admission, including its accepted pool/config.
// It does not manufacture a remote TLS peer from a local certificate.
func (s *OwnerAuthenticator) ObserveOwnerServing(ctx context.Context, server OwnerServingIdentity) (value.AuthenticatedOwner, error) {
	if server == nil {
		return value.AuthenticatedOwner{}, value.ErrInvalid
	}
	certificate, e := server.ServingCertificate()
	if e != nil || certificate.Usage != "server" {
		return value.AuthenticatedOwner{}, value.ErrDenied
	}
	return s.authenticate(ctx, func() (value.OwnerCertificate, error) { return certificate, nil }, server.VerifyServingCertificate)
}

// ObserveOwnerClient returns the same full current observation as local client
// admission. It retains the actual private client identity and both independent
// registry/guard reads; it does not fabricate a remote TLS connection.
func (s *OwnerAuthenticator) ObserveOwnerClient(ctx context.Context, client OwnerClientIdentity) (value.AuthenticatedOwner, error) {
	if client == nil {
		return value.AuthenticatedOwner{}, value.ErrInvalid
	}
	certificate, err := client.ClientCertificate()
	if err != nil || certificate.Usage != "client" {
		return value.AuthenticatedOwner{}, value.ErrDenied
	}
	return s.authenticate(ctx, func() (value.OwnerCertificate, error) { return certificate, nil }, client.VerifyClientCertificate)
}
