package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// This port exposes public CSR/certificate snapshots of an owned process key.
// It grants no signing, peer authentication or request authority.
type OwnerReadinessIdentity interface {
	ReadinessRequest() (value.OwnerCertificate, value.OwnerEnrollmentRequest, error)
	VerifyReadinessCertificate(value.OwnerConfigurationObservation) (value.OwnerCertificate, error)
}

// Startup cannot depend on a Ready endpoint: Kubernetes publishes that endpoint
// only AFTER this process becomes ready. Current Pod/token/protection proof and
// activated identity supply readiness; OwnerAuthenticator remains mandatory for
// every real peer/request and still requires a Ready route.
type OwnerStartupReadiness struct {
	Binding        value.OwnerBinding
	Pool           value.OwnerPool
	Server, Client OwnerReadinessIdentity
	Registry       OwnerCertificateRegistry
	Proofs         OwnerEnrollmentProofReader
	Now            func() time.Time
}

func (s OwnerStartupReadiness) Check(ctx context.Context) (time.Time, error) {
	if ctx == nil || ctx.Err() != nil || !s.Binding.Valid() || !s.Pool.Valid() || s.Server == nil || s.Client == nil || s.Registry == nil || s.Proofs == nil || s.Now == nil || s.Binding.InstallationID != s.Pool.InstallationID || s.Binding.ClusterID != s.Pool.ClusterID || s.Binding.IssuerEpoch != s.Pool.IssuerEpoch {
		return time.Time{}, value.ErrInvalid
	}
	start := s.Now()
	until := start.Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	var checked []struct {
		key           OwnerReadinessIdentity
		certificate   value.OwnerCertificate
		configuration value.OwnerConfigurationObservation
	}
	var configuration *value.OwnerConfiguration
	for _, part := range []struct {
		key   OwnerReadinessIdentity
		usage string
	}{{s.Server, "server"}, {s.Client, "client"}} {
		cert, request, err := part.key.ReadinessRequest()
		if err != nil || !cert.Valid(s.Now()) || cert.Binding != s.Binding || cert.Usage != part.usage || !request.Valid() || request.Binding != s.Binding || request.Usage != part.usage {
			return time.Time{}, value.ErrUnavailable
		}
		first, err := s.Registry.ReadOwnerRegistration(ctx, cert)
		if err != nil || !first.Valid(s.Now()) || first.Certificate != cert || first.Enrollment.Pool != s.Pool {
			return time.Time{}, value.ErrUnavailable
		}
		first.Configuration.Configuration = first.Configuration.Configuration.Clone()
		verified, err := part.key.VerifyReadinessCertificate(first.Configuration)
		if err != nil || verified != cert {
			return time.Time{}, value.ErrUnavailable
		}
		proof, err := s.Proofs.ReadOwnerEnrollmentProof(ctx, request)
		if err != nil || !proof.Valid(s.Now()) || !first.Enrollment.Matches(proof) || !first.Configuration.Configuration.Equal(proof.Configuration.Configuration) {
			return time.Time{}, value.ErrUnavailable
		}
		last, err := s.Registry.ReadOwnerRegistration(ctx, cert)
		if err != nil || !last.Valid(s.Now()) || last.Certificate != cert || last.Enrollment != first.Enrollment || !last.Configuration.Configuration.Equal(first.Configuration.Configuration) {
			return time.Time{}, value.ErrUnavailable
		}
		verified, err = part.key.VerifyReadinessCertificate(last.Configuration)
		if err != nil || verified != cert {
			return time.Time{}, value.ErrUnavailable
		}
		if configuration == nil {
			c := first.Configuration.Configuration.Clone()
			configuration = &c
		} else if !configuration.Equal(first.Configuration.Configuration) {
			return time.Time{}, value.ErrUnavailable
		}
		checked = append(checked, struct {
			key           OwnerReadinessIdentity
			certificate   value.OwnerCertificate
			configuration value.OwnerConfigurationObservation
		}{part.key, cert, first.Configuration})
		for _, d := range []time.Time{first.FreshUntil, last.FreshUntil, proof.FreshUntil, cert.NotAfter} {
			until = identity.Earlier(until, d)
		}
		if ctx.Err() != nil || s.Now().Before(start) || !s.Now().Before(until) {
			return time.Time{}, value.ErrUnavailable
		}
	}
	// The first purpose's key can close or renew while the second is checked.
	for _, item := range checked {
		cert, err := item.key.VerifyReadinessCertificate(item.configuration)
		if err != nil || cert != item.certificate {
			return time.Time{}, value.ErrUnavailable
		}
	}
	if ctx.Err() != nil || s.Now().Before(start) || !s.Now().Before(until) {
		return time.Time{}, value.ErrUnavailable
	}
	return until, nil
}
