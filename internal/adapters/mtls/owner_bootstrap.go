package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerBootstrapServerName derives a verification name from the original
// accepted Service identity. It is not a DNS discovery address or a callback.
func OwnerBootstrapServerName(pool value.OwnerPool) (string, error) {
	if !pool.Valid() || pool.NativeBootstrap != value.OwnerBootstrapProfile {
		return "", value.ErrInvalid
	}
	return "s-" + pool.ServiceUID + ".e-" + pool.IssuerEpoch + ".hub-bootstrap." + pool.ClusterID + ".asservat." + pool.InstallationID, nil
}

// NewOwnerPeerVerifierForPool selects the leaf profile from independently
// installed/accepted input, never from the received certificate's names. An
// omitted capability is the original strict single-SAN constructor behavior.
func NewOwnerPeerVerifierForPool(roots *x509.CertPool, pool value.OwnerPool, now func() time.Time) (*OwnerPeerVerifier, error) {
	if !pool.Valid() {
		return nil, value.ErrInvalid
	}
	v, err := NewOwnerPeerVerifier(roots, pool.InstallationID, pool.ClusterID, pool.IssuerEpoch, now)
	if err != nil {
		return nil, err
	}
	if pool.NativeBootstrap != "" {
		v.bootstrapPool = pool
	}
	return v, nil
}

func (v *OwnerPeerVerifier) matchesPool(pool value.OwnerPool) bool {
	if v == nil || !pool.Valid() || pool.InstallationID != v.installation || pool.ClusterID != v.cluster || pool.IssuerEpoch != v.epoch {
		return false
	}
	if v.bootstrapPool.NativeBootstrap == "" {
		return pool.NativeBootstrap == ""
	}
	return pool == v.bootstrapPool
}

func (v *OwnerPeerVerifier) currentVerifier(configuration value.OwnerConfigurationObservation) (*OwnerPeerVerifier, error) {
	if v == nil || v.now == nil || !configuration.Valid(v.now()) || configuration.Configuration.Suspended || !v.matchesPool(configuration.Configuration.Pool) {
		return nil, value.ErrDenied
	}
	roots, _, err := OwnerTrustRoots(configuration.Configuration.IssuerRoots, v.now())
	if err != nil {
		return nil, err
	}
	current := *v
	current.roots = roots
	return &current, nil
}

func (v *OwnerPeerVerifier) serverNames(names []string, exact string) bool {
	if v.bootstrapPool.NativeBootstrap == "" {
		return len(names) == 1 && names[0] == exact
	}
	common, err := OwnerBootstrapServerName(v.bootstrapPool)
	return err == nil && len(names) == 2 && names[0] != names[1] && slices.Contains(names, exact) && slices.Contains(names, common)
}

// VerifyBootstrapServer is only the cryptographic/candidate-set phase on an
// actual TLS connection. Exact current SQL registration plus the original
// local source/guard/route proofs must still succeed before metadata or effects.
// Existing VerifyServer continues to require one exact expected process SNI.
func (v *OwnerPeerVerifier) VerifyBootstrapServer(state *tls.ConnectionState, candidates value.APIContextOwnerCandidates) (value.OwnerCertificate, error) {
	var zero value.OwnerCertificate
	if v == nil || v.now == nil || !candidates.Valid(v.now()) || len(candidates.Owners) == 0 || !v.matchesPool(candidates.Pool) || v.bootstrapPool.NativeBootstrap != value.OwnerBootstrapProfile || state == nil || state.DidResume || state.NegotiatedProtocol != "h2" {
		return zero, value.ErrDenied
	}
	common, err := OwnerBootstrapServerName(candidates.Pool)
	if err != nil || state.ServerName != common {
		return zero, value.ErrDenied
	}
	certificate, err := v.verify(state, "server")
	if err != nil || !slices.Contains(candidates.Owners, certificate.Binding) || !candidates.Valid(v.now()) {
		return zero, value.ErrDenied
	}
	// The actual handshake already used ordinary hostname verification. Repeat
	// it on the exact leaf rather than trusting a copied ServerName field alone.
	if state.PeerCertificates[0].VerifyHostname(common) != nil {
		return zero, value.ErrDenied
	}
	return certificate, nil
}

// NewOwnerCredentialsForPool keeps one original process key and signing
// lifecycle. It changes only the independently selected strict leaf profile.
func NewOwnerCredentialsForPool(binding value.OwnerBinding, usage string, pool value.OwnerPool, roots *x509.CertPool, enrollment app.OwnerCredentialEnrollment, registry app.OwnerCertificateRegistry, now func() time.Time) (*OwnerCredentials, error) {
	v, err := NewOwnerPeerVerifierForPool(roots, pool, now)
	if err != nil || binding.InstallationID != pool.InstallationID || binding.ClusterID != pool.ClusterID || binding.IssuerEpoch != pool.IssuerEpoch {
		return nil, value.ErrInvalid
	}
	c, err := NewOwnerCredentials(binding, usage, roots, enrollment, registry, now)
	if err != nil {
		return nil, err
	}
	c.verifier = v
	return c, nil
}

// OwnerBootstrapServing belongs only to the explicitly composed observation
// listener. Ordinary OwnerCredentials.GetCertificate remains exact-SNI-only,
// including on owner-relay/public listeners. The receiving mux must additionally
// bind actual TLS SNI, HTTP authority and fixed observation path before dispatch.
type OwnerBootstrapServing struct {
	owner *OwnerCredentials
	pool  value.OwnerPool
}

func NewOwnerBootstrapServing(owner *OwnerCredentials, pool value.OwnerPool) (*OwnerBootstrapServing, error) {
	if owner == nil || owner.usage != "server" || !owner.verifier.matchesPool(pool) || pool.NativeBootstrap != value.OwnerBootstrapProfile {
		return nil, value.ErrInvalid
	}
	return &OwnerBootstrapServing{owner: owner, pool: pool}, nil
}
func (s *OwnerBootstrapServing) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if s == nil || s.owner == nil || hello == nil || !slices.Contains(hello.SupportedVersions, tls.VersionTLS13) {
		return nil, value.ErrDenied
	}
	exact, _ := OwnerServerName(s.owner.binding)
	if hello.ServerName == exact {
		return s.owner.GetCertificate(hello)
	}
	common, err := OwnerBootstrapServerName(s.pool)
	if err != nil || hello.ServerName != common {
		return nil, value.ErrDenied
	}
	out, err := s.owner.snapshot()
	if err != nil {
		return nil, err
	}
	if out.Leaf == nil || out.Leaf.VerifyHostname(common) != nil || !s.owner.verifier.serverNames(out.Leaf.DNSNames, exact) || hello.SupportsCertificate(out) != nil {
		return nil, value.ErrDenied
	}
	return out, nil
}
