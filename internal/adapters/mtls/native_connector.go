package mtls

import (
	"asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"crypto/tls"
	"crypto/x509"
	"time"
)

// NativeConnectorIdentity consumes a separately installed connector client key;
// it never substitutes a hub-owner leaf or issues a certificate. The producer
// must own the signer/process lifetime; this adapter only verifies its current
// exact certificate and accepted registry before use.
type NativeConnectorIdentity struct {
	binding     value.PeerBinding
	verifier    *PeerVerifier
	registry    *fleet.PeerAuthenticator
	certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	now         func() time.Time
}

func NewNativeConnectorIdentity(binding value.PeerBinding, roots *x509.CertPool, registry *fleet.PeerAuthenticator, certificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error), now func() time.Time) (*NativeConnectorIdentity, error) {
	if !binding.Valid() || binding.Role != value.ConnectorPeer || registry == nil || certificate == nil || now == nil {
		return nil, value.ErrInvalid
	}
	verifier, e := NewPeerVerifier(roots, binding.InstallationID, value.ConnectorPeer, now)
	if e != nil {
		return nil, e
	}
	return &NativeConnectorIdentity{binding, verifier, registry, certificate, now}, nil
}
func (c *NativeConnectorIdentity) current(ctx context.Context) (*tls.Certificate, value.PeerCertificate, time.Time, error) {
	var zero value.PeerCertificate
	if c == nil || ctx == nil || ctx.Err() != nil {
		return nil, zero, time.Time{}, value.ErrUnavailable
	}
	started := c.now()
	call, stop := context.WithDeadline(ctx, started.Add(5*time.Second))
	defer stop()
	// This is a preflight snapshot selection, not a fabricated TLS handshake.
	// A real process-owned callback checks SupportsCertificate, so supply the
	// TLS1.3 signing schemes accepted by this profile. Actual TLS still chooses
	// and verifies its own negotiated signing scheme before any forwarded data.
	cert, e := c.certificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS13, SignatureSchemes: []tls.SignatureScheme{
		tls.ECDSAWithP256AndSHA256, tls.ECDSAWithP384AndSHA384, tls.ECDSAWithP521AndSHA512,
		tls.Ed25519, tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
	}})
	if e != nil || cert == nil || cert.PrivateKey == nil || len(cert.Certificate) < 1 || len(cert.Certificate) > 4 {
		return nil, zero, time.Time{}, value.ErrDenied
	}
	chain := make([]*x509.Certificate, 0, len(cert.Certificate))
	for _, der := range cert.Certificate {
		if len(der) > 16<<10 {
			return nil, zero, time.Time{}, value.ErrDenied
		}
		parsed, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, zero, time.Time{}, value.ErrDenied
		}
		chain = append(chain, parsed)
	}
	checked, e := c.verifier.verifyCertificates(chain)
	if e != nil || checked.Binding != c.binding {
		return nil, zero, time.Time{}, value.ErrDenied
	}
	accepted, e := c.registry.AuthenticatePeer(call, checked)
	until := identity.Earlier(started.Add(5*time.Second), accepted.ValidUntil)
	if d, ok := call.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	if e != nil || call.Err() != nil || !c.now().Before(until) {
		return nil, zero, time.Time{}, value.ErrUnavailable
	}
	// The callback's DER slices are not retained as mutable identity observations.
	out := *cert
	out.Certificate = make([][]byte, len(cert.Certificate))
	for i, der := range cert.Certificate {
		out.Certificate[i] = append([]byte(nil), der...)
	}
	return &out, checked, until, nil
}
func (c *NativeConnectorIdentity) CheckNativeConnector(ctx context.Context) (time.Time, error) {
	_, _, until, e := c.current(ctx)
	return until, e
}
