package kms

import (
	"crypto/x509"
	"net/http"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	value "asservat.local/asservat/internal/domain/fleet"
)

// These constructors select the server leaf profile from the independently
// accepted original pool. The legacy constructors keep their original profile.
func NewOwnerCertificateIssuerForPool(endpoint, token, mount, role string, pool value.OwnerPool, usage string, roots *x509.CertPool, h *http.Client, now func() time.Time) (*OwnerCertificateIssuer, error) {
	return newOwnerCertificateIssuerForPool(endpoint, token, mount, role, pool, usage, roots, nil, h, now)
}
func NewOwnerCertificateIssuerForPoolWithTokenSource(endpoint, mount, role string, pool value.OwnerPool, usage string, roots *x509.CertPool, source TokenSource, h *http.Client, now func() time.Time) (*OwnerCertificateIssuer, error) {
	if source == nil {
		return nil, value.ErrInvalid
	}
	return newOwnerCertificateIssuerForPool(endpoint, "", mount, role, pool, usage, roots, source, h, now)
}
func newOwnerCertificateIssuerForPool(endpoint, token, mount, role string, pool value.OwnerPool, usage string, roots *x509.CertPool, source TokenSource, h *http.Client, now func() time.Time) (*OwnerCertificateIssuer, error) {
	verifier, err := mtls.NewOwnerPeerVerifierForPool(roots, pool, now)
	if err != nil {
		return nil, err
	}
	issuer, err := newOwnerCertificateIssuer(endpoint, token, mount, role, pool.InstallationID, pool.ClusterID, pool.IssuerEpoch, usage, roots, source, h, now)
	if err != nil {
		return nil, err
	}
	issuer.verify = verifier
	if pool.NativeBootstrap != "" {
		issuer.pool = pool
	}
	return issuer, nil
}
func (s *OwnerCertificateIssuer) matchesPool(pool value.OwnerPool) bool {
	if !pool.Valid() {
		return false
	}
	if s.pool.NativeBootstrap == "" {
		return pool.NativeBootstrap == ""
	}
	return s.pool == pool
}
