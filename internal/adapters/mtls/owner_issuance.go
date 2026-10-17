package mtls

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
)

func (v *OwnerPeerVerifier) CheckOwnerCertificate(p value.OwnerCertificatePermit, csr, der []byte, chain [][]byte) (value.IssuedOwnerCertificate, error) {
	if v == nil || v.now == nil || !p.Valid(v.now()) {
		return value.IssuedOwnerCertificate{}, value.ErrInvalid
	}
	return v.CheckOwnerCertificateCurrent(p, csr, der, chain, p.Configuration)
}

// A stored result may finish audit after the signing deadline. It must still
// validate against current trust; this method cannot issue or refresh a permit.
func (v *OwnerPeerVerifier) CheckOwnerCertificateCurrent(p value.OwnerCertificatePermit, csr, der []byte, chain [][]byte, configuration value.OwnerConfigurationObservation) (value.IssuedOwnerCertificate, error) {
	var zero value.IssuedOwnerCertificate
	if v == nil || v.now == nil || !v.matchesPool(p.Configuration.Configuration.Pool) || !p.Valid(p.CheckedAt) || !configuration.Valid(v.now()) || configuration.Configuration.Suspended || configuration.Configuration.Revision.UID != p.Configuration.Configuration.Revision.UID || configuration.Configuration.Pool != p.Configuration.Configuration.Pool || len(der) < 1 || len(der) > 16<<10 || len(chain) > 3 {
		return zero, value.ErrInvalid
	}
	key, err := EnrollmentKey(csr)
	if err != nil || key != p.PublicKeyDigest {
		return zero, value.ErrDenied
	}
	leaf, err := x509.ParseCertificate(bytes.Clone(der))
	if err != nil || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != key {
		return zero, value.ErrDenied
	}
	certs := []*x509.Certificate{leaf}
	total := len(der)
	for _, raw := range chain {
		total += len(raw)
		if len(raw) < 1 || len(raw) > 16<<10 || total > 32<<10 {
			return zero, value.ErrInvalid
		}
		c, err := x509.ParseCertificate(bytes.Clone(raw))
		if err != nil {
			return zero, value.ErrInvalid
		}
		certs = append(certs, c)
	}
	c, err := v.verifyCertificates(certs, p.Usage)
	if err != nil {
		return zero, err
	}
	// Constructor trust cannot outlive administrator removal from the accepted
	// current source. Require both independently pinned and current roots.
	current, err := v.currentVerifier(configuration)
	if err != nil {
		return zero, err
	}
	currentCertificate, err := current.verifyCertificates(certs, p.Usage)
	if err != nil || currentCertificate != c {
		return zero, value.ErrDenied
	}
	out := value.IssuedOwnerCertificate{Certificate: c, DER: der, ChainDER: chain}
	if !p.Matches(out) || !configuration.Valid(v.now()) {
		return zero, value.ErrDenied
	}
	return out.Clone(), nil
}

func (v *OwnerPeerVerifier) EnrollmentKey(csr []byte) (artifact.Digest, error) {
	return EnrollmentKey(csr)
}
