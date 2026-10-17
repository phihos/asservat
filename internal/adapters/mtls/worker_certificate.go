package mtls

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"crypto/sha256"
	"crypto/x509"
	"net/url"
)

func WorkerCertificateURI(a value.WorkerCertificateAttempt) (*url.URL, error) {
	if !a.Valid(a.CheckedAt) {
		return nil, artifact.ErrInvalid
	}
	b := a.Enrollment.Worker.Binding
	return &url.URL{Scheme: "spiffe", Host: "asservat." + b.InstallationID, Path: "/key-client/acquisition/" + b.PodUID}, nil
}

// CheckWorkerCertificate validates an actual issuer response. It does not
// manufacture a TLS handshake or activate the certificate in the registry.
func (v *KeyPeerVerifier) CheckWorkerCertificate(a value.WorkerCertificateAttempt, csr, der []byte, chain [][]byte) (value.WorkerCertificate, error) {
	var out value.WorkerCertificate
	if v == nil || v.now == nil || !a.Valid(v.now()) || len(der) < 1 || len(der) > 16<<10 || len(chain) > 3 {
		return out, artifact.ErrInvalid
	}
	key, e := EnrollmentKey(csr)
	if e != nil || key != a.Enrollment.PublicKeyDigest {
		return out, artifact.ErrInvalid
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil || artifact.Digest(sha256.Sum256(leaf.RawSubjectPublicKeyInfo)) != key {
		return out, artifact.ErrIntegrity
	}
	certs := []*x509.Certificate{leaf}
	total := len(der)
	for _, raw := range chain {
		if len(raw) < 1 || len(raw) > 16<<10 {
			return out, artifact.ErrInvalid
		}
		total += len(raw)
		c, e := x509.ParseCertificate(raw)
		if e != nil {
			return out, artifact.ErrInvalid
		}
		certs = append(certs, c)
	}
	if total > 32<<10 {
		return out, artifact.ErrInvalid
	}
	peer, e := v.verifyCertificates(certs)
	if e != nil {
		return out, e
	}
	out = value.WorkerCertificate{Peer: peer, DER: der, ChainDER: chain}
	if !a.Matches(out) || !a.Valid(v.now()) {
		return value.WorkerCertificate{}, artifact.ErrIntegrity
	}
	return out, nil
}
