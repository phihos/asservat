package mtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// EnrollmentKey validates a DER-only, identity-free CSR and proof of key
// possession. The issued identity always comes from the bootstrap binding.
// Re-signing an otherwise identical key request cannot allocate another peer.
func EnrollmentKey(der []byte) (artifact.Digest, error) {
	var out artifact.Digest
	if len(der) < 32 || len(der) > 8192 {
		return out, value.ErrInvalid
	}
	c, err := x509.ParseCertificateRequest(der)
	if err != nil || !bytes.Equal(c.Raw, der) || c.Version != 0 || len(c.Subject.Names) != 0 || len(c.Subject.ExtraNames) != 0 || len(c.DNSNames) != 0 || len(c.IPAddresses) != 0 || len(c.EmailAddresses) != 0 || len(c.URIs) != 0 || len(c.Attributes) != 0 || len(c.Extensions) != 0 || len(c.ExtraExtensions) != 0 {
		return out, value.ErrDenied
	}
	// The deprecated parsed Attributes field drops unrecognized attribute
	// shapes. Inspect the bounded signed ASN.1 sequence for an empty attribute
	// set, while x509 continues to own public-key parsing and cryptography.
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	rest, e := asn1.Unmarshal(c.RawTBSCertificateRequest, &info)
	if e != nil || len(rest) != 0 || len(info.Attributes) != 0 || !bytes.Equal(c.RawSubject, []byte{0x30, 0}) {
		return out, value.ErrDenied
	}
	switch c.PublicKey.(type) {
	case ed25519.PublicKey:
		if c.SignatureAlgorithm != x509.PureEd25519 {
			return out, value.ErrDenied
		}
	case *ecdsa.PublicKey:
		k := c.PublicKey.(*ecdsa.PublicKey)
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return out, value.ErrDenied
		}
		if c.SignatureAlgorithm != x509.ECDSAWithSHA256 && c.SignatureAlgorithm != x509.ECDSAWithSHA384 && c.SignatureAlgorithm != x509.ECDSAWithSHA512 {
			return out, value.ErrDenied
		}
	case *rsa.PublicKey:
		k := c.PublicKey.(*rsa.PublicKey)
		if k.N.BitLen() < 2048 || k.N.BitLen() > 4096 || k.E != 65537 {
			return out, value.ErrDenied
		}
		switch c.SignatureAlgorithm {
		case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		default:
			return out, value.ErrDenied
		}
	default:
		return out, value.ErrDenied
	}
	if c.CheckSignature() != nil {
		return out, value.ErrDenied
	}
	canonical, err := x509.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil || !bytes.Equal(canonical, c.RawSubjectPublicKeyInfo) {
		return out, value.ErrDenied
	}
	return artifact.Digest(sha256.Sum256(canonical)), nil
}

// BootstrapDigest accepts one canonical base64url 256-bit random secret. The
// token must come from a CSPRNG issuer; passing syntax does not prove entropy.
// Purpose, installation and bootstrap identity separate hash domains. Callers
// never log the secret or attach it to a URL, CRD status or error text.
func BootstrapDigest(installation, bootstrap, secret string) (artifact.Digest, error) {
	var out artifact.Digest
	if !authorization.UUID(installation) || !authorization.UUID(bootstrap) || len(secret) != 43 {
		return out, value.ErrInvalid
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != secret {
		return out, value.ErrInvalid
	}
	defer clear(b)
	h := sha256.New()
	h.Write([]byte("asservat-bootstrap/v1\x00"))
	h.Write([]byte(installation))
	h.Write([]byte{0})
	h.Write([]byte(bootstrap))
	h.Write([]byte{0})
	h.Write(b)
	copy(out[:], h.Sum(nil))
	return out, nil
}

// EnrollmentProof is the standard-library proof-of-possession adapter. The
// result is a key digest, never an issued identity or authorization decision.
type EnrollmentProof struct{}

func (EnrollmentProof) EnrollmentKey(csr []byte) (artifact.Digest, error) { return EnrollmentKey(csr) }
func (EnrollmentProof) BootstrapKey(csr []byte) (ed25519.PublicKey, artifact.Digest, error) {
	return EnrollmentEd25519Key(csr)
}
func (EnrollmentProof) BootstrapSecretDigest(installation, bootstrap, secret string) (artifact.Digest, error) {
	return BootstrapDigest(installation, bootstrap, secret)
}

// EnrollmentEd25519Key validates an identity-free CSR like EnrollmentKey and
// additionally requires an Ed25519 key, returning the raw key with its SPKI
// digest (ADR-193: the generation-1 cluster credential key).
func EnrollmentEd25519Key(der []byte) (ed25519.PublicKey, artifact.Digest, error) {
	digest, err := EnrollmentKey(der)
	if err != nil {
		return nil, digest, err
	}
	c, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, artifact.Digest{}, value.ErrDenied
	}
	key, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, artifact.Digest{}, value.ErrDenied
	}
	return key, digest, nil
}
