package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
)

// OwnerTrustRoots validates public DER anchors and returns their earliest
// expiry. Selection/administrator protection is a separate source boundary.
func OwnerTrustRoots(raw [][]byte, now time.Time) (*x509.CertPool, time.Time, error) {
	if len(raw) < 1 || len(raw) > 4 || now.IsZero() {
		return nil, time.Time{}, value.ErrInvalid
	}
	roots := x509.NewCertPool()
	seen := map[[32]byte]bool{}
	total := 0
	var until time.Time
	for _, der := range raw {
		total += len(der)
		digest := sha256.Sum256(der)
		if len(der) < 1 || len(der) > 16<<10 || total > 32<<10 || seen[digest] {
			return nil, time.Time{}, value.ErrInvalid
		}
		seen[digest] = true
		cert, err := x509.ParseCertificate(bytes.Clone(der))
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || len(cert.UnhandledCriticalExtensions) != 0 || !cert.NotBefore.Before(cert.NotAfter) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, time.Time{}, value.ErrDenied
		}
		if until.IsZero() || cert.NotAfter.Before(until) {
			until = cert.NotAfter.UTC()
		}
		roots.AddCert(cert)
	}
	return roots, until, nil
}
