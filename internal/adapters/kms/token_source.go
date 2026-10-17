package kms

import (
	"context"
	"crypto/x509"
	"net/http"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// TokenSource returns a newly owned buffer on every provider request. The
// adapter clears it after RoundTrip; it never caches a previous successful token
// when the current source is missing. This is installation wiring, not user input.
type TokenSource func(context.Context) ([]byte, error)

func ValidProviderToken(b []byte) bool {
	if len(b) < 1 || len(b) > 16384 {
		return false
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func NewSealerWithTokenSource(endpoint, mount, key string, source TokenSource, h *http.Client) (*Sealer, error) {
	if source == nil || !keyName.MatchString(mount) || !keyName.MatchString(key) {
		return nil, artifact.ErrInvalid
	}
	c, err := clientWithSource(endpoint, "", source, h)
	if err != nil {
		return nil, err
	}
	return &Sealer{c, mount, key, mount + "/" + key}, nil
}
func NewOpenerWithTokenSource(endpoint, mount, key string, source TokenSource, h *http.Client) (*Opener, error) {
	if source == nil || !keyName.MatchString(mount) || !keyName.MatchString(key) {
		return nil, artifact.ErrInvalid
	}
	c, err := clientWithSource(endpoint, "", source, h)
	if err != nil {
		return nil, err
	}
	return &Opener{c, mount, key, mount + "/" + key}, nil
}
func NewOwnerCertificateIssuerWithTokenSource(endpoint, mount, role, installation, cluster, epoch, usage string, roots *x509.CertPool, source TokenSource, h *http.Client, now func() time.Time) (*OwnerCertificateIssuer, error) {
	if source == nil {
		return nil, value.ErrInvalid
	}
	return newOwnerCertificateIssuer(endpoint, "", mount, role, installation, cluster, epoch, usage, roots, source, h, now)
}

// These clients own cloned transports. Close releases their idle connections;
// active effects are separately cancelled and joined by their runtime owner.
func (s *Sealer) Close() {
	if s != nil && s.client != nil {
		s.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
}
func (s *Opener) Close() {
	if s != nil && s.client != nil {
		s.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
}
func (s *OwnerCertificateIssuer) Close() {
	if s != nil && s.client != nil {
		s.client.CloneConfig().HttpClient.CloseIdleConnections()
	}
}
