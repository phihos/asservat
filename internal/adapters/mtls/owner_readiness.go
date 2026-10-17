package mtls

import (
	"bytes"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
)

var _ app.OwnerReadinessIdentity = (*OwnerCredentials)(nil)

func (c *OwnerCredentials) ReadinessRequest() (value.OwnerCertificate, value.OwnerEnrollmentRequest, error) {
	if c == nil || c.now == nil {
		return value.OwnerCertificate{}, value.OwnerEnrollmentRequest{}, value.ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.key == nil || c.cert == nil || !c.identity.Valid(c.now()) {
		return value.OwnerCertificate{}, value.OwnerEnrollmentRequest{}, value.ErrUnavailable
	}
	return c.identity, value.OwnerEnrollmentRequest{Binding: c.binding, Usage: c.usage, CSRDER: bytes.Clone(c.csr)}, nil
}

func (c *OwnerCredentials) VerifyReadinessCertificate(configuration value.OwnerConfigurationObservation) (value.OwnerCertificate, error) {
	if c == nil {
		return value.OwnerCertificate{}, value.ErrInvalid
	}
	return c.verifyLocalCertificate(configuration, c.usage)
}
