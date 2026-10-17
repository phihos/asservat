package mtls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// connectorObservationKeys is a private process-owned snapshot, never a source
// observation, independent SQL activation or authority for metadata. It carries
// no private key or signer; the process pointer is only a replacement veto.
type connectorObservationKeys struct {
	process              *connectorOwnedProcess
	request              value.ConnectorProcessRequest
	leaf                 value.ConnectorCredentialCertificate
	chain                [][]byte
	keys                 [2]artifact.Digest
	observedAt, runUntil time.Time
}

func (c *ConnectorProcessCredentials) observationKeys(ctx context.Context, leaf value.ConnectorCredentialCertificate) (connectorObservationKeys, error) {
	var zero connectorObservationKeys
	if c == nil || ctx == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// The key mutex can block past the caller's original cutoff.
	if contextExpired(ctx) {
		return zero, value.ErrUnavailable
	}
	p := c.active
	now := c.now()
	if c.closed || c.root.Err() != nil || p == nil || p.retired || p.certs[0] == nil || p.installed[0] != leaf || !leaf.Valid(now) || !now.Before(p.process.RunUntil) {
		return zero, value.ErrUnavailable
	}
	out := connectorObservationKeys{process: p, request: cloneConnectorRequest(p.request), leaf: leaf, observedAt: now, runUntil: p.process.RunUntil}
	for i, csr := range [][]byte{out.request.ClientCSRDER, out.request.ServerCSRDER} {
		if p.keys[i] == nil {
			return zero, value.ErrUnavailable
		}
		public, err := x509.MarshalPKIXPublicKey(p.keys[i].Public())
		if err != nil {
			return zero, value.ErrUnavailable
		}
		out.keys[i] = sha256.Sum256(public)
		key, err := EnrollmentKey(csr)
		if err != nil || key != out.keys[i] {
			return zero, value.ErrUnavailable
		}
	}
	if out.keys[0] != leaf.PublicKeyDigest || out.keys[0] == out.keys[1] {
		return zero, value.ErrUnavailable
	}
	for _, der := range p.certs[0].Certificate {
		out.chain = append(out.chain, bytes.Clone(der))
	}
	if len(out.chain) < 1 || len(out.chain) > 4 || contextExpired(ctx) {
		return zero, value.ErrUnavailable
	}
	return out, nil
}

// contextExpired reports a cancelled context or a passed deadline. A deadline
// is real time, and the timer that cancels its context can run late on a
// loaded machine, so ctx.Err alone can still be nil after the cutoff.
func contextExpired(ctx context.Context) bool {
	d, ok := ctx.Deadline()
	return ctx.Err() != nil || ok && !time.Now().Before(d)
}

func (c *ConnectorProcessCredentials) observationKeysCurrent(ctx context.Context, before connectorObservationKeys) error {
	now, err := c.observationKeys(ctx, before.leaf)
	if err != nil || now.process != before.process || now.request.Process != before.request.Process || now.keys != before.keys || !bytes.Equal(now.request.ClientCSRDER, before.request.ClientCSRDER) || !bytes.Equal(now.request.ServerCSRDER, before.request.ServerCSRDER) || !now.runUntil.Equal(before.runUntil) || now.observedAt.Before(before.observedAt) || len(now.chain) != len(before.chain) {
		return value.ErrUnavailable
	}
	for i := range now.chain {
		if !bytes.Equal(now.chain[i], before.chain[i]) {
			return value.ErrUnavailable
		}
	}
	return nil
}

// Check both original pinned and current proof roots using the unchanged strict
// connector verifier. This performs no source/registry read or certificate issue.
func (c *ConnectorProcessCredentials) verifyObservationKeys(keys connectorObservationKeys, current value.ConnectorCredentialObservation) error {
	if !current.Valid(c.now()) || current.Profile.Binding != keys.request.Process.Binding {
		return value.ErrUnavailable
	}
	roots, _, err := OwnerTrustRoots(current.Profile.ClientIssuerRoots, c.now())
	if err != nil {
		return value.ErrUnavailable
	}
	chain := make([]*x509.Certificate, len(keys.chain))
	for i, der := range keys.chain {
		chain[i], err = x509.ParseCertificate(der)
		if err != nil {
			return value.ErrUnavailable
		}
	}
	actual, err := c.verifier.verify(chain, "client", roots)
	if err != nil || actual != keys.leaf || actual.PublicKeyDigest != keys.keys[0] || actual.NotAfter.After(keys.runUntil) {
		return value.ErrUnavailable
	}
	return nil
}
