package mtls

import (
	"context"
	"crypto/x509"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorProcessObservation contains public CSR provenance only, never a
// signer, private key, Pod token or fabricated TLS connection. It supports a
// separate current Pod attestation and does not grant collection authority.
type ConnectorProcessObservation struct {
	Request                value.ConnectorProcessRequest
	Registration           app.ConnectorLeafRegistration
	Configuration          value.ConnectorCredentialObservation
	ObservedAt, ValidUntil time.Time
}

func (c *ConnectorProcessCredentials) ObserveConnectorProcess(ctx context.Context) (ConnectorProcessObservation, error) {
	if c == nil {
		return ConnectorProcessObservation{}, value.ErrUnavailable
	}
	return c.observeConnectorProcess(ctx, c.source.ReadConnectorIdentitySource, false)
}

// ObserveConnectorProcessAt checks this process against one source
// observation its caller read within the same original interval (ADR-199):
// it reads the source no further. The caller brackets the source itself.
func (c *ConnectorProcessCredentials) ObserveConnectorProcessAt(ctx context.Context, source value.ConnectorIdentitySource) (ConnectorProcessObservation, error) {
	if c == nil {
		return ConnectorProcessObservation{}, value.ErrUnavailable
	}
	return c.observeConnectorProcess(ctx, func(context.Context) (value.ConnectorIdentitySource, error) {
		out := source
		out.Observation.Profile = out.Observation.Profile.Clone()
		return out, nil
	}, true)
}

func (c *ConnectorProcessCredentials) observeConnectorProcess(ctx context.Context, read func(context.Context) (value.ConnectorIdentitySource, error), bracketed bool) (ConnectorProcessObservation, error) {
	var zero ConnectorProcessObservation
	if c == nil || ctx == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	start := c.now()
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(c.root, func() { cancel(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	c.mu.Lock()
	p := c.active
	if c.closed || c.root.Err() != nil || p == nil || p.retired || p.certs[0] == nil || !c.now().Before(p.process.RunUntil) {
		c.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	r := cloneConnectorRequest(p.request)
	cert := p.installed[0]
	runUntil := p.process.RunUntil
	raw := make([][]byte, len(p.certs[0].Certificate))
	for i, b := range p.certs[0].Certificate {
		raw[i] = append([]byte(nil), b...)
	}
	c.mu.Unlock()
	first, e := read(call)
	if e != nil || !first.Valid(c.now()) || first.Observation.Profile.Binding != r.Process.Binding {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, identity.Earlier(runUntil, first.Observation.FreshUntil))
	call, stopSource := context.WithDeadline(call, until)
	defer stopSource()
	roots, _, e := OwnerTrustRoots(first.Observation.Profile.ClientIssuerRoots, c.now())
	if e != nil {
		return zero, value.ErrUnavailable
	}
	chain := make([]*x509.Certificate, len(raw))
	for i, b := range raw {
		chain[i], e = x509.ParseCertificate(b)
		if e != nil {
			return zero, value.ErrUnavailable
		}
	}
	actual, e := c.verifier.verify(chain, "client", roots)
	key, ke := EnrollmentKey(r.ClientCSRDER)
	if e != nil || ke != nil || actual != cert || cert.PublicKeyDigest != key {
		return zero, value.ErrUnavailable
	}
	var registered app.ConnectorLeafRegistration
	if scoped, ok := c.registry.(app.ConnectorLeafRegistryAt); bracketed && ok {
		registered, e = scoped.ConnectorLeafRegistrationAt(call, cert, first)
	} else {
		registered, e = c.registry.ConnectorLeafRegistration(call, cert)
	}
	if e != nil || !registered.Valid(c.now()) || registered.Certificate != cert || registered.Process != r.Process {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, registered.FreshUntil)
	call, stopRegistry := context.WithDeadline(call, until)
	defer stopRegistry()
	last, e := read(call)
	if e != nil || !last.Valid(c.now()) || last.Roles != first.Roles || !last.Observation.SameSource(first.Observation) {
		return zero, value.ErrUnavailable
	}
	until = identity.Earlier(until, last.Observation.FreshUntil)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.root.Err() != nil || c.active != p || p.retired || p.installed[0] != cert || call.Err() != nil || !identity.Fresh(start, until, c.now(), 5*time.Second) || !first.Valid(c.now()) || !registered.Valid(c.now()) {
		return zero, value.ErrUnavailable
	}
	return ConnectorProcessObservation{Request: r, Registration: registered, Configuration: first.Observation, ObservedAt: start, ValidUntil: until}, nil
}

// ConfirmConnectorProcessAt closes the executor proof locally (ADR-199): the
// same active process, request and installed client leaf as the opening
// observation, whose chain still verifies under the closing source's roots.
// No new hub conversation: the opening registration's original FreshUntil
// bounds the result, and nothing renews it (ADR-173).
func (c *ConnectorProcessCredentials) ConfirmConnectorProcessAt(ctx context.Context, opened ConnectorProcessObservation, source value.ConnectorIdentitySource) (ConnectorProcessObservation, error) {
	var zero ConnectorProcessObservation
	if c == nil || ctx == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	now := c.now()
	c.mu.Lock()
	p := c.active
	if c.closed || c.root.Err() != nil || p == nil || p.retired || p.certs[0] == nil || !now.Before(p.process.RunUntil) || p.installed[0] != opened.Registration.Certificate || p.request.Process != opened.Request.Process {
		c.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	runUntil := p.process.RunUntil
	raw := make([][]byte, len(p.certs[0].Certificate))
	for i, b := range p.certs[0].Certificate {
		raw[i] = append([]byte(nil), b...)
	}
	c.mu.Unlock()
	if !source.Valid(now) || source.Observation.Profile.Binding != opened.Request.Process.Binding || !source.Observation.SameSource(opened.Configuration) {
		return zero, value.ErrUnavailable
	}
	roots, _, e := OwnerTrustRoots(source.Observation.Profile.ClientIssuerRoots, now)
	if e != nil {
		return zero, value.ErrUnavailable
	}
	chain := make([]*x509.Certificate, len(raw))
	for i, b := range raw {
		if chain[i], e = x509.ParseCertificate(b); e != nil {
			return zero, value.ErrUnavailable
		}
	}
	if actual, e := c.verifier.verify(chain, "client", roots); e != nil || actual != opened.Registration.Certificate {
		return zero, value.ErrUnavailable
	}
	until := identity.Earlier(opened.ValidUntil, identity.Earlier(source.Observation.FreshUntil, identity.Earlier(runUntil, opened.Registration.FreshUntil)))
	if !now.Before(until) || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	out := opened
	out.Request = cloneConnectorRequest(opened.Request)
	out.Configuration = source.Observation
	out.Configuration.Profile = source.Observation.Profile.Clone()
	out.ValidUntil = until
	return out, nil
}
