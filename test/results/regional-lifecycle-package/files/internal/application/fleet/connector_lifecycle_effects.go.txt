package fleet

import (
	"bytes"
	"context"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorLifecycleEnrollment explicitly selects ADR153's private native
// operation. SQL/audit effects are the same runner used by legacy enrollment.
type ConnectorLifecycleEnrollment struct {
	Native   ConnectorLifecycleOperationReader
	Keys     EnrollmentProofVerifier
	Recovery RecoveryReader
	Journal  ConnectorProcessJournal
	Audit    ConnectorCredentialAudit
	MAC      *auditapp.OperationMAC
	Now      func() time.Time
}

func (s ConnectorLifecycleEnrollment) Enroll(ctx context.Context, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	if s.Native == nil || s.Keys == nil || !r.Valid() {
		return value.ConnectorCredentialProcess{}, value.ErrUnavailable
	}
	r.ClientCSRDER, r.ServerCSRDER = bytes.Clone(r.ClientCSRDER), bytes.Clone(r.ServerCSRDER)
	checks := &connectorLifecycleChecks{reader: s.Native, keys: s.Keys, recovery: s.Recovery, now: s.Now, id: id, purpose: value.ConnectorLifecycleEnroll, request: r}
	service := ConnectorProcessEnrollment{Recovery: s.Recovery, Journal: s.Journal, Audit: s.Audit, MAC: s.MAC, Now: s.Now}
	return service.enrollUsing(ctx, id, r, connectorLifecycleProcessChecks{checks})
}

// ConnectorLifecycleRenewal is process-only. It cannot accept the historical
// bootstrap Peer/TLS path or recreate a provider attempt after unknown output.
type ConnectorLifecycleRenewal struct {
	Native   ConnectorLifecycleOperationReader
	Keys     EnrollmentProofVerifier
	Recovery RecoveryReader
	Journal  ConnectorCredentialJournal
	Audit    ConnectorCredentialAudit
	MAC      *auditapp.OperationMAC
	Issuer   ConnectorCredentialIssuer
	Verifier ConnectorCredentialResultVerifier
	Now      func() time.Time
}

func (s ConnectorLifecycleRenewal) IssueProcess(ctx context.Context, id, usage string, r value.ConnectorProcessRequest) (value.IssuedConnectorCredential, error) {
	if s.Native == nil || s.Keys == nil || !r.Valid() || usage != "client" && usage != "server" {
		return value.IssuedConnectorCredential{}, value.ErrUnavailable
	}
	r.ClientCSRDER, r.ServerCSRDER = bytes.Clone(r.ClientCSRDER), bytes.Clone(r.ServerCSRDER)
	csr, purpose := r.ClientCSRDER, value.ConnectorLifecycleClient
	if usage == "server" {
		csr, purpose = r.ServerCSRDER, value.ConnectorLifecycleServer
	}
	request := ConnectorCredentialRequest{ID: id, Usage: usage, Attested: &r.Process, CSR: csr}
	checks := &connectorLifecycleChecks{reader: s.Native, keys: s.Keys, recovery: s.Recovery, now: s.Now, id: id, purpose: purpose, request: r}
	service := ConnectorRenewal{Proof: s.Keys, Recovery: s.Recovery, Journal: s.Journal, Audit: s.Audit, MAC: s.MAC, Issuer: s.Issuer, Verifier: s.Verifier, Now: s.Now}
	return service.issueUsing(ctx, value.PeerCertificate{}, request, &r, connectorLifecycleCredentialChecks{checks})
}

// These interfaces are private to the one effect runner. The legacy branches
// still perform their full reads; no general exported proof port is cached.
type connectorProcessChecks interface {
	Current(context.Context, value.ConnectorLifecyclePhase, time.Time, time.Time) (ConnectorProcessCurrent, error)
	Close()
}

type connectorCredentialChecks interface {
	Current(context.Context, value.ConnectorLifecyclePhase, time.Time, time.Time) (ConnectorCredentialCurrent, error)
	Close()
}

type connectorLegacyProcessChecks struct {
	s       ConnectorProcessEnrollment
	request value.ConnectorProcessRequest
}

func (c connectorLegacyProcessChecks) Current(ctx context.Context, _ value.ConnectorLifecyclePhase, start, until time.Time) (ConnectorProcessCurrent, error) {
	return c.s.current(ctx, c.request, start, until)
}
func (connectorLegacyProcessChecks) Close() {}

type connectorLegacyCredentialChecks struct {
	s       ConnectorRenewal
	cert    value.PeerCertificate
	process *value.ConnectorProcessRequest
}

func (c connectorLegacyCredentialChecks) Current(ctx context.Context, _ value.ConnectorLifecyclePhase, start, until time.Time) (ConnectorCredentialCurrent, error) {
	return c.s.current(ctx, c.cert, start, until, c.process)
}
func (connectorLegacyCredentialChecks) Close() {}

type connectorLifecycleChecks struct {
	reader    ConnectorLifecycleOperationReader
	keys      EnrollmentProofVerifier
	recovery  RecoveryReader
	now       func() time.Time
	id        string
	purpose   value.ConnectorLifecyclePurpose
	request   value.ConnectorProcessRequest
	binding   value.ConnectorLifecycleBinding
	clientKey artifact.Digest
	serverKey artifact.Digest
	op        ConnectorLifecycleOperation
	prior     *value.ConnectorLifecycleObservation
	closed    bool
}

func (c *connectorLifecycleChecks) Close() {
	if c == nil || c.closed {
		return
	}
	c.closed = true
	if c.op != nil {
		c.op.Close()
	}
	clear(c.request.ClientCSRDER)
	clear(c.request.ServerCSRDER)
}

func (c *connectorLifecycleChecks) read(ctx context.Context, phase value.ConnectorLifecyclePhase, start, until time.Time) (out value.ConnectorLifecycleObservation, recovery value.RecoveryState, end time.Time, err error) {
	err = value.ErrUnavailable
	defer func() {
		if err != nil {
			c.Close()
		}
	}()
	if c == nil || c.closed || ctx == nil || ctx.Err() != nil || c.now == nil || c.keys == nil || c.recovery == nil || c.reader == nil || !c.now().Before(until) {
		return
	}
	if c.op == nil {
		if phase != value.ConnectorLifecycleInitial {
			return
		}
		c.binding = value.ConnectorLifecycleBinding{ID: c.id, Purpose: c.purpose, Process: c.request.Process, RequestedAt: start, NotAfter: until}
		if d, ok := ctx.Deadline(); ok {
			c.binding.NotAfter = identity.Earlier(c.binding.NotAfter, d)
		} else {
			return
		}
		var e error
		c.clientKey, e = c.keys.EnrollmentKey(c.request.ClientCSRDER)
		if e != nil {
			return
		}
		c.serverKey, e = c.keys.EnrollmentKey(c.request.ServerCSRDER)
		if e != nil || c.clientKey == c.serverKey || c.clientKey == (artifact.Digest{}) || c.serverKey == (artifact.Digest{}) {
			return
		}
		// Keep the effect runner's original request context. A child cancelled
		// on return from this current check would terminate the retained owner.
		if d, _ := ctx.Deadline(); d.After(c.binding.NotAfter) {
			return
		}
		c.op, e = c.reader.BeginConnectorLifecycle(ctx, ConnectorLifecycleRequest{Binding: c.binding, Request: c.request})
		if e != nil || c.op == nil {
			return
		}
	}
	observed, e := c.op.Read(ctx, phase)
	if e != nil || ctx.Err() != nil || observed.Phase != phase || !observed.Valid(c.now()) ||
		observed.Binding.ID != c.binding.ID || observed.Binding.Purpose != c.binding.Purpose || observed.Binding.Process != c.binding.Process ||
		!observed.Binding.RequestedAt.Equal(c.binding.RequestedAt) || !observed.Binding.NotAfter.Equal(c.binding.NotAfter) ||
		observed.Original.ClientKeyDigest != c.clientKey || observed.Original.ServerKeyDigest != c.serverKey ||
		c.prior != nil && !observed.Continues(*c.prior) {
		return
	}
	end = identity.Earlier(until, observed.Until)
	call, cancel := context.WithDeadline(ctx, end)
	defer cancel()
	recovery, e = c.recovery.RecoveryState(call)
	end = identity.Earlier(end, recovery.FreshUntil)
	if e != nil || call.Err() != nil || !observed.Valid(c.now()) || !recovery.Valid(c.now()) || !c.now().Before(end) ||
		recovery.InstallationID != c.binding.Process.Binding.InstallationID || recovery.IssuerEpoch != c.binding.Process.Binding.IssuerEpoch {
		return
	}
	owned := observed.Clone()
	c.prior = &owned
	return observed.Clone(), recovery, end, nil
}

type connectorLifecycleProcessChecks struct{ *connectorLifecycleChecks }

func (c connectorLifecycleProcessChecks) Current(ctx context.Context, phase value.ConnectorLifecyclePhase, start, until time.Time) (ConnectorProcessCurrent, error) {
	observation, recovery, end, err := c.read(ctx, phase, start, until)
	if err != nil {
		return ConnectorProcessCurrent{}, err
	}
	// The SQL proof remains the actual ORIGINAL observation, including dates.
	out := ConnectorProcessCurrent{Proof: observation.Original.Clone(), Recovery: recovery, ObservedAt: start, Until: end}
	if ctx.Err() != nil || !out.Valid(c.now()) {
		c.Close()
		return ConnectorProcessCurrent{}, value.ErrUnavailable
	}
	return out, nil
}

type connectorLifecycleCredentialChecks struct{ *connectorLifecycleChecks }

func (c connectorLifecycleCredentialChecks) Current(ctx context.Context, phase value.ConnectorLifecyclePhase, start, until time.Time) (ConnectorCredentialCurrent, error) {
	observation, recovery, end, err := c.read(ctx, phase, start, until)
	if err != nil {
		return ConnectorCredentialCurrent{}, err
	}
	proof := observation.Original.Clone()
	out := ConnectorCredentialCurrent{ProcessProof: &proof, Source: observation.Source, Recovery: recovery, ObservedAt: start, Until: end}
	if ctx.Err() != nil || !out.Valid(c.now()) {
		c.Close()
		return ConnectorCredentialCurrent{}, value.ErrUnavailable
	}
	return out, nil
}
