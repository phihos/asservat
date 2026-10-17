package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// One protected complete source observation and one actual Pod/key proof share
// the original caller interval. Neither a stored candidate nor a digest renews it.
type ConnectorBackingCurrent struct {
	Configuration     ConnectorIdentityConfiguration
	Proof             value.ConnectorProcessProof
	Recovery          value.RecoveryState
	ObservedAt, Until time.Time
}

func (c ConnectorBackingCurrent) Valid(now time.Time) bool {
	b := c.Proof.Process.Binding
	return c.Configuration.Valid(now) && !c.Configuration.Source.Observation.Profile.Suspended && c.Proof.Valid(now) && c.Proof.Configuration.SameSource(c.Configuration.Source.Observation) && c.Recovery.Valid(now) && c.Recovery.InstallationID == b.InstallationID && c.Recovery.IssuerEpoch == b.IssuerEpoch && identity.Fresh(c.ObservedAt, c.Until, now, 5*time.Second) && !c.Until.After(c.Configuration.Source.Observation.FreshUntil) && !c.Until.After(c.Proof.FreshUntil) && !c.Until.After(c.Recovery.FreshUntil)
}

// The transition is a separate paid child of its original audit pair. It never
// borrows or extends an existing process's shorter retention interval.
type ConnectorBackingAdmission struct {
	Before            ConnectorIdentityBacking
	Proposed          ConnectorIdentityConfiguration
	Intent            audit.OperationIntent
	Outcome           *audit.OperationOutcome
	Activated, Closed bool
}

func (a ConnectorBackingAdmission) matches(id string, c ConnectorBackingCurrent) bool {
	in := a.Intent
	if a.Closed || !a.Proposed.Backing.CanRenew(a.Before) || !in.Valid() || in.Name != "connector_backing_acceptance" || in.ID != id || in.RootID != c.Configuration.Backing.Policy.RootID || in.Lifecycle == nil || in.Process == nil || *in.Process != connectorProcessActor(c.Proof) || !sameConnectorJSON(in.Lifecycle.Policy, a.Before.Policy) || in.RetainUntil.After(in.CreatedAt.Add(time.Duration(a.Before.RetainedSeconds)*time.Second)) || a.Proposed.Backing.Policy.ValidUntil.Add(time.Minute).After(in.Lifecycle.OriginalPurgeAt) || !sameConnectorConfiguration(a.Proposed, c.Configuration) {
		return false
	}
	if a.Outcome == nil {
		return !a.Activated
	}
	return a.Outcome.Valid() && a.Outcome.Status == "success" && a.Outcome.Effect == "accepted" && sameConnectorJSON(a.Outcome.Intent, in)
}
func sameConnectorJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func sameConnectorConfiguration(a, b ConnectorIdentityConfiguration) bool {
	return a.Source.Roles == b.Source.Roles && a.Source.Observation.SameSource(b.Source.Observation) && sameConnectorJSON(a.Backing, b.Backing)
}

type ConnectorBackingJournal interface {
	PrepareConnectorBacking(context.Context, string, ConnectorBackingCurrent) (ConnectorBackingAdmission, error)
	StoreConnectorBackingOutcome(context.Context, ConnectorBackingAdmission, audit.OperationOutcome) error
}

// This port is separately credentialed from both journal and acknowledgement.
// It compares original candidate, both immutable receipts and live source under
// root/pool locks before promotion; a found receipt is not caller authority.
type ConnectorBackingPromotion interface {
	PromoteConnectorBacking(context.Context, ConnectorBackingAdmission, ConnectorBackingCurrent) (ConnectorIdentityBacking, error)
}
type ConnectorBackingAcceptance struct {
	Source    ConnectorIdentityConfigurationReader
	Proof     ConnectorProcessProofReader
	Recovery  RecoveryReader
	Journal   ConnectorBackingJournal
	Promotion ConnectorBackingPromotion
	Audit     ConnectorCredentialAudit
	MAC       *auditapp.OperationMAC
	Now       func() time.Time
}

func (s ConnectorBackingAcceptance) current(ctx context.Context, r value.ConnectorProcessRequest, start, until time.Time) (ConnectorBackingCurrent, error) {
	var c ConnectorBackingCurrent
	source, e := s.Source.ReadConnectorIdentityConfiguration(ctx)
	if e != nil {
		return c, value.ErrUnavailable
	}
	proof, e := s.Proof.ReadConnectorProcessProof(ctx, r)
	if e != nil {
		return c, value.ErrUnavailable
	}
	recovery, e := s.Recovery.RecoveryState(ctx)
	if e != nil {
		return c, value.ErrUnavailable
	}
	c = ConnectorBackingCurrent{Configuration: source.Clone(), Proof: proof.Clone(), Recovery: recovery, ObservedAt: start, Until: identity.Earlier(until, identity.Earlier(source.Source.Observation.FreshUntil, identity.Earlier(proof.FreshUntil, recovery.FreshUntil)))}
	if ctx.Err() != nil || !c.Valid(s.Now()) {
		return ConnectorBackingCurrent{}, value.ErrUnavailable
	}
	return c, nil
}

// Accept retries only the supplied original transition ID. It never creates a
// replacement process/key, re-issues a leaf or invents a fresh acceptance ID.
func (s ConnectorBackingAcceptance) Accept(ctx context.Context, id string, r value.ConnectorProcessRequest) (ConnectorIdentityBacking, error) {
	var zero ConnectorIdentityBacking
	if ctx == nil || ctx.Err() != nil || s.Source == nil || s.Proof == nil || s.Recovery == nil || s.Journal == nil || s.Promotion == nil || s.Audit == nil || s.MAC == nil || s.Now == nil || !authorization.UUID(id) || !r.Valid() {
		return zero, value.ErrUnavailable
	}
	r.ClientCSRDER = bytes.Clone(r.ClientCSRDER)
	r.ServerCSRDER = bytes.Clone(r.ServerCSRDER)
	start := s.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(5 * time.Second)
	if deadline, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, deadline)
	}
	live, end := context.WithDeadline(ctx, until)
	defer end()
	c, e := s.current(live, r, start, until)
	if e != nil {
		return zero, e
	}
	until = c.Until
	live, firstEnd := context.WithDeadline(live, until)
	defer firstEnd()
	a, e := s.Journal.PrepareConnectorBacking(live, id, c)
	if e != nil {
		return zero, e
	}
	if !a.matches(id, c) || !c.Valid(s.Now()) || live.Err() != nil {
		return zero, value.ErrUnavailable
	}
	if a.Outcome == nil {
		if !s.Now().Before(a.Intent.RequestUntil) {
			return zero, value.ErrUnavailable
		}
		if e = s.Audit.Begin(live, a.Intent); e != nil {
			return zero, e
		}
		next, e := s.current(live, r, start, until)
		if e != nil || !sameConnectorConfiguration(next.Configuration, c.Configuration) {
			return zero, value.ErrUnavailable
		}
		payload, e := json.Marshal(struct {
			ID      string
			Backing ConnectorIdentityBacking
		}{id, a.Proposed.Backing})
		if e != nil {
			return zero, value.ErrUnavailable
		}
		digest, e := s.MAC.Digest("connector-result/v1", payload)
		if e != nil {
			return zero, e
		}
		out := audit.OperationOutcome{Intent: a.Intent, Status: "success", Reason: "prepared", Effect: "accepted", ClientReceipt: "unknown", OutputDigest: digest, OutputBytes: int64(len(payload)), MetadataUntil: identity.Earlier(a.Intent.RequestUntil, next.Until), RecordedAt: s.Now().UTC().Truncate(time.Microsecond)}
		if !out.Valid() || !next.Valid(s.Now()) || live.Err() != nil {
			return zero, value.ErrUnavailable
		}
		narrowed, cancel := context.WithDeadline(live, next.Until)
		defer cancel()
		live = narrowed
		e = s.Journal.StoreConnectorBackingOutcome(live, a, out)
		if e != nil {
			return zero, e
		}
		if live.Err() != nil || !next.Valid(s.Now()) {
			return zero, value.ErrUnavailable
		}
		until = next.Until
		a.Outcome = &out
	}
	if !a.Activated {
		if e = s.Audit.Finish(live, *a.Outcome); e != nil {
			return zero, e
		}
	}
	next, e := s.current(live, r, start, until)
	if e != nil || !sameConnectorConfiguration(next.Configuration, c.Configuration) {
		return zero, value.ErrUnavailable
	}
	bounded, cancel := context.WithDeadline(live, next.Until)
	defer cancel()
	backing, e := s.Promotion.PromoteConnectorBacking(bounded, a, next)
	if e != nil {
		return zero, e
	}
	if !sameConnectorJSON(backing, a.Proposed.Backing) || bounded.Err() != nil || !next.Valid(s.Now()) {
		return zero, value.ErrUnavailable
	}
	final, e := s.current(bounded, r, start, next.Until)
	if e != nil || !sameConnectorConfiguration(final.Configuration, c.Configuration) {
		return zero, value.ErrUnavailable
	}
	return backing.Clone(), nil
}
