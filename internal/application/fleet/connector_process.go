package fleet

import (
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"time"
)

type ConnectorProcessCurrent struct {
	Proof             value.ConnectorProcessProof
	Recovery          value.RecoveryState
	ObservedAt, Until time.Time
}

func (c ConnectorProcessCurrent) Valid(now time.Time) bool {
	b := c.Proof.Process.Binding
	return c.Proof.Valid(now) && c.Recovery.Valid(now) && c.Recovery.InstallationID == b.InstallationID && c.Recovery.IssuerEpoch == b.IssuerEpoch && identity.Fresh(c.ObservedAt, c.Until, now, 5*time.Second) && !c.Until.After(c.Proof.FreshUntil) && !c.Until.After(c.Recovery.FreshUntil)
}

type ConnectorProcessAdmission struct {
	Process   value.ConnectorCredentialProcess
	Intent    audit.OperationIntent
	Outcome   *audit.OperationOutcome
	Activated bool
}

func (a ConnectorProcessAdmission) matches(id string, c ConnectorProcessCurrent) bool {
	p, in := a.Process, a.Intent
	q := c.Proof
	if !p.Valid() || p.Attested == nil || *p.Attested != q.Process || p.ClientKeyDigest != q.ClientKeyDigest || p.ServerKeyDigest != q.ServerKeyDigest || !p.ClaimedAt.Equal(in.CreatedAt) || in.ID != id || in.RootID != q.Configuration.Profile.RootID || in.Name != "connector_process_enrollment" || !in.Valid() || in.Lifecycle == nil || p.RunUntil.After(in.Lifecycle.OriginalPurgeAt.Add(-time.Minute)) || in.Process == nil || *in.Process != connectorProcessActor(q) {
		return false
	}
	if a.Outcome == nil {
		return !a.Activated
	}
	if !a.Outcome.Valid() || a.Outcome.Status != "success" || a.Outcome.Effect != "accepted" {
		return false
	}
	x, e := json.Marshal(a.Outcome.Intent)
	y, f := json.Marshal(in)
	return e == nil && f == nil && bytes.Equal(x, y)
}

type ConnectorProcessJournal interface {
	PrepareConnectorProcess(context.Context, string, ConnectorProcessCurrent) (ConnectorProcessAdmission, error)
	StoreConnectorProcessOutcome(context.Context, ConnectorProcessAdmission, audit.OperationOutcome) error
	AcceptConnectorProcess(context.Context, ConnectorProcessAdmission, ConnectorProcessCurrent) (value.ConnectorCredentialProcess, error)
}

// ConnectorProcessEnrollment admits only the immutable initial process keys.
// Signing, paired serving activation and retirement are distinct SQL effects.
// Original pending/history spend remains on unknown or denied completion.
type ConnectorProcessEnrollment struct {
	Proof    ConnectorProcessProofReader
	Recovery RecoveryReader
	Journal  ConnectorProcessJournal
	Audit    ConnectorCredentialAudit
	MAC      *auditapp.OperationMAC
	Now      func() time.Time
}

func (s ConnectorProcessEnrollment) current(ctx context.Context, r value.ConnectorProcessRequest, start, until time.Time) (ConnectorProcessCurrent, error) {
	p, e := s.Proof.ReadConnectorProcessProof(ctx, r)
	if e != nil {
		return ConnectorProcessCurrent{}, value.ErrUnavailable
	}
	recovery, e := s.Recovery.RecoveryState(ctx)
	if e != nil {
		return ConnectorProcessCurrent{}, value.ErrUnavailable
	}
	c := ConnectorProcessCurrent{Proof: p.Clone(), Recovery: recovery, ObservedAt: start, Until: identity.Earlier(until, identity.Earlier(p.FreshUntil, recovery.FreshUntil))}
	if ctx.Err() != nil || !c.Valid(s.Now()) {
		return ConnectorProcessCurrent{}, value.ErrUnavailable
	}
	return c, nil
}
func (s ConnectorProcessEnrollment) Enroll(ctx context.Context, id string, r value.ConnectorProcessRequest) (value.ConnectorCredentialProcess, error) {
	if s.Proof == nil || !r.Valid() {
		return value.ConnectorCredentialProcess{}, value.ErrUnavailable
	}
	r.ClientCSRDER = bytes.Clone(r.ClientCSRDER)
	r.ServerCSRDER = bytes.Clone(r.ServerCSRDER)
	return s.enrollUsing(ctx, id, r, connectorLegacyProcessChecks{s: s, request: r})
}

func (s ConnectorProcessEnrollment) enrollUsing(ctx context.Context, id string, r value.ConnectorProcessRequest, checks connectorProcessChecks) (value.ConnectorCredentialProcess, error) {
	var zero value.ConnectorCredentialProcess
	if ctx == nil || checks == nil || s.Recovery == nil || s.Journal == nil || s.Audit == nil || s.MAC == nil || s.Now == nil || !authorization.UUID(id) || !r.Valid() {
		return zero, value.ErrUnavailable
	}
	defer checks.Close()
	r.ClientCSRDER = bytes.Clone(r.ClientCSRDER)
	r.ServerCSRDER = bytes.Clone(r.ServerCSRDER)
	start := s.Now().UTC().Truncate(time.Microsecond)
	until := start.Add(5 * time.Second)
	live, end := context.WithDeadline(ctx, until)
	defer end()
	c, e := checks.Current(live, value.ConnectorLifecycleInitial, start, until)
	if e != nil {
		return zero, e
	}
	until = c.Until
	live, firstEnd := context.WithDeadline(live, until)
	defer firstEnd()
	a, e := s.Journal.PrepareConnectorProcess(live, id, c)
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
		next, e := checks.Current(live, value.ConnectorLifecycleBeforeEffect, start, until)
		if e != nil {
			return zero, e
		}
		if !next.Proof.Configuration.SameSource(c.Proof.Configuration) || next.Proof.WorkloadDigest != c.Proof.WorkloadDigest || next.Proof.ProtectionDigest != c.Proof.ProtectionDigest {
			return zero, value.ErrUnavailable
		}
		until = next.Until
		active, close := context.WithDeadline(live, until)
		defer close()
		live = active
		payload, e := json.Marshal(struct {
			ID      string
			Process value.ConnectorCredentialProcess
		}{id, a.Process})
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
		if e = s.Journal.StoreConnectorProcessOutcome(live, a, out); e != nil {
			return zero, e
		}
		a.Outcome = &out
	}
	// Activated is a durable exact-receipt fact, not fresh authority. Re-enter
	// the current SQL activation check below; never reopen its old audit window.
	if !a.Activated {
		if e = s.Audit.Finish(live, *a.Outcome); e != nil {
			return zero, e
		}
	}
	next, e := checks.Current(live, value.ConnectorLifecycleBeforeActivation, start, until)
	if e != nil {
		return zero, e
	}
	if !next.Proof.Configuration.SameSource(c.Proof.Configuration) || next.Proof.WorkloadDigest != c.Proof.WorkloadDigest || next.Proof.ProtectionDigest != c.Proof.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	active, close := context.WithDeadline(live, next.Until)
	defer close()
	p, e := s.Journal.AcceptConnectorProcess(active, a, next)
	if e != nil {
		return zero, e
	}
	x, e := json.Marshal(p)
	y, f := json.Marshal(a.Process)
	if e != nil || f != nil || !bytes.Equal(x, y) || !next.Valid(s.Now()) || active.Err() != nil {
		return zero, value.ErrUnavailable
	}
	final, e := checks.Current(active, value.ConnectorLifecycleFinal, start, next.Until)
	if e != nil || !final.Proof.Configuration.SameSource(c.Proof.Configuration) || final.Proof.WorkloadDigest != c.Proof.WorkloadDigest || final.Proof.ProtectionDigest != c.Proof.ProtectionDigest {
		return zero, value.ErrUnavailable
	}
	// This is an acknowledged process admission, never a serving identity.
	return p, nil
}
