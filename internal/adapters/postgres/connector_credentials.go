package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ConnectorCredentials struct{ processes *ConnectorProcesses }

var _ app.ConnectorCredentialJournal = (*ConnectorCredentials)(nil)

func NewConnectorCredentials(ctx context.Context, pool *pgxpool.Pool, root string, binding value.PeerBinding, backing app.ConnectorIdentityBacking, mac *auditapp.OperationMAC) (*ConnectorCredentials, error) {
	p, e := NewConnectorProcesses(ctx, pool, root, binding, backing, mac)
	if e != nil {
		return nil, e
	}
	return &ConnectorCredentials{p}, nil
}
func (s *ConnectorCredentials) candidate(c app.ConnectorCredentialCandidate) bool {
	return s != nil && s.processes != nil && c.Valid(time.Now()) && c.Attested != nil && c.BootstrapID == "" && c.Attested.Binding == s.processes.binding && c.Current.Source.Observation.Profile.RootID == s.processes.root
}
func connectorCredentialAttempt(b []byte) (app.ConnectorCredentialAttempt, error) {
	var a app.ConnectorCredentialAttempt
	if len(b) == 0 || len(b) > 320<<10 || json.Unmarshal(b, &a) != nil || !a.Permit.WellFormed() || !a.Intent.Valid() || a.Intent.Lifecycle == nil || a.Permit.ID != a.Intent.ID || a.Permit.IntentDigest != auditapp.OperationLifecycleDigest(a.Intent) || a.Permit.CertificateNotAfter.After(a.Intent.Lifecycle.OriginalPurgeAt.Add(-time.Minute)) {
		return a, value.ErrUnavailable
	}
	if a.Certificate == nil {
		if a.Outcome != nil || a.Activated {
			return a, value.ErrUnavailable
		}
		return a, nil
	}
	if !a.ProviderStarted || !a.Permit.Matches(*a.Certificate) || artifact.Digest(sha256.Sum256(a.Certificate.DER)) != a.Certificate.Certificate.Digest || a.Outcome == nil || !a.Outcome.Valid() || !sameAuditJSON(a.Outcome.Intent, a.Intent) || a.Outcome.Credential == nil || a.Outcome.Credential.CertificateDigest != a.Certificate.Certificate.Digest {
		return a, value.ErrUnavailable
	}
	return a, nil
}
func (s *ConnectorCredentials) PrepareConnectorCredential(ctx context.Context, c app.ConnectorCredentialCandidate) (app.ConnectorCredentialAttempt, error) {
	var out app.ConnectorCredentialAttempt
	if ctx == nil || ctx.Err() != nil || !s.candidate(c) {
		return out, value.ErrUnavailable
	}
	p := s.processes
	current, e := json.Marshal(c)
	if e != nil || len(current) > 256<<10 {
		return out, value.ErrInvalid
	}
	live, end := context.WithDeadline(ctx, c.Current.Until)
	defer end()
	e = p.ledger.transaction(live, func(q *custodydb.Queries) error {
		stored, err := q.ReadConnectorCredentialAttempt(live, custodydb.ReadConnectorCredentialAttemptParams{RootID: id(p.root), OperationID: id(c.ID), CandidateValue: current})
		if err != nil {
			return err
		}
		if len(stored) > 0 {
			out, err = connectorCredentialAttempt(stored)
			return err
		}
		b, err := q.ReadConnectorCredentialProcess(live, custodydb.ReadConnectorCredentialProcessParams{RootID: id(p.root), CandidateValue: current})
		if err != nil {
			return err
		}
		var state struct {
			Backing                                                  app.ConnectorIdentityBacking
			Process                                                  value.ConnectorCredentialProcess
			ClientEpoch, ClientAttempts, ServerEpoch, ServerAttempts int64
		}
		if len(b) > 40<<10 || json.Unmarshal(b, &state) != nil || !state.Backing.SameResources(p.backing) || !state.Process.Valid() || state.Process.Attested == nil || *state.Process.Attested != *c.Attested {
			return value.ErrUnavailable
		}
		epoch, leafEnd, err := state.Process.Window(c.Current.ObservedAt)
		if err != nil {
			return err
		}
		prior, tries := state.ClientEpoch, state.ClientAttempts
		if c.Usage == "server" {
			prior, tries = state.ServerEpoch, state.ServerAttempts
		}
		ordinal := 1
		if epoch == prior {
			ordinal = int(tries) + 1
		}
		if epoch < prior || ordinal > 2 {
			return value.ErrCapacity
		}
		actor := &audit.OperationPeerActor{Binding: p.binding, CertificateDigest: c.Current.Peer.Certificate.Digest}
		var processActor *audit.OperationConnectorProcessActor
		if proof := c.Current.ProcessProof; proof != nil {
			actor = nil
			processActor = &audit.OperationConnectorProcessActor{Process: proof.Process, Deployment: proof.Configuration.Profile.Deployment, ClientKeyDigest: proof.ClientKeyDigest, ServerKeyDigest: proof.ServerKeyDigest}
		}
		payload, err := json.Marshal(struct {
			ID, Usage string
			Process   value.ConnectorProcessIdentity
			Key       artifact.Digest
			Source    identity.Revision
			Peer      *audit.OperationPeerActor
			Attested  *audit.OperationConnectorProcessActor
		}{c.ID, c.Usage, *c.Attested, c.PublicKeyDigest, c.Current.Source.Observation.Profile.Revision, actor, processActor})
		if err != nil {
			return err
		}
		input, err := p.mac.Digest("connector-credential/v1", payload)
		if err != nil {
			return err
		}
		account, err := p.mac.ConnectorAccount(p.binding)
		if err != nil {
			return err
		}
		start := c.Current.ObservedAt.UTC().Truncate(time.Microsecond)
		in := audit.OperationIntent{ID: c.ID, RootID: p.root, TraceID: c.ID, Name: "connector_" + c.Usage + "_certificate", InputFormat: "connector-credential/v1", MACVersion: p.mac.Version(), AccountVersion: p.mac.AccountVersion(), Peer: actor, Process: processActor, PrincipalDigest: account, InputDigest: input, CreatedAt: start, RequestUntil: c.Current.Until.UTC().Truncate(time.Microsecond), WriteUntil: start.Add(30 * time.Second), RetainUntil: start.Add(time.Duration(state.Backing.RetainedSeconds) * time.Second)}
		in, err = auditapp.BindOperationLifecycle(in, state.Backing.Policy)
		if err != nil {
			return err
		}
		permit := value.ConnectorCredentialPermit{ID: c.ID, Process: state.Process, Usage: c.Usage, Configuration: c.Current.Source.Observation, CurrentPeer: c.Current.Peer, ProcessProof: c.Current.ProcessProof, Recovery: c.Current.Recovery, IntentDigest: auditapp.OperationLifecycleDigest(in), Epoch: epoch, Ordinal: ordinal, CheckedAt: start, SignBefore: in.RequestUntil, CertificateNotAfter: leafEnd}
		if !permit.Valid(time.Now()) || leafEnd.After(in.Lifecycle.OriginalPurgeAt.Add(-time.Minute)) {
			return value.ErrUnavailable
		}
		intent, err := json.Marshal(in)
		if err != nil || len(intent) > 8192 {
			return value.ErrUnavailable
		}
		body, err := json.Marshal(permit)
		if err != nil || len(body) > 256<<10 {
			return value.ErrUnavailable
		}
		stored, err = q.AdmitConnectorCredential(live, custodydb.AdmitConnectorCredentialParams{RootID: id(p.root), CandidateValue: current, IntentValue: intent, PermitValue: body})
		if err != nil {
			return err
		}
		out, err = connectorCredentialAttempt(stored)
		return err
	})
	if e != nil || live.Err() != nil || !s.candidate(c) || out.Intent.ID != c.ID || out.Permit.Process.Attested == nil || *out.Permit.Process.Attested != *c.Attested {
		return app.ConnectorCredentialAttempt{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ConnectorCredentials) currentCandidate(a app.ConnectorCredentialAttempt, c app.ConnectorCredentialCurrent) (app.ConnectorCredentialCandidate, error) {
	candidate := app.ConnectorCredentialCandidate{ID: a.Permit.ID, Attested: a.Permit.Process.Attested, Usage: a.Permit.Usage, PublicKeyDigest: a.Permit.PublicKeyDigest(), Current: c}
	if !s.candidate(candidate) || !a.Permit.WellFormed() || !a.Intent.Valid() {
		return candidate, value.ErrUnavailable
	}
	return candidate, nil
}
func (s *ConnectorCredentials) ClaimConnectorCredential(ctx context.Context, a app.ConnectorCredentialAttempt, c app.ConnectorCredentialCurrent) (bool, error) {
	candidate, e := s.currentCandidate(a, c)
	if e != nil || ctx == nil || ctx.Err() != nil {
		return false, value.ErrUnavailable
	}
	current, e := json.Marshal(candidate)
	if e != nil {
		return false, value.ErrUnavailable
	}
	permit, e := json.Marshal(a.Permit)
	if e != nil {
		return false, value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, identity.Earlier(c.Until, a.Permit.SignBefore))
	defer end()
	fresh := false
	e = s.processes.ledger.transaction(live, func(q *custodydb.Queries) error {
		var err error
		fresh, err = q.ClaimConnectorCredential(live, custodydb.ClaimConnectorCredentialParams{RootID: id(s.processes.root), OperationID: id(a.Permit.ID), CandidateValue: current, PermitValue: permit})
		return err
	})
	if e != nil || live.Err() != nil || !a.Permit.Valid(time.Now()) || !c.Valid(time.Now()) {
		return false, value.ErrUnavailable
	}
	return fresh, nil
}
func (s *ConnectorCredentials) StoreConnectorCredential(ctx context.Context, a app.ConnectorCredentialAttempt, issued value.IssuedConnectorCredential, o audit.OperationOutcome) error {
	if s == nil || s.processes == nil || ctx == nil || ctx.Err() != nil || !a.Permit.Valid(time.Now()) || a.Permit.Process.Binding != s.processes.binding || !a.Permit.Matches(issued) || !o.Valid() || !sameAuditJSON(o.Intent, a.Intent) {
		return value.ErrUnavailable
	}
	permit, e := json.Marshal(a.Permit)
	if e != nil {
		return value.ErrUnavailable
	}
	cert, e := json.Marshal(issued)
	if e != nil {
		return value.ErrUnavailable
	}
	out, e := json.Marshal(o)
	if e != nil {
		return value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, a.Permit.SignBefore)
	defer end()
	return s.processes.ledger.transaction(live, func(q *custodydb.Queries) error {
		return q.StoreConnectorCredential(live, custodydb.StoreConnectorCredentialParams{RootID: id(s.processes.root), OperationID: id(a.Permit.ID), PermitValue: permit, IssuedValue: cert, OutcomeValue: out})
	})
}
func (s *ConnectorCredentials) ActivateConnectorCredential(ctx context.Context, a app.ConnectorCredentialAttempt, c app.ConnectorCredentialCurrent) (value.IssuedConnectorCredential, error) {
	var out value.IssuedConnectorCredential
	candidate, e := s.currentCandidate(a, c)
	if e != nil || ctx == nil || ctx.Err() != nil {
		return out, value.ErrUnavailable
	}
	current, e := json.Marshal(candidate)
	if e != nil {
		return out, value.ErrUnavailable
	}
	permit, e := json.Marshal(a.Permit)
	if e != nil {
		return out, value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, identity.Earlier(c.Until, a.Permit.CertificateNotAfter))
	defer end()
	e = s.processes.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, err := q.ActivateConnectorCredential(live, custodydb.ActivateConnectorCredentialParams{RootID: id(s.processes.root), OperationID: id(a.Permit.ID), CandidateValue: current, PermitValue: permit})
		if err != nil {
			return err
		}
		if len(b) > 64<<10 || json.Unmarshal(b, &out) != nil || !a.Permit.Matches(out) || a.Certificate == nil || !sameAuditJSON(out, *a.Certificate) {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !c.Valid(time.Now()) || !out.Certificate.Valid(time.Now()) {
		return value.IssuedConnectorCredential{}, value.ErrUnavailable
	}
	return out, nil
}
