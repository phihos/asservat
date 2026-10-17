package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This facet receives an actual current Pod proof from ConnectorProcessEnrollment.
// Its private SQL role can execute only closed process/audit RPCs, not read human
// audit rows or configure source/backing. A role pin is checked inside each RPC.
type ConnectorProcesses struct {
	ledger  *Ledger
	root    string
	binding value.PeerBinding
	backing app.ConnectorIdentityBacking
	mac     *auditapp.OperationMAC
}

var _ app.ConnectorProcessJournal = (*ConnectorProcesses)(nil)

func NewConnectorProcesses(ctx context.Context, pool *pgxpool.Pool, root string, binding value.PeerBinding, backing app.ConnectorIdentityBacking, mac *auditapp.OperationMAC) (*ConnectorProcesses, error) {
	if !authorization.UUID(root) || !binding.Valid() || binding.Role != value.ConnectorPeer || !backing.Valid() || backing.Policy.RootID != root || backing.Policy.InstallationID != binding.InstallationID || mac == nil || mac.AccountVersion() != backing.AccountVersion {
		return nil, value.ErrInvalid
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ConnectorProcesses{ledger: l, root: root, binding: binding, backing: backing.Clone(), mac: mac}, nil
}
func (s *ConnectorProcesses) current(c app.ConnectorProcessCurrent) bool {
	return s != nil && c.Valid(time.Now()) && c.Proof.Process.Binding == s.binding && c.Proof.Configuration.Profile.RootID == s.root && s.backing.SupportsDeployment(c.Proof.Configuration.Profile.Deployment)
}
func connectorProcessAdmission(b []byte) (app.ConnectorProcessAdmission, error) {
	var a app.ConnectorProcessAdmission
	if len(b) == 0 || len(b) > 40<<10 || json.Unmarshal(b, &a) != nil || !a.Process.Valid() || !a.Intent.Valid() || a.Intent.Lifecycle == nil || a.Intent.Name != "connector_process_enrollment" || a.Intent.Process == nil || a.Process.Attested == nil || *a.Process.Attested != a.Intent.Process.Process || a.Process.ClientKeyDigest != a.Intent.Process.ClientKeyDigest || a.Process.ServerKeyDigest != a.Intent.Process.ServerKeyDigest || !a.Process.ClaimedAt.Equal(a.Intent.CreatedAt) || a.Process.RunUntil.After(a.Intent.Lifecycle.OriginalPurgeAt.Add(-time.Minute)) {
		return app.ConnectorProcessAdmission{}, value.ErrUnavailable
	}
	if a.Outcome == nil {
		if a.Activated {
			return app.ConnectorProcessAdmission{}, value.ErrUnavailable
		}
	} else if !a.Outcome.Valid() || !sameAuditJSON(a.Outcome.Intent, a.Intent) || a.Outcome.Status != "success" || a.Outcome.Effect != "accepted" {
		return app.ConnectorProcessAdmission{}, value.ErrUnavailable
	}
	return a, nil
}
func (s *ConnectorProcesses) PrepareConnectorProcess(ctx context.Context, operation string, c app.ConnectorProcessCurrent) (app.ConnectorProcessAdmission, error) {
	var out app.ConnectorProcessAdmission
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(operation) || !s.current(c) {
		return out, value.ErrUnavailable
	}
	c.Proof = c.Proof.Clone()
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	current, e := json.Marshal(c)
	if e != nil || len(current) > 192<<10 {
		return out, value.ErrInvalid
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		stored, err := q.ReadConnectorProcessAdmission(live, custodydb.ReadConnectorProcessAdmissionParams{RootID: id(s.root), OperationID: id(operation), CurrentValue: current})
		if err != nil {
			return err
		}
		if len(stored) > 0 {
			out, err = connectorProcessAdmission(stored)
			return err
		}
		activeBytes, err := q.ReadConnectorProcessBacking(live, custodydb.ReadConnectorProcessBackingParams{RootID: id(s.root), CurrentValue: current})
		if err != nil {
			return err
		}
		var backing app.ConnectorIdentityBacking
		if len(activeBytes) > 32<<10 || json.Unmarshal(activeBytes, &backing) != nil || !backing.SameResources(s.backing) || !backing.SupportsDeployment(c.Proof.Configuration.Profile.Deployment) {
			return value.ErrUnavailable
		}
		actor := audit.OperationConnectorProcessActor{Process: c.Proof.Process, Deployment: c.Proof.Configuration.Profile.Deployment, ClientKeyDigest: c.Proof.ClientKeyDigest, ServerKeyDigest: c.Proof.ServerKeyDigest}
		// MAC only immutable admitted facts. A renewed token or observation cannot
		// become a new account or an alternative original process binding.
		payload, err := json.Marshal(struct {
			Actor      audit.OperationConnectorProcessActor
			Source     identity.Revision
			Protection artifact.Digest
		}{actor, c.Proof.Configuration.Profile.Revision, c.Proof.Configuration.Profile.ProtectionDigest})
		if err != nil {
			return err
		}
		input, err := s.mac.Digest("connector-process/v1", payload)
		if err != nil {
			return err
		}
		account, err := s.mac.ConnectorAccount(s.binding)
		if err != nil {
			return err
		}
		start := c.ObservedAt.UTC().Truncate(time.Microsecond)
		in := audit.OperationIntent{ID: operation, RootID: s.root, TraceID: operation, Name: "connector_process_enrollment", InputFormat: "connector-process/v1", MACVersion: s.mac.Version(), AccountVersion: s.mac.AccountVersion(), Process: &actor, PrincipalDigest: account, InputDigest: input, CreatedAt: start, RequestUntil: c.Until.UTC().Truncate(time.Microsecond), WriteUntil: start.Add(30 * time.Second), RetainUntil: start.Add(time.Duration(backing.RetainedSeconds) * time.Second)}
		var ticketImages [][]byte
		if backing.Policy.History.Layout == audit.ConnectorRetirementHistoryLayout {
			planBytes, e := q.ReadConnectorProcessTicket(live, custodydb.ReadConnectorProcessTicketParams{RootID: id(s.root), CurrentValue: current})
			if e != nil {
				return e
			}
			var plan struct {
				Existing bool
				Cohort   app.ConnectorRetirementCohort
			}
			cfg := c.Proof.Configuration.Profile
			if len(planBytes) > 4096 || json.Unmarshal(planBytes, &plan) != nil || !plan.Cohort.Valid() || plan.Cohort.RootID != s.root || plan.Cohort.Binding != s.binding || plan.Cohort.Behavior != cfg.Revision || plan.Cohort.ServingSlots != cfg.Deployment.ServingSlots || plan.Cohort.RetainedProcesses != cfg.Deployment.RetainedProcesses || plan.Cohort.BackingRevision != backing.Policy.BackingRevision {
				return value.ErrUnavailable
			}
			if !plan.Existing {
				// This happens only after exact original-operation lookup, inside
				// the same transaction. Unknown commits can only replay that
				// existing event; they cannot replace its ticket or original dates.
				ticketID, e := uuid.NewRandom()
				if e != nil {
					return e
				}
				ticket, e := app.ConnectorRetirementProposal(in, ticketID.String(), plan.Cohort, backing, plan.Cohort.BackingDigest, account)
				if e != nil {
					return e
				}
				image, _, e := app.CanonicalConnectorRetirementTicket(ticket)
				if e != nil {
					return e
				}
				ticketImages = [][]byte{image}
				in, err = app.BindConnectorRetirementAcceptance(in, backing.Policy, []audit.ConnectorRetirementTicket{ticket})
			} else {
				in, err = auditapp.BindOperationLifecycle(in, backing.Policy)
			}
		} else {
			in, err = auditapp.BindOperationLifecycle(in, backing.Policy)
		}
		if err != nil {
			return err
		}
		admitted := c.Proof.Process
		process := value.ConnectorCredentialProcess{Attested: &admitted, Binding: s.binding, ClientKeyDigest: c.Proof.ClientKeyDigest, ServerKeyDigest: c.Proof.ServerKeyDigest, ClaimedAt: start, InitialCertificateNotAfter: start.Add(value.ConnectorCertificatePeriod).Truncate(time.Second), RunUntil: in.Lifecycle.OriginalPurgeAt.Add(-time.Minute)}
		if !process.Valid() {
			return value.ErrUnavailable
		}
		intent, err := json.Marshal(in)
		if err != nil || len(intent) > 8192 {
			return value.ErrUnavailable
		}
		body, err := json.Marshal(process)
		if err != nil || len(body) > 4096 {
			return value.ErrUnavailable
		}
		if backing.Policy.History.Layout == audit.ConnectorRetirementHistoryLayout {
			stored, err = q.AdmitConnectorProcessReserved(live, custodydb.AdmitConnectorProcessReservedParams{RootID: id(s.root), CurrentValue: current, IntentValue: intent, ProcessValue: body, TicketImages: ticketImages})
		} else {
			stored, err = q.AdmitConnectorProcess(live, custodydb.AdmitConnectorProcessParams{RootID: id(s.root), CurrentValue: current, IntentValue: intent, ProcessValue: body})
		}
		if err != nil {
			return err
		}
		out, err = connectorProcessAdmission(stored)
		return err
	})
	if e != nil || live.Err() != nil || !s.current(c) || out.Intent.ID != operation || out.Intent.RootID != s.root || out.Process.Attested == nil || *out.Process.Attested != c.Proof.Process {
		return app.ConnectorProcessAdmission{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ConnectorProcesses) StoreConnectorProcessOutcome(ctx context.Context, a app.ConnectorProcessAdmission, o audit.OperationOutcome) error {
	if s == nil || ctx == nil || ctx.Err() != nil || !a.Intent.Valid() || a.Intent.RootID != s.root || a.Intent.Name != "connector_process_enrollment" || !o.Valid() || !sameAuditJSON(o.Intent, a.Intent) {
		return value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, a.Intent.RequestUntil)
	defer end()
	intent, e := json.Marshal(a.Intent)
	if e != nil {
		return value.ErrUnavailable
	}
	out, e := json.Marshal(o)
	if e != nil {
		return value.ErrUnavailable
	}
	return s.ledger.transaction(live, func(q *custodydb.Queries) error {
		return q.StoreConnectorProcessOutcome(live, custodydb.StoreConnectorProcessOutcomeParams{RootID: id(s.root), OperationID: id(a.Intent.ID), IntentValue: intent, OutcomeValue: out})
	})
}
func (s *ConnectorProcesses) AcceptConnectorProcess(ctx context.Context, a app.ConnectorProcessAdmission, c app.ConnectorProcessCurrent) (value.ConnectorCredentialProcess, error) {
	var out value.ConnectorCredentialProcess
	if ctx == nil || ctx.Err() != nil || !s.current(c) || !a.Intent.Valid() || a.Intent.RootID != s.root || a.Outcome == nil || !a.Outcome.Valid() {
		return out, value.ErrUnavailable
	}
	c.Proof = c.Proof.Clone()
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	current, e := json.Marshal(c)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, err := q.AcceptConnectorProcess(live, custodydb.AcceptConnectorProcessParams{RootID: id(s.root), OperationID: id(a.Intent.ID), CurrentValue: current})
		if err != nil {
			return err
		}
		if len(b) > 4096 || json.Unmarshal(b, &out) != nil || !out.Valid() || !sameAuditJSON(out, a.Process) {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !s.current(c) {
		return value.ConnectorCredentialProcess{}, value.ErrUnavailable
	}
	return out, nil
}
