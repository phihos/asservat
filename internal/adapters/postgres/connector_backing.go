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

type ConnectorBackingJournal struct {
	ledger        *Ledger
	root          string
	binding       value.PeerBinding
	qualification app.ConnectorQualificationPin
	mac           *auditapp.OperationMAC
}

var _ app.ConnectorBackingJournal = (*ConnectorBackingJournal)(nil)
var _ app.ConnectorBackingPromotion = (*ConnectorIdentitySources)(nil)

func NewConnectorBackingJournal(ctx context.Context, pool *pgxpool.Pool, root string, binding value.PeerBinding, qualification app.ConnectorQualificationPin, mac *auditapp.OperationMAC) (*ConnectorBackingJournal, error) {
	if !authorization.UUID(root) || !binding.Valid() || binding.Role != value.ConnectorPeer || qualification.InstallationID != binding.InstallationID || !qualification.Qualification.Valid() || mac == nil {
		return nil, value.ErrInvalid
	}
	ledger, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ConnectorBackingJournal{ledger: ledger, root: root, binding: binding, qualification: qualification, mac: mac}, nil
}
func (s *ConnectorBackingJournal) current(c app.ConnectorBackingCurrent) bool {
	return s != nil && s.ledger != nil && c.Valid(time.Now()) && c.Proof.Process.Binding == s.binding && c.Configuration.Backing.Policy.RootID == s.root && s.qualification.Matches(c.Configuration) && s.mac.AccountVersion() == c.Configuration.Backing.AccountVersion
}
func decodeConnectorBackingAdmission(b []byte) (app.ConnectorBackingAdmission, error) {
	var a app.ConnectorBackingAdmission
	if len(b) == 0 || len(b) > 256<<10 || json.Unmarshal(b, &a) != nil || !a.Intent.Valid() || a.Intent.Name != "connector_backing_acceptance" || a.Intent.Lifecycle == nil || !a.Proposed.Backing.CanRenew(a.Before) || !sameAuditJSON(a.Intent.Lifecycle.Policy, a.Before.Policy) || a.Proposed.Backing.Policy.ValidUntil.Add(time.Minute).After(a.Intent.Lifecycle.OriginalPurgeAt) || a.Intent.RetainUntil.After(a.Intent.CreatedAt.Add(time.Duration(a.Before.RetainedSeconds)*time.Second)) {
		return a, value.ErrUnavailable
	}
	if a.Outcome == nil {
		if a.Activated {
			return a, value.ErrUnavailable
		}
	} else if !a.Outcome.Valid() || !sameAuditJSON(a.Outcome.Intent, a.Intent) {
		return a, value.ErrUnavailable
	}
	return a, nil
}

// CandidateID is read from the protected source's already persisted singleton;
// a process cannot replace an uncertain candidate by generating another UUID.
func (s *ConnectorBackingJournal) ConnectorBackingCandidateID(ctx context.Context, c app.ConnectorBackingCurrent) (string, error) {
	if ctx == nil || ctx.Err() != nil || !s.current(c) {
		return "", value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	b, e := json.Marshal(c)
	if e != nil {
		return "", value.ErrUnavailable
	}
	var result struct {
		ID     string
		Before app.ConnectorIdentityBacking
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, e := q.ReadConnectorBackingCandidate(live, custodydb.ReadConnectorBackingCandidateParams{RootID: id(s.root), CurrentValue: b})
		if e != nil {
			return e
		}
		if len(b) > 32<<10 || json.Unmarshal(b, &result) != nil || !authorization.UUID(result.ID) || !c.Configuration.Backing.CanRenew(result.Before) {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !s.current(c) {
		return "", value.ErrUnavailable
	}
	return result.ID, nil
}
func (s *ConnectorBackingJournal) PrepareConnectorBacking(ctx context.Context, operation string, c app.ConnectorBackingCurrent) (app.ConnectorBackingAdmission, error) {
	var out app.ConnectorBackingAdmission
	if ctx == nil || ctx.Err() != nil || !authorization.UUID(operation) || !s.current(c) {
		return out, value.ErrUnavailable
	}
	c.Configuration = c.Configuration.Clone()
	c.Proof = c.Proof.Clone()
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	current, e := json.Marshal(c)
	if e != nil || len(current) > 384<<10 {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		stored, err := q.ReadConnectorBackingAdmission(live, custodydb.ReadConnectorBackingAdmissionParams{RootID: id(s.root), OperationID: id(operation), CurrentValue: current})
		if err != nil {
			return err
		}
		if len(stored) > 0 {
			out, err = decodeConnectorBackingAdmission(stored)
			return err
		}
		b, err := q.ReadConnectorBackingCandidate(live, custodydb.ReadConnectorBackingCandidateParams{RootID: id(s.root), CurrentValue: current})
		if err != nil {
			return err
		}
		var candidate struct {
			ID     string
			Before app.ConnectorIdentityBacking
		}
		if len(b) > 32<<10 || json.Unmarshal(b, &candidate) != nil || candidate.ID != operation || !c.Configuration.Backing.CanRenew(candidate.Before) {
			return value.ErrUnavailable
		}
		actor := audit.OperationConnectorProcessActor{Process: c.Proof.Process, Deployment: c.Proof.Configuration.Profile.Deployment, ClientKeyDigest: c.Proof.ClientKeyDigest, ServerKeyDigest: c.Proof.ServerKeyDigest}
		payload, err := json.Marshal(struct {
			Actor         audit.OperationConnectorProcessActor
			Before, After app.ConnectorIdentityBacking
			Source        value.ConnectorBackingObservation
			Revision      identity.Revision
		}{actor, candidate.Before, c.Configuration.Backing, c.Configuration.Source.Observation.Backing, c.Configuration.Source.Observation.Profile.Revision})
		if err != nil {
			return err
		}
		input, err := s.mac.Digest("connector-backing/v1", payload)
		if err != nil {
			return err
		}
		account, err := s.mac.ConnectorAccount(s.binding)
		if err != nil {
			return err
		}
		start := c.ObservedAt.UTC().Truncate(time.Microsecond)
		in := audit.OperationIntent{ID: operation, RootID: s.root, TraceID: operation, Name: "connector_backing_acceptance", InputFormat: "connector-backing/v1", MACVersion: s.mac.Version(), AccountVersion: s.mac.AccountVersion(), Process: &actor, PrincipalDigest: account, InputDigest: input, CreatedAt: start, RequestUntil: identity.Earlier(c.Until, candidate.Before.Policy.ValidUntil).UTC().Truncate(time.Microsecond), WriteUntil: start.Add(30 * time.Second), RetainUntil: start.Add(time.Duration(candidate.Before.RetainedSeconds) * time.Second)}
		var ticketImages [][]byte
		if candidate.Before.Policy.History.Layout == audit.ConnectorRetirementHistoryLayout {
			cohortBytes, e := q.ReadConnectorSuccessorCohorts(live, custodydb.ReadConnectorSuccessorCohortsParams{RootID: id(s.root), CurrentValue: current})
			if e != nil {
				return e
			}
			var cohorts []struct {
				Cohort        app.ConnectorRetirementCohort
				AccountDigest artifact.Digest
			}
			if len(cohortBytes) > 8<<20 || json.Unmarshal(cohortBytes, &cohorts) != nil || len(cohorts) == 0 || len(cohorts) > app.ConnectorRetirementSetLimit || int64(len(cohorts)) > candidate.Before.ProfileLimit {
				return value.ErrUnavailable
			}
			tickets := make([]audit.ConnectorRetirementTicket, 0, len(cohorts))
			ticketImages = make([][]byte, 0, len(cohorts))
			for _, row := range cohorts {
				if live.Err() != nil || !row.Cohort.Valid() || row.Cohort.RootID != s.root || row.Cohort.Binding.InstallationID != s.binding.InstallationID || row.Cohort.Binding.IssuerEpoch != s.binding.IssuerEpoch || row.Cohort.BackingRevision != candidate.Before.Policy.BackingRevision {
					return value.ErrUnavailable
				}
				peerAccount, e := s.mac.ConnectorAccount(row.Cohort.Binding)
				if e != nil || peerAccount != row.AccountDigest {
					return value.ErrUnavailable
				}
				ticketID, e := uuid.NewRandom()
				if e != nil {
					return e
				}
				ticket, e := app.ConnectorRetirementProposal(in, ticketID.String(), row.Cohort, c.Configuration.Backing, c.Configuration.Source.Observation.Backing.Digest, row.AccountDigest)
				if e != nil {
					return e
				}
				image, _, e := app.CanonicalConnectorRetirementTicket(ticket)
				if e != nil {
					return e
				}
				tickets = append(tickets, ticket)
				ticketImages = append(ticketImages, image)
			}
			in, err = app.BindConnectorRetirementAcceptance(in, candidate.Before.Policy, tickets)
		} else {
			in, err = auditapp.BindOperationLifecycle(in, candidate.Before.Policy)
		}
		if err != nil {
			return err
		}
		if c.Configuration.Backing.Policy.ValidUntil.Add(time.Minute).After(in.Lifecycle.OriginalPurgeAt) {
			return value.ErrCapacity
		}
		intent, err := json.Marshal(in)
		if err != nil || len(intent) > 8192 {
			return value.ErrUnavailable
		}
		if candidate.Before.Policy.History.Layout == audit.ConnectorRetirementHistoryLayout {
			stored, err = q.AdmitConnectorBackingReserved(live, custodydb.AdmitConnectorBackingReservedParams{RootID: id(s.root), CurrentValue: current, IntentValue: intent, TicketImages: ticketImages})
		} else {
			stored, err = q.AdmitConnectorBacking(live, custodydb.AdmitConnectorBackingParams{RootID: id(s.root), CurrentValue: current, IntentValue: intent})
		}
		if err != nil {
			return err
		}
		out, err = decodeConnectorBackingAdmission(stored)
		return err
	})
	if e != nil || live.Err() != nil || !s.current(c) || out.Intent.ID != operation {
		return app.ConnectorBackingAdmission{}, value.ErrUnavailable
	}
	return out, nil
}
func (s *ConnectorBackingJournal) StoreConnectorBackingOutcome(ctx context.Context, a app.ConnectorBackingAdmission, o audit.OperationOutcome) error {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !a.Intent.Valid() || a.Intent.RootID != s.root || a.Intent.Name != "connector_backing_acceptance" || !o.Valid() || !sameAuditJSON(o.Intent, a.Intent) {
		return value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, a.Intent.RequestUntil)
	defer end()
	in, e := json.Marshal(a.Intent)
	if e != nil {
		return value.ErrUnavailable
	}
	out, e := json.Marshal(o)
	if e != nil {
		return value.ErrUnavailable
	}
	return s.ledger.transaction(live, func(q *custodydb.Queries) error {
		return q.StoreConnectorBackingOutcome(live, custodydb.StoreConnectorBackingOutcomeParams{RootID: id(s.root), OperationID: id(a.Intent.ID), IntentValue: in, OutcomeValue: out})
	})
}
func (s *ConnectorIdentitySources) PromoteConnectorBacking(ctx context.Context, a app.ConnectorBackingAdmission, c app.ConnectorBackingCurrent) (app.ConnectorIdentityBacking, error) {
	var out app.ConnectorIdentityBacking
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !c.Valid(time.Now()) || c.Proof.Process.Binding != s.binding || c.Configuration.Backing.Policy.RootID != s.root || !s.qualification.Matches(c.Configuration) || !a.Intent.Valid() || a.Intent.RootID != s.root || a.Outcome == nil || !a.Outcome.Valid() {
		return out, value.ErrUnavailable
	}
	live, end := context.WithDeadline(ctx, c.Until)
	defer end()
	current, e := json.Marshal(c)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(live, func(q *custodydb.Queries) error {
		b, e := q.PromoteConnectorBacking(live, custodydb.PromoteConnectorBackingParams{RootID: id(s.root), OperationID: id(a.Intent.ID), CurrentValue: current})
		if e != nil {
			return e
		}
		if len(b) > 32<<10 || json.Unmarshal(b, &out) != nil || !sameAuditJSON(out, a.Proposed.Backing) {
			return value.ErrUnavailable
		}
		return nil
	})
	if e != nil || live.Err() != nil || !c.Valid(time.Now()) {
		return app.ConnectorIdentityBacking{}, value.ErrUnavailable
	}
	return out.Clone(), nil
}
