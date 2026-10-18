package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capacity"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Separate read and producer facets prevent a query coordinator from receiving
// configuration-writing methods. Both require explicit protected pools; neither
// grants itself a role, imports administrator credentials or fabricates setup.
type ContextQueryCapacityReads struct {
	ledger             *Ledger
	root, installation string
}
type ContextQueryCapacityProducer struct {
	ledger             *Ledger
	root, installation string
}

var _ app.QueryCapacityReader = (*ContextQueryCapacityReads)(nil)
var _ app.QueryCapacityWriter = (*ContextQueryCapacityProducer)(nil)

func NewContextQueryCapacityReads(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*ContextQueryCapacityReads, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ContextQueryCapacityReads{l, root, installation}, nil
}
func NewContextQueryCapacityProducer(ctx context.Context, pool *pgxpool.Pool, root, installation string) (*ContextQueryCapacityProducer, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, e
	}
	return &ContextQueryCapacityProducer{l, root, installation}, nil
}

func decodeQueryCapacity(raw []byte, out any) error {
	if len(raw) < 2 || len(raw) > 256<<10 {
		return value.ErrUnavailable
	}
	v := jsontext.Value(bytes.Clone(raw))
	if v.Canonicalize() != nil {
		return value.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return value.ErrUnavailable
	}
	canonical, e := json.Marshal(out)
	if e != nil || !capacitySameJSONFields(raw, canonical) {
		return value.ErrUnavailable
	}
	return nil
}

func (s *ContextQueryCapacityReads) ReadQueryCapacitySource(ctx context.Context, recovery artifact.RecoveryProof) (app.QueryCapacitySource, error) {
	var out app.QueryCapacitySource
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !recovery.Valid(time.Now()) || recovery.InstallationID != s.installation {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(time.Now().Add(5*time.Second), recovery.FreshUntil))
	defer cancel()
	b, e := json.Marshal(recovery)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		raw, e := q.ReadContextQueryCapacitySource(ctx, custodydb.ReadContextQueryCapacitySourceParams{RootID: id(s.root), Recovery: b})
		if e != nil {
			return e
		}
		return decodeQueryCapacity(raw, &out)
	})
	if e != nil || ctx.Err() != nil || !out.Valid(time.Now()) || out.Root.RootID != s.root || out.Qualification.RootBacking.InstallationID != s.installation {
		return app.QueryCapacitySource{}, value.ErrUnavailable
	}
	if out.Recovery.InstallationID != recovery.InstallationID || out.Recovery.IssuerEpoch != recovery.IssuerEpoch || out.Recovery.Revision != recovery.Revision || !out.Recovery.ObservedAt.Equal(recovery.ObservedAt) || !out.Recovery.FreshUntil.Equal(recovery.FreshUntil) {
		return app.QueryCapacitySource{}, value.ErrUnavailable
	}
	out.Recovery = recovery // retain the original Go cancellation-independent bounds
	return out, nil
}

func queryCapacityObservationJSON(source app.QueryCapacitySource) ([]byte, error) {
	return json.Marshal(struct {
		SourceRevision         int64
		SourceDigest           artifact.Digest
		Recovery               artifact.RecoveryProof
		ObservedAt, FreshUntil time.Time
	}{source.SourceRevision, source.SourceDigest, source.Recovery, capacityObservedMicro(source.ObservedAt), source.FreshUntil.UTC().Truncate(time.Microsecond)})
}

func (s *ContextQueryCapacityProducer) BeginQueryCapacityObservation(ctx context.Context, source app.QueryCapacitySource, plan app.QueryBackingPlan, claimID string) (app.QueryCapacityObservation, error) {
	var out app.QueryCapacityObservation
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !source.Valid(time.Now()) || source.Root.RootID != s.root || plan.RootID != s.root || plan.InstallationID != s.installation || !authorization.UUID(claimID) || source.ObservationCount >= plan.Qualification.SourceTransitionLimit {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, source.FreshUntil)
	defer cancel()
	b, e := json.Marshal(plan)
	if e != nil {
		return out, value.ErrUnavailable
	}
	o, e := queryCapacityObservationJSON(source)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		raw, e := q.BeginContextQueryCapacityObservation(ctx, custodydb.BeginContextQueryCapacityObservationParams{RootID: id(s.root), Proposal: b, Observation: o, ClaimID: id(claimID), PriorCount: source.ObservationCount})
		if e != nil {
			return e
		}
		return decodeQueryCapacity(raw, &out)
	})
	// transaction returns success only after COMMIT acknowledgement. A lost
	// reply leaves the attempt spent and never exposes a usable result.
	if e != nil || ctx.Err() != nil || !out.Valid(source, plan, time.Now()) || out.ID != claimID || out.Ordinal != source.ObservationCount+1 {
		return app.QueryCapacityObservation{}, value.ErrUnavailable
	}
	return out, nil
}

func (s *ContextQueryCapacityProducer) AcceptQueryCapacity(ctx context.Context, source app.QueryCapacitySource, plan app.QueryBackingPlan, claim app.QueryCapacityObservation) (app.QueryBackingPlan, error) {
	var out app.QueryBackingPlan
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !source.Valid(time.Now()) || source.Root.RootID != s.root || plan.RootID != s.root || plan.InstallationID != s.installation || claim.AcceptanceID != plan.AcceptanceID || claim.Ordinal != source.ObservationCount || !time.Now().Before(claim.ValidUntil) {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, source.FreshUntil)
	defer cancel()
	// Normalize only in the restrictive direction before PostgreSQL parses
	// timestamps. No future source observation replaces the original context.
	b, e := json.Marshal(plan)
	if e != nil {
		return out, value.ErrUnavailable
	}
	o, e := queryCapacityObservationJSON(source)
	if e != nil {
		return out, value.ErrUnavailable
	}
	c, e := json.Marshal(claim)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		raw, e := q.AcceptContextQueryCapacity(ctx, custodydb.AcceptContextQueryCapacityParams{RootID: id(s.root), Proposal: b, Observation: o, Claim: c})
		if e != nil {
			return e
		}
		return decodeQueryCapacity(raw, &out)
	})
	if e != nil || ctx.Err() != nil || !source.Valid(time.Now()) {
		return app.QueryBackingPlan{}, value.ErrUnavailable
	}
	return out, nil
}

func (s *ContextQueryCapacityProducer) AllocateQueryCapacity(ctx context.Context, plan app.QueryBackingPlan, key app.WorkloadCapacityKey, newID string) (string, error) {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || plan.RootID != s.root || plan.InstallationID != s.installation || key.RootID != s.root || !authorization.UUID(newID) || !time.Now().Before(plan.HardUntil) {
		return "", value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(time.Now().Add(5*time.Second), plan.HardUntil))
	defer cancel()
	var out string
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		u, e := q.AllocateContextQueryCapacity(ctx, custodydb.AllocateContextQueryCapacityParams{RootID: id(s.root), AcceptanceID: id(plan.AcceptanceID), ClusterID: id(key.ClusterID), NamespaceUid: key.NamespaceUID, WorkloadUid: key.WorkloadUID, NewID: id(newID)})
		out = uid(u)
		return e
	})
	if e != nil || ctx.Err() != nil || !authorization.UUID(out) {
		return "", value.ErrUnavailable
	}
	return out, nil
}

func (s *ContextQueryCapacityProducer) CompleteQueryCapacityObservation(ctx context.Context, claim app.QueryCapacityObservation) error {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !authorization.UUID(claim.ID) || !authorization.UUID(claim.AcceptanceID) || !time.Now().Before(claim.ValidUntil) {
		return value.ErrUnavailable
	}
	until := claim.ValidUntil
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	b, e := json.Marshal(claim)
	if e != nil {
		return value.ErrUnavailable
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.CompleteContextQueryCapacityObservation(ctx, custodydb.CompleteContextQueryCapacityObservationParams{RootID: id(s.root), Claim: b, UntilAt: ts(until.UTC().Truncate(time.Microsecond))})
	})
	if e != nil || ctx.Err() != nil || !time.Now().Before(until) {
		return value.ErrUnavailable
	}
	return nil
}

func (s *ContextQueryCapacityReads) ReadQueryCapacityPlan(ctx context.Context, source app.QueryCapacitySource, a value.ContextProjectionAuthority, account string) (value.ContextQueryPlan, error) {
	var out value.ContextQueryPlan
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !source.Valid(time.Now()) || !source.Ready || !a.Valid(time.Now()) || a.Scope.RootID != s.root || !authorization.UUID(source.AcceptanceID) || !authorization.UUID(account) {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, identity.Earlier(source.FreshUntil, a.ValidUntil))
	defer cancel()
	actor, e := json.Marshal(a.Scope.Principal)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		raw, e := q.ReadContextQueryCapacityPlan(ctx, custodydb.ReadContextQueryCapacityPlanParams{RootID: id(s.root), AcceptanceID: id(source.AcceptanceID), ClusterID: id(a.Scope.ClusterID), NamespaceUid: a.Scope.NamespaceUID, WorkloadUid: a.Scope.WorkloadUID, Actor: actor, PrincipalKey: principalKey(a.Scope.Principal), ProposedAccount: id(account)})
		if e != nil {
			return e
		}
		return decodeQueryCapacity(raw, &out)
	})
	if e != nil || ctx.Err() != nil || !out.Valid(a.Scope, time.Now()) || out.InstallationID != s.installation || out.Profile != source.Qualification.ContextQuery.Profile {
		return value.ContextQueryPlan{}, value.ErrUnavailable
	}
	out.ValidUntil = identity.Earlier(out.ValidUntil, identity.Earlier(source.FreshUntil, a.ValidUntil))
	return out, nil
}

func (s *ContextQueryCapacityProducer) SuspendQueryCapacity(ctx context.Context, observed time.Time) error {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || observed.IsZero() || observed.After(time.Now()) {
		return value.ErrUnavailable
	}
	// Persisting an older negative only restricts authority. Bound this write
	// from the current call while retaining caller cancellation/deadlines; the
	// original observation remains the SQL watermark and never gains freshness.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.SuspendContextQueryCapacity(ctx, custodydb.SuspendContextQueryCapacityParams{RootID: id(s.root), Observed: ts(capacityObservedMicro(observed))})
	})
	if e != nil || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}
