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

func (s *ContextQueryCapacityProducer) AcceptQueryCapacity(ctx context.Context, source app.QueryCapacitySource, plan app.QueryBackingPlan) (app.QueryBackingPlan, error) {
	var out app.QueryBackingPlan
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !source.Valid(time.Now()) || source.Root.RootID != s.root || plan.RootID != s.root || plan.InstallationID != s.installation {
		return out, value.ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(ctx, source.FreshUntil)
	defer cancel()
	// Normalize only in the restrictive direction before PostgreSQL parses
	// timestamps. No future source observation replaces the original context.
	observation := struct {
		SourceRevision         int64
		SourceDigest           artifact.Digest
		Recovery               artifact.RecoveryProof
		ObservedAt, FreshUntil time.Time
	}{source.SourceRevision, source.SourceDigest, source.Recovery, capacityObservedMicro(source.ObservedAt), source.FreshUntil.UTC().Truncate(time.Microsecond)}
	b, e := json.Marshal(plan)
	if e != nil {
		return out, value.ErrUnavailable
	}
	o, e := json.Marshal(observation)
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		raw, e := q.AcceptContextQueryCapacity(ctx, custodydb.AcceptContextQueryCapacityParams{RootID: id(s.root), Proposal: b, Observation: o})
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
	ctx, cancel := context.WithDeadline(ctx, observed.Add(5*time.Second))
	defer cancel()
	e := s.ledger.transaction(ctx, func(q *custodydb.Queries) error {
		return q.SuspendContextQueryCapacity(ctx, custodydb.SuspendContextQueryCapacityParams{RootID: id(s.root), Observed: ts(capacityObservedMicro(observed))})
	})
	if e != nil || ctx.Err() != nil {
		return value.ErrUnavailable
	}
	return nil
}
