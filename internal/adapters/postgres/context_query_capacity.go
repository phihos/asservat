package postgres

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SharedContextQueryPlans consumes the original installed capacity root. The
// existing producer owns root/workload acceptance; this read facet cannot create
// an anchor/allocation, refresh a source or invent a deployment qualification.
// The same private backing wrapper is usable by the key service without a
// Kubernetes client, HTTP owner, capacity producer or nested pool acquisition.
type SharedContextQueryPlans struct {
	ledger             *Ledger
	root, installation string
	profile            authorization.DownloadWorkerProfile
}

var _ app.ContextQueryPlans = (*SharedContextQueryPlans)(nil)
var _ ContextQueryBackingGuard = (*SharedContextQueryPlans)(nil)

func NewSharedContextQueryPlans(ctx context.Context, pool *pgxpool.Pool, root, installation string, profile authorization.DownloadWorkerProfile) (*SharedContextQueryPlans, error) {
	if !authorization.UUID(root) || !authorization.UUID(installation) || !profile.Valid() || profile.InstallationID != installation || profile.StoreCredentialSecret == "" {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &SharedContextQueryPlans{l, root, installation, profile}, nil
}

func (s *SharedContextQueryPlans) matches(p value.ContextQueryResourceProfile) bool {
	return s != nil && p.Valid() && p.Path.AcquisitionClusterID == s.profile.ClusterID && p.Path.WorkerConfiguration == s.profile.Configuration &&
		p.Worker.CPUMilli == s.profile.CPUMillis && p.Worker.MemoryBytes == s.profile.MemoryBytes && p.Worker.EphemeralStorageBytes == 4<<20 && p.Worker.Runtime <= s.profile.MaxRuntime
}

func (s *SharedContextQueryPlans) ContextQueryPlan(ctx context.Context, a value.ContextProjectionAuthority) (value.ContextQueryPlan, error) {
	var out value.ContextQueryPlan
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || a.Scope.RootID != s.root || !a.Valid(time.Now()) || a.Environment.InstallationID != s.installation || a.Environment.Path.AcquisitionClusterID != s.profile.ClusterID || a.Environment.Path.WorkerConfiguration != s.profile.Configuration {
		return out, value.ErrUnavailable
	}
	until := identity.Earlier(time.Now().Add(5*time.Second), a.ValidUntil)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	actor, e := json.Marshal(a.Scope.Principal)
	if e != nil {
		return out, value.ErrUnavailable
	}
	path, e := json.Marshal(a.Environment.Path)
	if e != nil {
		return out, value.ErrUnavailable
	}
	account, e := uuid.NewRandom()
	if e != nil {
		return out, value.ErrUnavailable
	}
	e = s.ledger.transaction(call, func(q *custodydb.Queries) error {
		raw, e := q.ReadSharedContextQueryPlan(call, custodydb.ReadSharedContextQueryPlanParams{RootID: id(s.root), ClusterID: id(a.Scope.ClusterID), NamespaceUid: a.Scope.NamespaceUID, WorkloadUid: a.Scope.WorkloadUID, Actor: actor, PrincipalKey: principalKey(a.Scope.Principal), ProposedAccount: id(account.String()), Path: path})
		if e != nil {
			return e
		}
		return queryDecode(raw, 65536, &out)
	})
	if e != nil || call.Err() != nil || !out.Valid(a.Scope, time.Now()) || out.InstallationID != s.installation || out.Profile.Path != a.Environment.Path || !s.matches(out.Profile) {
		return value.ContextQueryPlan{}, value.ErrUnavailable
	}
	out.ValidUntil = identity.Earlier(out.ValidUntil, until)
	if d, ok := call.Deadline(); ok {
		out.ValidUntil = identity.Earlier(out.ValidUntil, d)
	}
	if !out.Valid(a.Scope, time.Now()) {
		return value.ContextQueryPlan{}, value.ErrUnavailable
	}
	return out, nil
}

func (s *SharedContextQueryPlans) WithCurrentQueryBacking(ctx context.Context, p value.ContextQueryPlan, a value.ContextProjectionAuthority, fn func(context.Context) error) error {
	// p's observation is historical on a later paid poll. The new authority
	// bounds this invocation; its immutable accepted profile/dates stay exact.
	// ContextQueries.current independently checks current installed source,
	// charged allocation and accepted configuration inside the effect's SAME
	// transaction, before and after work. A callback alone never supplies them.
	if s == nil || ctx == nil || ctx.Err() != nil || fn == nil || p.RootID != s.root || p.InstallationID != s.installation || !p.Matches(a.Scope) || !a.Valid(time.Now()) || p.Profile.Path != a.Environment.Path || !s.matches(p.Profile) {
		return value.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, a.ValidUntil)
	defer stop()
	if e := fn(call); e != nil {
		return e
	}
	if call.Err() != nil || !a.Valid(time.Now()) {
		return value.ErrUnavailable
	}
	return nil
}
