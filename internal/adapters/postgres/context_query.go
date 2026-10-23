package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/analysis"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContextQueryBackingGuard is private C-07 composition. Its implementation must
// independently accept the exact qualified parent envelope, complete source,
// original disclosure/effect/cleanup/history horizons and purpose-specific path. A caller profile or qualification digest is not proof.
// The callback performs SQL only, at most once. SQL still locks and compares the
// accepted epochs/profile/accounts: a remote observation cannot make SQL atomic.
// SharedContextQueryPlans is the installed implementation; current source,
// allocation and configuration checks remain inside the effect transaction.
type ContextQueryBackingGuard interface {
	WithCurrentQueryBacking(context.Context, value.ContextQueryPlan, value.ContextProjectionAuthority, func(context.Context) error) error
}

// ContextQueryWorkerGuard checks the purpose-specific attested worker/peer,
// original signing periods and live request ownership around SQL. A download
// worker proof or a structurally valid ContextQueryWorker cannot implement it.
// Missing composition leaves all batch/start operations unavailable.
type ContextQueryWorkerGuard interface {
	WithCurrentProjectionWorker(context.Context, value.ContextQuery, value.ContextQueryRequest, value.ContextQueryWorker, value.ContextProjectionAuthority, func(context.Context) error) error
}

type ContextQueries struct {
	ledger    *Ledger
	root      string
	retention *RetentionTransactionGuard
	recovery  *RecoveryTransactionGuard
	backing   ContextQueryBackingGuard
	workers   ContextQueryWorkerGuard
}

var _ app.ContextQueryLedger = (*ContextQueries)(nil)

func NewContextQueries(ctx context.Context, pool *pgxpool.Pool, root string, effects EffectTransactionGuards, backing ContextQueryBackingGuard, workers ContextQueryWorkerGuard) (*ContextQueries, error) {
	if !authorization.UUID(root) || effects.Retention == nil || effects.Recovery == nil || effects.Retention.root != root || effects.Recovery.root != root || backing == nil {
		return nil, value.ErrUnavailable
	}
	l, e := New(ctx, pool)
	if e != nil {
		return nil, value.ErrUnavailable
	}
	return &ContextQueries{ledger: l, root: root, retention: effects.Retention, recovery: effects.Recovery, backing: backing, workers: workers}, nil
}

func queryJSON(v any) ([]byte, error) { return json.Marshal(v) }
func queryDecode(raw []byte, limit int, out any) error {
	if len(raw) == 0 || len(raw) > limit {
		return value.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return value.ErrUnavailable
	}
	if d.Decode(new(any)) != io.EOF {
		return value.ErrUnavailable
	}
	return nil
}
func queryFromRow(r custodydb.ContextQuery) (value.ContextQuery, error) {
	var q value.ContextQuery
	if queryDecode(r.Query, 65536, &q) != nil || !q.Valid() || q.ID != uid(r.ID) || q.Scope.RootID != uid(r.RootID) || q.OperationID != uid(r.OperationID) || q.WorkerID != uid(r.WorkerID) || q.Plan.AllocationID != uid(r.AllocationID) || q.Plan.AccountID != uid(r.AccountID) || q.RecoveryIssuerEpoch != uid(r.IssuerEpoch) || !q.CreatedAt.Equal(r.CreatedAt.Time) || !q.Deadline.Equal(r.Deadline.Time) || !q.CleanupUntil.Equal(r.CleanupUntil.Time) || !q.Plan.RetireBy.Equal(r.RetireBy.Time) || !bytes.Equal(principalKey(q.Scope.Principal), r.PrincipalKey) {
		return value.ContextQuery{}, value.ErrUnavailable
	}
	var actor identity.Principal
	if queryDecode(r.Actor, 4096, &actor) != nil || actor != q.Scope.Principal {
		return value.ContextQuery{}, value.ErrUnavailable
	}
	return q, nil
}

// Original request cancellation/deadline, authority and query bounds cover the
// guard, topology read, pool wait, SQL, and final guard return. Fresh is never
// returned after unknown commit, a failed guard return, or an omitted/repeated
// callback. Committed obligations are deliberately not undone in those cases.
func (s *ContextQueries) current(ctx context.Context, query value.ContextQuery, request value.ContextQueryRequest, authority value.ContextProjectionAuthority, effect func(context.Context, *custodydb.Queries, custodydb.ContextQueryBacking, custodydb.ContextQueryAllocation) error) error {
	if s == nil || s.ledger == nil || s.backing == nil || ctx == nil || ctx.Err() != nil || query.Scope.RootID != s.root || !query.Current(authority, time.Now()) || !request.Valid(time.Now()) || request.Call.RootID != s.root || request.Call.Principal != query.Scope.Principal {
		return queryRefusal("input", nil)
	}
	until := identity.Earlier(query.Deadline, identity.Earlier(request.Call.Until, authority.ValidUntil))
	ctx, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	topology, e := s.retention.observe(ctx, query.Scope.ClusterID)
	if e != nil {
		return queryRefusal("topology", nil)
	}
	e = queryGuarded(ctx, func(bound context.Context, callback func(context.Context) error) error {
		return s.backing.WithCurrentQueryBacking(bound, query.Plan, authority, callback)
	}, func(callback context.Context) error {
		return s.ledger.transaction(callback, func(tx *custodydb.Queries) error {
			recovery, e := s.recovery.lock(callback, tx, s.root, authority.Environment.Recovery)
			if e != nil {
				return queryRefusal("recovery-lock", e)
			}
			permissions, e := tx.LockPermissionStream(callback, id(s.root))
			if e != nil {
				return queryRefusal("permission-lock", e)
			}
			// The original installed root and immutable residual reservation are
			// mandatory, including when a backing callback reports success.
			// Lock source/anchor before query backing and allocation; missing or
			// negative protected state never falls back to caller-supplied facts.
			accepted, e := tx.LockContextQueryCapacity(callback, custodydb.LockContextQueryCapacityParams{RootID: id(s.root), AcceptanceID: id(query.Plan.AcceptanceID)})
			if e != nil || !accepted {
				return queryRefusal("capacity", nil)
			}
			backing, e := tx.LockContextQueryBacking(callback, id(s.root))
			if e != nil {
				return queryRefusal("backing-lock", e)
			}
			allocation, e := tx.LockContextQueryAllocation(callback, custodydb.LockContextQueryAllocationParams{ID: id(query.Plan.AllocationID), RootID: id(s.root)})
			if e != nil {
				return queryRefusal("allocation-lock", e)
			}
			fence := func() error {
				return s.fence(callback, tx, query, request, authority, topology, recovery, permissions, backing, allocation)
			}
			if e = fence(); e != nil {
				return e
			}
			if e = effect(callback, tx, backing, allocation); e != nil {
				return queryRefusal("effect", e)
			}
			return fence()
		})
	})
	if e != nil {
		return queryRefusal("transaction", e)
	}
	if ctx.Err() != nil || !query.Current(authority, time.Now()) || !request.Valid(time.Now()) {
		return queryRefusal("final", nil)
	}
	return nil
}

func (s *ContextQueries) fence(ctx context.Context, tx *custodydb.Queries, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority, topology privacy.PolicyTopology, recovery custodydb.FleetCurrentTrust, p custodydb.PermissionStream, b custodydb.ContextQueryBacking, allocation custodydb.ContextQueryAllocation) error {
	now, e := tx.CurrentTime(ctx)
	if e != nil {
		return queryRefusal("fence-time", e)
	}
	switch {
	case ctx.Err() != nil || !q.Current(a, now.Time) || !r.Valid(now.Time):
		return queryRefusal("fence-request", nil)
	case b.Suspended || uid(b.InstallationID) != q.Plan.InstallationID || uid(b.AcceptanceID) != q.Plan.AcceptanceID:
		return queryRefusal("fence-backing", nil)
	case a.PermissionRevision.UID != uid(p.Epoch) || a.PermissionRevision.Generation != p.Sequence || !bytes.Equal(a.PermissionRevision.Digest[:], p.ProjectionDigest):
		return queryRefusal("fence-permission-revision", nil)
	case p.Suspended || !p.InitialAuditID.Valid:
		return queryRefusal("fence-permission-suspended", nil)
	case !now.Time.Before(p.LeaseUntil.Time) || !identity.Fresh(p.ObservedAt.Time, p.FreshUntil.Time, now.Time, 5*time.Second):
		return queryRefusal("fence-permission-fresh", nil)
	}
	var profile value.ContextQueryResourceProfile
	var pool, policy, qualification identity.Revision
	if queryDecode(b.Profile, 32768, &profile) != nil || profile != q.Plan.Profile.SharedBudget() || queryDecode(b.Qualification, 32768, &qualification) != nil || qualification != profile.Qualification ||
		!b.HardUntil.Time.Equal(q.Plan.HardUntil) || !b.EffectsUntil.Time.Equal(q.Plan.EffectsUntil) || !b.CleanupUntil.Time.Equal(q.Plan.CleanupUntil) || !b.RetireBy.Time.Equal(q.Plan.RetireBy) || queryDecode(allocation.PoolSource, 4096, &pool) != nil || queryDecode(allocation.PolicySource, 4096, &policy) != nil || pool != q.Plan.PoolSource || policy != q.Plan.PolicySource || allocation.Revision != q.Plan.AllocationRevision || uid(allocation.ClusterID) != q.Scope.ClusterID || allocation.NamespaceUid != q.Scope.NamespaceUID || allocation.WorkloadUid != q.Scope.WorkloadUID {
		return queryRefusal("fence-profile", nil)
	}
	for _, auditID := range []string{uid(p.Epoch), uid(p.InitialAuditID)} {
		proof, e := tx.ReadAuthorityAudit(ctx, id(auditID))
		if e != nil || !currentAuthorityAudit(proof, p.ID, id(auditID)) {
			return queryRefusal("fence-audit", nil)
		}
	}
	if e = s.retention.check(ctx, tx, topology, a.Retention, authorization.Target{ClusterID: q.Scope.ClusterID, NamespaceUID: q.Scope.NamespaceUID, WorkloadUID: q.Scope.WorkloadUID, PodUID: q.Scope.PodUID}); e != nil {
		return queryRefusal("fence-retention", e)
	}
	expected := a.Environment.Processing
	snapshot, processing, e := readProcessingSnapshot(ctx, tx, s.root, q.Plan.InstallationID, q.RecoveryIssuerEpoch, q.Scope.ArtifactID, expected.ObservedAt, expected.ValidUntil)
	if e != nil {
		return queryRefusal("fence-processing-read", e)
	}
	observed := processingProof(snapshot, processing)
	if observed.RootID != expected.RootID || observed.Epoch != expected.Epoch || observed.Sequence != expected.Sequence || observed.CaptureID != expected.CaptureID || observed.Location != expected.Location || observed.StateDigest != expected.StateDigest {
		return queryRefusal("fence-processing", nil)
	}
	published, e := tx.ReadPublishedContext(ctx, custodydb.ReadPublishedContextParams{ArtifactID: id(q.Scope.ArtifactID), RootID: id(s.root)})
	if e != nil {
		return queryRefusal("fence-published-read", e)
	}
	original, e := currentPublishedContext(published)
	if e != nil || original.CaseID != q.Scope.CaseID || original.CaptureUID != q.Scope.CaptureID || original.NamespaceUID != q.Scope.NamespaceUID || original.WorkloadUID != q.Scope.WorkloadUID || original.PodUID != q.Scope.PodUID || original.Registration.Location != a.Environment.Location || original.Registration.StoreID != a.Environment.StoreID || original.Registration.NativeLimit != artifact.MaxContextBytes || original.DataClass != "metadata" || !bytes.Equal(published.ContextVerification.CopiesDigest, q.Scope.Version[:]) || a.AccessUntil.After(published.EffectiveExpiresAt.Time) || a.DeleteBy.After(published.EffectiveDeleteBy.Time) {
		return queryRefusal("fence-published", nil)
	}
	linked, e := tx.ContextQueryCaseExists(ctx, custodydb.ContextQueryCaseExistsParams{RootID: id(s.root), CaseID: id(q.Scope.CaseID), CaptureID: id(q.Scope.CaptureID), ArtifactID: id(q.Scope.ArtifactID)})
	if e != nil || !linked {
		return queryRefusal("fence-case", nil)
	}
	if e = queryIntentFence(ctx, tx, r.Call, recovery); e != nil {
		return queryRefusal("fence-intent", e)
	}
	if e = s.recovery.check(ctx, tx, recovery, s.root, a.Environment.Recovery); e != nil {
		return queryRefusal("fence-recovery", e)
	}
	profileBody, e := queryJSON(q.Plan.Profile)
	if e != nil {
		return queryRefusal("fence-profile-json", nil)
	}
	configured, e := tx.ContextQuerySharedProfileCurrent(ctx, custodydb.ContextQuerySharedProfileCurrentParams{RootID: id(s.root), Profile: profileBody})
	if e != nil || !configured {
		return queryRefusal("fence-shared-profile", nil)
	}
	// The same root can acquire a restrictive workload/source change. Compare
	// the exact original allocation to current protected base capacity at the
	// end of both the pre-effect and post-effect fence, after blocking reads.
	current, e := tx.ContextQueryCapacityAllocationCurrent(ctx, custodydb.ContextQueryCapacityAllocationCurrentParams{RootID: id(s.root), AllocationID: id(q.Plan.AllocationID)})
	if e != nil || !current {
		return queryRefusal("fence-allocation", nil)
	}
	now, e = tx.CurrentTime(ctx)
	if e != nil || ctx.Err() != nil || !q.Current(a, now.Time) || !r.Valid(now.Time) || !now.Time.Before(published.EffectiveExpiresAt.Time) || !now.Time.Before(topology.FreshUntil) || !now.Time.Before(p.FreshUntil.Time) || !now.Time.Before(p.LeaseUntil.Time) {
		return queryRefusal("fence-final", nil)
	}
	return nil
}

func (s *ContextQueries) AdmitQuery(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) (app.ContextQueryAdmission, error) {
	var out app.ContextQueryAdmission
	if !q.Plan.Valid(q.Scope, time.Now()) || q.OperationID != r.Call.ID || r.Call.Tool != "get_file_excerpt" || q.CreatedAt.Before(r.Call.StartedAt) {
		return out, value.ErrUnavailable
	}
	e := s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries, b custodydb.ContextQueryBacking, allocation custodydb.ContextQueryAllocation) error {
		// Lock/account lookup precedes the query lock, including replay.
		principal, e := tx.LockContextQueryPrincipal(ctx, custodydb.LockContextQueryPrincipalParams{RootID: id(s.root), PrincipalKey: principalKey(q.Scope.Principal)})
		if errors.Is(e, pgx.ErrNoRows) {
			principal, e = tx.InsertContextQueryPrincipal(ctx, custodydb.InsertContextQueryPrincipalParams{ID: id(q.Plan.AccountID), RootID: id(s.root), PrincipalKey: principalKey(q.Scope.Principal)})
		}
		if e != nil || uid(principal.ID) != q.Plan.AccountID {
			return value.ErrUnavailable
		}
		old, e := tx.LockContextQuery(ctx, custodydb.LockContextQueryParams{ID: id(q.ID), RootID: id(s.root)})
		if e == nil {
			stored, e := queryFromRow(old)
			if e != nil || !stored.Equal(q) {
				return value.ErrUnavailable
			}
			out.Query = stored
			return s.call(ctx, tx, q, r, false)
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		initialRequest, e := queryJSON(r)
		if e != nil {
			return e
		}
		raw, e := queryJSON(q)
		if e != nil {
			return e
		}
		actor, e := queryJSON(q.Scope.Principal)
		if e != nil {
			return e
		}
		incarnation, e := tx.ReadContextDatabaseIncarnation(ctx, id(q.Plan.InstallationID))
		if e != nil {
			return e
		}
		row, e := tx.InsertContextQuery(ctx, custodydb.InsertContextQueryParams{ID: id(q.ID), RootID: id(s.root), AllocationID: id(q.Plan.AllocationID), AccountID: id(q.Plan.AccountID), PrincipalKey: principalKey(q.Scope.Principal), Actor: actor, Query: raw, InitialRequest: initialRequest, OperationID: id(q.OperationID), WorkerID: id(q.WorkerID), CreatedAt: ts(q.CreatedAt), Deadline: ts(q.Deadline), CleanupUntil: ts(q.CleanupUntil), RetireBy: ts(q.Plan.RetireBy), IssuerEpoch: id(q.RecoveryIssuerEpoch), PostmasterAt: incarnation.PostmasterAt, DatabaseOid: incarnation.DatabaseOid})
		if e != nil {
			return e
		}
		out.Query, e = queryFromRow(row)
		if e != nil {
			return e
		}
		out.Fresh = true
		return s.call(ctx, tx, q, r, false)
	})
	if e != nil {
		return app.ContextQueryAdmission{}, queryRefusal("admission", e)
	}
	return out, nil
}
func (s *ContextQueries) call(ctx context.Context, tx *custodydb.Queries, q value.ContextQuery, r value.ContextQueryRequest, poll bool) error {
	row, e := tx.ReadContextQueryCall(ctx, custodydb.ReadContextQueryCallParams{OperationID: id(r.Call.ID), QueryID: id(q.ID)})
	if e == nil {
		var old value.ContextQueryRequest
		if queryDecode(row.Request, 8192, &old) != nil || !sameAuditJSON(old, r) || row.IsPoll != poll {
			return value.ErrUnavailable
		}
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	raw, e := queryJSON(r)
	if e != nil {
		return e
	}
	return tx.InsertContextQueryCall(ctx, custodydb.InsertContextQueryCallParams{OperationID: id(r.Call.ID), QueryID: id(q.ID), Request: raw, IsPoll: poll})
}
func (s *ContextQueries) LookupQuery(ctx context.Context, p identity.Principal, key string) (value.ContextQuery, error) {
	if s == nil || s.ledger == nil || ctx == nil || ctx.Err() != nil || !p.Valid() || !authorization.UUID(key) {
		return value.ContextQuery{}, value.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	actor, e := queryJSON(p)
	if e != nil {
		return value.ContextQuery{}, value.ErrUnavailable
	}
	row, e := custodydb.New(s.ledger.pool).ReadContextQuery(ctx, custodydb.ReadContextQueryParams{ID: id(key), RootID: id(s.root), Actor: actor})
	if e != nil || ctx.Err() != nil {
		return value.ContextQuery{}, value.ErrUnavailable
	}
	return queryFromRow(row)
}
func queryExact(ctx context.Context, tx *custodydb.Queries, q value.ContextQuery) (custodydb.ContextQuery, error) {
	row, e := tx.LockContextQuery(ctx, custodydb.LockContextQueryParams{ID: id(q.ID), RootID: id(q.Scope.RootID)})
	if e != nil {
		return row, e
	}
	stored, e := queryFromRow(row)
	if e != nil || !stored.Equal(q) {
		return row, value.ErrUnavailable
	}
	return row, nil
}
func (s *ContextQueries) AdmitQueryPoll(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	if r.Call.Tool != "get_query_result" || r.Call.ID == q.OperationID {
		return value.ErrUnavailable
	}
	return s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
		row, e := queryExact(ctx, tx, q)
		if e != nil || row.Uncertain {
			return value.ErrUnavailable
		}
		return s.call(ctx, tx, q, r, true)
	})
}
func (s *ContextQueries) PermitQuery(ctx context.Context, q value.ContextQuery, r value.ContextQueryRequest, a value.ContextProjectionAuthority) error {
	return s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
		row, e := queryExact(ctx, tx, q)
		if e != nil || row.Uncertain {
			return value.ErrUnavailable
		}
		call, e := tx.ReadContextQueryCall(ctx, custodydb.ReadContextQueryCallParams{OperationID: id(r.Call.ID), QueryID: id(q.ID)})
		var old value.ContextQueryRequest
		if e != nil || queryDecode(call.Request, 8192, &old) != nil || !sameAuditJSON(old, r) {
			return value.ErrUnavailable
		}
		return nil
	})
}

// queryStepError names the refusing admission/poll check for the operator
// report. It always unwraps to value.ErrUnavailable, so no caller decision
// changes; the dependency error is kept only for its own step name.
type queryStepError struct {
	step  string
	cause error
}

func (e *queryStepError) Error() string { return value.ErrUnavailable.Error() }
func (e *queryStepError) Unwrap() error { return value.ErrUnavailable }
func (e *queryStepError) FixedStep() string {
	var inner interface{ FixedStep() string }
	if e.cause != nil && errors.As(e.cause, &inner) {
		return e.step + "/" + inner.FixedStep()
	}
	return e.step
}

func queryRefusal(step string, cause error) error {
	return &queryStepError{step: step, cause: cause}
}
