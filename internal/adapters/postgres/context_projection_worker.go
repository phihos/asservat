package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

// Query authority stays typed and independent of DownloadAuthority. The table,
// signing lifecycle, physical limits and exact Job identities are shared.
type ProjectionWorkers struct {
	queries *ContextQueries
	profile value.DownloadWorkerProfile
}

var _ evidence.ProjectionWorkerLedger = (*ProjectionWorkers)(nil)

func NewProjectionWorkers(queries *ContextQueries, profile value.DownloadWorkerProfile) (*ProjectionWorkers, error) {
	if queries == nil || queries.ledger == nil || !profile.Valid() || queries.recovery.installation != profile.InstallationID {
		return nil, query.ErrUnavailable
	}
	return &ProjectionWorkers{queries, profile}, nil
}
func (s *ProjectionWorkers) current(ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, a query.ContextProjectionAuthority, f func(context.Context, *custodydb.Queries) error) error {
	if s == nil || s.queries == nil || q.Plan.InstallationID != s.profile.InstallationID || a.Environment.Path.AcquisitionClusterID != s.profile.ClusterID || a.Environment.Path.WorkerConfiguration != s.profile.Configuration {
		return queryRefusal("worker-profile", nil)
	}
	return s.queries.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries, _ custodydb.ContextQueryBacking, _ custodydb.ContextQueryAllocation) error {
		row, e := queryExact(ctx, tx, q)
		if e != nil || row.Uncertain {
			return queryRefusal("worker-query", e)
		}
		call, e := tx.ReadContextQueryCall(ctx, custodydb.ReadContextQueryCallParams{OperationID: id(r.Call.ID), QueryID: id(q.ID)})
		var original query.ContextQueryRequest
		if e != nil || queryDecode(call.Request, 8192, &original) != nil || !sameAuditJSON(original, r) {
			return queryRefusal("worker-call", e)
		}
		if _, e = currentWorkerConfiguration(ctx, tx, s.profile, q.RecoveryIssuerEpoch); e != nil {
			return queryRefusal("worker-configuration", e)
		}
		if e = f(ctx, tx); e != nil {
			return queryRefusal("worker-effect", e)
		}
		if _, e = currentWorkerConfiguration(ctx, tx, s.profile, q.RecoveryIssuerEpoch); e != nil {
			return queryRefusal("worker-configuration-after", e)
		}
		return nil
	})
}
func projectionWorkerState(row custodydb.DownloadWorker, q query.ContextQuery) (evidence.ProjectionWorkerState, error) {
	var out evidence.ProjectionWorkerState
	if queryDecode(row.IntentJson, 65536, &out.Intent) != nil || !out.Intent.Valid() || !out.Intent.Query.Equal(q) ||
		uid(row.QueryID) != q.ID || row.SessionID.Valid || row.AllocationID.Valid || uid(row.QueryAllocationID) != q.Plan.AllocationID ||
		uid(row.ID) != q.WorkerID || uid(row.RootID) != q.Scope.RootID || uid(row.InstallationID) != q.Plan.InstallationID || row.Generation != 1 ||
		!row.RunUntil.Time.Equal(out.Intent.Worker.RunUntil) || !bytes.Equal(row.PrincipalKey, principalKey(q.Scope.Principal)) {
		return out, query.ErrUnavailable
	}
	out.Claimed = row.ClaimedAt.Valid
	if row.AuditReceiptJson != nil {
		if queryDecode(row.AuditReceiptJson, 8192, &out.Receipt) != nil || !out.Receipt.ValidProjectionWorker(out.Intent) {
			return out, query.ErrUnavailable
		}
		out.Audited = true
	}
	if row.JobJson != nil {
		if !out.Claimed || queryDecode(row.JobJson, 8192, &out.Job) != nil || !out.Job.ValidAcquisition(out.Intent.Worker) {
			return out, query.ErrUnavailable
		}
	}
	if row.BindingJson != nil {
		out.Worker.Intent, out.Worker.Job = out.Intent.Worker, out.Job
		if queryDecode(row.BindingJson, 16384, &out.Worker.Binding) != nil || !out.Worker.Valid() {
			return out, query.ErrUnavailable
		}
	}
	if out.Claimed && !out.Audited {
		return out, query.ErrUnavailable
	}
	return out, nil
}
func (s *ProjectionWorkers) ReserveProjectionWorker(ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, a query.ContextProjectionAuthority) (evidence.ProjectionWorkerState, error) {
	var out evidence.ProjectionWorkerState
	if r.Call.ID != q.OperationID || r.Call.Tool != "get_file_excerpt" {
		return out, query.ErrUnavailable
	}
	err := s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.ReadQueryAcquisitionWorker(ctx, custodydb.ReadQueryAcquisitionWorkerParams{QueryID: id(q.ID), RootID: id(q.Scope.RootID)})
		if e == nil {
			out, e = projectionWorkerState(row, q)
			return e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		counts, e := tx.AcquisitionWorkerCapacity(ctx, custodydb.AcquisitionWorkerCapacityParams{InstallationID: id(q.Plan.InstallationID), ClusterID: id(q.Scope.ClusterID), NamespaceUid: q.Scope.NamespaceUID, WorkloadUid: q.Scope.WorkloadUID, PrincipalKey: principalKey(q.Scope.Principal)})
		if e != nil || counts.Total >= 16 || counts.Workload >= 2 || counts.Principal >= 2 {
			return query.ErrUnavailable
		}
		i := query.ContextProjectionWorkerIntent{Query: q, Worker: value.AcquisitionWorkerIntent{ID: q.WorkerID, Parent: value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: q.ID}, Profile: s.profile, CreatedAt: q.CreatedAt, RunUntil: q.WorkerUntil}}
		if !i.Valid() {
			return query.ErrUnavailable
		}
		raw, e := json.Marshal(i)
		if e != nil || len(raw) > 65536 {
			return query.ErrUnavailable
		}
		if e = tx.InsertQueryAcquisitionWorker(ctx, custodydb.InsertQueryAcquisitionWorkerParams{ID: id(q.WorkerID), QueryID: id(q.ID), RootID: id(q.Scope.RootID), InstallationID: id(q.Plan.InstallationID), QueryAllocationID: id(q.Plan.AllocationID), PrincipalKey: principalKey(q.Scope.Principal), IntentJson: raw, RunUntil: ts(q.WorkerUntil)}); e != nil {
			return e
		}
		out.Intent = i
		return nil
	})
	if err != nil {
		return evidence.ProjectionWorkerState{}, query.ErrUnavailable
	}
	return out, nil
}
func (s *ProjectionWorkers) ReadProjectionWorker(ctx context.Context, q query.ContextQuery, r query.ContextQueryRequest, a query.ContextProjectionAuthority) (evidence.ProjectionWorkerState, error) {
	var out evidence.ProjectionWorkerState
	e := s.current(ctx, q, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.ReadQueryAcquisitionWorker(ctx, custodydb.ReadQueryAcquisitionWorkerParams{QueryID: id(q.ID), RootID: id(q.Scope.RootID)})
		if e != nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return query.ErrUnavailable
		}
		out, e = projectionWorkerState(row, q)
		return e
	})
	if e != nil {
		return evidence.ProjectionWorkerState{}, query.ErrUnavailable
	}
	return out, nil
}
func (s *ProjectionWorkers) ClaimProjectionWorker(ctx context.Context, i query.ContextProjectionWorkerIntent, r query.ContextQueryRequest, a query.ContextProjectionAuthority, receipt audit.Receipt) (value.AcquisitionWorkerLaunch, error) {
	var out value.AcquisitionWorkerLaunch
	if !i.Valid() || !receipt.ValidProjectionWorker(i) || r.Call.ID != i.Query.OperationID || r.Call.Tool != "get_file_excerpt" {
		return out, query.ErrUnavailable
	}
	e := s.current(ctx, i.Query, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.Worker.ID), RootID: id(i.Query.Scope.RootID)})
		if e != nil || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return queryRefusal("claim-lock", e)
		}
		old, e := projectionWorkerState(row, i.Query)
		if e != nil {
			return queryRefusal("claim-state", e)
		}
		if !sameAuditJSON(old.Intent, i) {
			return queryRefusal("claim-intent", nil)
		}
		raw, _ := json.Marshal(receipt)
		if old.Audited {
			if !bytes.Equal(raw, row.AuditReceiptJson) {
				return queryRefusal("claim-receipt", nil)
			}
		} else {
			n, e := tx.AuditDownloadWorker(ctx, custodydb.AuditDownloadWorkerParams{ID: row.ID, RootID: row.RootID, AuditReceiptJson: raw})
			if e != nil || n != 1 {
				return queryRefusal("claim-audit", e)
			}
		}
		now, e := tx.CurrentTime(ctx)
		if e != nil {
			return e
		}
		out = value.AcquisitionWorkerLaunch{Intent: i.Worker, CheckedAt: now.Time.UTC(), Until: identity.Earlier(i.Query.Deadline, identity.Earlier(a.ValidUntil, r.Call.Until)), MayCreate: !old.Claimed}
		if !out.Valid(now.Time) {
			return queryRefusal("claim-launch", nil)
		}
		if out.MayCreate {
			if out.Until.Sub(now.Time) < time.Second {
				return queryRefusal("claim-time", nil)
			}
			n, e := tx.ClaimDownloadWorker(ctx, custodydb.ClaimDownloadWorkerParams{ID: row.ID, RootID: row.RootID})
			if e != nil || n != 1 {
				return queryRefusal("claim-row", e)
			}
		}
		return nil
	})
	if e != nil {
		return value.AcquisitionWorkerLaunch{}, queryRefusal("claim", e)
	}
	return out, nil
}
func (s *ProjectionWorkers) RecordProjectionWorkerJob(ctx context.Context, i query.ContextProjectionWorkerIntent, job value.DownloadWorkerJob, r query.ContextQueryRequest, a query.ContextProjectionAuthority) error {
	if !i.Valid() || !job.ValidAcquisition(i.Worker) {
		return query.ErrUnavailable
	}
	return s.current(ctx, i.Query, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.Worker.ID), RootID: id(i.Query.Scope.RootID)})
		if e != nil {
			return e
		}
		old, e := projectionWorkerState(row, i.Query)
		if e != nil || !sameAuditJSON(old.Intent, i) || !old.Claimed || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return query.ErrUnavailable
		}
		raw, _ := json.Marshal(job)
		if row.JobJson != nil {
			if !bytes.Equal(raw, row.JobJson) {
				return query.ErrUnavailable
			}
			return nil
		}
		n, e := tx.RecordDownloadWorkerJob(ctx, custodydb.RecordDownloadWorkerJobParams{ID: row.ID, RootID: row.RootID, JobJson: raw})
		if e != nil || n != 1 {
			return query.ErrUnavailable
		}
		return nil
	})
}
func (s *ProjectionWorkers) BindProjectionWorker(ctx context.Context, i query.ContextProjectionWorkerIntent, worker value.AcquisitionWorker, r query.ContextQueryRequest, a query.ContextProjectionAuthority) error {
	if !i.Valid() || !worker.Valid() || worker.Intent != i.Worker {
		return query.ErrUnavailable
	}
	return s.current(ctx, i.Query, r, a, func(ctx context.Context, tx *custodydb.Queries) error {
		row, e := tx.LockDownloadWorker(ctx, custodydb.LockDownloadWorkerParams{ID: id(i.Worker.ID), RootID: id(i.Query.Scope.RootID)})
		if e != nil {
			return e
		}
		old, e := projectionWorkerState(row, i.Query)
		if e != nil || !sameAuditJSON(old.Intent, i) || old.Job != worker.Job || row.TerminationJson != nil || row.RetiredProofJson != nil {
			return query.ErrUnavailable
		}
		raw, _ := json.Marshal(worker.Binding)
		if row.BindingJson != nil {
			if !bytes.Equal(raw, row.BindingJson) {
				return query.ErrUnavailable
			}
			return nil
		}
		n, e := tx.BindDownloadWorker(ctx, custodydb.BindDownloadWorkerParams{ID: row.ID, RootID: row.RootID, BindingJson: raw})
		if e != nil || n != 1 {
			return query.ErrUnavailable
		}
		return nil
	})
}

// AttachProjectionWorkers closes the installed composition over this exact
// query ledger. It is a startup-only constructor; it cannot replace a guard on
// a running ledger or accept a caller-provided peer identity.
func AttachProjectionWorkers(q *ContextQueries, profile value.DownloadWorkerProfile) (*ProjectionWorkers, error) {
	if q == nil || q.workers != nil {
		return nil, query.ErrUnavailable
	}
	w, e := NewProjectionWorkers(q, profile)
	if e != nil {
		return nil, e
	}
	q.workers = projectionIdentityGuard{workers: w}
	return w, nil
}
