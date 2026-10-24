package bootstrap

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// These existing audit purposes use the same finite material observation as
// C08, retaining their own formats, pre-paid claims, key calls and completion
// producers. They never borrow another purpose's SQL or disclosure authority.
var _ auditapp.BootstrapIssueWriter = (*installedOperationAudit)(nil)
var _ auditapp.DownloadWorkerWriter = (*installedOperationAudit)(nil)
var _ auditapp.WorkerEnrollmentWriter = (*installedOperationAudit)(nil)
var _ auditapp.DownloadWriter = (*installedOperationAudit)(nil)
var _ auditapp.DownloadWindowObjects = (*installedOperationAudit)(nil)
var _ evidence.DownloadStopObjects = (*installedOperationAudit)(nil)
var _ evidence.ClosedDownloadStopObjects = (*installedOperationAudit)(nil)

func (s *installedOperationAudit) WriteBootstrapIssue(ctx context.Context, r audit.BootstrapIssue) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.BootstrapIssueObjects{Store: store, Seal: s.seal, Open: s.open}).WriteBootstrapIssue(call, r)
	})
}
func (s *installedOperationAudit) WriteDownloadWorkerIntent(ctx context.Context, r authorization.DownloadWorkerIntent) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.DownloadWorkerAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteDownloadWorkerIntent(call, r)
	})
}
func (s *installedOperationAudit) WriteWorkerEnrollment(ctx context.Context, r authorization.WorkerEnrollment) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.WorkerEnrollmentAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteWorkerEnrollment(call, r)
	})
}
func (s *installedOperationAudit) WriteWorkerCertificate(ctx context.Context, r audit.WorkerCertificate) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.WorkerEnrollmentAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteWorkerCertificate(call, r)
	})
}
func (s *installedOperationAudit) WriteDownloadIntent(ctx context.Context, r audit.DownloadIntent) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.DownloadAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteDownloadIntent(call, r)
	})
}
func (s *installedOperationAudit) WriteDownloadOutcome(ctx context.Context, r audit.DownloadOutcome) (audit.Receipt, error) {
	if !r.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.DownloadAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteDownloadOutcome(call, r)
	})
}
func (s *installedOperationAudit) stop(ctx context.Context, r artifact.DownloadStopDecision, create bool) (audit.Receipt, error) {
	if s == nil || !r.Valid() || r.StoreID != s.storeID {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	until := r.RetainUntil
	if create {
		until = r.WriteUntil
	}
	return withInstalledAudit(ctx, s, until, func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		writer := &objectstore.DownloadStopObjects{Store: store, Seal: s.seal, Open: s.open, StoreID: s.storeID}
		if create {
			return writer.CreateDownloadStop(call, r)
		}
		return writer.FindDownloadStop(call, r)
	})
}
func (s *installedOperationAudit) CreateDownloadStop(ctx context.Context, r artifact.DownloadStopDecision) (audit.Receipt, error) {
	return s.stop(ctx, r, true)
}
func (s *installedOperationAudit) FindDownloadStop(ctx context.Context, r artifact.DownloadStopDecision) (audit.Receipt, error) {
	return s.stop(ctx, r, false)
}
func (s *installedOperationAudit) CreateClosedDownloadStop(ctx context.Context, b audit.DownloadStopLifecycleBinding, r artifact.DownloadStopDecision) (audit.DownloadStopWriteCompletion, error) {
	if s == nil || !r.Valid() || r.StoreID != s.storeID || !b.Valid() {
		return audit.DownloadStopWriteCompletion{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, r.WriteUntil, func(call context.Context, store *objectstore.Store) (audit.DownloadStopWriteCompletion, error) {
		writer, e := objectstore.NewClosedDownloadStopObjects(store, s.storeID, s.seal, s.open)
		if e != nil {
			return audit.DownloadStopWriteCompletion{}, e
		}
		return writer.CreateClosedDownloadStop(call, b, r)
	})
}
func (s *installedOperationAudit) window(ctx context.Context, i audit.DownloadWindowIntent, o *audit.DownloadWindowAuditOutcome, create bool) (audit.DownloadWindowWriteResult, error) {
	if s == nil || !i.Valid() || i.Window.AuditStoreID != s.storeID || o != nil && (!o.Valid() || o.Intent != i) {
		return audit.DownloadWindowWriteResult{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, i.Window.WriteUntil, func(call context.Context, store *objectstore.Store) (audit.DownloadWindowWriteResult, error) {
		writer, e := objectstore.NewDownloadWindowAuditObjects(store, s.storeID, s.seal, s.open)
		if e != nil {
			return audit.DownloadWindowWriteResult{}, e
		}
		if create {
			if o == nil {
				return writer.CreateDownloadWindowIntent(call, i)
			}
			return writer.CreateDownloadWindowOutcome(call, *o)
		}
		var receipt audit.Receipt
		if o == nil {
			receipt, e = writer.FindDownloadWindowIntent(call, i)
		} else {
			receipt, e = writer.FindDownloadWindowOutcome(call, *o)
		}
		return audit.DownloadWindowWriteResult{Receipt: receipt}, e
	})
}
func (s *installedOperationAudit) CreateDownloadWindowIntent(ctx context.Context, i audit.DownloadWindowIntent) (audit.DownloadWindowWriteResult, error) {
	return s.window(ctx, i, nil, true)
}
func (s *installedOperationAudit) CreateDownloadWindowOutcome(ctx context.Context, o audit.DownloadWindowAuditOutcome) (audit.DownloadWindowWriteResult, error) {
	return s.window(ctx, o.Intent, &o, true)
}
func (s *installedOperationAudit) FindDownloadWindowIntent(ctx context.Context, i audit.DownloadWindowIntent) (audit.Receipt, error) {
	r, e := s.window(ctx, i, nil, false)
	return r.Receipt, e
}
func (s *installedOperationAudit) FindDownloadWindowOutcome(ctx context.Context, o audit.DownloadWindowAuditOutcome) (audit.Receipt, error) {
	r, e := s.window(ctx, o.Intent, &o, false)
	return r.Receipt, e
}

func (a publicAuditStore) storageConfigured() bool { return a.store != nil || a.operation != nil }
func (a publicAuditStore) bootstrapObjects() auditapp.BootstrapIssueWriter {
	if a.operation != nil {
		return a.operation
	}
	return &objectstore.BootstrapIssueObjects{Store: a.store, Seal: a.seal, Open: a.open}
}
func (a publicAuditStore) workerObjects() auditapp.DownloadWorkerWriter {
	if a.operation != nil {
		return a.operation
	}
	return &objectstore.DownloadWorkerAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}
}
func (a publicAuditStore) enrollmentObjects() auditapp.WorkerEnrollmentWriter {
	if a.operation != nil {
		return a.operation
	}
	return &objectstore.WorkerEnrollmentAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}
}
func (a publicAuditStore) downloadObjects() auditapp.DownloadWriter {
	if a.operation != nil {
		return a.operation
	}
	return &objectstore.DownloadAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}
}
func (a publicAuditStore) stopObjects(id string) (evidence.DownloadStopObjects, evidence.ClosedDownloadStopObjects, error) {
	if !authorization.UUID(id) {
		return nil, nil, mounts.ErrUnavailable
	}
	if a.operation != nil {
		s := *a.operation
		s.storeID = id
		return &s, &s, nil
	}
	closed, e := objectstore.NewClosedDownloadStopObjects(a.store, id, a.seal, a.open)
	if e != nil {
		return nil, nil, e
	}
	return &objectstore.DownloadStopObjects{Store: a.store, Seal: a.seal, Open: a.open, StoreID: id}, closed, nil
}
func (a publicAuditStore) windowObjects(id string) (auditapp.DownloadWindowObjects, error) {
	if !authorization.UUID(id) {
		return nil, mounts.ErrUnavailable
	}
	if a.operation != nil {
		s := *a.operation
		s.storeID = id
		return &s, nil
	}
	return objectstore.NewDownloadWindowAuditObjects(a.store, id, a.seal, a.open)
}
