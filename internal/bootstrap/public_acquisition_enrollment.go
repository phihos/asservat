package bootstrap

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
)

// Reuse the existing identity write/audit/activation credential boundaries.
// These are the same three pools already held by this process for downloads.
type projectionEnrollmentEffects struct {
	*postgres.ProjectionEnrollments
	acknowledgements, activation *postgres.ProjectionEnrollments
}

func (s projectionEnrollmentEffects) AcknowledgeAcquisitionEnrollment(ctx context.Context, e value.AcquisitionEnrollment, r audit.Receipt) error {
	return s.acknowledgements.AcknowledgeAcquisitionEnrollment(ctx, e, r)
}
func (s projectionEnrollmentEffects) ReadAcquisitionCertificateReceipt(ctx context.Context, c audit.AcquisitionCertificate) (audit.Receipt, bool, error) {
	return s.acknowledgements.ReadAcquisitionCertificateReceipt(ctx, c)
}
func (s projectionEnrollmentEffects) AcknowledgeAcquisitionCertificate(ctx context.Context, c audit.AcquisitionCertificate, r audit.Receipt) error {
	return s.acknowledgements.AcknowledgeAcquisitionCertificate(ctx, c, r)
}
func (s projectionEnrollmentEffects) ActivateAcquisitionCertificate(ctx context.Context, p value.AcquisitionWorkerProof, a value.AcquisitionCertificateAttempt) (value.WorkerCertificate, error) {
	return s.activation.ActivateAcquisitionCertificate(ctx, p, a)
}

func (a publicAuditStore) acquisitionObjects() auditapp.AcquisitionEnrollmentWriter {
	if a.operation != nil {
		return a.operation
	}
	return &objectstore.WorkerEnrollmentAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}
}
func (a publicAuditStore) projectionWorkerObjects() auditapp.ProjectionWorkerWriter {
	if a.operation != nil {
		return a.operation
	}
	return &objectstore.WorkerEnrollmentAuditObjects{Store: a.store, Seal: a.seal, Open: a.open}
}
func (s *installedOperationAudit) WriteProjectionWorkerIntent(ctx context.Context, i analysis.ContextProjectionWorkerIntent) (audit.Receipt, error) {
	if !i.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.WorkerEnrollmentAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteProjectionWorkerIntent(call, i)
	})
}
func (s *installedOperationAudit) WriteAcquisitionEnrollment(ctx context.Context, e value.AcquisitionEnrollment) (audit.Receipt, error) {
	if !e.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.WorkerEnrollmentAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteAcquisitionEnrollment(call, e)
	})
}
func (s *installedOperationAudit) WriteAcquisitionCertificate(ctx context.Context, c audit.AcquisitionCertificate) (audit.Receipt, error) {
	if !c.Valid() {
		return audit.Receipt{}, mounts.ErrUnavailable
	}
	return withInstalledAudit(ctx, s, time.Now().Add(5*time.Second), func(call context.Context, store *objectstore.Store) (audit.Receipt, error) {
		return (&objectstore.WorkerEnrollmentAuditObjects{Store: store, Seal: s.seal, Open: s.open}).WriteAcquisitionCertificate(call, c)
	})
}
