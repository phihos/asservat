package audit

import (
	"asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

type ProjectionWorkerWriter interface {
	WriteProjectionWorkerIntent(context.Context, analysis.ContextProjectionWorkerIntent) (audit.Receipt, error)
}
type AcquisitionEnrollmentWriter interface {
	WriteAcquisitionEnrollment(context.Context, value.AcquisitionEnrollment) (audit.Receipt, error)
	WriteAcquisitionCertificate(context.Context, audit.AcquisitionCertificate) (audit.Receipt, error)
}
