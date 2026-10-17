package audit

import (
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
)

type WorkerEnrollmentWriter interface {
	WriteWorkerEnrollment(context.Context, value.WorkerEnrollment) (audit.Receipt, error)
	WriteWorkerCertificate(context.Context, audit.WorkerCertificate) (audit.Receipt, error)
}
type WorkerEnrollmentAcknowledgements interface {
	AcknowledgeWorkerEnrollment(context.Context, value.WorkerEnrollment, audit.Receipt) error
	ReadWorkerCertificateReceipt(context.Context, audit.WorkerCertificate) (audit.Receipt, bool, error)
	AcknowledgeWorkerCertificate(context.Context, audit.WorkerCertificate, audit.Receipt) error
}
