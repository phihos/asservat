package audit

import (
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

type OwnerEnrollmentWriter interface {
	WriteOwnerEnrollment(context.Context, value.OwnerEnrollment) (audit.Receipt, error)
	WriteOwnerCertificate(context.Context, audit.OwnerCertificate) (audit.Receipt, error)
}
type OwnerEnrollmentAcknowledgements interface {
	AcknowledgeOwnerEnrollment(context.Context, value.OwnerEnrollment, audit.Receipt) error
	ReadOwnerCertificateReceipt(context.Context, audit.OwnerCertificate) (audit.Receipt, bool, error)
	AcknowledgeOwnerCertificate(context.Context, audit.OwnerCertificate, audit.Receipt) error
}
