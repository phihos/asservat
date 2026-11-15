package integration

import (
	"context"

	auditvalue "asservat.local/asservat/internal/domain/audit"
)

// discardAuditRows lets fixtures that predate the audit_event call row compile
// against presentation.NewAuditedOperations. It records nothing.
type discardAuditRows struct{}

func (discardAuditRows) Record(context.Context, auditvalue.Event) error { return nil }
