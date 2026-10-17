package audit

import (
	value "asservat.local/asservat/internal/domain/audit"
	"context"
)

type ContextVerificationWriter interface {
	WriteContextVerification(context.Context, value.ContextVerification) (value.Receipt, error)
}
