// Package capture owns capture admission and progress, not protocol handlers.
package capture

import (
	"context"

	value "asservat.local/asservat/internal/domain/capture"
)

// AdmissionTransaction atomically rechecks current permission state, accepted
// allocation ownership and capacity, creates the immutable capture, and registers
// every initial object obligation. It performs no acquisition or remote I/O.
type AdmissionTransaction interface {
	AdmitContext(context.Context, value.Admission) (value.Accepted, error)
}
