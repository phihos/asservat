package kubernetes

import (
	"fmt"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// ErrInitialPreparationPolicyPending reports only an exact original policy
// waiting for API type checking. It permits bounded read-only observation, never
// another CREATE or replacement. Warnings and changed generation are not pending.
var ErrInitialPreparationPolicyPending = fmt.Errorf("%w: original policy compilation pending", cfg.ErrUnavailable)
