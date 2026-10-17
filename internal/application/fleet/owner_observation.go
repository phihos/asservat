package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// The concrete local Kubernetes reader checks the installed immutable template,
// actual current Pod/controller/account chain and independent guard. It neither
// obtains a remote token nor changes SQL or Kubernetes state.
type OwnerObservationWorkloadReader interface {
	ObserveOwnerWorkload(context.Context, value.OwnerBinding, string) (value.OwnerObservationWorkload, error)
}
