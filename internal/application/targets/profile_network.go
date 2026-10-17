package targets

import (
	"context"

	value "asservat.local/asservat/internal/domain/targets"
)

// ProfileNetworkReader observes the exact selected Pod; it does not choose a
// workload, connect to an endpoint or grant collection/credential authority.
type ProfileNetworkReader interface {
	ObserveProfileNetwork(context.Context, value.Request) (value.ProfileNetwork, error)
}
