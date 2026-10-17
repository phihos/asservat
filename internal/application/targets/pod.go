package targets

import (
	value "asservat.local/asservat/internal/domain/targets"
	"context"
)

// PodResolver observes an exact pod/owner/node incarnation. Its output cannot
// grant authority, supply a new selector or silently adopt a replacement pod.
type PodResolver interface {
	ResolvePod(context.Context, value.Request) (value.PodResolution, error)
}
