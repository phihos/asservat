package configuration

import (
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
)

// These read facets expose accepted configuration, not observed Kubernetes
// lists or self-declared status. Configuration bootstrap/restore owns authority.
type RetentionTopologyReader interface {
	RetentionTopology(context.Context, string) (value.PolicyTopology, error)
}
type RetentionSourceReader interface {
	AcceptedRetentionSource(context.Context, string, value.PolicySourceRef) (value.AcceptedSource, error)
}
