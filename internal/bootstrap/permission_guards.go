package bootstrap

import (
	"context"

	cfg "asservat.local/asservat/internal/domain/configuration"
)

// sharedNamespaceGuards answers the permission reconciler's remote metadata
// reads. Joined clusters deliver no namespace or workload observation, so
// their metadata sources stay unavailable.
type sharedNamespaceGuards struct{}

// RemoteNamespaces implements configapp.RemoteNamespaceReader.
func (sharedNamespaceGuards) RemoteNamespaces(context.Context, string, cfg.NamespaceKeys) (cfg.NamespaceList, error) {
	return cfg.NamespaceList{}, cfg.ErrUnavailable
}

// RemoteWorkloads implements configapp.RemoteWorkloadReader.
func (sharedNamespaceGuards) RemoteWorkloads(context.Context, string, cfg.WorkloadSelection) (cfg.WorkloadList, error) {
	return cfg.WorkloadList{}, cfg.ErrUnavailable
}
