package integration

import (
	"context"
	"sync/atomic"

	"asservat.local/asservat/internal/contracts"
)

// This matrix qualifies actual SQL roles and locked replay. Kubernetes
// enforcement and the launched-object receipt are explicitly synthetic here;
// the separate native API matrix exercises the concrete protected root.
type configurationLaunchedSQLRoot struct {
	*configurationRoleSQLRoot
	reads atomic.Int32
}

func (r *configurationLaunchedSQLRoot) ReadLaunchedConfigurationRuntimeRoles(ctx context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	r.reads.Add(1)
	return r.ReadConfigurationRuntimeRoles(ctx)
}
