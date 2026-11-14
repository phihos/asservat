package kubernetes

import (
	"context"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// SQL locks and the three precompleted SQL roles are explicitly synthetic, as
// in the existing owner operation fixture. The concrete worker Advance driver,
// eight-GET SetupReader, native/bridge/current/final reads and receipt CAS run.
type workerInputFinalStatusVerifier struct {
	t         *testing.T
	change    func()
	calls     int
	operation *ConfigurationWorkerOperation
	requests  *atomic.Int64
}

func (s *workerInputFinalStatusVerifier) VerifyConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	return contracts.ConfigurationRuntimeRoleSnapshot{}, cfg.ErrUnavailable
}
func (s *workerInputFinalStatusVerifier) VerifyLaunchedConfigurationRuntimeRoles(context.Context) (contracts.ConfigurationRuntimeRoleSnapshot, error) {
	return contracts.ConfigurationRuntimeRoleSnapshot{}, cfg.ErrUnavailable
}
