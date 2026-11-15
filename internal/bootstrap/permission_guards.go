package bootstrap

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// NamespaceGuardProfile is the guardRef of an admissionEnforced
// PermissionSource that names a cluster's protected namespace guard
// (ADR-247): the installation's capacity namespace guard of that cluster,
// whose administrators alone may set or change its label keys.
const NamespaceGuardProfile = "namespace-guard"

// sharedNamespaceGuards answers the permission reconciler's namespace
// guard proof for the hub cluster: the evidence opt-out key, which only
// administrators set in the admin-only release namespace (ADR-328). Joined
// clusters have no remote namespace or workload observation, so their
// admissionEnforced sources stay unavailable.
type sharedNamespaceGuards struct {
	mu      sync.Mutex
	cluster string
}

func (s *sharedNamespaceGuards) share(cluster string) func() {
	s.mu.Lock()
	s.cluster = cluster
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.cluster = ""
		s.mu.Unlock()
	}
}

// NamespaceGuard implements configapp.NamespaceGuardReader.
func (s *sharedNamespaceGuards) NamespaceGuard(_ context.Context, cluster string) (cfg.NamespaceGuardProof, error) {
	s.mu.Lock()
	current := s.cluster
	s.mu.Unlock()
	if current == "" || current != cluster {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	now := time.Now()
	return cfg.NamespaceGuardProof{ClusterID: cluster, Name: NamespaceGuardProfile, LabelKeys: contracts.CapacityNamespaceKeys(), ObservedAt: now, FreshUntil: identity.Check(now, identity.SQLFenced).Until()}, nil
}

// identityDirectory served groupID sources from the removed eligibleGroups
// list. Identity settings name no group directory any more (ADR-335 D14), so
// groupID mapping reports DirectoryUnavailable; groupName mapping needs none.
type identityDirectory struct {
	settings interface {
		IdentityPolicy(context.Context, string) (identity.Policy, error)
	}
}

func (d identityDirectory) GroupDirectory(context.Context, string) (cfg.GroupDirectory, error) {
	return cfg.GroupDirectory{}, cfg.ErrUnavailable
}

// RemoteNamespaces implements configapp.RemoteNamespaceReader; joined
// clusters deliver no namespace observation.
func (s *sharedNamespaceGuards) RemoteNamespaces(context.Context, string, cfg.NamespaceKeys) (cfg.NamespaceList, error) {
	return cfg.NamespaceList{}, cfg.ErrUnavailable
}

// RemoteWorkloads implements configapp.RemoteWorkloadReader.
func (s *sharedNamespaceGuards) RemoteWorkloads(context.Context, string, cfg.WorkloadSelection) (cfg.WorkloadList, error) {
	return cfg.WorkloadList{}, cfg.ErrUnavailable
}

// WorkloadGuard implements configapp.WorkloadGuardReader.
func (s *sharedNamespaceGuards) WorkloadGuard(context.Context, string) (cfg.NamespaceGuardProof, error) {
	return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
}
