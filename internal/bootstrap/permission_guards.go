package bootstrap

import (
	"context"
	"slices"
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

// identityDirectory is the configured group directory of groupID sources
// (ADR-247): the protected identity settings' eligibleGroups for their
// issuer, read through the existing pinned identity settings reader. It is
// not a directory reader and knows no group members.
type identityDirectory struct {
	settings interface {
		IdentityPolicy(context.Context, string) (identity.Policy, error)
	}
}

func (d identityDirectory) GroupDirectory(ctx context.Context, issuer string) (cfg.GroupDirectory, error) {
	p, err := d.settings.IdentityPolicy(ctx, issuer)
	if err != nil || p.Issuer != issuer {
		return cfg.GroupDirectory{}, cfg.ErrUnavailable
	}
	return cfg.GroupDirectory{Issuer: issuer, Groups: slices.Clone(p.EligibleGroups), ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}, nil
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
