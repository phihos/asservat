package bootstrap

import (
	"context"
	"slices"
	"sync"

	capacityapp "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// NamespaceGuardProfile is the guardRef of an admissionEnforced
// PermissionSource that names a cluster's protected namespace guard
// (ADR-247): the installation's capacity namespace guard of that cluster,
// whose administrators alone may set or change its label keys.
const NamespaceGuardProfile = "namespace-guard"

// sharedNamespaceGuards lends the capacity child's per-cluster namespace
// guard readers (hub cluster and joined regional clusters) to the permission
// reconciler of the same hub-worker. While no capacity child runs there is no
// proof: admissionEnforced sources are then unavailable.
type sharedNamespaceGuards struct {
	mu         sync.Mutex
	readers    map[string]capacityapp.CapacityNamespaceProtectionReader
	namespaces map[string]permissionNamespaceObserver
}

// permissionNamespaceObserver is a joined cluster's namespace journal reader
// over the cluster-observation channel (ADR-247).
type permissionNamespaceObserver interface {
	ObservePermissionNamespaces(context.Context, cfg.NamespaceKeys) (cfg.NamespaceList, error)
	ObservePermissionWorkloads(context.Context, cfg.WorkloadSelection) (cfg.WorkloadList, error)
	ObservePermissionWorkloadGuard(context.Context) (cfg.NamespaceGuardProof, error)
}

// share publishes clusters' readers until the returned release is called.
func (s *sharedNamespaceGuards) share(clusters []capacityapp.CapacityClusterReaders) func() {
	m := map[string]capacityapp.CapacityNamespaceProtectionReader{}
	n := map[string]permissionNamespaceObserver{}
	for _, c := range clusters {
		if c.Guard != nil {
			m[c.ClusterID] = c.Guard
		}
		if o, ok := c.Guard.(permissionNamespaceObserver); ok {
			n[c.ClusterID] = o
		}
	}
	s.mu.Lock()
	s.readers, s.namespaces = m, n
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.readers, s.namespaces = nil, nil
		s.mu.Unlock()
	}
}

// NamespaceGuard implements configapp.NamespaceGuardReader with the
// cluster's current live dry-run proof, within its original interval.
func (s *sharedNamespaceGuards) NamespaceGuard(ctx context.Context, cluster string) (cfg.NamespaceGuardProof, error) {
	s.mu.Lock()
	reader := s.readers[cluster]
	s.mu.Unlock()
	if reader == nil {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	p, err := reader.CapacityNamespaceProtection(ctx)
	if err != nil || p.ClusterID != cluster {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	return cfg.NamespaceGuardProof{ClusterID: cluster, Name: NamespaceGuardProfile, LabelKeys: slices.Clone(p.Keys), ObservedAt: p.ObservedAt, FreshUntil: p.FreshUntil}, nil
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

// RemoteNamespaces implements configapp.RemoteNamespaceReader for a joined
// cluster: its connector's namespace journal over the cluster-observation
// channel (ADR-247).
func (s *sharedNamespaceGuards) RemoteNamespaces(ctx context.Context, cluster string, keys cfg.NamespaceKeys) (cfg.NamespaceList, error) {
	s.mu.Lock()
	o := s.namespaces[cluster]
	s.mu.Unlock()
	if o == nil {
		return cfg.NamespaceList{}, cfg.ErrUnavailable
	}
	l, err := o.ObservePermissionNamespaces(ctx, keys)
	if err != nil || l.ClusterID != cluster {
		return cfg.NamespaceList{}, cfg.ErrUnavailable
	}
	return l, nil
}

// RemoteWorkloads implements configapp.RemoteWorkloadReader: a cluster's
// connector workload journal (ADR-247), the hub cluster's included.
func (s *sharedNamespaceGuards) RemoteWorkloads(ctx context.Context, cluster string, sel cfg.WorkloadSelection) (cfg.WorkloadList, error) {
	s.mu.Lock()
	o := s.namespaces[cluster]
	s.mu.Unlock()
	if o == nil {
		return cfg.WorkloadList{}, cfg.ErrUnavailable
	}
	l, err := o.ObservePermissionWorkloads(ctx, sel)
	if err != nil || l.ClusterID != cluster {
		return cfg.WorkloadList{}, cfg.ErrUnavailable
	}
	return l, nil
}

// WorkloadGuard implements configapp.WorkloadGuardReader.
func (s *sharedNamespaceGuards) WorkloadGuard(ctx context.Context, cluster string) (cfg.NamespaceGuardProof, error) {
	s.mu.Lock()
	o := s.namespaces[cluster]
	s.mu.Unlock()
	if o == nil {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	p, err := o.ObservePermissionWorkloadGuard(ctx)
	if err != nil || p.ClusterID != cluster {
		return cfg.NamespaceGuardProof{}, cfg.ErrUnavailable
	}
	return p, nil
}
