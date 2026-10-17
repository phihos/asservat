package bootstrap

import (
	"context"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A fresh read of the fixed kubelet projection is delayed until the concrete
// installed client has proved the selected server. No cached token or remote
// token file is accepted; the server independently reviews its audience/Pod.
type mountedCapacityObservationToken struct{ inputs *providerInputs }

func (s mountedCapacityObservationToken) ReadClusterObservationToken(ctx context.Context) ([]byte, error) {
	if s.inputs == nil {
		return nil, mounts.ErrUnavailable
	}
	b, err := s.inputs.token(contracts.HubWorkerClusterObservationTokenFile)(ctx)
	if err != nil || !contracts.ValidWorkerToken(b) {
		clear(b)
		return nil, mounts.ErrUnavailable
	}
	return b, nil
}

func (d *CapacityWorkerDeployment) installedClusterReaders(ctx context.Context, s *installedCapacityWorkerInputs, observer, probe *kube.PermissionClient, in *providerInputs, pool *pgxpool.Pool, observerToken, probeToken string) ([]app.CapacityClusterReaders, []app.CapacityNamespaceQualification, error) {
	c, m := d.input, d.manifest
	if !s.matches(c, m) || pool == nil {
		return nil, nil, mounts.ErrUnavailable
	}
	pin, err := kube.CapacityLocalOwnerBinding(c, m)
	if err != nil {
		return nil, nil, err
	}
	podUID := os.Getenv(contracts.OwnerPodUIDEnvironment)
	if !authorization.UUID(podUID) {
		return nil, nil, mounts.ErrUnavailable
	}
	roots, _, err := mtls.OwnerTrustRoots(c.LocalOwner.Pool.IssuerRoots, time.Now())
	if err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	protection, err := kube.NewCapacityLocalOwnerProtection(observer, probe, c, m)
	if err != nil {
		return nil, nil, err
	}
	endpoints, err := kube.NewOwnerEndpoints(observer, pin.Pool)
	if err != nil {
		return nil, nil, err
	}
	workloads, err := kube.NewOwnerObservationWorkload(observer, protection, pin)
	if err != nil {
		return nil, nil, err
	}
	// Both read facets use the existing role70/MaxConns1 pool. Constructors and
	// every actual read are sequential; no capacity transaction is held here.
	configuration, err := postgres.NewOwnerConfigurations(ctx, pool, c.InstallationID, c.Control.ClusterID, c.Control.Namespace.UID, c.LocalOwner.Source.UID)
	if err != nil {
		return nil, nil, err
	}
	registry, err := postgres.NewOwnerEnrollments(ctx, pool, c.InstallationID, c.Control.ClusterID, c.Control.Namespace.UID, c.LocalOwner.Source.UID, ownerRandomID)
	if err != nil {
		return nil, nil, err
	}
	client, err := NewInstalledClusterObservationClient(d.root, pin, podUID, roots, registry, configuration, endpoints, protection, workloads, mountedCapacityObservationToken{in}, 2, time.Now)
	if err != nil {
		return nil, nil, err
	}
	// Registered after the pools: reverse close joins all client conversations
	// before either scoped SQL pool or its mounted input ownership is released.
	d.closers = append(d.closers, client.Close)
	out := make([]app.CapacityClusterReaders, 0, len(c.Clusters))
	for _, cluster := range c.Clusters {
		read, e := newCapacityRemoteObservation(client, c.PermissionRootID, cluster.ClusterID, time.Now)
		if e != nil {
			return nil, nil, e
		}
		out = append(out, app.CapacityClusterReaders{ClusterID: cluster.ClusterID, Workloads: read, Guard: read})
	}
	// ADR-197: each regional qualification is observed over v2 through the
	// owner holding its standby. Guarded makes ReconcileWorkload use one
	// combined guard-and-workload observation.
	qualifications, err := postgres.NewCapacityClusterQualifications(ctx, pool, c.PermissionRootID)
	if err != nil {
		return nil, nil, err
	}
	regional, err := qualifications.ReadCapacityClusterQualifications(ctx)
	if err != nil {
		return nil, nil, err
	}
	if len(regional) > 0 {
		// The v2 client's own client instances of the same identities, each
		// at the fixed 20 QPS, so regional observation never spends the local
		// cluster's or the source observer's budget.
		control := capacityWorkerRef(c.Control.Namespace)
		v2Observer, err := kube.NewPermissionClient(in.kubernetes(observerToken), c.Control.ClusterID, control, time.Now)
		if err != nil {
			return nil, nil, mounts.ErrUnavailable
		}
		v2Probe, err := kube.NewPermissionClient(in.kubernetes(probeToken), c.Control.ClusterID, control, time.Now)
		if err != nil {
			return nil, nil, mounts.ErrUnavailable
		}
		v2Protection, err := protection.WithClients(v2Observer, v2Probe)
		if err != nil {
			return nil, nil, err
		}
		v2Endpoints, err := kube.NewOwnerEndpoints(v2Observer, pin.Pool)
		if err != nil {
			return nil, nil, err
		}
		proof, err := kube.NewOwnerObservationOperationReader(v2Observer, v2Protection, pin)
		if err != nil {
			return nil, nil, err
		}
		direct, err := NewDirectHolderObservationClient(d.root, pin, podUID, roots, registry, v2Endpoints, proof, mountedCapacityObservationToken{in}, 2, time.Now)
		if err != nil {
			return nil, nil, err
		}
		d.closers = append(d.closers, direct.Close)
		for _, q := range regional {
			read, e := newCapacityRemoteObservation(direct, c.PermissionRootID, q.ClusterID, time.Now)
			if e != nil {
				return nil, nil, e
			}
			read.diagnose = true
			out = append(out, app.CapacityClusterReaders{ClusterID: q.ClusterID, Workloads: read, Guard: read, Guarded: read, Pace: 2 * time.Second})
		}
	}
	d.qualifications = qualifications
	if ctx.Err() != nil || !time.Now().Before(s.until) {
		return nil, nil, mounts.ErrUnavailable
	}
	return out, regional, nil
}
