package bootstrap

import (
	cfg "asservat.local/asservat/internal/domain/configuration"
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
	// The local observation path re-reads owner protection, endpoints and
	// workload on both sides of every exchange. On the shared observer, which
	// also serves the source, guard and processing loops every second, those
	// reads were throttled past the five-second window (ADR-197 runs 24a-c:
	// selected/tls/post after 2.3-4.9 s). Own client instances of the same
	// identities, each at the fixed 20 QPS, as for the regional path.
	localObserver, localProbe, err := capacityLocalObservationClients(in, c.Control.ClusterID, capacityWorkerRef(c.Control.Namespace), observerToken, probeToken)
	if err != nil {
		return nil, nil, err
	}
	protection, err := kube.NewCapacityLocalOwnerProtection(localObserver, localProbe, c, m)
	if err != nil {
		return nil, nil, err
	}
	endpoints, err := kube.NewOwnerEndpoints(localObserver, pin.Pool)
	if err != nil {
		return nil, nil, err
	}
	workloads, err := kube.NewOwnerObservationWorkload(localObserver, protection, pin)
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
		read.diagnose = "local"
		out = append(out, app.CapacityClusterReaders{ClusterID: cluster.ClusterID, Workloads: read, Guard: read, Report: read.reportWorkload, Progress: read.reportProgress})
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
		// The v2 client's own client instances of the same identities, so
		// regional observation never spends the local cluster's or the source
		// observer's budget. Discovery and the ADR-200 demand lane share them;
		// at 20/20 a guarded demand read took 2.6-3.7 s against a five-second
		// binding (local journey hold), so they use the ADR-208 opening limiter.
		control := capacityWorkerRef(c.Control.Namespace)
		v2Observer, err := kube.NewPermissionClient(kube.WithOpeningBurst(in.kubernetes(observerToken)), c.Control.ClusterID, control, time.Now)
		if err != nil {
			return nil, nil, mounts.ErrUnavailable
		}
		v2Probe, err := kube.NewPermissionClient(kube.WithOpeningBurst(in.kubernetes(probeToken)), c.Control.ClusterID, control, time.Now)
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
		direct, err := NewDirectHolderObservationClient(d.root, pin, podUID, roots, registry, v2Endpoints, proof, mountedCapacityObservationToken{in}, capacityRegionalCalls(len(regional)), time.Now)
		if err != nil {
			return nil, nil, err
		}
		d.closers = append(d.closers, direct.Close)
		for _, q := range regional {
			read, e := newCapacityRemoteObservation(direct, c.PermissionRootID, q.ClusterID, time.Now)
			if e != nil {
				return nil, nil, e
			}
			// Each joined region logs under its own configured cluster ID, so two
			// regions' per-change outcomes are not read as one alternating line.
			read.diagnose = "regional " + q.ClusterID
			out = append(out, app.CapacityClusterReaders{ClusterID: q.ClusterID, Workloads: read, Guard: read, Guarded: read, Pace: 2 * time.Second, Report: read.reportWorkload, Progress: read.reportProgress})
		}
	}
	d.qualifications = qualifications
	if ctx.Err() != nil || !time.Now().Before(s.until) {
		return nil, nil, mounts.ErrUnavailable
	}
	return out, regional, nil
}

// capacityLocalObservationClients returns the local observation path's own
// observer and probe clients: the same mounted identities as the shared
// capacity clients, with their own fixed 20 QPS limiters.
func capacityLocalObservationClients(in *providerInputs, cluster string, control cfg.NamespaceRef, observerToken, probeToken string) (observer, probe *kube.PermissionClient, err error) {
	if observer, err = kube.NewPermissionClient(in.kubernetes(observerToken), cluster, control, time.Now); err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	if probe, err = kube.NewPermissionClient(in.kubernetes(probeToken), cluster, control, time.Now); err != nil {
		return nil, nil, mounts.ErrUnavailable
	}
	return observer, probe, nil
}
