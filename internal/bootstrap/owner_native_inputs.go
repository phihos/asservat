package bootstrap

import (
	"context"
	"encoding/hex"
	"slices"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	configvalue "asservat.local/asservat/internal/domain/configuration"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
	"k8s.io/apimachinery/pkg/util/validation"
)

type ownerNativeAPIKey struct{ cluster, namespace string }

// nativeKubernetesTokenName is keyed by cluster UUID and namespace name
// (ADR-204): the installed owner template is pinned before the worker
// namespace exists, so it can project only names known then. The client
// still checks the pinned namespace UID on every read.
func nativeKubernetesTokenName(c contracts.OwnerNativeWorkerAPI) string {
	return contracts.NativeKubernetesTokenFile(c.ClusterID, c.Namespace.Name)
}

// nativeKubernetesProbeTokenName is the worker namespace's separate probe
// credential (ADR-204 decision 2): it proves the worker profile source's guard
// by a denied dry-run update, as kube-probe.token does in the hub namespace.
func nativeKubernetesProbeTokenName(c contracts.OwnerNativeWorkerAPI) string {
	return contracts.NativeKubernetesProbeTokenFile(c.ClusterID, c.Namespace.Name)
}

// workerAPIClient is one pinned worker API's client for one fixed token file
// of the backend projection; the returned func closes its HTTP transport.
func (d *OwnerDeployment) workerAPIClient(a contracts.OwnerNativeWorkerAPI, token string) (*kube.PermissionClient, func(), error) {
	in := &providerInputs{files: d.backendInputs().files, kubernetesEndpoint: a.Kubernetes}
	client, err := kube.NewPermissionClient(in.kubernetes(token), a.ClusterID, configvalue.NamespaceRef{Name: a.Namespace.Name, UID: a.Namespace.UID}, time.Now)
	if err != nil {
		in.closeHTTP()
		return nil, nil, err
	}
	return client, in.closeHTTP, nil
}

// hub is the owner's own cluster: download-peer proofs read only that cluster
// API (ADR-179). Workload clusters are never addressed directly. ADR-194 D2/D3:
// the provider-installed layout may start with no worker API and no topology;
// both arrive with regional provisioning, and until then downloads and
// retention effects fail closed.
func validateOwnerNativeInputs(c *contracts.OwnerNativeDeployment, hub string, installed bool) error {
	if c == nil {
		return nil
	}
	least := 1
	if installed {
		least = 0
	}
	if c.Connections < 1 || c.Connections > 64 || c.Concurrency < 1 || c.Concurrency > 16 || c.Concurrency > c.Connections || c.WorkerAPIs == nil || len(c.WorkerAPIs) < least || len(c.WorkerAPIs) > 256 || c.RetentionTopologies == nil || len(c.RetentionTopologies) < least || len(c.RetentionTopologies) > 1024 {
		return mounts.ErrUnavailable
	}
	if _, _, err := mtls.OwnerTrustRoots(c.ConnectorRoots, time.Now()); err != nil {
		return mounts.ErrUnavailable
	}
	seen, files := map[ownerNativeAPIKey]bool{}, map[string]bool{}
	for _, a := range c.WorkerAPIs {
		key := ownerNativeAPIKey{a.ClusterID, a.Namespace.UID}
		// Token files are keyed by namespace name: two pins may not share one.
		if !value.UUID(a.ClusterID) || a.ClusterID != hub || !value.UUID(a.Namespace.UID) || len(validation.IsDNS1123Label(a.Namespace.Name)) != 0 || seen[key] || files[nativeKubernetesTokenName(a)] || !ownerEndpoint(a.Kubernetes.Endpoint) {
			return mounts.ErrUnavailable
		}
		files[nativeKubernetesTokenName(a)] = true
		if _, _, err := mtls.OwnerTrustRoots(a.Kubernetes.Roots, time.Now()); err != nil {
			return mounts.ErrUnavailable
		}
		seen[key] = true
	}
	clusters, names := map[string]bool{}, map[string]bool{}
	for _, p := range c.RetentionTopologies {
		if !validOwnerNativeTopology(p) || clusters[p.TargetClusterID] || names[p.Name] {
			return mounts.ErrUnavailable
		}
		clusters[p.TargetClusterID], names[p.Name] = true, true
	}
	return nil
}

func validOwnerNativeTopology(p contracts.OwnerNativeTopology) bool {
	b, err := hex.DecodeString(p.SHA256)
	return value.UUID(p.TargetClusterID) && value.UUID(p.UID) && len(validation.IsDNS1123Subdomain(p.Name)) == 0 && err == nil && len(b) == 32 && hex.EncodeToString(b) == p.SHA256 && p.SHA256 != "0000000000000000000000000000000000000000000000000000000000000000"
}

// ownerNativeProofs chooses the API only after an exact current SQL worker read.
// Each client is installation-pinned to its real cluster/control namespace;
// neither forwarded Hello nor its certificate selects an endpoint or credential.
type ownerNativeProofs struct {
	readers *postgres.NativeReaders
	clients map[ownerNativeAPIKey]*kube.PermissionClient
	token   evidence.DownloadPeerToken
}

func (p *ownerNativeProofs) ReadDownloadPeerProof(ctx context.Context, session string, peer value.KeyPeer) (value.KeyWorkerProof, error) {
	result, err := p.ReadNativeResponsePeerProof(ctx, session, peer)
	return result.Proof, err
}
func (p *ownerNativeProofs) ReadNativeResponsePeerProof(ctx context.Context, session string, peer value.KeyPeer) (evidence.NativeResponsePeerProof, error) {
	var zero evidence.NativeResponsePeerProof
	if p == nil || ctx == nil || p.token == nil {
		return zero, artifact.ErrInvalid
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	observed, err := p.readers.ReadDownloadWorkerIdentity(call, session, peer)
	if err != nil {
		return zero, err
	}
	profile := observed.Worker.Intent.Profile
	client := p.clients[ownerNativeAPIKey{profile.ClusterID, profile.NamespaceUID}]
	if client == nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	proof, err := kube.NewDispatchedDownloadPeerAttester(client, p.readers, p.token)
	if err != nil {
		return zero, err
	}
	bounded, end := context.WithDeadline(call, observed.FreshUntil)
	defer end()
	out, err := proof.ReadNativeResponsePeerProof(bounded, session, peer)
	if err != nil || bounded.Err() != nil || !observed.Valid(time.Now()) || out.Proof.Binding != observed.Worker.Binding {
		return zero, artifact.ErrDownloadUnavailable
	}
	return out, nil
}

// nativeConfiguration unions the input's retention topology pins with each
// joined slot's pin from the catalog (ADR-196 decision 7); a slot's pin must
// name its own cluster and fixed slot topology.
func (d *OwnerDeployment) nativeConfiguration(ctx context.Context, pool *pgxpool.Pool, observer *kube.PermissionClient, clusters []contracts.OwnerPublicCluster) (*OwnerNativeRuntimeConfig, error) {
	c := d.inputs.config
	n := c.Native
	if n == nil || validateOwnerNativeInputs(n, c.ClusterID, c.ProviderAuthentication != nil) != nil {
		return nil, mounts.ErrUnavailable
	}
	all := slices.Clone(n.RetentionTopologies)
	for i, v := range clusters {
		t := v.Topology
		if t.TargetClusterID != v.ClusterID || t.Name != contracts.OwnerClusterSourceName(c.InstallationID, i+1, "topology") || !validOwnerNativeTopology(t) {
			return nil, mounts.ErrUnavailable
		}
		all = append(all, t)
	}
	pins := make([]kube.RetentionTopologyPin, len(all))
	for i, p := range all {
		b, _ := hex.DecodeString(p.SHA256)
		pins[i] = kube.RetentionTopologyPin{TargetClusterID: p.TargetClusterID, Name: p.Name, UID: p.UID}
		copy(pins[i].ContentDigest[:], b)
	}
	topologies, err := kube.NewRetentionTopologies(observer, c.PermissionRootID, pins)
	if err != nil {
		return nil, err
	}
	retention, err := postgres.NewRetentionTransactionGuard(c.PermissionRootID, topologies)
	if err != nil {
		return nil, err
	}
	recovery, err := postgres.NewRecoveryTransactionGuard(c.PermissionRootID, c.InstallationID)
	if err != nil {
		return nil, err
	}
	d.shared = publicShared{topologies: topologies, guards: postgres.EffectTransactionGuards{Retention: retention, Recovery: recovery}, nativeRead: pool}
	readers, err := postgres.NewNativeReaders(ctx, pool, c.PermissionRootID, c.InstallationID, postgres.DownloadTransactionGuards{Retention: retention, Recovery: recovery})
	if err != nil {
		return nil, err
	}
	clients := make(map[ownerNativeAPIKey]*kube.PermissionClient, len(n.WorkerAPIs))
	for _, a := range n.WorkerAPIs {
		client, closeHTTP, err := d.workerAPIClient(a, nativeKubernetesTokenName(a))
		if err != nil {
			return nil, err
		}
		d.closers = append(d.closers, closeHTTP)
		clients[ownerNativeAPIKey{a.ClusterID, a.Namespace.UID}] = client
	}
	roots, _, err := mtls.OwnerTrustRoots(n.ConnectorRoots, time.Now())
	if err != nil {
		return nil, err
	}
	verifier, err := mtls.NewPeerVerifier(roots, c.InstallationID, fleetvalue.ConnectorPeer, time.Now)
	if err != nil {
		return nil, err
	}
	registry, err := postgres.NewPeerRegistry(ctx, pool, c.InstallationID)
	if err != nil {
		return nil, err
	}
	origins := evidence.NativeOrigins{Locators: readers, Operations: readers, Now: time.Now, Recent: evidence.NewNativeRecentObservations(), Proofs: func(token evidence.DownloadPeerToken) (evidence.DownloadPeerProofReader, error) {
		if token == nil {
			return nil, artifact.ErrInvalid
		}
		return &ownerNativeProofs{readers, clients, token}, nil
	}}
	d.shared.workers, d.shared.origins = clients, origins
	peers := &mtls.NativePeerChecks{Workers: readers, WorkerTrust: d.trust, Certificates: readers, Origins: origins, ConnectorVerifier: verifier, Connectors: &fleetapp.PeerAuthenticator{Registry: registry, Now: time.Now}, Now: time.Now}
	return &OwnerNativeRuntimeConfig{Peers: peers, ConnectorRoots: roots, Connections: n.Connections, Concurrency: n.Concurrency}, nil
}
