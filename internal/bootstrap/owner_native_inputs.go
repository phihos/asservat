package bootstrap

import (
	"context"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	configvalue "asservat.local/asservat/internal/domain/configuration"
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
	if c.Connections < 1 || c.Connections > 64 || c.Concurrency < 1 || c.Concurrency > 16 || c.Concurrency > c.Connections || c.WorkerAPIs == nil || len(c.WorkerAPIs) < least || len(c.WorkerAPIs) > 256 {
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
	return nil
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

// nativeConfiguration composes the native download peer checks.
func (d *OwnerDeployment) nativeConfiguration(ctx context.Context, pool *pgxpool.Pool) (*OwnerNativeRuntimeConfig, error) {
	c := d.inputs.config
	n := c.Native
	if n == nil || validateOwnerNativeInputs(n, c.ClusterID, c.ProviderAuthentication != nil) != nil {
		return nil, mounts.ErrUnavailable
	}
	d.shared = publicShared{nativeRead: pool}
	readers, err := postgres.NewNativeReaders(ctx, pool, c.PermissionRootID, c.InstallationID)
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
	origins := evidence.NativeOrigins{Locators: readers, Operations: readers, Now: time.Now, Recent: evidence.NewNativeRecentObservations(), Proofs: func(token evidence.DownloadPeerToken) (evidence.DownloadPeerProofReader, error) {
		if token == nil {
			return nil, artifact.ErrInvalid
		}
		return &ownerNativeProofs{readers, clients, token}, nil
	}}
	d.shared.workers, d.shared.origins = clients, origins
	peers := &mtls.NativePeerChecks{Workers: readers, WorkerTrust: d.trust, Certificates: readers, Origins: origins, Now: time.Now}
	return &OwnerNativeRuntimeConfig{Peers: peers, Connections: n.Connections, Concurrency: n.Concurrency}, nil
}
