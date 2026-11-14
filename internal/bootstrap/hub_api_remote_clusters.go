package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"time"

	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
)

// hubAPIRemoteCluster is one joined mode=cluster workload cluster (values
// clusters[]) with its derived connector peer.
type hubAPIRemoteCluster struct {
	contracts.RemoteCluster
	peerID string
}

// remoteClusterLimit bounds the joined clusters as the context-start router
// does (16 clusters including the hub's own).
const remoteClusterLimit = 15

// hubAPIRemoteClusters checks the configured remote clusters: DNS-label
// names, distinct cluster IDs other than the hub's, a release namespace and
// the router's per-cluster reservations. Joining needs the regional offer.
func hubAPIRemoteClusters(h contracts.HubAPIConfig, ids hubAPIIDs) ([]hubAPIRemoteCluster, error) {
	if len(h.Clusters) == 0 {
		return nil, nil
	}
	if len(h.Clusters) > remoteClusterLimit || h.Public == nil || h.Public.RegionalOffer == nil || h.Public.RegionalOffer.Remote == nil || h.Public.Fleet == nil {
		return nil, hubAPIInputError("clusters")
	}
	seen := map[string]bool{ids.ClusterID: true}
	out := make([]hubAPIRemoteCluster, 0, len(h.Clusters))
	for _, c := range h.Clusters {
		peer, ok := contracts.RemotePeerID(ids.InstallationID, c.ClusterID)
		if !ok || !authorization.UUID(c.ClusterID) || seen[c.ClusterID] || seen["name/"+c.Name] || len(validation.IsDNS1123Label(c.Name)) != 0 ||
			len(validation.IsDNS1123Subdomain(contracts.RemoteJoinSecretName(h.Name, c.Name))) != 0 || len(validation.IsDNS1123Label(c.Namespace)) != 0 ||
			c.Standby < 1 || c.Standby > 16 || c.Captures < 1 || c.Captures > 16 {
			return nil, hubAPIInputError("clusters")
		}
		seen[c.ClusterID], seen["name/"+c.Name] = true, true
		out = append(out, hubAPIRemoteCluster{RemoteCluster: c, peerID: peer})
	}
	return out, nil
}

// validRemoteAddresses checks values remote.*: https endpoints without
// path and a host:port for the owners.
func validRemoteAddresses(a *contracts.HubAPIRemote) bool {
	return a != nil && ownerEndpoint(a.Federation) && ownerEndpoint(a.KeyService) && ownerEndpoint(a.ObjectStore) && ownerDialAddress(a.Owners)
}

// remoteJoinOffer is the stored offer as a remote connector dials it: the
// externally reachable addresses from values, each with the in-cluster
// server name its certificate carries (TCP passthrough, never TLS
// termination). The connector backing and every root stay those of the
// stored offer, so the federation reads the same backing.
func remoteJoinOffer(stored contracts.RegionalOffer, a *contracts.HubAPIRemote) (contracts.RegionalOffer, error) {
	out := stored
	if !validRemoteAddresses(a) || stored.Owners == nil || stored.KeyService == nil || stored.EvidenceStore == nil {
		return out, &fixedStepError{"remote-offer", mounts.ErrUnavailable}
	}
	host := func(endpoint string) string {
		u, err := url.Parse(endpoint)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	owners, keys, store := *stored.Owners, *stored.KeyService, *stored.EvidenceStore
	out.Federation.Endpoint = a.Federation
	owners.Address = a.Owners
	keys.ServerName, keys.Endpoint = host(keys.Endpoint), a.KeyService
	store.ServerName, store.Endpoint = host(store.Endpoint), a.ObjectStore
	if keys.ServerName == "" || store.ServerName == "" {
		return out, &fixedStepError{"remote-offer", mounts.ErrUnavailable}
	}
	out.Owners, out.KeyService, out.EvidenceStore = &owners, &keys, &store
	return out, nil
}

// remoteJoinSecret is one cluster's join Secret `<name>-join-<cluster>`:
// the cluster and peer IDs, the remote offer, the cluster's own regional
// executor object-store capabilities (copied from its
// `<name>-s3-regional-write-<cluster>` and `-regional-history-<cluster>`
// Secrets) and, when just issued, the one-use bootstrap record. The hub-api creates it when it is missing; the operator
// copies it unchanged to the cluster's release namespace.
type remoteJoinSecret struct {
	api                       kubernetes.Interface
	namespace, name           string
	cluster, peer             string
	offer                     []byte
	evidenceName, historyName string
}

// Present updates an existing Secret's public join values in place (the
// offer changes with the hub's configuration); bootstrap.json stays.
func (s remoteJoinSecret) Present(ctx context.Context) (bool, error) {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	secrets := s.api.CoreV1().Secrets(s.namespace)
	current, err := secrets.Get(call, s.name, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	want, err := s.public(call)
	if err != nil {
		return true, err
	}
	next := current.DeepCopy()
	if next.Data == nil {
		next.Data = map[string][]byte{}
	}
	changed := false
	for k, v := range want {
		if !bytes.Equal(next.Data[k], v) {
			next.Data[k], changed = v, true
		}
	}
	if changed {
		_, err = secrets.Update(call, next, meta.UpdateOptions{})
	}
	return true, err
}

// public is the Secret's data without the record.
func (s remoteJoinSecret) public(ctx context.Context) (map[string][]byte, error) {
	data := map[string][]byte{contracts.ConnectorJoinClusterFile: []byte(s.cluster), contracts.ConnectorJoinPeerFile: []byte(s.peer), contracts.RegionalOfferFile: s.offer}
	for file, name := range map[string]string{contracts.ConnectorEvidenceFile: s.evidenceName, contracts.RegionalHistoryCredentialFile: s.historyName} {
		source, err := s.api.CoreV1().Secrets(s.namespace).Get(ctx, name, meta.GetOptions{})
		if err != nil || len(source.Data[contracts.ObjectStoreCredentialFile]) == 0 {
			return nil, mounts.ErrUnavailable
		}
		data[file] = source.Data[contracts.ObjectStoreCredentialFile]
	}
	return data, nil
}

func (s remoteJoinSecret) Create(ctx context.Context, e *value.BootstrapEnvelope) error {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	data, err := s.public(call)
	if err != nil {
		return err
	}
	if e != nil {
		raw, err := kms.EncodeBootstrapRecord(*e)
		defer clear(raw)
		if err != nil {
			return err
		}
		data[contracts.ConnectorBootstrapFile] = raw
	}
	object := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: s.name, Namespace: s.namespace, Labels: map[string]string{"app.kubernetes.io/part-of": "asservat", "app.kubernetes.io/component": "cluster-join"}}, Type: core.SecretTypeOpaque, Data: data}
	_, err = s.api.CoreV1().Secrets(s.namespace).Create(call, object, meta.CreateOptions{})
	return err
}

// newRemoteClusterJoins composes one join runner per remote cluster: the
// combined-mode bootstrap pipeline with the installation as actor, the slot
// fixed to that cluster and peer, and the join Secret as its record.
func newRemoteClusterJoins(ctx context.Context, in *ownerInputs, pools *publicPools, issuance *fleetapp.FleetBootstrapIssuance, channel *kms.BootstrapChannel) ([]fleetapp.RemoteClusterJoin, error) {
	c := in.config
	if len(in.remote) == 0 {
		return nil, nil
	}
	if issuance == nil || channel == nil || c.Public == nil || c.Public.Fleet == nil || len(in.remoteOffers) != len(in.remote) {
		return nil, &fixedStepError{"remote-join-inputs", mounts.ErrUnavailable}
	}
	pool, err := pools.open(ctx, "fleet-bootstrap-reserve")
	if err != nil {
		return nil, &fixedStepError{"remote-join-pool", mounts.ErrUnavailable}
	}
	api, err := kubernetes.NewForConfig(in.kubernetes(contracts.HubAPIKubernetesTokenFile))
	if err != nil {
		return nil, &fixedStepError{"remote-join-kubernetes", mounts.ErrUnavailable}
	}
	s := issuance
	out := make([]fleetapp.RemoteClusterJoin, 0, len(in.remote))
	for i, r := range in.remote {
		reserve, err := postgres.NewLocalBootstrapReservations(ctx, pool, c.InstallationID, r.ClusterID, r.peerID, ownerRandomID)
		if err != nil {
			return nil, &fixedStepError{"remote-join-reserve", mounts.ErrUnavailable}
		}
		offer, err := json.Marshal(in.remoteOffers[i])
		if err != nil {
			return nil, &fixedStepError{"remote-join-offer", mounts.ErrUnavailable}
		}
		issuer := fleetapp.BootstrapIssuer{Authority: fleetapp.InstallationEnrollmentAuthorizer{Settings: s.Settings, Now: s.Now}, Reservations: reserve, Credentials: s.Credentials, Records: s.Records, Audits: s.Audits, Objects: s.Objects, Activation: s.Activation, Now: s.Now}
		binding := value.PeerBinding{InstallationID: c.InstallationID, ClusterID: r.ClusterID, PeerID: r.peerID, IssuerEpoch: in.remoteOffers[i].IssuerEpoch, Role: value.ConnectorPeer}
		release := in.release
		out = append(out, fleetapp.RemoteClusterJoin{
			Bootstrap: fleetapp.LocalClusterBootstrap{Issuer: issuer, Envelopes: channel, Binding: binding, DeliveryProfile: c.Public.Fleet.DeliveryProfile, DisplayName: r.Name, Region: "remote"},
			Records: remoteJoinSecret{api: api, namespace: c.Namespace.Name, name: contracts.RemoteJoinSecretName(release, r.Name), cluster: r.ClusterID, peer: r.peerID, offer: offer,
				evidenceName: contracts.RemoteObjectStoreSecret(release, "regional-write", r.Name), historyName: contracts.RemoteObjectStoreSecret(release, "regional-history", r.Name)}})
	}
	return out, nil
}
