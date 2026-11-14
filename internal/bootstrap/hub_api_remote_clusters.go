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

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
)

// hubAPIRemoteCluster is one joined mode=cluster workload cluster (values
// clusters[]) with its derived connector peer.
type hubAPIRemoteCluster struct {
	contracts.RemoteCluster
	peerID string
}

// hubAPIRemoteClusters checks the configured remote clusters: DNS-label
// names, distinct cluster IDs other than the hub's, a release namespace and
// the router's per-cluster reservations. Joining needs the regional offer.
func hubAPIRemoteClusters(h contracts.HubAPIConfig, ids hubAPIIDs) ([]hubAPIRemoteCluster, error) {
	if len(h.Clusters) == 0 {
		return nil, nil
	}
	if h.Public == nil || h.Public.RegionalOffer == nil || h.Public.RegionalOffer.Remote == nil {
		return nil, hubAPIInputError("clusters")
	}
	seen := map[string]bool{ids.ClusterID: true}
	out := make([]hubAPIRemoteCluster, 0, len(h.Clusters))
	for _, c := range h.Clusters {
		peer, ok := contracts.RemotePeerID(ids.InstallationID, c.ClusterID)
		if !ok || !authorization.UUID(c.ClusterID) || seen[c.ClusterID] || seen["name/"+c.Name] || len(validation.IsDNS1123Label(c.Name)) != 0 ||
			len(validation.IsDNS1123Subdomain(contracts.RemoteJoinSecretName(h.Name, c.Name))) != 0 || len(validation.IsDNS1123Label(c.Namespace)) != 0 ||
			c.Standby < 1 || c.Standby > 16 || c.Captures < 1 {
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
// the cluster and peer IDs, the remote offer and the cluster's own regional
// executor object-store capabilities (copied from its
// `<name>-s3-regional-write-<cluster>` and `-regional-history-<cluster>`
// Secrets). It holds no connector credential: the connector authenticates
// with its ServiceAccount token (ADR-334).
type remoteJoinSecret struct {
	api                       kubernetes.Interface
	namespace, name           string
	cluster, peer             string
	offer                     []byte
	evidenceName, historyName string
	display                   string
	// seen is the resourceVersion of the last read or write; Changed
	// watches from it so no change between them is missed.
	seen string
}

// Present updates an existing Secret's join values in place (the offer
// changes with the hub's configuration).
func (s *remoteJoinSecret) Present(ctx context.Context) (bool, error) {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	secrets := s.api.CoreV1().Secrets(s.namespace)
	current, err := secrets.Get(call, s.name, meta.GetOptions{})
	if apierrors.IsNotFound(err) {
		s.seen = ""
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
	s.seen = current.ResourceVersion
	if changed {
		var updated *core.Secret
		if updated, err = secrets.Update(call, next, meta.UpdateOptions{}); err == nil {
			s.seen = updated.ResourceVersion
		}
	}
	return true, err
}

// Changed watches this one Secret by name from the last seen version and
// returns on its first event or when the watch ends.
func (s *remoteJoinSecret) Changed(ctx context.Context) error {
	w, err := s.api.CoreV1().Secrets(s.namespace).Watch(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + s.name, ResourceVersion: s.seen, AllowWatchBookmarks: false})
	if err != nil {
		return err
	}
	defer w.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-w.ResultChan():
		return nil
	}
}

// public is the Secret's data.
func (s *remoteJoinSecret) public(ctx context.Context) (map[string][]byte, error) {
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

func (s *remoteJoinSecret) create(ctx context.Context) error {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	data, err := s.public(call)
	if err != nil {
		return err
	}
	object := &core.Secret{ObjectMeta: meta.ObjectMeta{Name: s.name, Namespace: s.namespace, Labels: map[string]string{"app.kubernetes.io/part-of": "asservat", "app.kubernetes.io/component": "cluster-join"}}, Type: core.SecretTypeOpaque, Data: data}
	created, err := s.api.CoreV1().Secrets(s.namespace).Create(call, object, meta.CreateOptions{})
	if err == nil {
		s.seen = created.ResourceVersion
	}
	return err
}

// Run keeps the join Secret present and current: checked once and again
// whenever a watch reports that it changed or was deleted (ADR-330 D1).
// Only a failed read or watch waits a fixed retry delay.
func (s *remoteJoinSecret) Run(ctx context.Context, report func(string)) error {
	for {
		exists, err := s.Present(ctx)
		switch {
		case err != nil:
			report("not-read")
		case !exists:
			if err = s.create(ctx); err != nil {
				report("not-written")
			}
		}
		if err == nil {
			err = s.Changed(ctx)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			timer := time.NewTimer(5 * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
}

// newRemoteClusterJoins composes one join Secret runner per remote cluster.
func newRemoteClusterJoins(in *ownerInputs) ([]*remoteJoinSecret, error) {
	c := in.config
	if len(in.remote) == 0 {
		return nil, nil
	}
	if len(in.remoteOffers) != len(in.remote) {
		return nil, &fixedStepError{"remote-join-inputs", mounts.ErrUnavailable}
	}
	api, err := kubernetes.NewForConfig(in.kubernetes(contracts.HubAPIKubernetesTokenFile))
	if err != nil {
		return nil, &fixedStepError{"remote-join-kubernetes", mounts.ErrUnavailable}
	}
	out := make([]*remoteJoinSecret, 0, len(in.remote))
	for i, r := range in.remote {
		offer, err := json.Marshal(in.remoteOffers[i])
		if err != nil {
			return nil, &fixedStepError{"remote-join-offer", mounts.ErrUnavailable}
		}
		release := in.release
		out = append(out, &remoteJoinSecret{api: api, namespace: c.Namespace.Name, name: contracts.RemoteJoinSecretName(release, r.Name), cluster: r.ClusterID, peer: r.peerID, offer: offer, display: r.Name,
			evidenceName: contracts.RemoteObjectStoreSecret(release, "regional-write", r.Name), historyName: contracts.RemoteObjectStoreSecret(release, "regional-history", r.Name)})
	}
	return out, nil
}
