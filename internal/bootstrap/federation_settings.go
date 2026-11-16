package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/url"
	"sync"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
)

// federationSettings answers a connector's settings on connect
// (REQ-FED-001): its IDs, the hub's stored offer and its cluster's own
// object-store capabilities, read from the hub's namespace. Nothing is
// copied to the workload cluster. The stored offer also names the services
// a connector may tunnel to.
type federationSettings struct {
	api               kubernetes.Interface
	namespace, prefix string
	ids               contracts.ServiceIDs
	// names maps a registered cluster's ID to its name.
	names map[string]string
	mu    sync.Mutex
	offer *contracts.RegionalOffer
}

func newFederationSettings(c federationInputs) (*federationSettings, error) {
	config, err := serviceKubernetes()
	if err != nil {
		return nil, &fixedStepError{"kubernetes", mounts.ErrUnavailable}
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, &fixedStepError{"kubernetes", mounts.ErrUnavailable}
	}
	names := map[string]string{}
	for _, r := range c.ConnectorTokens.Clusters {
		names[contracts.RemoteClusterID(c.InstallationID, r.Name)] = r.Name
	}
	return &federationSettings{api: api, namespace: c.Namespace, prefix: c.Name, ids: c.ServiceIDs, names: names}, nil
}

// stored reads the hub-api's offer once: the first written offer never
// changes.
func (s *federationSettings) stored(ctx context.Context) (contracts.RegionalOffer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offer != nil {
		return *s.offer, nil
	}
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	object, err := s.api.CoreV1().ConfigMaps(s.namespace).Get(call, contracts.HubAPIName(s.prefix, "regional-offer"), meta.GetOptions{})
	if err != nil {
		return contracts.RegionalOffer{}, mounts.ErrUnavailable
	}
	var offer contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader([]byte(object.Data[contracts.RegionalOfferFile])))
	if d.Decode(&offer) != nil || !offer.Complete() || offer.InstallationID != s.ids.InstallationID {
		return offer, mounts.ErrUnavailable
	}
	s.offer = &offer
	return offer, nil
}

func (s *federationSettings) credential(ctx context.Context, name string) (contracts.OwnerStorageCredential, error) {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	object, err := s.api.CoreV1().Secrets(s.namespace).Get(call, name, meta.GetOptions{})
	if err != nil {
		return contracts.OwnerStorageCredential{}, mounts.ErrUnavailable
	}
	defer clearData(object.Data)
	return contracts.DecodeOwnerStorageCredential(bytes.NewReader(object.Data[contracts.ObjectStoreCredentialFile]))
}

// Settings answers the presented cluster only: the hub's own cluster
// (mode=combined) gets the release's regional capabilities, a registered
// cluster its own.
func (s *federationSettings) Settings(ctx context.Context, p value.ConnectorCluster) (connectorlifecycle.Settings, error) {
	var out connectorlifecycle.Settings
	if p.InstallationID != s.ids.InstallationID {
		return out, mounts.ErrUnavailable
	}
	secret := func(purpose string) string { return s.prefix + "-s3-" + purpose }
	if p.ClusterID != s.ids.ClusterID {
		name, ok := s.names[p.ClusterID]
		if !ok {
			return out, mounts.ErrUnavailable
		}
		secret = func(purpose string) string { return contracts.RemoteObjectStoreSecret(s.prefix, purpose, name) }
	}
	offer, err := s.stored(ctx)
	if err != nil {
		return out, err
	}
	out = connectorlifecycle.Settings{ClusterID: p.ClusterID, PeerID: p.PeerID, Offer: offer}
	if out.Evidence, err = s.credential(ctx, secret("regional-write")); err != nil {
		return connectorlifecycle.Settings{}, err
	}
	if out.History, err = s.credential(ctx, secret("regional-history")); err != nil {
		return connectorlifecycle.Settings{}, err
	}
	return out, nil
}

// allowed reports whether target is one of the offer's services: the
// owners' native address, the key service or the evidence store.
func (s *federationSettings) allowed(ctx context.Context, target string) bool {
	offer, err := s.stored(ctx)
	if err != nil {
		return false
	}
	return target == offer.Owners.Address || target == endpointAddress(offer.KeyService.Endpoint) || target == endpointAddress(offer.EvidenceStore.Endpoint)
}

// endpointAddress is an https URL's host:port.
func endpointAddress(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() == "" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return u.Host
}
