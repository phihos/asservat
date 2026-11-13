package bootstrap

import (
	"context"
	"encoding/json"
	"os"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

// hubAPIRegionalOffer is the combined-mode offer (decision 11): the hub-api
// holds every value a regional connector source names, so it writes
// ConfigMap <name>-regional-offer, key regional-offer.json, which Helm
// renders empty and keeps. The first written offer stays: its connector
// backing carries the original validity, and a later write never replaces
// it (ADR-193, an offer confers no authority).
type hubAPIRegionalOffer struct {
	namespace, name string
	offer           contracts.RegionalOffer
}

// buildHubAPIRegionalOffer derives the plain connector offer (no regional
// executor section) from the config, the IDs and the connector roots.
func buildHubAPIRegionalOffer(ctx context.Context, files *os.Root, h contracts.HubAPIConfig, ids hubAPIIDs, connectorRoots [][]byte, now time.Time) (*hubAPIRegionalOffer, error) {
	if h.Public == nil || h.Public.RegionalOffer == nil {
		return nil, nil
	}
	o := h.Public.RegionalOffer
	federationRoots, err := readCA(ctx, files, contracts.HubAPIFederationCAFile, now)
	if err != nil {
		return nil, err
	}
	var names [6]string
	for i, purpose := range []string{"connector-source", "connector-journal", "connector-ack", "connector-cleanup", "connector-verifier", "connector-finalizer"} {
		name, ok := postgres.PublicRuntimeRoleName(ids.InstallationID, purpose)
		if !ok {
			return nil, hubAPIInputError("regional-offer-roles")
		}
		names[i] = name
	}
	backing, err := buildConnectorBacking(o.Connector, o.Backup, ids.PermissionRootID, ids.InstallationID, capacityAccountVersion(ids), ids.RoleSetupID, now)
	if err != nil {
		return nil, hubAPIInputError("regional-offer-backing")
	}
	raw, err := json.Marshal(backing)
	if err != nil {
		return nil, hubAPIInputError("regional-offer-backing")
	}
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: ids.InstallationID, HubClusterID: ids.ClusterID, PermissionRootID: ids.PermissionRootID, IssuerEpoch: ids.IssuerEpoch,
		Federation:            contracts.RegionalHubEndpoint{Endpoint: o.Federation, ServerName: o.ServerName, Roots: federationRoots},
		ConnectorServerSuffix: contracts.ConnectorServerSuffix(ids.InstallationID), ConnectorIssuerRoots: connectorRoots,
		Roles:            contracts.ConnectorIdentityRoles{Source: names[0], Journal: names[1], Acknowledgement: names[2], Cleanup: names[3], Verifier: names[4], Finalizer: names[5]},
		ConnectorBacking: raw, Image: o.Image}
	return &hubAPIRegionalOffer{namespace: h.Namespace, name: contracts.HubAPIName(h.Name, "regional-offer"), offer: offer}, nil
}

// publish writes the offer into the empty Helm-rendered ConfigMap; an
// existing offer is kept. It retries every ten seconds until written.
func (o *hubAPIRegionalOffer) publish(ctx context.Context, in *providerInputs) error {
	if o == nil {
		return nil
	}
	api, err := kubernetes.NewForConfig(in.kubernetes(contracts.HubAPIKubernetesTokenFile))
	if err != nil {
		return mounts.ErrUnavailable
	}
	raw, err := json.Marshal(o.offer)
	if err != nil {
		return mounts.ErrUnavailable
	}
	log := eventLog(os.Stderr, "regional offer")
	for {
		if err = o.write(ctx, api, string(raw)); err == nil {
			log("published")
			return nil
		}
		log("not-published")
		if !sleepContext(ctx, 10*time.Second) {
			return ctx.Err()
		}
	}
}

func (o *hubAPIRegionalOffer) write(ctx context.Context, api kubernetes.Interface, raw string) error {
	call, end := context.WithTimeout(ctx, 5*time.Second)
	defer end()
	configMaps := api.CoreV1().ConfigMaps(o.namespace)
	current, err := configMaps.Get(call, o.name, meta.GetOptions{})
	if err != nil {
		return err
	}
	if current.Data[contracts.RegionalOfferFile] != "" {
		return nil
	}
	next := current.DeepCopy()
	if next.Data == nil {
		next.Data = map[string]string{}
	}
	next.Data[contracts.RegionalOfferFile] = raw
	_, err = configMaps.Update(call, next, meta.UpdateOptions{})
	return err
}
