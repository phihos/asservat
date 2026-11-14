package bootstrap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/fleet"
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
	// peerID and bootstrapSecret are the local connector's generated peer
	// and the Secret its bootstrap record is written to (mode=combined).
	peerID, bootstrapSecret string
	// ownersAddress is the hub-api native Service the regional executor
	// dials; setOwners adds the accepted owner configuration at startup.
	ownersAddress string
	// release is the chart's object name prefix.
	release string
	// hubOnly is mode=hub (no local connector).
	hubOnly bool
}

// regionalWorkKeyValidity bounds the offered work key: the offer is
// written once per installation.
const regionalWorkKeyValidity = 5 * 365 * 24 * time.Hour

// addExecutor completes the regional executor section (ADR-196/198) of the
// combined-mode offer except Owners: the key service (its Service endpoint,
// serving CA and artifact key), the hub's work-signing public key and the
// evidence store (from the capacity qualification).
func (o *hubAPIRegionalOffer) addExecutor(ctx context.Context, files *os.Root, h contracts.HubAPIConfig, c contracts.OwnerDeployment, storeID string, now time.Time) error {
	p := c.Public
	if p == nil || !authorization.UUID(storeID) {
		return hubAPIInputError("regional-offer-store")
	}
	keyRoots, err := readCA(ctx, files, HubAPIDownloadKeyServiceCAFile, now)
	if err != nil {
		return err
	}
	if len(p.WorkSigning.PublicKey) != 32 || p.WorkSigning.KeyID == "" {
		return hubAPIInputError("regional-offer-work-key")
	}
	from := now.UTC().Truncate(time.Second)
	o.offer.KeyService = &contracts.RegionalWrapService{Endpoint: "https://" + contracts.HubAPIName(h.Name, "key-service") + "." + h.Namespace + ".svc:9447", Roots: keyRoots, KeyID: p.ArtifactKeyID}
	o.offer.WorkKey = &contracts.APIContextWorkPublicKey{ID: p.WorkSigning.KeyID, PublicKey: base64.RawURLEncoding.EncodeToString(p.WorkSigning.PublicKey), NotBefore: from.Format(time.RFC3339Nano), NotAfter: from.Add(regionalWorkKeyValidity).Format(time.RFC3339Nano)}
	o.offer.EvidenceStore = &contracts.RegionalEvidenceStore{Endpoint: h.ObjectStore.Endpoint, Roots: c.AuditStore.Roots, Region: h.ObjectStore.Region, Bucket: h.ObjectStore.EvidenceBucket, StoreID: storeID}
	o.ownersAddress = contracts.HubAPIName(h.Name, "hub-api-native") + "." + h.Namespace + ".svc:9444"
	return nil
}

// setOwners pins the accepted owner configuration (pool and issuer roots),
// completing the executor section.
func (o *hubAPIRegionalOffer) setOwners(pool value.OwnerPool, revision int64, roots [][]byte) error {
	if o == nil || o.ownersAddress == "" || !pool.Valid() || pool.NativePort == 0 || len(roots) == 0 {
		return mounts.ErrUnavailable
	}
	o.offer.Owners = &contracts.RegionalContextOwners{Address: o.ownersAddress, Configuration: contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat,
		InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, Revision: revision,
		Namespace: contracts.WorkerObjectReference{Name: pool.Namespace, UID: pool.NamespaceUID}, Service: contracts.WorkerObjectReference{Name: pool.Service, UID: pool.ServiceUID},
		Deployment: contracts.WorkerObjectReference{Name: pool.Deployment, UID: pool.DeploymentUID}, ServiceAccount: contracts.WorkerObjectReference{Name: pool.ServiceAccount, UID: pool.AccountUID},
		Port: pool.Port, NativePort: pool.NativePort, NativeBootstrap: pool.NativeBootstrap, NativeCandidateLimit: pool.NativeCandidateLimit, OperationPort: pool.OperationPort, IssuerRoots: roots}}
	if offered, err := o.offer.RegionalExecutorOffered(); err != nil || !offered {
		return mounts.ErrUnavailable
	}
	return nil
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
	return &hubAPIRegionalOffer{namespace: h.Namespace, name: contracts.HubAPIName(h.Name, "regional-offer"), offer: offer, peerID: ids.PeerID, bootstrapSecret: contracts.HubAPIName(h.Name, "region-bootstrap"), release: h.Name, hubOnly: o.HubOnly}, nil
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
