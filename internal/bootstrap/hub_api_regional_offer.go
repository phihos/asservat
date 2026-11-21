package bootstrap

import (
	"context"
	"os"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"asservat.local/asservat/internal/adapters/mounts"
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
	// peerID is the local connector's generated peer (mode=combined).
	peerID string
	// release is the chart's object name prefix.
	release string
	// hubOnly is mode=hub (no local connector).
	hubOnly bool
}

// addExecutor completes the regional executor section (ADR-196/198) of the
// combined-mode offer except Owners: the key service (its Service endpoint,
// serving CA and artifact key) and the evidence store (from the capacity qualification).
func (o *hubAPIRegionalOffer) addExecutor(ctx context.Context, files *os.Root, h contracts.HubAPIConfig, c contracts.OwnerDeployment, storeID string, now time.Time) error {
	p := c.Public
	if p == nil || !authorization.UUID(storeID) {
		return hubAPIInputError("regional-offer-store")
	}
	keyRoots, err := readCA(ctx, files, HubAPIDownloadKeyServiceCAFile, now)
	if err != nil {
		return err
	}
	o.offer.KeyService = &contracts.RegionalWrapService{Endpoint: "https://" + contracts.HubAPIName(h.Name, "key-service") + "." + h.Namespace + ".svc:9447", Roots: keyRoots, KeyID: p.ArtifactKeyID}
	o.offer.EvidenceStore = &contracts.RegionalEvidenceStore{Endpoint: h.ObjectStore.Endpoint, Roots: c.AuditStore.Roots, Region: h.ObjectStore.Region, Bucket: h.ObjectStore.EvidenceBucket, StoreID: storeID}
	return nil
}

// setOwners pins the accepted owner configuration (pool and issuer roots),
// completing the executor section.
func (o *hubAPIRegionalOffer) setOwners(pool value.OwnerPool, revision int64, roots [][]byte) error {
	if o == nil || !pool.Valid() || pool.NativePort == 0 || len(roots) == 0 {
		return mounts.ErrUnavailable
	}
	o.offer.Owners = &contracts.RegionalContextOwners{Configuration: contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat,
		InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, Revision: revision,
		Namespace: contracts.WorkerObjectReference{Name: pool.Namespace, UID: pool.NamespaceUID}, Service: contracts.WorkerObjectReference{Name: pool.Service, UID: pool.ServiceUID},
		Deployment: contracts.WorkerObjectReference{Name: pool.Deployment, UID: pool.DeploymentUID}, ServiceAccount: contracts.WorkerObjectReference{Name: pool.ServiceAccount, UID: pool.AccountUID},
		Port: pool.Port, NativePort: pool.NativePort, NativeBootstrap: pool.NativeBootstrap, NativeCandidateLimit: pool.NativeCandidateLimit, OperationPort: pool.OperationPort, IssuerRoots: roots}}
	if !o.offer.Complete() {
		return mounts.ErrUnavailable
	}
	return nil
}

// buildHubAPIRegionalOffer derives the offer's identity fields from the
// config and the IDs; addExecutor and setOwners complete it.
func buildHubAPIRegionalOffer(h contracts.HubAPIConfig, ids hubAPIIDs) *hubAPIRegionalOffer {
	if h.Public == nil || h.Public.RegionalOffer == nil {
		return nil
	}
	o := h.Public.RegionalOffer
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: ids.InstallationID, HubClusterID: ids.ClusterID, PermissionRootID: ids.PermissionRootID, IssuerEpoch: ids.IssuerEpoch, Image: o.Image}
	return &hubAPIRegionalOffer{namespace: h.Namespace, name: contracts.HubAPIName(h.Name, "regional-offer"), offer: offer, peerID: ids.PeerID, release: h.Name, hubOnly: o.HubOnly}
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
