package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"

	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	fleetvalue "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// HubAPIDownloadKeyServiceCAFile is the key service's serving CA in
// OwnerDeploymentRoot: the hub-local download workers' key-service roots.
const HubAPIDownloadKeyServiceCAFile = "download-key-service-ca.crt"

// hubAPIDownloadControl holds the hub-local download workers' control values
// known at input load (H, S and J values): the workers' namespace and profile,
// the evidence store they read and the key service. The owner pool, its
// issuer roots and the store Secret UID are added at startup.
type hubAPIDownloadControl struct {
	namespace, profile string
	store              contracts.WorkerNativeStore
	keys               contracts.WorkerNativeKeyService
}

func buildHubAPIDownloadControl(ctx context.Context, files *os.Root, h contracts.HubAPIConfig, c contracts.OwnerDeployment, storeID string, now time.Time) (*hubAPIDownloadControl, error) {
	if c.Public == nil || c.Native == nil || len(c.Native.WorkerAPIs) != 1 {
		return nil, nil
	}
	if !authorization.UUID(storeID) {
		return nil, hubAPIInputError("evidence-store-id")
	}
	keyRoots, err := readCA(ctx, files, HubAPIDownloadKeyServiceCAFile, now)
	if err != nil {
		return nil, err
	}
	return &hubAPIDownloadControl{namespace: c.Native.WorkerAPIs[0].Namespace.Name, profile: contracts.HubAPIName(h.Name, "worker-profile"),
		store: contracts.WorkerNativeStore{ID: storeID, Endpoint: h.ObjectStore.Endpoint, Region: h.ObjectStore.Region, Bucket: h.ObjectStore.EvidenceBucket, ServerRoots: c.AuditStore.Roots},
		keys: contracts.WorkerNativeKeyService{Endpoint: "https://" + contracts.HubAPIName(h.Name, "key-service") + "." + h.Namespace + ".svc:9447", ServerRoots: keyRoots,
			Scope: contracts.KeyScope{InstallationID: c.InstallationID, Purpose: "artifact", KeyID: c.Public.ArtifactKeyID}}}, nil
}

// downloadWorkerControl is the worker.json v2 control document of a
// hub-local worker (ADR-204 decisions 3 and 9): it dials the owner Service
// but verifies the pool's fixed serving name under the owner issuer roots,
// for both enrollment and the native path; its leaves chain to the worker
// PKI roots. It must parse with the worker's own closed parser.
func downloadWorkerControl(installation, cluster string, pool fleetvalue.OwnerPool, ownerRoots, workerRoots [][]byte, store contracts.WorkerNativeStore, keys contracts.WorkerNativeKeyService) ([]byte, error) {
	e, err := ownerWorkerEndpointsFor(pool)
	if err != nil || pool.InstallationID != installation || pool.ClusterID != cluster {
		return nil, mounts.ErrUnavailable
	}
	raw, err := json.Marshal(contracts.WorkerControl{Format: contracts.WorkerNativeControlFormat, InstallationID: installation, ClusterID: cluster, Endpoint: e.Endpoint, Address: e.Address,
		ServerRoots: ownerRoots, IssuerRoots: workerRoots,
		Native: &contracts.WorkerNativeControl{Format: contracts.WorkerNativeStartupFormat, ExchangeEndpoint: e.ExchangeEndpoint, ExchangeAddress: e.Address, ExchangeServerRoots: ownerRoots, ObjectStore: store, KeyService: keys}})
	if err != nil || len(raw) > contracts.WorkerControlMaxBytes {
		return nil, mounts.ErrUnavailable
	}
	if _, err = mtls.ParseWorkerControl(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// publish completes the control document from the Helm-rendered worker
// profile (control ConfigMap and store Secret names), the store Secret's UID
// and the accepted owner pool and roots, and writes it as worker.json of the
// kept control ConfigMap. Dispatch and the worker parse the same document;
// the hub-api's worker trust catalog holds it too.
func (o *hubAPIDownloadControl) publish(ctx context.Context, api kubernetes.Interface, installation, cluster string, pool fleetvalue.OwnerPool, ownerRoots, workerRoots [][]byte) ([]byte, error) {
	call, end := context.WithTimeout(ctx, 10*time.Second)
	defer end()
	configMaps := api.CoreV1().ConfigMaps(o.namespace)
	source, err := configMaps.Get(call, o.profile, meta.GetOptions{})
	if err != nil {
		return nil, &fixedStepError{"download-control-profile", mounts.ErrUnavailable}
	}
	var profile contracts.WorkerConfiguration
	decoder := json.NewDecoder(strings.NewReader(source.Data["worker-profile.json"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&profile) != nil || profile.Format != contracts.WorkerConfigurationFormat || profile.Namespace != o.namespace || profile.ControlConfig == "" || profile.StoreCredentials == "" {
		return nil, &fixedStepError{"download-control-profile", mounts.ErrUnavailable}
	}
	secret, err := api.CoreV1().Secrets(o.namespace).Get(call, profile.StoreCredentials, meta.GetOptions{})
	if err != nil {
		return nil, &fixedStepError{"download-control-store", mounts.ErrUnavailable}
	}
	store := o.store
	store.CredentialSecretName, store.CredentialSecretUID = secret.Name, string(secret.UID)
	raw, err := downloadWorkerControl(installation, cluster, pool, ownerRoots, workerRoots, store, o.keys)
	if err != nil {
		return nil, &fixedStepError{"download-control-document", mounts.ErrUnavailable}
	}
	current, err := configMaps.Get(call, profile.ControlConfig, meta.GetOptions{})
	if err != nil {
		return nil, &fixedStepError{"download-control-read", mounts.ErrUnavailable}
	}
	if len(current.Data) == 1 && len(current.BinaryData) == 0 && bytes.Equal([]byte(current.Data["worker.json"]), raw) {
		return raw, nil
	}
	next := current.DeepCopy()
	next.Data, next.BinaryData = map[string]string{"worker.json": string(raw)}, nil
	if _, err = configMaps.Update(call, next, meta.UpdateOptions{}); err != nil {
		return nil, &fixedStepError{"download-control-write", mounts.ErrUnavailable}
	}
	return raw, nil
}

// pathTargets are the clusters with a template-derived download path: the
// guarded catalog's clusters and, in mode=combined, the hub cluster itself.
func (in *ownerInputs) pathTargets(catalog publicCatalog) []string {
	targets := catalogTargets(catalog.catalog)
	if in.local != nil {
		targets = append([]string{in.local.ClusterID}, targets...)
	}
	return targets
}

func downloadRevision(r identity.Revision) contracts.DownloadEnvironmentRevision {
	return contracts.DownloadEnvironmentRevision{UID: r.UID, Generation: r.Generation, SHA256: hex.EncodeToString(r.Digest[:])}
}

// hubLocalPathTemplate sets the download path template of the hub-local
// workers (ADR-204 decisions 3 and 4): the evidence store and region, the hub
// as acquisition, connector and hub cluster, the worker profile revision the
// hub-api observes now and the accepted owner configuration revision. A later
// revision of either takes a new process, as for the profile itself.
func (d *OwnerDeployment) hubLocalPathTemplate(ctx context.Context, observer *kube.PermissionClient, hub identity.Revision) error {
	c, o := d.inputs.config, d.inputs.downloadControl
	p := c.Public
	if p == nil || o == nil || !hub.Valid() {
		return &fixedStepError{"path-template-inputs", mounts.ErrUnavailable}
	}
	client, err := d.workerSourceClient(observer, cfg.NamespaceRef{Name: c.Namespace.Name, UID: c.Namespace.UID})
	if err != nil {
		return &fixedStepError{"path-template-client", err}
	}
	guard, err := kube.NewPlainWorkerConfigurationProtection(client, p.WorkerConfiguration.Source.Name)
	if err != nil {
		return &fixedStepError{"path-template-guard", mounts.ErrUnavailable}
	}
	source, err := kube.NewWorkerConfigurationSource(client, guard, p.WorkerConfiguration.Source.Name, p.WorkerConfiguration.Source.UID, c.InstallationID, p.WorkerPKI.IssuerEpoch)
	if err != nil {
		return &fixedStepError{"path-template-source", mounts.ErrUnavailable}
	}
	observed, err := source.ReadWorkerConfiguration(ctx)
	if err != nil || !observed.Valid(time.Now()) {
		return &fixedStepError{"path-template-profile", mounts.ErrUnavailable}
	}
	region := o.store.Region
	t := contracts.DownloadEnvironmentPathTemplate{StoreID: o.store.ID, StorageRegion: region, AcquisitionClusterID: c.ClusterID, AcquisitionRegion: region, ConnectorClusterID: c.ClusterID, ConnectorRegion: region,
		HubClusterID: c.ClusterID, HubRegion: region, WorkerConfiguration: downloadRevision(observed.Configuration.Profile.Configuration), HubConfiguration: downloadRevision(hub)}
	if !downloadPathTemplate(t, c.ClusterID) {
		return &fixedStepError{"path-template", mounts.ErrUnavailable}
	}
	p.DownloadEnvironment.PathTemplate = &t
	return nil
}
