package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The installed worker profile's fixed, unqualified limits (ADR-204): one
// process container per download, at most the hub-api's DownloadMaxSeconds.
// They are bounds, not a qualified capacity claim.
const (
	downloadWorkerCPUMillis         = 500
	downloadWorkerMemoryBytes       = 256 << 20
	downloadWorkerMaxRuntimeSeconds = 3600
)

// installerDownloads is the ADR-204 installer state: the hub-cluster worker
// objects from the early step and, after promotion, the configured profile,
// its control document and the download path template.
type installerDownloads struct {
	sources    kube.DownloadWorkerSources
	configured bool
	control    []byte
	profile    contracts.WorkerConfiguration
	template   contracts.DownloadEnvironmentPathTemplate
}

// promotedDownloads are the owner input pins a configured profile adds
// (ADR-204 decisions 2 and 4).
type promotedDownloads struct {
	API      contracts.OwnerNativeWorkerAPI
	Source   contracts.OwnerPublicGuardedSource
	Template contracts.DownloadEnvironmentPathTemplate
}

// downloadsEnabled: workers read what the publisher verifies, unwrap through
// the key service and serve the promoted hub-api's downloads, so they exist
// exactly when the publisher does. The phase-3 inbox then must carry their
// own evidence read credential (ADR-204 decision 5).
func (k *InstallerContinuation) downloadsEnabled() bool {
	return k.publisherEnabled()
}

// workerConfigurationAudit is the worker configuration observer's own audit
// Transit key on the configuration audit mount (ADR-204 decision 7), or zero
// without downloads. It binds the resource journal through the provider
// selection, before the owner input exists, so the mount comes from the
// original preparation services; the permission step checks it against the
// owner's audit mount.
func (k *InstallerContinuation) workerConfigurationAudit() (contracts.OwnerPublicTransit, error) {
	if !k.downloadsEnabled() {
		return contracts.OwnerPublicTransit{}, nil
	}
	s := k.plan.Services
	if s == nil || s.KeyService.AuditMount == "" {
		return contracts.OwnerPublicTransit{}, mounts.ErrUnavailable
	}
	return contracts.OwnerPublicTransit{Mount: s.KeyService.AuditMount, Key: contracts.WorkerConfigurationAuditKeyName(k.record.Scope.InstallationID)}, nil
}

// DownloadWorkers is the early ADR-204 step before the permission step: the
// restricted worker namespace, worker account, PriorityClass, empty store
// Secret, guarded unconfigured profile source and the hub accounts' named
// access there. Without downloads it does nothing.
func (k *InstallerContinuation) DownloadWorkers(ctx context.Context, inventory kube.InitialRuntimeResourceInventory) error {
	if !k.downloadsEnabled() {
		return nil
	}
	// The path regions must be permitted region names (privacy policy limit).
	if r := k.input.Public.Federation.EvidenceStore.Region; !identity.Text(r, 63) {
		return mounts.ErrUnavailable
	}
	k.at("downloads/workers")
	control := cfg.NamespaceRef{Name: inventory.Namespace.Name, UID: inventory.Namespace.UID}
	sources, err := kube.EnsureDownloadWorkerSources(ctx, k.in.kubernetes("administrator-token"), k.record.Scope.InstallationID, control, inventory.BridgeAdministration.Owner.Administrators, inventory.OwnerAccount, inventory.WorkerAccount)
	if err != nil {
		return err
	}
	k.downloads = &installerDownloads{sources: sources}
	return nil
}

// workerConfigurationSection is the permission projection's worker
// configuration section (ADR-204 decision 7), or nil without downloads.
func (k *InstallerContinuation) workerConfigurationSection(owner contracts.OwnerDeployment) (*contracts.WorkerConfigurationDeployment, error) {
	if !k.downloadsEnabled() {
		return nil, nil
	}
	audit, err := k.workerConfigurationAudit()
	if err != nil || k.downloads == nil || audit.Mount != owner.KeyService.AuditMount || audit.Key == owner.KeyService.AuditKey {
		return nil, mounts.ErrUnavailable
	}
	s := k.downloads.sources
	return &contracts.WorkerConfigurationDeployment{Namespace: s.Namespace, Source: s.Profile.Source, Guard: s.Profile.Guard, AuditTransit: audit}, nil
}

// workerProfileSource replaces the hub namespace's unconfigured marker with
// the worker namespace's guarded source (ADR-204 decision 2), or nil.
func (k *InstallerContinuation) workerProfileSource() *contracts.OwnerPublicGuardedSource {
	if k.downloads == nil {
		return nil
	}
	s := k.downloads.sources.Profile
	return &s
}

// downloadRegion is the one region of the hub-local path: the evidence
// store's region, which the hub's acquisition, connector and hub roles share
// (ADR-204 decision 3); the installer input names no other hub region.
func (k *InstallerContinuation) downloadRegion() string {
	return k.input.Public.Federation.EvidenceStore.Region
}

// downloadClients are the download environment's clients: every human client
// of the installer's identity settings, for the context captures' data,
// privacy class, evidence type and the retention baseline's purpose, with no
// path yet; joining a cluster adds its derived path (ADR-204 decision 4).
// Without a baseline no capture resolves a purpose, so there is no client.
func downloadClients(p contracts.InstallerPublicSettings) []contracts.DownloadEnvironmentClient {
	out := []contracts.DownloadEnvironmentClient{}
	if p.RetentionBaseline == nil {
		return out
	}
	for _, c := range p.Clients {
		if c.Kind != string(identity.Human) {
			continue
		}
		out = append(out, contracts.DownloadEnvironmentClient{Issuer: p.Issuer, ID: c.ID, Kind: c.Kind, DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"},
			EvidenceTypes: []string{"context", "packetCapture"}, Purposes: []string{p.RetentionBaseline.PurposeRef}, PathIDs: []string{}})
	}
	return out
}

// readDownloadEvidenceCredential reads the operator's download evidence read
// credential file for installer-provider-apply, or nil without one. The store
// Secret is immutable and cannot renew in place, so a temporary credential is
// refused.
func readDownloadEvidenceCredential(file string) ([]byte, error) {
	if file == "" {
		return nil, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if c, e := contracts.DecodeOwnerStorageCredential(bytes.NewReader(b)); e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken != "" {
		clear(b)
		return nil, mounts.ErrUnavailable
	}
	return b, nil
}

// downloadWorkerStoreCredential converts the operator's credential to the
// worker's closed credentials.json document.
func downloadWorkerStoreCredential(raw []byte) ([]byte, error) {
	c, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(raw))
	if err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken != "" {
		return nil, mounts.ErrUnavailable
	}
	out, err := json.Marshal(contracts.WorkerStoreCredentials{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey})
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	return out, nil
}

// downloadWorkerControl is the immutable worker.json v2 control document of
// a hub-local worker (ADR-204 decisions 3 and 9): it dials the owner Service
// but verifies the pool's fixed serving name under the owner issuer roots,
// for both enrollment and the native path; its leaves chain to the worker
// PKI roots. It must parse with the worker's own closed parser.
func downloadWorkerControl(installation, cluster string, pool fleet.OwnerPool, ownerRoots, workerRoots [][]byte, store contracts.WorkerNativeStore, keys contracts.WorkerNativeKeyService) ([]byte, error) {
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

// downloadWorkerProfile is the configured worker-profile.json: the product
// image, the exact control and store objects and the fixed limits, at
// revision 1 of a fresh source.
func downloadWorkerProfile(installation, cluster, epoch, image string, s kube.DownloadWorkerSources, control contracts.LocalKeySecretReference) contracts.WorkerConfiguration {
	store := s.StoreCredentials
	return contracts.WorkerConfiguration{Format: "asservat-worker-configuration/v2", InstallationID: installation, ClusterID: cluster, RecoveryEpoch: epoch, Revision: 1,
		Namespace: s.Namespace, ServiceAccount: s.ServiceAccount, PriorityClass: s.PriorityClass, ControlConfig: control, Image: image, ImagePullSecrets: []string{},
		CPUMillis: downloadWorkerCPUMillis, MemoryBytes: downloadWorkerMemoryBytes, MaxRuntimeSeconds: downloadWorkerMaxRuntimeSeconds, StoreCredentials: &store}
}

func downloadRevision(r identity.Revision) contracts.DownloadEnvironmentRevision {
	return contracts.DownloadEnvironmentRevision{UID: r.UID, Generation: r.Generation, SHA256: hex.EncodeToString(r.Digest[:])}
}

// downloadPathTemplate is the one hub-local path template (ADR-204 decisions
// 3 and 4): the evidence store, and the hub as acquisition, connector and hub
// cluster in the store's region, at the configured worker profile's and the
// accepted owner configuration's revisions.
func buildDownloadPathTemplate(cluster, region, store string, worker, hub identity.Revision) contracts.DownloadEnvironmentPathTemplate {
	return contracts.DownloadEnvironmentPathTemplate{StoreID: store, StorageRegion: region, AcquisitionClusterID: cluster, AcquisitionRegion: region, ConnectorClusterID: cluster, ConnectorRegion: region,
		HubClusterID: cluster, HubRegion: region, WorkerConfiguration: downloadRevision(worker), HubConfiguration: downloadRevision(hub)}
}

// DownloadConfigure is the ADR-204 step after the public readback, before the
// owner input is derived: it fills the store Secret from the phase-3
// credential, creates the immutable control ConfigMap and, as an
// administrator, replaces the unconfigured profile with the configured one.
// workerRoots are the read-back worker PKI roots. It returns the owner input
// pins; without downloads it returns nil.
func (k *InstallerContinuation) DownloadConfigure(ctx context.Context, inventory kube.InitialRuntimeResourceInventory, input contracts.OwnerDeployment, credential []byte, workerRoots [][]byte) (*promotedDownloads, error) {
	d := k.downloads
	if d == nil {
		if k.downloadsEnabled() || len(credential) != 0 {
			return nil, mounts.ErrUnavailable
		}
		return nil, nil
	}
	settings := k.input.Public.Federation
	if k.ownerConfiguration == nil || k.capacity == nil || len(k.capacity.qualification.Backends) != 1 || len(workerRoots) == 0 || settings == nil || settings.EvidenceStore == nil {
		return nil, mounts.ErrUnavailable
	}
	admin := k.in.kubernetes("administrator-token")
	installation, cluster := k.record.Scope.InstallationID, k.record.Scope.ClusterID
	k.at("downloads/store")
	store, err := downloadWorkerStoreCredential(credential)
	if err != nil {
		return nil, err
	}
	defer clear(store)
	if err = kube.FillDownloadWorkerStore(ctx, admin, d.sources, store); err != nil {
		return nil, err
	}
	k.at("downloads/control")
	endpoint, err := url.Parse(settings.KeyServiceEndpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.Path != "" {
		return nil, mounts.ErrUnavailable
	}
	keyRoots, err := kube.ReadKeyServiceServingRoots(ctx, admin, inventory.Namespace.Name, installation, endpoint.Hostname())
	if err != nil {
		return nil, err
	}
	e := settings.EvidenceStore
	storeRoots, err := providerconfig.TrustRootsPEM([]byte(e.RootsPEM), time.Now())
	if err != nil {
		return nil, err
	}
	storeID := k.capacity.qualification.Backends[0].EvidenceStoreID
	owner := k.ownerConfiguration
	control, err := downloadWorkerControl(installation, cluster, owner.Pool, owner.IssuerRoots, workerRoots,
		contracts.WorkerNativeStore{ID: storeID, Endpoint: e.Endpoint, Region: e.Region, Bucket: e.Bucket, ServerRoots: storeRoots, CredentialSecretName: d.sources.StoreCredentials.Name, CredentialSecretUID: d.sources.StoreCredentials.UID},
		contracts.WorkerNativeKeyService{Endpoint: settings.KeyServiceEndpoint, ServerRoots: keyRoots, Scope: contracts.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: promotedArtifactKeyID(installation)}})
	if err != nil {
		return nil, &fixedStepError{"control-document", err}
	}
	ref, err := kube.EnsureDownloadWorkerControl(ctx, admin, installation, d.sources.Namespace, control)
	if err != nil {
		return nil, err
	}
	k.at("downloads/profile")
	profile := downloadWorkerProfile(installation, cluster, k.record.Scope.IssuerEpoch, k.plan.Plan.Workload.Image, d.sources, ref)
	pinned, err := kube.PinnedWorkerConfiguration(profile, d.sources.Profile.Source.UID, installation, cluster)
	if err != nil {
		return nil, &fixedStepError{"profile-document", err}
	}
	body, err := json.Marshal(profile)
	if err != nil {
		return nil, mounts.ErrUnavailable
	}
	if err = kube.ConfigureDownloadWorkerProfile(ctx, admin, installation, d.sources, body); err != nil {
		return nil, err
	}
	d.configured, d.control, d.profile = true, control, profile
	d.template = buildDownloadPathTemplate(cluster, k.downloadRegion(), storeID, pinned.Profile.Configuration, owner.Revision)
	return &promotedDownloads{API: contracts.OwnerNativeWorkerAPI{ClusterID: cluster, Namespace: d.sources.Namespace, Kubernetes: input.Kubernetes}, Source: d.sources.Profile, Template: d.template}, nil
}

// workerControls is the owner's worker trust catalog: the one hub-local
// control document, or none.
func (k *InstallerContinuation) workerControls() [][]byte {
	if k.downloads == nil || !k.downloads.configured {
		return [][]byte{}
	}
	return [][]byte{k.downloads.control}
}

// downloadPathTemplateOrNil is the configured template that both the owner
// and the capacity input pin, or nil without downloads.
func (k *InstallerContinuation) downloadPathTemplateOrNil() *contracts.DownloadEnvironmentPathTemplate {
	if k.downloads == nil || !k.downloads.configured {
		return nil
	}
	t := k.downloads.template
	return &t
}

// DownloadAccepted waits, before the owner launch, until the hub-worker has
// accepted the configured revision and acknowledged its encrypted audit
// (ADR-070), so the hub-api starts with a current audited profile. It reads
// only the revision head with the operator superuser, as the retention
// baseline step does; nothing here accepts or audits anything itself.
func (k *InstallerContinuation) DownloadAccepted(ctx context.Context) error {
	d := k.downloads
	if d == nil {
		return nil
	}
	if !d.configured {
		return mounts.ErrUnavailable
	}
	k.at("downloads/accepted")
	wait, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	c := k.admin.Copy()
	c.MaxConns, c.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(wait, c)
	if err != nil {
		return mounts.ErrUnavailable
	}
	defer pool.Close()
	for {
		var acknowledged bool
		e := pool.QueryRow(wait, downloadAcceptedQuery, k.record.Scope.InstallationID, k.record.Scope.ClusterID, d.sources.Profile.Source.UID, d.profile.Revision).Scan(&acknowledged)
		if e == nil && acknowledged {
			return nil
		}
		select {
		case <-wait.Done():
			return errors.Join(mounts.ErrUnavailable, wait.Err())
		case <-time.After(2 * time.Second):
		}
	}
}

// downloadAcceptedQuery: the source's head is the configured revision and its
// immutable revision row carries the audit acknowledgement (migration 26).
const downloadAcceptedQuery = `SELECT r.audit_receipt_json IS NOT NULL FROM download_worker_configuration c JOIN download_worker_configuration_revision r
 ON r.installation_id=c.installation_id AND r.cluster_id=c.cluster_id AND r.source_uid=c.source_uid AND r.generation=c.generation
 WHERE c.installation_id=$1 AND c.cluster_id=$2 AND c.source_uid=$3 AND c.generation=$4`

// keyServiceDownloads is the key service's acquisition section (ADR-204
// decision 8): the pinned configured profile, which only selects it, and the
// guarded catalog for the topology pins; no fixed pins. Nil without downloads.
func (k *InstallerContinuation) keyServiceDownloads(owner contracts.OwnerDeployment) (*contracts.KeyServiceDownloads, error) {
	d := k.downloads
	if d == nil {
		return nil, nil
	}
	if !d.configured || owner.Public == nil {
		return nil, mounts.ErrUnavailable
	}
	return &contracts.KeyServiceDownloads{WorkerSource: d.sources.Profile.Source, WorkerProfile: d.profile, ClusterCatalog: owner.Public.ClusterCatalog, RetentionTopologies: []contracts.OwnerNativeTopology{}}, nil
}

// downloadEvidenceSetup is the phase-3 artifact's download evidence store, so
// the operator command requires the separate credential (ADR-204 decision 5).
func (k *InstallerContinuation) downloadEvidenceSetup() *contracts.InstallerEvidenceStore {
	if k.downloads == nil {
		return nil
	}
	return k.input.Public.Federation.EvidenceStore
}
