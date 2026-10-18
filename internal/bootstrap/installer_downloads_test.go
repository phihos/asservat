package bootstrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

func downloadTestRoot(t *testing.T, serial int64) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(serial), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func downloadTestPool() fleet.OwnerPool {
	return fleet.OwnerPool{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, Namespace: "hub", NamespaceUID: runtimeID, Service: "owner", ServiceUID: runtimeID, Deployment: "owner", DeploymentUID: runtimeID,
		ServiceAccount: "owner", AccountUID: runtimeID, Port: 9443, NativePort: 9444, NativeBootstrap: fleet.OwnerBootstrapProfile}
}

func downloadTestSources() kube.DownloadWorkerSources {
	ref := func(name, uid string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: uid}
	}
	return kube.DownloadWorkerSources{Namespace: ref(contracts.DownloadWorkerNamespaceName(runtimeID), "20000000-0000-4000-8000-000000000001"), ServiceAccount: ref(contracts.DownloadWorkerAccountName(runtimeID), "20000000-0000-4000-8000-000000000002"),
		PriorityClass: ref(contracts.DownloadWorkerPriorityClassName(runtimeID), "20000000-0000-4000-8000-000000000003"), StoreCredentials: ref(contracts.DownloadWorkerStoreName(runtimeID), "20000000-0000-4000-8000-000000000004"),
		Profile: contracts.OwnerPublicGuardedSource{Source: ref(contracts.DownloadWorkerProfileName(runtimeID), "20000000-0000-4000-8000-000000000005"),
			Guard: contracts.OwnerDeploymentGuard{Name: contracts.DownloadWorkerProfileGuardName(runtimeID), PolicyUID: runtimeID, PolicyGeneration: 1, BindingUID: runtimeID, BindingResourceVersion: "1", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "runner"}}}}}
}

// ADR-204 decisions 3 and 9: the hub-local control document dials the owner
// Service but names the pool's fixed serving name for enrollment and the
// native path, pins the owner and worker roots, the evidence store with the
// store Secret and the key service scope, and parses with the worker's own
// closed parser; the same inputs give the same bytes and digest.
func TestDownloadWorkerControlDocument(t *testing.T) {
	pool, owner, workers, store, keys := downloadTestPool(), downloadTestRoot(t, 1), downloadTestRoot(t, 2), downloadTestRoot(t, 3), downloadTestRoot(t, 4)
	s := downloadTestSources()
	objectStore := contracts.WorkerNativeStore{ID: runtimeID, Endpoint: "https://store.synthetic.invalid", Region: "synthetic-region", Bucket: "evidence", ServerRoots: [][]byte{store}, CredentialSecretName: s.StoreCredentials.Name, CredentialSecretUID: s.StoreCredentials.UID}
	keyService := contracts.WorkerNativeKeyService{Endpoint: "https://keys.synthetic.invalid:30447", ServerRoots: [][]byte{keys}, Scope: contracts.KeyScope{InstallationID: runtimeID, Purpose: "artifact", KeyID: promotedArtifactKeyID(runtimeID)}}
	raw, err := downloadWorkerControl(runtimeID, runtimeID, pool, [][]byte{owner}, [][]byte{workers}, objectStore, keyService)
	if err != nil {
		t.Fatal(err)
	}
	again, err := downloadWorkerControl(runtimeID, runtimeID, pool, [][]byte{owner}, [][]byte{workers}, objectStore, keyService)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("control document not deterministic", err)
	}
	d1, err := kube.WorkerControlDigest(map[string]string{"worker.json": string(raw)})
	d2, _ := kube.WorkerControlDigest(map[string]string{"worker.json": string(again)})
	if err != nil || d1 != d2 {
		t.Fatal("control digest", err)
	}
	trust, err := mtls.ParseWorkerControl(raw)
	if err != nil || trust.InstallationID != runtimeID || trust.ClusterID != runtimeID || trust.Native() == nil {
		t.Fatal("worker parser refused the control", err)
	}
	var c contracts.WorkerControl
	if err = json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	e, _ := ownerWorkerEndpointsFor(pool)
	n := c.Native
	if c.Format != contracts.WorkerNativeControlFormat || c.Endpoint != e.Endpoint || c.Address != "owner.hub.svc:9443" || n.ExchangeEndpoint != e.ExchangeEndpoint || n.ExchangeAddress != c.Address ||
		!reflect.DeepEqual(c.ServerRoots, [][]byte{owner}) || !reflect.DeepEqual(n.ExchangeServerRoots, [][]byte{owner}) || !reflect.DeepEqual(c.IssuerRoots, [][]byte{workers}) ||
		!reflect.DeepEqual(n.ObjectStore, objectStore) || !reflect.DeepEqual(n.KeyService, keyService) {
		t.Fatal("control pins", string(raw))
	}
	foreign := pool
	foreign.ClusterID = "10000000-0000-4000-8000-0000000000aa"
	if _, err = downloadWorkerControl(runtimeID, runtimeID, foreign, [][]byte{owner}, [][]byte{workers}, objectStore, keyService); err == nil {
		t.Fatal("control for another pool's cluster accepted")
	}
	keyService.Scope.Purpose = "verifier"
	if _, err = downloadWorkerControl(runtimeID, runtimeID, pool, [][]byte{owner}, [][]byte{workers}, objectStore, keyService); err == nil {
		t.Fatal("non-artifact key scope accepted")
	}
}

// The configured profile passes the source reader's own parse, names the
// product image and the exact objects, and its revision is the template's
// worker configuration revision; the template puts the hub in every role.
func TestDownloadWorkerProfileAndPathTemplate(t *testing.T) {
	s := downloadTestSources()
	image := "registry.synthetic.invalid/asservat@sha256:" + strings.Repeat("a", 64)
	control := contracts.LocalKeySecretReference{Name: contracts.DownloadWorkerControlName(runtimeID), UID: "20000000-0000-4000-8000-000000000006", SHA256: strings.Repeat("b", 64)}
	profile := downloadWorkerProfile(runtimeID, runtimeID, runtimeID, image, s, control)
	pinned, err := kube.PinnedWorkerConfiguration(profile, s.Profile.Source.UID, runtimeID, runtimeID)
	if err != nil {
		t.Fatal("profile refused by the source parse", err)
	}
	p := pinned.Profile
	if p.Image != image || p.Namespace != s.Namespace.Name || p.NamespaceUID != s.Namespace.UID || p.ServiceAccountUID != s.ServiceAccount.UID || p.PriorityClassUID != s.PriorityClass.UID ||
		p.StoreCredentialSecretUID != s.StoreCredentials.UID || hex.EncodeToString(p.ControlDigest[:]) != control.SHA256 || p.Configuration.UID != s.Profile.Source.UID || p.Configuration.Generation != 1 ||
		p.CPUMillis != downloadWorkerCPUMillis || p.MemoryBytes != downloadWorkerMemoryBytes || p.MaxRuntime != downloadWorkerMaxRuntimeSeconds*time.Second || pinned.Suspended || !p.Valid() {
		t.Fatal("profile", p)
	}
	body, _ := json.Marshal(profile)
	if len(body) > 16384 {
		t.Fatal("profile too large for the source")
	}
	hub := identity.Revision{UID: "20000000-0000-4000-8000-000000000007", Generation: 3, Digest: [32]byte{7}}
	template := downloadPathTemplate(runtimeID, "synthetic-region", "20000000-0000-4000-8000-000000000008", p.Configuration, hub)
	if template.AcquisitionClusterID != runtimeID || template.ConnectorClusterID != runtimeID || template.HubClusterID != runtimeID || template.StorageRegion != "synthetic-region" || template.AcquisitionRegion != "synthetic-region" ||
		template.ConnectorRegion != "synthetic-region" || template.HubRegion != "synthetic-region" || template.WorkerConfiguration != downloadRevision(p.Configuration) ||
		template.HubConfiguration != (contracts.DownloadEnvironmentRevision{UID: hub.UID, Generation: 3, SHA256: hex.EncodeToString(hub.Digest[:])}) {
		t.Fatal("template", template)
	}
	path := contracts.DownloadPathFor(runtimeID, template, "20000000-0000-4000-8000-000000000009")
	if !(privacy.DownloadPath{ID: path.ID, TargetClusterID: path.TargetClusterID, StoreID: path.StoreID, StorageRegion: path.StorageRegion, AcquisitionClusterID: path.AcquisitionClusterID, AcquisitionRegion: path.AcquisitionRegion,
		ConnectorClusterID: path.ConnectorClusterID, ConnectorRegion: path.ConnectorRegion, HubClusterID: path.HubClusterID, HubRegion: path.HubRegion, WorkerConfiguration: p.Configuration, HubConfiguration: hub}).Valid() {
		t.Fatal("derived path invalid")
	}
}

// The continuation's download environment permits the path's region and
// lists every human identity client for context captures under the baseline
// purpose, with no path yet; the policy stays well formed.
func TestDownloadEnvironmentSettingsWithDownloads(t *testing.T) {
	store := &contracts.InstallerEvidenceStore{Endpoint: "https://store.synthetic.invalid", Region: "synthetic-region", Bucket: "evidence"}
	public := contracts.InstallerPublicSettings{Issuer: "https://id.synthetic.invalid/realms/asservat", Clients: []contracts.IdentityClient{{ID: "console", Kind: "human", ClassQualified: true}, {ID: "mcp", Kind: "workload"}},
		ProcessingOperators: []contracts.ProcessingOperator{{ClientID: "console", Issuer: "https://id.synthetic.invalid/realms/asservat", Kind: "Group", ID: "privacy"}},
		RetentionBaseline:   &contracts.InstallerRetentionBaseline{PurposeRef: "synthetic-baseline"},
		Federation:          &contracts.InstallerFederationSettings{EvidenceStore: store, KeyServiceEndpoint: "https://keys.synthetic.invalid:30447"}, Promotion: &contracts.InstallerOwnerPromotion{}}
	k := &InstallerContinuation{input: contracts.InstallerContinuation{Public: &public}, record: audit.InitialInstallation{Scope: fleet.InstallationWitnessScope{InstallationID: runtimeID, IssuerEpoch: runtimeID}}}
	s := k.processingSettings(runtimeID)
	if !reflect.DeepEqual(s.PermittedRegions, []string{"synthetic-region"}) || len(s.Clients) != 1 || len(s.Paths) != 0 {
		t.Fatal("download settings", s)
	}
	c := s.Clients[0]
	if c.Issuer != public.Issuer || c.ID != "console" || c.Kind != "human" || !reflect.DeepEqual(c.Purposes, []string{"synthetic-baseline"}) || !reflect.DeepEqual(c.EvidenceTypes, []string{"context"}) || c.PathIDs == nil || len(c.PathIDs) != 0 {
		t.Fatal("download client", c)
	}
	policy := privacy.DownloadPolicy{RootID: runtimeID, InstallationID: runtimeID, RecoveryEpoch: runtimeID, Revision: identity.Revision{UID: runtimeID, Generation: 1, Digest: [32]byte{1}}, PermittedRegions: s.PermittedRegions, Paths: []privacy.DownloadPath{},
		Clients:   []privacy.DownloadClient{{Issuer: c.Issuer, ID: c.ID, Kind: identity.Kind(c.Kind), DataClasses: c.DataClasses, PrivacyClasses: c.PrivacyClasses, EvidenceTypes: c.EvidenceTypes, Purposes: c.Purposes, PathIDs: c.PathIDs}},
		Operators: []privacy.ProcessingOperator{{Issuer: public.Issuer, ClientID: "console", Kind: "Group", ID: "privacy"}}}
	if !policy.WellFormed() {
		t.Fatal("download environment would be refused")
	}
	public.RetentionBaseline = nil
	if s = k.processingSettings(runtimeID); len(s.Clients) != 0 || s.Clients == nil {
		t.Fatal("clients without a resolvable purpose")
	}
	public.Federation.EvidenceStore = nil
	if s = k.processingSettings(runtimeID); len(s.PermittedRegions) != 0 || s.PermittedRegions == nil || len(s.Clients) != 0 {
		t.Fatal("download settings without downloads", s)
	}
}

// The worker configuration audit key binds the journal only with downloads,
// on the original configuration audit mount.
func TestWorkerConfigurationAuditSelection(t *testing.T) {
	public := contracts.InstallerPublicSettings{Federation: &contracts.InstallerFederationSettings{EvidenceStore: &contracts.InstallerEvidenceStore{Region: "r"}, KeyServiceEndpoint: "https://keys.synthetic.invalid"}, Promotion: &contracts.InstallerOwnerPromotion{}}
	k := &InstallerContinuation{input: contracts.InstallerContinuation{}, record: audit.InitialInstallation{Scope: fleet.InstallationWitnessScope{InstallationID: runtimeID}}}
	if a, err := k.workerConfigurationAudit(); err != nil || a != (contracts.OwnerPublicTransit{}) {
		t.Fatal("audit key without downloads", a, err)
	}
	k.input.Public = &public
	if _, err := k.workerConfigurationAudit(); err == nil {
		t.Fatal("audit key without the original audit mount")
	}
	k.plan.Services = &contracts.InitialPreparationServices{KeyService: contracts.ConfigurationKeyService{AuditMount: "configuration-audit", AuditKey: "configuration"}}
	a, err := k.workerConfigurationAudit()
	if err != nil || a != (contracts.OwnerPublicTransit{Mount: "configuration-audit", Key: contracts.WorkerConfigurationAuditKeyName(runtimeID)}) {
		t.Fatal("audit key", a, err)
	}
	if _, err = k.workerConfigurationSection(contracts.OwnerDeployment{KeyService: contracts.OwnerKeyService{AuditMount: "configuration-audit", AuditKey: "configuration"}}); err == nil {
		t.Fatal("section without the worker objects")
	}
	k.downloads = &installerDownloads{sources: downloadTestSources()}
	if _, err = k.workerConfigurationSection(contracts.OwnerDeployment{KeyService: contracts.OwnerKeyService{AuditMount: "other-audit", AuditKey: "configuration"}}); err == nil {
		t.Fatal("section on another audit mount")
	}
	section, err := k.workerConfigurationSection(contracts.OwnerDeployment{KeyService: contracts.OwnerKeyService{AuditMount: "configuration-audit", AuditKey: "configuration"}})
	if err != nil || section.Source != k.downloads.sources.Profile.Source || section.Namespace != k.downloads.sources.Namespace || section.AuditTransit != a ||
		!kube.WorkerConfigurationSectionValid(contracts.PermissionDeployment{Control: contracts.PermissionControlDeployment{Namespace: contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}, Guard: contracts.OwnerDeploymentGuard{Name: "permission-guard"}}, WorkerConfiguration: section}) {
		t.Fatal("section", section, err)
	}
}

// The steps fail closed out of order: configuring needs the early worker
// objects, the accepted owner configuration and the capacity store; the
// acceptance wait, key service section, trust catalog and templates need a
// configured profile. Without downloads every step is a no-op.
func TestDownloadStepsFailClosedOutOfOrder(t *testing.T) {
	public := contracts.InstallerPublicSettings{Federation: &contracts.InstallerFederationSettings{EvidenceStore: &contracts.InstallerEvidenceStore{Region: "r"}, KeyServiceEndpoint: "https://keys.synthetic.invalid"}, Promotion: &contracts.InstallerOwnerPromotion{}}
	k := &InstallerContinuation{record: audit.InitialInstallation{Scope: fleet.InstallationWitnessScope{InstallationID: runtimeID, ClusterID: runtimeID}}}
	ctx := t.Context()
	if d, err := k.DownloadConfigure(ctx, kube.InitialRuntimeResourceInventory{}, contracts.OwnerDeployment{}, nil, nil); err != nil || d != nil || k.DownloadAccepted(ctx) != nil || k.downloadEvidenceSetup() != nil || k.workerProfileSource() != nil {
		t.Fatal("download steps without downloads", err)
	}
	if s, err := k.keyServiceDownloads(contracts.OwnerDeployment{}); err != nil || s != nil {
		t.Fatal("key service section without downloads", err)
	}
	if _, err := k.DownloadConfigure(ctx, kube.InitialRuntimeResourceInventory{}, contracts.OwnerDeployment{}, []byte("unexpected"), nil); err == nil {
		t.Fatal("download credential accepted without downloads")
	}
	k.input.Public = &public
	if _, err := k.DownloadConfigure(ctx, kube.InitialRuntimeResourceInventory{}, contracts.OwnerDeployment{}, []byte("{}"), nil); err == nil {
		t.Fatal("configured before the worker objects exist")
	}
	k.downloads = &installerDownloads{sources: downloadTestSources()}
	if _, err := k.DownloadConfigure(ctx, kube.InitialRuntimeResourceInventory{}, contracts.OwnerDeployment{}, []byte("{}"), [][]byte{{1}}); err == nil {
		t.Fatal("configured before the owner configuration and capacity")
	}
	if k.DownloadAccepted(ctx) == nil || len(k.workerControls()) != 0 || k.downloadPathTemplateOrNil() != nil {
		t.Fatal("unconfigured profile treated as configured")
	}
	if _, err := k.keyServiceDownloads(contracts.OwnerDeployment{Public: &contracts.OwnerPublicDeployment{}}); err == nil {
		t.Fatal("key service section before configuration")
	}
	k.downloads.configured, k.downloads.control = true, []byte("control")
	if c := k.workerControls(); len(c) != 1 || string(c[0]) != "control" || k.downloadPathTemplateOrNil() == nil || k.downloadEvidenceSetup() != public.Federation.EvidenceStore {
		t.Fatal("configured pins", c)
	}
	if s, err := k.keyServiceDownloads(contracts.OwnerDeployment{Public: &contracts.OwnerPublicDeployment{ClusterCatalog: contracts.OwnerPublicGuardedSource{Source: contracts.WorkerObjectReference{Name: "catalog", UID: runtimeID}}}}); err != nil ||
		s.WorkerSource != k.downloads.sources.Profile.Source || s.ClusterCatalog.Source.Name != "catalog" || s.RetentionTopologies == nil || len(s.RetentionTopologies) != 0 {
		t.Fatal("key service section", s, err)
	}
}

// ADR-204 decision 5: the operator's static read credential becomes the
// worker's closed credentials.json; temporary credentials cannot renew in an
// immutable Secret and are refused.
func TestDownloadEvidenceCredential(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if b, err := readDownloadEvidenceCredential(""); err != nil || b != nil {
		t.Fatal("absent flag", err)
	}
	for name, body := range map[string]string{"session": `{"accessKeyID":"a","secretAccessKey":"b","sessionToken":"c"}`, "missing": `{"accessKeyID":"a","secretAccessKey":"","sessionToken":""}`, "unknown": `{"accessKeyID":"a","secretAccessKey":"b","sessionToken":"","x":1}`} {
		if _, err := readDownloadEvidenceCredential(write(name, body)); err == nil {
			t.Fatal("accepted", name)
		}
	}
	raw, err := readDownloadEvidenceCredential(write("ok", `{"accessKeyID":"synthetic","secretAccessKey":"synthetic-secret","sessionToken":""}`))
	if err != nil {
		t.Fatal(err)
	}
	store, err := downloadWorkerStoreCredential(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := contracts.DecodeWorkerStoreCredentials(bytes.NewReader(store))
	if err != nil || c.AccessKeyID != "synthetic" || c.SecretAccessKey != "synthetic-secret" || c.SessionToken != "" || c.ExpiresAt != "" || string(store) != `{"accessKeyID":"synthetic","secretAccessKey":"synthetic-secret"}` {
		t.Fatal("worker credential", string(store), err)
	}
}
