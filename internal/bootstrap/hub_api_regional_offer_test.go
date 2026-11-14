package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// The combined-mode offer carries the IDs, the connector roots and a valid
// connector backing, decodes with the connector's closed reader and names no
// executor section; an existing offer is never replaced.
func TestHubAPIRegionalOfferBuildAndPublishOnce(t *testing.T) {
	ctx := context.Background()
	files := hubAPIFiles(t, "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, contracts.HubAPIFederationCAFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hubAPICAFixture[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ids, _ := readHubAPIIDs(ctx, hubAPIIDsRoot(t, ""))
	h := hubAPIConfigFixture()
	if o, err := buildHubAPIRegionalOffer(ctx, root, h, ids, hubAPICAFixture, time.Now()); o != nil || err != nil {
		t.Fatal("offer without the combined-mode section", err)
	}
	h.Public.RegionalOffer = &contracts.HubAPIRegionalOffer{Federation: "https://asservat-federation.hub.svc:9446", ServerName: "asservat-federation.hub.svc", Image: "registry.invalid/asservat@sha256:" + string(bytes.Repeat([]byte("a"), 64)),
		Connector: contracts.InstallerConnectorSettings{Accounts: 1, RecordsPerAccount: 96, RetainedSeconds: 4000, Profiles: 1, SourceTransitions: 8, PurgeLeases: 2, ValidSeconds: 3600, Footprint: contracts.InstallerCapacityFootprint{RowBytes: 1 << 20, TransitionWALBytes: 1 << 20}},
		Backup:    contracts.InstallerCapacityBackup{HorizonSeconds: 1, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 1, WALCopies: 1}}
	if _, err := buildHubAPIRegionalOffer(ctx, files, h, ids, hubAPICAFixture, time.Now()); err == nil {
		t.Fatal("offer without the federation CA")
	}
	o, err := buildHubAPIRegionalOffer(ctx, root, h, ids, hubAPICAFixture, time.Now())
	if err != nil || o == nil || o.name != "asservat-regional-offer" || o.namespace != "hub" {
		t.Fatal("offer", err)
	}
	raw, _ := json.Marshal(o.offer)
	var back contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&back) != nil || back.Format != contracts.RegionalOfferFormat || back.InstallationID != runtimeID || back.IssuerEpoch != runtimeID || len(back.ConnectorIssuerRoots) != 1 || len(back.ConnectorBacking) == 0 || len(back.Federation.Roots) != 1 || back.Roles.Source == "" {
		t.Fatal("offer content", string(raw))
	}
	if executor, err := back.RegionalExecutorOffered(); err != nil || executor {
		t.Fatal("plain connector offer", executor, err)
	}

	api := fake.NewSimpleClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: o.name, Namespace: o.namespace}})
	if err = o.write(ctx, api, string(raw)); err != nil {
		t.Fatal(err)
	}
	got, _ := api.CoreV1().ConfigMaps(o.namespace).Get(ctx, o.name, meta.GetOptions{})
	if got.Data[contracts.RegionalOfferFile] != string(raw) {
		t.Fatal("offer not written")
	}
	if err = o.write(ctx, api, `{"other":true}`); err != nil {
		t.Fatal(err)
	}
	got, _ = api.CoreV1().ConfigMaps(o.namespace).Get(ctx, o.name, meta.GetOptions{})
	if got.Data[contracts.RegionalOfferFile] != string(raw) {
		t.Fatal("published offer replaced")
	}
}

// mode=combined: the offer carries the complete regional executor section —
// key service, work key, evidence store and the accepted owner pool — which
// the connector's own conversion accepts.
func TestHubAPIRegionalOfferExecutorSection(t *testing.T) {
	ctx := context.Background()
	hubAPIFiles(t, "")
	dir := t.TempDir()
	for _, name := range []string{contracts.HubAPIFederationCAFile, HubAPIDownloadKeyServiceCAFile} {
		if err := os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hubAPICAFixture[0]}), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ids, _ := readHubAPIIDs(ctx, hubAPIIDsRoot(t, ""))
	h := hubAPIConfigFixture()
	h.Public.RegionalOffer = &contracts.HubAPIRegionalOffer{Federation: "https://asservat-federation.hub.svc:9446", ServerName: "asservat-federation.hub.svc", Image: "registry.invalid/asservat@sha256:" + string(bytes.Repeat([]byte("a"), 64)),
		Connector: contracts.InstallerConnectorSettings{Accounts: 1, RecordsPerAccount: 96, RetainedSeconds: 4000, Profiles: 1, SourceTransitions: 8, PurgeLeases: 2, ValidSeconds: 3600, Footprint: contracts.InstallerCapacityFootprint{RowBytes: 1 << 20, TransitionWALBytes: 1 << 20}},
		Backup:    contracts.InstallerCapacityBackup{HorizonSeconds: 1, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, BackupCopies: 1, WALCopies: 1}}
	o, err := buildHubAPIRegionalOffer(ctx, root, h, ids, hubAPICAFixture, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c := contracts.OwnerDeployment{InstallationID: runtimeID, AuditStore: contracts.OwnerAuditStore{Roots: hubAPICAFixture},
		Public: &contracts.OwnerPublicDeployment{ArtifactKeyID: artifactKeyID(runtimeID), WorkSigning: contracts.OwnerPublicSigning{KeyID: "work-v1", PublicKey: bytes.Repeat([]byte{1}, 32)}}}
	if err = o.addExecutor(ctx, root, h, c, "not-a-store", time.Now()); err == nil {
		t.Fatal("executor without the evidence store ID")
	}
	if err = o.addExecutor(ctx, root, h, c, runtimeID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if offered, err := o.offer.RegionalExecutorOffered(); err == nil || offered {
		t.Fatal("partial executor section offered before the owners")
	}
	pool := value.OwnerPool{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, Namespace: "hub", NamespaceUID: runtimeID, Service: "asservat-hub-api-owner", ServiceUID: runtimeID, Deployment: "asservat-hub-api", DeploymentUID: runtimeID, ServiceAccount: "asservat-hub-api", AccountUID: runtimeID, Port: 9443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
	if err = o.setOwners(pool, 3, hubAPICAFixture); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(o.offer)
	var back contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&back) != nil {
		t.Fatal("offer decode")
	}
	if offered, err := back.RegionalExecutorOffered(); err != nil || !offered || back.Owners.Address != "asservat-hub-api-native.hub.svc:9444" || back.KeyService.Endpoint != "https://asservat-key-service.hub.svc:9447" || back.EvidenceStore.StoreID != runtimeID || back.EvidenceStore.Bucket != "asservat-evidence" || back.WorkKey.ID != "work-v1" {
		t.Fatal("executor section", string(raw))
	}
	cfg := regionalConfig{binding: value.PeerBinding{InstallationID: runtimeID, IssuerEpoch: runtimeID}}
	if p, err := regionalOwnerPool(cfg, back.Owners.Configuration); err != nil || p != pool {
		t.Fatal("connector refused the offered owner pool", err)
	}
	// The local catalog entry pins the identity document and executor the
	// local connector derives from the stored offer.
	const peer, accountUID, capacityUID = "30000000-0000-4000-8000-000000000001", "30000000-0000-4000-8000-000000000002", "30000000-0000-4000-8000-000000000003"
	o.peerID = peer
	api := fake.NewClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "asservat-regional-offer", Namespace: "hub"}},
		&core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "asservat-connector", Namespace: "hub", UID: types.UID(accountUID)}})
	stored, err := o.ensure(ctx, api)
	if err != nil {
		t.Fatal("ensure", err)
	}
	c.Namespace, c.PermissionRootID, c.Public.Standby, c.Public.Captures = contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}, runtimeID, 2, 1
	local, err := localCatalogCluster(c, o, stored)
	if err != nil {
		t.Fatal("local cluster", err)
	}
	profile, err := publicConnectorProfile(local, runtimeID, runtimeID)
	if err != nil || profile.Binding.PeerID != peer || profile.Binding.ClusterID != runtimeID {
		t.Fatal("local connector profile", err)
	}
	binding := value.PeerBinding{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PeerID: peer, Role: value.ConnectorPeer}
	settings, err := kube.ConnectorAPISettings(runtimeID, binding, kube.ConnectorWorkload{Namespace: "hub", NamespaceUID: runtimeID, Account: "asservat-connector", AccountUID: accountUID, Deployment: "asservat-connector", DeploymentUID: runtimeID, Digest: kube.ConnectorWorkloadDigest(runtimeID, "hub", "asservat-connector")}, "asservat-connector-capacity", capacityUID, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	startup := kube.ConnectorAPIStartupDigest(settings)
	if local.Executor.StartupDigest != hex.EncodeToString(startup[:]) || local.Trust.Keys[0].ID != "work-v1" || local.Standby != 2 {
		t.Fatal("local executor pin differs from the connector's", local.Executor)
	}
	// A joined mode=cluster cluster derives the same entry for its own IDs
	// and release namespace, and its connector computes the same pin.
	const remote = "40000000-0000-4000-8000-000000000001"
	remotePeer, ok := contracts.RemotePeerID(runtimeID, remote)
	if !ok || remotePeer == peer {
		t.Fatal("remote peer", remotePeer)
	}
	entry, err := catalogCluster(stored, stored.Image, remote, remotePeer, "asservat-system", "asservat", 2, 1, "remote-cluster")
	if err != nil {
		t.Fatal("remote cluster", err)
	}
	if profile, err := publicConnectorProfile(entry, runtimeID, runtimeID); err != nil || profile.Binding.PeerID != remotePeer || profile.Binding.ClusterID != remote || profile.Deployment.Namespace != "asservat-system" {
		t.Fatal("remote connector profile", err)
	}
	binding = value.PeerBinding{InstallationID: runtimeID, ClusterID: remote, IssuerEpoch: runtimeID, PeerID: remotePeer, Role: value.ConnectorPeer}
	settings, err = kube.ConnectorAPISettings(runtimeID, binding, kube.ConnectorWorkload{Namespace: "asservat-system", NamespaceUID: "40000000-0000-4000-8000-000000000002", Account: "asservat-connector", AccountUID: accountUID, Deployment: "asservat-connector", DeploymentUID: runtimeID, Digest: kube.ConnectorWorkloadDigest(remote, "asservat-system", "asservat-connector")}, "asservat-connector-capacity", capacityUID, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if startup = kube.ConnectorAPIStartupDigest(settings); entry.Executor.StartupDigest != hex.EncodeToString(startup[:]) {
		t.Fatal("remote executor pin differs from the connector's")
	}
	// The join offer dials the configured addresses and verifies the
	// in-cluster names; backing and roots are the stored offer's.
	addresses := &contracts.HubAPIRemote{Federation: "https://hub.example.test:31446", Owners: "hub.example.test:31447", KeyService: "https://hub.example.test:31448", ObjectStore: "https://hub.example.test:31433"}
	join, err := remoteJoinOffer(stored, addresses)
	if err != nil {
		t.Fatal("join offer", err)
	}
	if join.Federation.Endpoint != addresses.Federation || join.Federation.ServerName != stored.Federation.ServerName || join.Owners.Address != addresses.Owners || join.KeyService.Endpoint != addresses.KeyService || join.KeyService.ServerName != "asservat-key-service.hub.svc" ||
		join.EvidenceStore.Endpoint != addresses.ObjectStore || join.EvidenceStore.ServerName == "" || !bytes.Equal(join.ConnectorBacking, stored.ConnectorBacking) || stored.KeyService.ServerName != "" {
		t.Fatalf("join offer %+v", join.KeyService)
	}
	addresses.Owners = "https://hub.example.test:31447"
	if _, err = remoteJoinOffer(stored, addresses); err == nil {
		t.Fatal("owners URL accepted as a dial address")
	}
	// The first stored offer stays: a second ensure returns it unchanged.
	again, err := o.ensure(ctx, api)
	if err != nil || again.WorkKey.NotBefore != stored.WorkKey.NotBefore {
		t.Fatal("stored offer replaced", err)
	}
}
