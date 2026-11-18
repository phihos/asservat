package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
)

// The combined-mode offer carries the IDs, the connector roots and a valid
// connector backing, decodes with the connector's closed reader and names no
// executor section; an existing offer is never replaced.
func TestHubAPIRegionalOfferBuildAndPublishOnce(t *testing.T) {
	ctx := context.Background()
	ids, _ := readHubAPIIDs(ctx, hubAPIIDsRoot(t, ""))
	h := hubAPIConfigFixture()
	if o := buildHubAPIRegionalOffer(h, ids); o != nil {
		t.Fatal("offer without the combined-mode section")
	}
	h.Public.RegionalOffer = &contracts.HubAPIRegionalOffer{Image: "registry.invalid/asservat@sha256:" + string(bytes.Repeat([]byte("a"), 64))}
	o := buildHubAPIRegionalOffer(h, ids)
	if o == nil || o.name != "asservat-regional-offer" || o.namespace != "hub" {
		t.Fatal("offer")
	}
	raw, _ := json.Marshal(o.offer)
	var back contracts.RegionalOffer
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&back) != nil || back.Format != contracts.RegionalOfferFormat || back.InstallationID != runtimeID || back.IssuerEpoch != runtimeID || back.Complete() {
		t.Fatal("offer content", string(raw))
	}
	var err error
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
	for _, name := range []string{HubAPIDownloadKeyServiceCAFile} {
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
	h.Public.RegionalOffer = &contracts.HubAPIRegionalOffer{Image: "registry.invalid/asservat@sha256:" + string(bytes.Repeat([]byte("a"), 64))}
	o := buildHubAPIRegionalOffer(h, ids)
	c := contracts.OwnerDeployment{InstallationID: runtimeID, AuditStore: contracts.OwnerAuditStore{Roots: hubAPICAFixture},
		Public: &contracts.OwnerPublicDeployment{ArtifactKeyID: artifactKeyID(runtimeID)}}
	if err = o.addExecutor(ctx, root, h, c, "not-a-store", time.Now()); err == nil {
		t.Fatal("executor without the evidence store ID")
	}
	if err = o.addExecutor(ctx, root, h, c, runtimeID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if o.offer.Complete() {
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
	if !back.Complete() || back.KeyService.Endpoint != "https://asservat-key-service.hub.svc:9447" || back.EvidenceStore.StoreID != runtimeID || back.EvidenceStore.Bucket != "asservat-evidence" {
		t.Fatal("executor section", string(raw))
	}
	// A kept offer from before owner-directed tunnels can be read after upgrade.
	legacy := bytes.Replace(raw, []byte(`"owners":{`), []byte(`"owners":{"address":"old-native.hub.svc:9444",`), 1)
	if bytes.Equal(raw, legacy) {
		t.Fatal("legacy offer missing owners")
	}
	legacyAPI := fake.NewSimpleClientset(&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: o.name, Namespace: o.namespace}, Data: map[string]string{contracts.RegionalOfferFile: string(legacy)}})
	if stored, err := o.ensure(ctx, legacyAPI); err != nil || !stored.Complete() || stored.Owners.Configuration.Service != back.Owners.Configuration.Service {
		t.Fatal("could not reuse the stored owner pool", err)
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
	c.Namespace, c.PermissionRootID, c.Public.Captures = contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}, runtimeID, 1
	local, err := localCatalogCluster(c, o, stored)
	if err != nil {
		t.Fatal("local cluster", err)
	}
	if local.Connector.SourceUID != peer || local.ClusterID != runtimeID {
		t.Fatal("local connector peer", local.Connector)
	}
	if local.Standby != local.Captures+1 {
		t.Fatal("local catalog entry", local.Standby)
	}
	// A registered mode=cluster cluster derives the same entry for its own IDs
	// and release namespace; no executor digest is pinned (ADR-334).
	const remote = "40000000-0000-4000-8000-000000000001"
	remotePeer, ok := contracts.RemotePeerID(runtimeID, remote)
	if !ok || remotePeer == peer {
		t.Fatal("remote peer", remotePeer)
	}
	entry, err := catalogCluster(stored, stored.Image, remote, remotePeer, "asservat-system", "asservat", 1, "remote-cluster")
	if err != nil {
		t.Fatal("remote cluster", err)
	}
	if entry.Connector.SourceUID != remotePeer || entry.ClusterID != remote {
		t.Fatal("remote connector peer", entry.Connector)
	}
	// The first stored offer stays: a second ensure returns it unchanged.
	again, err := o.ensure(ctx, api)
	if err != nil || again.EvidenceStore.StoreID != stored.EvidenceStore.StoreID {
		t.Fatal("stored offer replaced", err)
	}
}
