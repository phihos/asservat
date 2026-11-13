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
	"k8s.io/client-go/kubernetes/fake"

	"asservat.local/asservat/internal/contracts"
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
