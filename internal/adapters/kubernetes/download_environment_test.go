package kubernetes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// These use a local TLS API fixture, not a production administrative guard.
func TestDownloadEnvironmentClosedPolicyCannotInventInstalledPlacement(t *testing.T) {
	rev := identity.Revision{UID: ownerID(2), Generation: 1, Digest: artifact.Digest{1}}
	path := privacy.DownloadPath{ID: ownerID(3), TargetClusterID: permissionCluster, StoreID: ownerID(4), StorageRegion: "storage", AcquisitionClusterID: ownerID(5), AcquisitionRegion: "regional", ConnectorClusterID: ownerID(5), ConnectorRegion: "regional", HubClusterID: ownerID(6), HubRegion: "hub", WorkerConfiguration: rev, HubConfiguration: rev}
	wr := contracts.DownloadEnvironmentRevision{UID: rev.UID, Generation: rev.Generation, SHA256: hex.EncodeToString(rev.Digest[:])}
	w := contracts.DownloadEnvironmentSettings{Format: contracts.DownloadEnvironmentFormat, RootID: ownerID(1), InstallationID: ownerID(1), RecoveryEpoch: ownerID(7), Revision: 1, PermittedRegions: []string{"storage", "regional", "hub"}, Paths: []contracts.DownloadEnvironmentPath{{ID: path.ID, TargetClusterID: path.TargetClusterID, StoreID: path.StoreID, StorageRegion: path.StorageRegion, AcquisitionClusterID: path.AcquisitionClusterID, AcquisitionRegion: path.AcquisitionRegion, ConnectorClusterID: path.ConnectorClusterID, ConnectorRegion: path.ConnectorRegion, HubClusterID: path.HubClusterID, HubRegion: path.HubRegion, WorkerConfiguration: wr, HubConfiguration: wr}}, Clients: []contracts.DownloadEnvironmentClient{{Issuer: "https://id.example.test", ID: "browser", Kind: "human", DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, Purposes: []string{"diagnostics"}, PathIDs: []string{path.ID}}}, Operators: []contracts.ProcessingOperator{{Issuer: "https://id.example.test", ClientID: "browser", Kind: "Group", ID: "privacy"}}}
	for _, mode := range []string{"valid", "missing-client-decision", "null-paths", "missing-suspension", "unknown", "duplicate", "alias", "trailing", "uninstalled-path", "substituted-acquisition", "substituted-hub", "invented-region", "foreign-installation", "bad-issuer", "raw-class", "replaced-source"} {
		t.Run(mode, func(t *testing.T) {
			encoded, _ := json.Marshal(w)
			var m map[string]any
			_ = json.Unmarshal(encoded, &m)
			switch mode {
			case "missing-client-decision":
				delete(m, "clients")
			case "null-paths":
				m["paths"] = nil
			case "missing-suspension":
				delete(m, "suspended")
			case "unknown":
				m["allowByDefault"] = true
			case "alias":
				m["Revision"] = m["revision"]
				delete(m, "revision")
			case "uninstalled-path":
				m["paths"].([]any)[0].(map[string]any)["id"] = ownerID(99)
			case "substituted-acquisition":
				m["paths"].([]any)[0].(map[string]any)["acquisitionClusterID"] = ownerID(99)
			case "substituted-hub":
				m["paths"].([]any)[0].(map[string]any)["hubClusterID"] = ownerID(99)
			case "invented-region":
				m["paths"].([]any)[0].(map[string]any)["storageRegion"] = "approved-because-s3-said-so"
			case "foreign-installation":
				m["installationID"] = ownerID(99)
			case "bad-issuer":
				m["clients"].([]any)[0].(map[string]any)["issuer"] = "http://id.example.test"
			case "raw-class":
				m["clients"].([]any)[0].(map[string]any)["dataClasses"] = []string{"raw"}
			}
			b, _ := json.Marshal(m)
			raw := string(b)
			if mode == "duplicate" {
				raw = strings.Replace(raw, `"revision":1`, `"revision":1,"revision":1`, 1)
			}
			if mode == "trailing" {
				raw += `{}`
			}
			var payload atomic.Value
			payload.Store(raw)
			f := newPermissionFixture(t, func(out http.ResponseWriter, r *http.Request) bool {
				if r.URL.Path != "/api/v1/namespaces/"+permissionControl.Name+"/configmaps/processing" {
					return false
				}
				uid := ownerID(8)
				if mode == "replaced-source" {
					uid = ownerID(99)
				}
				permissionReply(out, map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "processing", "namespace": permissionControl.Name, "uid": uid, "resourceVersion": "1"}, "data": map[string]string{"download-environment.json": payload.Load().(string)}})
				return true
			})
			s := &DownloadEnvironmentSource{client: f.client, name: "processing", uid: ownerID(8), root: ownerID(1), installation: ownerID(1), paths: map[string]privacy.DownloadPath{path.ID: path}}
			p, e := s.snapshot(context.Background())
			if mode != "valid" {
				if e == nil {
					t.Fatal("invalid or unaccepted policy accepted")
				}
				return
			}
			if e != nil || !p.WellFormed() || len(p.Paths) != 1 || p.Paths[0] != path {
				t.Fatal("explicit installed placement rejected", e)
			}
			pretty, _ := json.MarshalIndent(m, "", "  ")
			payload.Store(string(pretty))
			again, e := s.snapshot(context.Background())
			if e != nil || again.Revision != p.Revision {
				t.Fatal("formatting changed identity", e)
			}
		})
	}
}
