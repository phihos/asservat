package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

// ADR-196 step 5: the join creates the slot's guarded sources and topology
// and appends the entry by CAS; a rerun is exact, and another entry for the
// same cluster or a full catalog is refused.
func TestJoinRegionalClusterCreatesSlotAndAppendsExactly(t *testing.T) {
	installation := ownerID(1)
	catalogName := contracts.OwnerClusterCatalogName(installation)
	catalogPath := "/api/v1/namespaces/hub/configmaps/" + catalogName
	empty, _ := json.Marshal(contracts.OwnerClusterCatalog{Format: contracts.OwnerClusterCatalogFormat, Clusters: []contracts.OwnerPublicCluster{}})
	api := newJoinAPI(t)
	api.put(catalogPath, catalogName, ownerID(50), contracts.OwnerClusterCatalogFile, string(empty))
	config := api.config
	cluster := ownerID(5)
	plan := ClusterJoinPlan{Control: cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}, Installation: installation, Slot: 1, Admins: []cfg.KubernetesActor{{Kind: "Group", Name: "synthetic-admins"}},
		Catalog:  contracts.WorkerObjectReference{Name: catalogName, UID: ownerID(50)},
		Topology: contracts.RetentionTopologySettings{SchemaVersion: "retention-topology/v1", Revision: 1, RootID: ownerID(3), TargetClusterID: cluster, Hub: contracts.RetentionPolicySource{ClusterID: ownerID(4), ControlNamespaceUID: ownerID(2), ProtectionSHA256: strings.Repeat("ab", 32)}},
		Entry: contracts.OwnerPublicCluster{ClusterID: cluster, Standby: 1, Captures: 1, Settings: contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, ClusterID: cluster},
			Trust: contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, ClusterID: cluster, Revision: 1, Keys: []contracts.APIContextWorkPublicKey{{ID: "work-v1"}}}}}
	first, err := JoinRegionalCluster(context.Background(), config, plan)
	if err != nil {
		t.Fatal(err)
	}
	if first.Capability.Source.Name != contracts.OwnerClusterSourceName(installation, 1, "capability") || first.WorkTrust.Guard.PolicyUID == "" || first.Topology.Name != contracts.OwnerClusterSourceName(installation, 1, "topology") || len(first.Topology.SHA256) != 64 {
		t.Fatal("slot sources", first)
	}
	read := func() contracts.OwnerClusterCatalog {
		c, err := contracts.DecodeOwnerClusterCatalog(strings.NewReader(api.data(t, catalogPath, contracts.OwnerClusterCatalogFile)))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := read(); len(c.Clusters) != 1 || !equalJSON(c.Clusters[0], first) {
		t.Fatal("catalog entry not appended")
	}
	again, err := JoinRegionalCluster(context.Background(), config, plan)
	if err != nil || !equalJSON(again, first) || len(read().Clusters) != 1 {
		t.Fatal("rerun not exact", err)
	}
	changed := plan
	changed.Entry.Standby = 2
	if _, err = JoinRegionalCluster(context.Background(), config, changed); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("another entry for the joined cluster accepted", err)
	}
	other := plan
	other.Entry.ClusterID, other.Entry.Settings.ClusterID, other.Entry.Trust.ClusterID, other.Topology.TargetClusterID = ownerID(6), ownerID(6), ownerID(6), ownerID(6)
	if _, err = JoinRegionalCluster(context.Background(), config, other); err == nil {
		t.Fatal("a second cluster joined beyond the slot")
	}
}

// ADR-204 decision 4: after the catalog entry the join adds the cluster's
// derived path to each guarded download environment source and its ID to
// every client, under the next revision. A rerun writes nothing; another
// path with the same ID or a replaced source refuses; without the section no
// source is touched.
func TestJoinRegionalClusterAddsDownloadPathOnce(t *testing.T) {
	installation, root, cluster := ownerID(1), ownerID(3), ownerID(5)
	catalogName := contracts.OwnerClusterCatalogName(installation)
	catalogPath := "/api/v1/namespaces/hub/configmaps/" + catalogName
	environment, processing := contracts.OwnerDownloadEnvironmentName(installation), installedProcessingSource(installation)
	environmentPath, processingPath := "/api/v1/namespaces/hub/configmaps/"+environment, "/api/v1/namespaces/hub/configmaps/"+processing
	empty, _ := json.Marshal(contracts.OwnerClusterCatalog{Format: contracts.OwnerClusterCatalogFormat, Clusters: []contracts.OwnerPublicCluster{}})
	pinned := contracts.DownloadEnvironmentPath{ID: ownerID(70), TargetClusterID: ownerID(71), StoreID: ownerID(72), StorageRegion: "synthetic-store", AcquisitionClusterID: ownerID(4), AcquisitionRegion: "synthetic-hub",
		ConnectorClusterID: ownerID(4), ConnectorRegion: "synthetic-hub", HubClusterID: ownerID(4), HubRegion: "synthetic-hub",
		WorkerConfiguration: contracts.DownloadEnvironmentRevision{UID: ownerID(73), Generation: 1, SHA256: strings.Repeat("ab", 32)}, HubConfiguration: contracts.DownloadEnvironmentRevision{UID: ownerID(74), Generation: 1, SHA256: strings.Repeat("cd", 32)}}
	client := func(id string, paths ...string) contracts.DownloadEnvironmentClient {
		return contracts.DownloadEnvironmentClient{Issuer: "https://issuer.synthetic.invalid", ID: id, Kind: "human", DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"},
			EvidenceTypes: []string{"context"}, Purposes: []string{"incident"}, PathIDs: append([]string{}, paths...)}
	}
	settings := contracts.DownloadEnvironmentSettings{Format: contracts.DownloadEnvironmentFormat, RootID: root, InstallationID: installation, RecoveryEpoch: ownerID(75), Revision: 3, PermittedRegions: []string{},
		Paths:     []contracts.DownloadEnvironmentPath{pinned},
		Operators: []contracts.ProcessingOperator{{ClientID: "synthetic-console", Issuer: "https://issuer.synthetic.invalid", Kind: "Group", ID: "synthetic-operators"}},
		Clients:   []contracts.DownloadEnvironmentClient{client("synthetic-downloads", pinned.ID), client("synthetic-mcp")}}
	body, _ := json.Marshal(settings)
	api := newJoinAPI(t)
	api.put(catalogPath, catalogName, ownerID(50), contracts.OwnerClusterCatalogFile, string(empty))
	api.put(environmentPath, environment, ownerID(51), contracts.DownloadEnvironmentFile, string(body))
	api.put(processingPath, processing, ownerID(52), contracts.DownloadEnvironmentFile, string(body))
	path := pinned
	path.ID, path.TargetClusterID = ownerID(80), cluster
	plan := ClusterJoinPlan{Control: cfg.NamespaceRef{Name: "hub", UID: ownerID(2)}, Installation: installation, Slot: 1, Admins: []cfg.KubernetesActor{{Kind: "Group", Name: "synthetic-admins"}},
		Catalog:  contracts.WorkerObjectReference{Name: catalogName, UID: ownerID(50)},
		Topology: contracts.RetentionTopologySettings{SchemaVersion: "retention-topology/v1", Revision: 1, RootID: root, TargetClusterID: cluster, Hub: contracts.RetentionPolicySource{ClusterID: ownerID(4), ControlNamespaceUID: ownerID(2), ProtectionSHA256: strings.Repeat("ab", 32)}},
		Entry: contracts.OwnerPublicCluster{ClusterID: cluster, Standby: 1, Captures: 1, Settings: contracts.ContextCapabilitySettings{Format: contracts.ContextCapabilityFormat, ClusterID: cluster},
			Trust: contracts.APIContextWorkTrustSettings{Format: contracts.APIContextTrustFormat, ClusterID: cluster, Revision: 1, Keys: []contracts.APIContextWorkPublicKey{{ID: "work-v1"}}}},
		Downloads: &ClusterJoinDownloads{RootID: root, Path: path, Sources: []contracts.WorkerObjectReference{{Name: environment, UID: ownerID(51)}, {Name: processing}}}}
	read := func(at string) contracts.DownloadEnvironmentSettings {
		var out contracts.DownloadEnvironmentSettings
		if err := strictGuardJSON([]byte(api.data(t, at, contracts.DownloadEnvironmentFile)), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	puts := func(at string) int {
		api.mu.Lock()
		defer api.mu.Unlock()
		return api.puts[at]
	}

	// Without the section the sources are untouched.
	without := plan
	without.Downloads = nil
	if _, err := JoinRegionalCluster(context.Background(), api.config, without); err != nil {
		t.Fatal(err)
	}
	if puts(environmentPath) != 0 || puts(processingPath) != 0 || !equalJSON(read(environmentPath), settings) {
		t.Fatal("a join without a path changed a download source")
	}
	for range 2 {
		if _, err := JoinRegionalCluster(context.Background(), api.config, plan); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []string{environmentPath, processingPath} {
		got := read(at)
		if puts(at) != 1 || got.Revision != 4 || len(got.Paths) != 2 || got.Paths[0] != pinned || got.Paths[1] != path ||
			!slices.Equal(got.Clients[0].PathIDs, []string{pinned.ID, path.ID}) || !slices.Equal(got.Clients[1].PathIDs, []string{path.ID}) ||
			!equalJSON(got.Operators, settings.Operators) || !equalJSON(got.PermittedRegions, settings.PermittedRegions) {
			t.Fatal("download source after the join and its rerun", at, puts(at), got)
		}
	}
	if c, err := contracts.DecodeOwnerClusterCatalog(strings.NewReader(api.data(t, catalogPath, contracts.OwnerClusterCatalogFile))); err != nil || len(c.Clusters) != 1 {
		t.Fatal("catalog entry", err)
	}

	conflicting := plan
	downloads := *plan.Downloads
	downloads.Path.StoreID = ownerID(90)
	conflicting.Downloads = &downloads
	if _, err := JoinRegionalCluster(context.Background(), api.config, conflicting); !errors.Is(err, cfg.ErrChanged) {
		t.Fatal("another path with the joined ID accepted", err)
	}
	replaced := plan
	downloads = *plan.Downloads
	downloads.Sources = []contracts.WorkerObjectReference{{Name: environment, UID: ownerID(59)}}
	replaced.Downloads = &downloads
	if _, err := JoinRegionalCluster(context.Background(), api.config, replaced); err == nil {
		t.Fatal("a replaced download environment source accepted")
	}
	for name, bad := range map[string]func(*ClusterJoinDownloads){
		"target":    func(d *ClusterJoinDownloads) { d.Path.TargetClusterID = ownerID(6) },
		"root":      func(d *ClusterJoinDownloads) { d.RootID = "root" },
		"no source": func(d *ClusterJoinDownloads) { d.Sources = nil },
		"twice": func(d *ClusterJoinDownloads) {
			d.Sources = []contracts.WorkerObjectReference{{Name: processing}, {Name: processing}}
		},
	} {
		invalid := plan
		downloads = *plan.Downloads
		bad(&downloads)
		invalid.Downloads = &downloads
		if _, err := JoinRegionalCluster(context.Background(), api.config, invalid); !errors.Is(err, cfg.ErrInvalid) {
			t.Fatal(name, "accepted", err)
		}
	}
	if puts(environmentPath) != 1 || puts(processingPath) != 1 {
		t.Fatal("a refused join wrote a download source")
	}
}

// joinAPI is a synthetic ConfigMap API: create-only POST, CAS PUT with an
// increasing resourceVersion, and GET.
type joinAPI struct {
	mu      sync.Mutex
	objects map[string]map[string]any
	puts    map[string]int
	version int
	config  *rest.Config
}

func newJoinAPI(t *testing.T) *joinAPI {
	t.Helper()
	a := &joinAPI{objects: map[string]map[string]any{}, puts: map[string]int{}, version: 1}
	status := func(w http.ResponseWriter, code int, reason meta.StatusReason) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{Kind: "Status", APIVersion: "v1"}, Status: meta.StatusFailure, Reason: reason, Code: int32(code)})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		var body map[string]any
		switch r.Method {
		case http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&body)
			m := body["metadata"].(map[string]any)
			key := r.URL.Path + "/" + m["name"].(string)
			if _, ok := a.objects[key]; ok {
				status(w, 409, meta.StatusReasonAlreadyExists)
				return
			}
			a.version++
			m["uid"], m["generation"], m["resourceVersion"] = ownerID(len(a.objects)+10), 1, strconv.Itoa(a.version)
			a.objects[key] = body
			_ = json.NewEncoder(w).Encode(body)
		case http.MethodPut:
			_ = json.NewDecoder(r.Body).Decode(&body)
			old, ok := a.objects[r.URL.Path]
			if !ok {
				status(w, 404, meta.StatusReasonNotFound)
				return
			}
			if body["metadata"].(map[string]any)["resourceVersion"] != old["metadata"].(map[string]any)["resourceVersion"] {
				status(w, 409, meta.StatusReasonConflict)
				return
			}
			a.version++
			body["metadata"].(map[string]any)["resourceVersion"] = strconv.Itoa(a.version)
			a.objects[r.URL.Path] = body
			a.puts[r.URL.Path]++
			_ = json.NewEncoder(w).Encode(body)
		default:
			if o, ok := a.objects[r.URL.Path]; ok {
				_ = json.NewEncoder(w).Encode(o)
				return
			}
			status(w, 404, meta.StatusReasonNotFound)
		}
	}))
	t.Cleanup(server.Close)
	a.config = &rest.Config{Host: server.URL, BearerToken: "synthetic-only", TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}
	return a
}

func (a *joinAPI) put(path, name, uid, key, value string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version++
	a.objects[path] = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": name, "namespace": "hub", "uid": uid, "resourceVersion": strconv.Itoa(a.version)}, "data": map[string]any{key: value}}
}

func (a *joinAPI) data(t *testing.T, path, key string) string {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.objects[path]["data"].(map[string]any)[key].(string)
}
