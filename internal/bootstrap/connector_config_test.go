package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/types"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func connectorTestID(n string) string { return "10000000-0000-4000-8000-0000000000" + n }

// connectorTestOffer is a synthetic executor offer; roots are the fixture CA.
func connectorTestOffer(t *testing.T, roots [][]byte) contracts.RegionalOffer {
	t.Helper()
	id := connectorTestID
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC()
	return contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: id("01"), HubClusterID: id("30"), PermissionRootID: id("03"), IssuerEpoch: id("04"),
		Federation:            contracts.RegionalHubEndpoint{Endpoint: "https://federation.synthetic.invalid:30443", ServerName: "federation.synthetic.invalid", Roots: roots},
		ConnectorServerSuffix: "connectors.synthetic.invalid", ConnectorIssuerRoots: roots, ConnectorBacking: json.RawMessage(`{}`), Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64),
		Owners: &contracts.RegionalContextOwners{Address: "hub.synthetic.invalid:30444", Configuration: contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat, InstallationID: id("01"), ClusterID: id("30"), IssuerEpoch: id("04"), Revision: 1,
			Namespace: contracts.WorkerObjectReference{Name: "asservat", UID: id("31")}, Service: contracts.WorkerObjectReference{Name: "hub-api", UID: id("32")}, Deployment: contracts.WorkerObjectReference{Name: "hub-api", UID: id("33")}, ServiceAccount: contracts.WorkerObjectReference{Name: "hub-api", UID: id("34")}, Port: 9443, NativePort: 9444, IssuerRoots: roots}},
		KeyService:    &contracts.RegionalWrapService{Endpoint: "https://keys.synthetic.invalid:30448", Roots: roots, KeyID: "artifact-key"},
		WorkKey:       &contracts.APIContextWorkPublicKey{ID: "synthetic-key", PublicKey: base64.RawURLEncoding.EncodeToString(public), NotBefore: n.Add(-time.Minute).Format(time.RFC3339Nano), NotAfter: n.Add(time.Hour).Format(time.RFC3339Nano)},
		EvidenceStore: &contracts.RegionalEvidenceStore{Endpoint: "https://evidence.synthetic.invalid", Roots: roots, Region: "local", Bucket: "evidence", StoreID: connectorTestID("14")}}
}

func connectorTestConfig(offer contracts.RegionalOffer) contracts.ConnectorConfig {
	return contracts.ConnectorConfig{Format: contracts.ConnectorConfigFormat, Mode: contracts.ConnectorModeCluster, ClusterID: connectorTestID("02"), PeerID: connectorTestID("05"), Namespace: "asservat-region",
		Deployment: "asservat-connector", ServiceAccount: "asservat-connector", ClusterCredential: "asservat-cluster-credential", ImageDigest: strings.Repeat("a", 64), Offer: &offer,
		Executor: &contracts.ConnectorExecutorConfig{CapacityAccount: "asservat-connector-capacity", CapacityAudience: "https://kubernetes.default.svc", Concurrency: 4}}
}

// The loader accepts exactly one topology's inputs and the Helm-rendered
// names; every other combination stops the process before any client.
func TestConnectorConfigIsClosed(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	offer := connectorTestOffer(t, [][]byte{f.ca.Raw})
	if err := validConnectorConfig(connectorTestConfig(offer)); err != nil {
		t.Fatal("cluster mode", err)
	}
	combined := connectorTestConfig(offer)
	combined.Mode, combined.Offer, combined.OfferConfigMap = contracts.ConnectorModeCombined, nil, "asservat-regional-offer"
	combined.Hub = &contracts.ConnectorHubAddresses{Federation: "https://asservat-federation.asservat.svc:8443", Owners: "asservat-hub-api.asservat.svc:9444", KeyService: "https://asservat-key-service.asservat.svc:8448"}
	if err := validConnectorConfig(combined); err != nil {
		t.Fatal("combined mode", err)
	}
	for name, mutate := range map[string]func(*contracts.ConnectorConfig){
		"format":                    func(c *contracts.ConnectorConfig) { c.Format = "asservat-regional-deployment/v1" },
		"mode":                      func(c *contracts.ConnectorConfig) { c.Mode = "hub" },
		"cluster without offer":     func(c *contracts.ConnectorConfig) { c.Offer = nil },
		"cluster with addresses":    func(c *contracts.ConnectorConfig) { c.Hub = combined.Hub },
		"cluster ID":                func(c *contracts.ConnectorConfig) { c.ClusterID = "cluster" },
		"peer ID":                   func(c *contracts.ConnectorConfig) { c.PeerID = "" },
		"namespace":                 func(c *contracts.ConnectorConfig) { c.Namespace = "Region" },
		"credential name":           func(c *contracts.ConnectorConfig) { c.ClusterCredential = "" },
		"image digest":              func(c *contracts.ConnectorConfig) { c.ImageDigest = "latest" },
		"capacity is the connector": func(c *contracts.ConnectorConfig) { c.Executor.CapacityAccount = c.ServiceAccount },
		"no concurrency":            func(c *contracts.ConnectorConfig) { c.Executor.Concurrency = 0 },
		"alertmanager credentials":  func(c *contracts.ConnectorConfig) { c.Executor.Alertmanager = "http://user:pass@alerts.invalid" },
		"collector in connector namespace": func(c *contracts.ConnectorConfig) {
			c.Collector = &contracts.RegionalCollector{Namespace: c.Namespace, DaemonSet: "node", ServiceAccount: "node", ListenerSecret: "nodes", RootConfigMap: "nodes", ServerName: "nodes.svc"}
		},
	} {
		c := connectorTestConfig(offer)
		x := *c.Executor
		c.Executor = &x
		mutate(&c)
		if validConnectorConfig(c) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad := combined
	bad.Hub = &contracts.ConnectorHubAddresses{Federation: "http://asservat-federation.asservat.svc:8443"}
	if validConnectorConfig(bad) == nil {
		t.Error("plain HTTP federation accepted")
	}
}

// Combined mode dials the in-cluster addresses but keeps the offer's server
// names and roots; the binding is the browser receipt's cluster and peer.
func TestResolveConnectorConfigAppliesAddressesAndBinding(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	offer := connectorTestOffer(t, [][]byte{f.ca.Raw})
	c := connectorTestConfig(offer)
	out, err := resolveRegionalConfig(t.Context(), nil, c)
	if err != nil {
		t.Fatal(err)
	}
	if !out.executor || out.binding.ClusterID != c.ClusterID || out.binding.PeerID != c.PeerID || out.binding.InstallationID != offer.InstallationID || out.binding.IssuerEpoch != offer.IssuerEpoch || out.hub.Endpoint != offer.Federation.Endpoint || out.owners.Address != offer.Owners.Address {
		t.Fatalf("cluster mode resolution %+v", out.binding)
	}
	c.Executor = nil
	if out, err = resolveRegionalConfig(t.Context(), nil, c); err != nil || out.executor {
		t.Fatal("executor without config", err)
	}
	c = connectorTestConfig(offer)
	plain := offer
	plain.Owners, plain.KeyService, plain.WorkKey, plain.EvidenceStore = nil, nil, nil, nil
	c.Offer = &plain
	if out, err = resolveRegionalConfig(t.Context(), nil, c); err != nil || out.executor {
		t.Fatal("plain connector offer", err)
	}
	// The combined offer comes from the hub's named ConfigMap in the same
	// namespace.
	raw, _ := json.Marshal(offer)
	var reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/namespaces/asservat-region/configmaps/asservat-regional-offer" {
			http.NotFound(w, r)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: "asservat-regional-offer"}, Data: map[string]string{contracts.RegionalOfferFile: string(raw)}})
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, contracts.ConnectorKubeTokenFile), []byte("synthetic-only"), 0600); err != nil {
		t.Fatal(err)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	in := &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}}
	got, err := readCombinedOffer(t.Context(), in, "asservat-region", "asservat-regional-offer")
	if err != nil || got.InstallationID != offer.InstallationID || reads.Load() != 1 {
		t.Fatal("combined offer read", err, reads.Load())
	}
	if _, err = readCombinedOffer(t.Context(), in, "asservat-region", "another-offer"); err == nil {
		t.Fatal("another ConfigMap accepted")
	}
}

// Exercise the actual executor constructor: it mints the capacity token,
// resolves the capacity account by name and derives the settings in process.
func TestRegionalContextComposesWithoutInstallerInputs(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	offer := connectorTestOffer(t, [][]byte{f.ca.Raw})
	pod := connectorTestID("50")
	uid := func(n string) types.UID { return types.UID(connectorTestID(n)) }
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
			v := auth.SelfSubjectReview{}
			v.Status.UserInfo.Extra = map[string]auth.ExtraValue{"authentication.kubernetes.io/pod-uid": {pod}}
			_ = json.NewEncoder(w).Encode(v)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/asservat-region":
			_ = json.NewEncoder(w).Encode(core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: "asservat-region", UID: uid("06")}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/asservat-region/serviceaccounts/asservat-connector-capacity":
			_ = json.NewEncoder(w).Encode(core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: "asservat-connector-capacity", Namespace: "asservat-region", UID: uid("11")}})
		case r.Method == http.MethodGet && r.URL.Path == "/apis/apps/v1/namespaces/asservat-region/deployments/asservat-connector":
			_ = json.NewEncoder(w).Encode(apps.Deployment{TypeMeta: meta.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"}, ObjectMeta: meta.ObjectMeta{Name: "asservat-connector", Namespace: "asservat-region", UID: uid("07")}})
		default:
			t.Errorf("unexpected constructor API call %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	for _, name := range []string{contracts.ConnectorKubeTokenFile, contracts.ConnectorPodTokenFile} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic-only"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	in := &providerInputs{files: files, kubernetesEndpoint: contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}}
	c, err := resolveRegionalConfig(t.Context(), in, connectorTestConfig(offer))
	if err != nil {
		t.Fatal(err)
	}
	workload, err := kube.ReadConnectorWorkload(t.Context(), in.kubernetes(contracts.ConnectorKubeTokenFile), c.ClusterID, c.Namespace, "asservat-connector-capacity", c.Deployment)
	if err != nil {
		t.Fatal(err)
	}
	// The fixture serves the capacity account for both names; the execution
	// account must differ, so name it explicitly.
	workload.Account, workload.AccountUID = c.ServiceAccount, connectorTestID("12")
	observer, err := kube.NewPermissionClient(in.kubernetes(contracts.ConnectorKubeTokenFile), c.ClusterID, cfg.NamespaceRef{Name: c.Namespace, UID: workload.NamespaceUID}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	source, err := kube.NewConnectorIdentitySource(observer, connectorTestDocument(t, offer, c), c.rootID(), c.binding)
	if err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	built, closers, err := newRegionalContext(t.Context(), c, in, pod, workload, source, &RegionalLifecycle{}, nil)
	defer func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}()
	if err != nil {
		t.Fatal("executor constructor", err)
	}
	if built.output.recordings == nil || built.logsClient == nil || built.output.store == nil || built.output.client == nil {
		t.Fatal("incomplete node-free output composition")
	}
	s := built.settings
	if s.NamespaceUID != connectorTestID("06") || s.AccountUID != connectorTestID("12") || s.CapacityAccountUID != connectorTestID("11") || s.DeploymentUID != connectorTestID("07") || len(s.Inputs) != 0 || s.TemplateDigest != "" {
		t.Fatalf("settings %+v", s)
	}
	if got := calls.Load() - before; got != 4 {
		t.Fatal("constructor API calls", got)
	}
	if kube.ConnectorAPIStartupDigest(s) != kube.ConnectorAPIStartupDigest(withUIDs(s)) {
		t.Fatal("startup digest depends on UIDs the hub cannot know")
	}
}

func withUIDs(s contracts.ConnectorAPIContextSettings) contracts.ConnectorAPIContextSettings {
	s.NamespaceUID, s.AccountUID, s.DeploymentUID, s.CapacityAccountUID = connectorTestID("96"), connectorTestID("97"), connectorTestID("98"), connectorTestID("99")
	return s
}

// The node collector reads the connector's published listener root when its
// rendered input carries none.
func TestKubernetesRootsReadsProjectedBundle(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	dir := t.TempDir()
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw})
	if err := os.WriteFile(filepath.Join(dir, contracts.ConnectorKubeRootsFile), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	roots, err := kubernetesRoots(t.Context(), &providerInputs{files: files})
	if err != nil || len(roots) != 1 {
		t.Fatal(err)
	}
}

// connectorTestDocument is the identity document of c with a valid synthetic
// backing (the offer's placeholder backing only satisfies the loader).
func connectorTestDocument(t *testing.T, offer contracts.RegionalOffer, c regionalConfig) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	q := audit.OperationHistoryQualification{ID: connectorTestID("40"), Digest: artifact.Digest{1}, Layout: audit.ConnectorOperationHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	p := audit.OperationLifecyclePolicy{RootID: offer.PermissionRootID, Lane: "identity", OverdueTerminal: audit.OperationOverdueTerminal, InstallationID: offer.InstallationID, StoreID: connectorTestID("41"), PolicyID: connectorTestID("42"), BackupProfileID: connectorTestID("43"), PolicyDigest: artifact.Digest{2}, BackupProfileDigest: artifact.Digest{3}, BackingRevision: 1, MetadataSlots: 256, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: now.Add(time.Hour), History: &q}
	b, w := q.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes, p.WALReservedBytes = 256*b, 256*w
	backing, err := json.Marshal(fleetapp.ConnectorIdentityBacking{AccountVersion: "connector-accounts/v1", AccountLimit: 2, RecordsPerAccount: 128, RetainedSeconds: 10800, ProfileLimit: 2, SourceTransitionLimit: 10, SourceBackupReservedBytes: 6 << 20, SourceWALReservedBytes: 20 << 20, Policy: p})
	if err != nil {
		t.Fatal(err)
	}
	offer.ConnectorBacking = backing
	offer.Roles = contracts.ConnectorIdentityRoles{Source: "connector_source", Journal: "connector_journal", Acknowledgement: "connector_ack", Cleanup: "connector_cleanup", Verifier: "connector_verifier", Finalizer: "connector_finalizer"}
	doc, err := kube.ConnectorIdentityDocument(offer, c.ClusterID, c.PeerID, c.connectorDeployment())
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// scripts/check-helm-region.py renders the chart and points this test at each
// rendered config.json, so the chart and the loader share one contract.
func TestRenderedConnectorConfigDecodes(t *testing.T) {
	path := os.Getenv("ASSERVAT_RENDERED_CONNECTOR_CONFIG")
	if path == "" {
		t.Skip("set by scripts/check-helm-region.py")
	}
	for _, file := range strings.Split(path, string(os.PathListSeparator)) {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		c, err := contracts.DecodeConnectorConfig(strings.NewReader(string(b)))
		if err != nil {
			t.Fatal(file, "decode", err)
		}
		if err = validConnectorConfig(c); err != nil {
			t.Fatal(file, "validate", err)
		}
	}
}
