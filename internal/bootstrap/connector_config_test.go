package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/transport/connectorlifecycle"
	auth "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/types"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func connectorTestID(n string) string { return "10000000-0000-4000-8000-0000000000" + n }

// connectorTestOffer is a synthetic executor offer; roots are the fixture CA.
func connectorTestOffer(t *testing.T, roots [][]byte) contracts.RegionalOffer {
	t.Helper()
	id := connectorTestID
	return contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: id("01"), HubClusterID: id("30"), PermissionRootID: id("03"), IssuerEpoch: id("04"),
		Image: "registry.invalid/asservat@sha256:" + strings.Repeat("a", 64),
		Owners: &contracts.RegionalContextOwners{Address: "hub.synthetic.invalid:30444", Configuration: contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat, InstallationID: id("01"), ClusterID: id("30"), IssuerEpoch: id("04"), Revision: 1,
			Namespace: contracts.WorkerObjectReference{Name: "asservat", UID: id("31")}, Service: contracts.WorkerObjectReference{Name: "hub-api", UID: id("32")}, Deployment: contracts.WorkerObjectReference{Name: "hub-api", UID: id("33")}, ServiceAccount: contracts.WorkerObjectReference{Name: "hub-api", UID: id("34")}, Port: 9443, NativePort: 9444, IssuerRoots: roots}},
		KeyService:    &contracts.RegionalWrapService{Endpoint: "https://keys.synthetic.invalid:30448", Roots: roots, KeyID: "artifact-key"},
		EvidenceStore: &contracts.RegionalEvidenceStore{Endpoint: "https://evidence.synthetic.invalid", Roots: roots, Region: "local", Bucket: "evidence", StoreID: connectorTestID("14")}}
}

func connectorTestConfig() contracts.ConnectorConfig {
	return contracts.ConnectorConfig{Format: contracts.ConnectorConfigFormat, Mode: contracts.ConnectorModeCluster, Hub: "https://hub.synthetic.invalid", Namespace: "asservat-region",
		Deployment: "asservat-connector", ServiceAccount: "asservat-connector", ImageDigest: strings.Repeat("a", 64),
		Executor: &contracts.ConnectorExecutorConfig{Concurrency: 4}}
}

// settingsHub serves the lifecycle channel with fixed settings for every
// token.
type settingsHub struct {
	clusterTokens
	settings connectorlifecycle.Settings
}

func (h settingsHub) Settings(context.Context, value.ConnectorCluster) (connectorlifecycle.Settings, error) {
	return h.settings, nil
}
func (settingsHub) OwnerCandidates(context.Context, *connectorlifecycle.Region) (value.APIContextOwnerCandidates, error) {
	return value.APIContextOwnerCandidates{}, value.ErrUnavailable
}
func (settingsHub) AuthenticateOwner(context.Context, *connectorlifecycle.Region, value.OwnerCertificate) (connectorlifecycle.OwnerAuthentication, error) {
	return connectorlifecycle.OwnerAuthentication{}, value.ErrUnavailable
}

// connectorTestSettings reads the settings for offer from a synthetic hub.
func connectorTestSettings(t *testing.T, c contracts.ConnectorConfig, offer contracts.RegionalOffer) (regionalConfig, error) {
	t.Helper()
	credential := contracts.OwnerStorageCredential{AccessKeyID: "AK", SecretAccessKey: "SK"}
	hub := settingsHub{clusterTokens{connectorTestID("02"), offer.PermissionRootID, connectorTestID("05"), offer.InstallationID},
		connectorlifecycle.Settings{ClusterID: connectorTestID("02"), PeerID: connectorTestID("05"), Offer: offer, Evidence: credential, History: credential}}
	h, err := connectorlifecycle.NewHandler(hub, hub, 2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(h)
	server.EnableHTTP2 = true
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client, err := connectorlifecycle.NewClient(server.URL, roots, func() ([]byte, error) { return []byte("synthetic"), nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return readHubSettings(t.Context(), client, c)
}

// The loader accepts exactly one topology's inputs and the Helm-rendered
// names; every other combination stops the process before any client.
func TestConnectorConfigIsClosed(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	_ = f
	if err := validConnectorConfig(connectorTestConfig()); err != nil {
		t.Fatal("cluster mode", err)
	}
	combined := connectorTestConfig()
	combined.Mode, combined.Hub = contracts.ConnectorModeCombined, "https://asservat-federation.asservat.svc:9446"
	if err := validConnectorConfig(combined); err != nil {
		t.Fatal("combined mode", err)
	}
	for name, mutate := range map[string]func(*contracts.ConnectorConfig){
		"format":                   func(c *contracts.ConnectorConfig) { c.Format = "asservat-regional-deployment/v1" },
		"mode":                     func(c *contracts.ConnectorConfig) { c.Mode = "hub" },
		"plain HTTP hub":           func(c *contracts.ConnectorConfig) { c.Hub = "http://hub.synthetic.invalid" },
		"hub with a path":          func(c *contracts.ConnectorConfig) { c.Hub = "https://hub.synthetic.invalid/console" },
		"no hub":                   func(c *contracts.ConnectorConfig) { c.Hub = "" },
		"namespace":                func(c *contracts.ConnectorConfig) { c.Namespace = "Region" },
		"image digest":             func(c *contracts.ConnectorConfig) { c.ImageDigest = "latest" },
		"no concurrency":           func(c *contracts.ConnectorConfig) { c.Executor.Concurrency = 0 },
		"alertmanager credentials": func(c *contracts.ConnectorConfig) { c.Executor.Alertmanager = "http://user:pass@alerts.invalid" },
		"collector in connector namespace": func(c *contracts.ConnectorConfig) {
			c.Collector = &contracts.RegionalCollector{Namespace: c.Namespace, ServiceAccount: "node", ListenerSecret: "nodes", RootConfigMap: "nodes", ServerName: "nodes.svc"}
		},
	} {
		c := connectorTestConfig()
		x := *c.Executor
		c.Executor = &x
		mutate(&c)
		if validConnectorConfig(c) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The hub's settings on connect supply the cluster and peer IDs, the offer
// and the object-store capabilities; nothing is read from copied files.
func TestHubSettingsCompleteTheConfig(t *testing.T) {
	f, _, l := newRuntimeFixture(t)
	l.Close()
	offer := connectorTestOffer(t, [][]byte{f.ca.Raw})
	out, err := connectorTestSettings(t, connectorTestConfig(), offer)
	if err != nil {
		t.Fatal(err)
	}
	if !out.executor || out.ClusterID != connectorTestID("02") || out.binding.PeerID != connectorTestID("05") || out.binding.InstallationID != offer.InstallationID ||
		out.owners.Address != offer.Owners.Address || out.evidence.AccessKeyID != "AK" || out.rootID() != offer.PermissionRootID {
		t.Fatalf("settings %+v", out.binding)
	}
	c := connectorTestConfig()
	c.Executor = nil
	if out, err = connectorTestSettings(t, c, offer); err != nil || out.executor {
		t.Fatal("executor without config", err)
	}
	partial := offer
	partial.EvidenceStore = nil
	if _, err = connectorTestSettings(t, connectorTestConfig(), partial); err == nil {
		t.Fatal("executor without an evidence store accepted")
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
	for _, name := range []string{contracts.ConnectorKubeTokenFile} {
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
	c, err := connectorTestSettings(t, connectorTestConfig(), offer)
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
	before := calls.Load()
	built, closers, err := newRegionalContext(t.Context(), c, in, pod, workload, &RegionalLifecycle{}, func() ([]byte, error) { return []byte("synthetic-only"), nil }, (&net.Dialer{}).DialContext)
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
	if s.NamespaceUID != connectorTestID("06") || s.AccountUID != connectorTestID("12") || s.DeploymentUID != connectorTestID("07") || len(s.Inputs) != 0 || s.TemplateDigest != "" {
		t.Fatalf("settings %+v", s)
	}
	if got := calls.Load() - before; got != 0 {
		t.Fatal("constructor API calls", got)
	}
	if kube.ConnectorAPIStartupDigest(s) != kube.ConnectorAPIStartupDigest(withUIDs(s)) {
		t.Fatal("startup digest depends on UIDs the hub cannot know")
	}
}

func withUIDs(s contracts.ConnectorAPIContextSettings) contracts.ConnectorAPIContextSettings {
	s.NamespaceUID, s.AccountUID, s.DeploymentUID = connectorTestID("96"), connectorTestID("97"), connectorTestID("98")
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
