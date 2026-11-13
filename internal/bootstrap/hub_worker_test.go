package bootstrap

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

func hubWorkerTestConfig() contracts.HubWorkerConfig {
	return contracts.HubWorkerConfig{Format: contracts.HubWorkerConfigFormat, Namespace: "asservat", ServiceAccount: "asservat-hub-worker",
		FleetSource: "asservat-fleet", OwnerSource: "asservat-owner-source", LeaderLease: "asservat-hub-worker-leader",
		Postgres:   contracts.HubWorkerPostgres{Host: "asservat-postgres.asservat.svc", Port: 5432, Database: "asservat"},
		AuditStore: contracts.HubWorkerObjectStore{Endpoint: "https://asservat-objectstore.asservat.svc:8333", Region: "us-east-1", Bucket: "asservat-audit"},
		KeyService: contracts.HubWorkerKeyService{Endpoint: "https://asservat-openbao.asservat.svc:8200"},
		Provider:   contracts.HubWorkerProvider{Roles: contracts.HubWorkerProviderRoles{AuditWrap: "asservat-hub-worker-audit-wrap", AuditUnwrap: "asservat-hub-worker-audit-unwrap"}}}
}

func hubWorkerTestIDs() contracts.InstallationIDs {
	return contracts.InstallationIDs{InstallationID: runtimeID, ClusterID: runtimeID, IssuerEpoch: runtimeID, PermissionRootID: runtimeID, BrowserRootID: runtimeID, SessionEpoch: runtimeID, RoleSetupID: runtimeID, PeerID: runtimeID}
}

// hubWorkerFiles writes a complete mount for config c with the PEM roots of
// server, and the generated IDs.
func hubWorkerFiles(t *testing.T, c contracts.HubWorkerConfig, server *httptest.Server) (*os.Root, *os.Root) {
	t.Helper()
	dir, ids := t.TempDir(), t.TempDir()
	writeOwnerJSON(t, dir, contracts.HubWorkerConfigFile, c)
	roots := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.MkdirAll(filepath.Join(dir, "roots"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{contracts.HubWorkerKubernetesRootsFile, contracts.HubWorkerPostgresRootsFile, contracts.HubWorkerAuditStoreRootsFile, contracts.HubWorkerKeyServiceRootsFile} {
		if err := os.WriteFile(filepath.Join(dir, name), roots, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, contracts.HubWorkerKubernetesTokenFile), []byte("synthetic-worker"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"installationID", "clusterID", "issuerEpoch", "permissionRootID", "browserRootID", "sessionEpoch", "roleSetupID", "peerID"} {
		if err := os.WriteFile(filepath.Join(ids, key), []byte(runtimeID+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { files.Close() })
	idFiles, err := os.OpenRoot(ids)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idFiles.Close() })
	return files, idFiles
}

func TestHubWorkerConfigValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	for name, change := range map[string]func(*contracts.HubWorkerConfig){
		"valid":          func(*contracts.HubWorkerConfig) {},
		"namespace":      func(c *contracts.HubWorkerConfig) { c.Namespace = "Not_A_Label" },
		"shared-source":  func(c *contracts.HubWorkerConfig) { c.OwnerSource = c.FleetSource },
		"http-audit":     func(c *contracts.HubWorkerConfig) { c.AuditStore.Endpoint = "http://objectstore.invalid" },
		"http-provider":  func(c *contracts.HubWorkerConfig) { c.KeyService.Endpoint = "http://openbao.invalid" },
		"port":           func(c *contracts.HubWorkerConfig) { c.Postgres.Port = 0 },
		"role":           func(c *contracts.HubWorkerConfig) { c.Provider.Roles.AuditWrap = "bad/role" },
		"lease":          func(c *contracts.HubWorkerConfig) { c.LeaderLease = "" },
		"service-acount": func(c *contracts.HubWorkerConfig) { c.ServiceAccount = "" },
	} {
		t.Run(name, func(t *testing.T) {
			c := hubWorkerTestConfig()
			change(&c)
			files, _ := hubWorkerFiles(t, c, server)
			got, err := readHubWorkerConfig(context.Background(), files, hubWorkerTestIDs())
			if name == "valid" {
				if err != nil || got.FleetSource != c.FleetSource || got.Provider.AuthMount != "asservat-configuration" || got.Provider.Audience != "asservat-configuration-provider" ||
					got.KeyService.AuditMount != "asservat-audit" || got.KeyService.AuditKey != "audit" || got.Provider.ContextDeletionSigning.Key != "" {
					t.Fatal(err, got.Provider, got.KeyService)
				}
			} else if err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestHubWorkerRootsAndInClusterEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	files, _ := hubWorkerFiles(t, hubWorkerTestConfig(), server)
	roots, err := readPEMRoots(context.Background(), files, contracts.HubWorkerPostgresRootsFile)
	if err != nil || len(roots) != 1 || string(roots[0]) != string(server.Certificate().Raw) {
		t.Fatal("PEM roots not read", err)
	}
	if _, err := readPEMRoots(context.Background(), files, "config.json"); err == nil {
		t.Fatal("non-PEM roots accepted")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "fd00::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	k, err := inClusterKubernetes(context.Background(), files)
	if err != nil || k.Endpoint != "https://[fd00::1]:443" || len(k.Roots) != 1 {
		t.Fatal("in-cluster endpoint", k.Endpoint, err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := inClusterKubernetes(context.Background(), files); err == nil {
		t.Fatal("missing in-cluster service accepted")
	}
}

// Startup reads the namespace and both source ConfigMap UIDs by name with the
// worker's projected token before it opens any SQL credential.
func TestHubWorkerStartupReadsUIDsByNameBeforeSQL(t *testing.T) {
	var reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-worker" || r.Method != http.MethodGet {
			t.Error("unexpected credential or method")
		}
		meta := map[string]any{"uid": "22222222-2222-4222-8222-222222222222", "resourceVersion": "1"}
		var body map[string]any
		switch r.URL.Path {
		case "/api/v1/namespaces/asservat":
			meta["name"] = "asservat"
			body = map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": meta}
		case "/api/v1/namespaces/asservat/configmaps/asservat-fleet", "/api/v1/namespaces/asservat/configmaps/asservat-owner-source":
			meta["name"], meta["namespace"] = filepath.Base(r.URL.Path), "asservat"
			body = map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta}
		default:
			t.Error("unexpected path", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)
	files, ids := hubWorkerFiles(t, hubWorkerTestConfig(), server)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	w, err := newHubWorker(ctx, files, ids)
	if err == nil {
		w.Close()
		t.Fatal("started without SQL credentials")
	}
	var step interface{ FixedStep() string }
	if !errors.As(err, &step) || !strings.HasPrefix(step.FixedStep(), "sql") || reads.Load() != 3 {
		t.Fatal("startup did not reach SQL after three by-name reads", err, reads.Load())
	}
}

func TestHubWorkerChildrenFollowSections(t *testing.T) {
	w := &hubWorker{config: hubWorkerTestConfig()}
	if c := w.children(); len(c) != 1 || c[0].name != "configuration" {
		t.Fatal("unexpected children without sections")
	}
	w.config.Capacity, w.config.Cleanup, w.config.Permission = &contracts.HubWorkerCapacity{}, &contracts.HubWorkerCleanup{}, &contracts.HubWorkerPermission{}
	var names []string
	for _, c := range w.children() {
		names = append(names, c.name)
	}
	if strings.Join(names, ",") != "configuration,capacity,cleanup,permission" {
		t.Fatal("children", names)
	}
}

// The first returning child cancels the others; the callback returns only
// after every child has joined.
func TestHubWorkerChildrenJoinBeforeReturn(t *testing.T) {
	var joined atomic.Int32
	failed := errors.New("child failed")
	wait := func(ctx context.Context) error {
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		joined.Add(1)
		return ctx.Err()
	}
	err := runHubWorkerChildren(context.Background(), []hubWorkerChild{{"configuration", wait}, {"capacity", func(context.Context) error { return failed }}, {"permission", wait}})
	var step interface{ FixedStep() string }
	if !errors.Is(err, failed) || !errors.As(err, &step) || step.FixedStep() != "capacity" || joined.Load() != 2 {
		t.Fatal("children not joined or first stop not named", err, joined.Load())
	}
	if err := runHubWorkerChildren(context.Background(), []hubWorkerChild{{"configuration", nil}}); err == nil {
		t.Fatal("nil child accepted")
	}
	if HubWorkerDiagnostic(err) == "" {
		t.Fatal("empty diagnostic")
	}
}

// The loader derives the OpenBao key names that `asservat setup` creates from
// the installation ID; Helm renders none of them.
func TestHubWorkerConfigCompletesDerivedNames(t *testing.T) {
	c := hubWorkerTestConfig()
	c.Cleanup = &contracts.HubWorkerCleanup{}
	c.Permission = &contracts.HubWorkerPermission{WorkerConfiguration: &contracts.HubWorkerWorkerConfiguration{Namespace: "asservat-downloads", Source: "asservat-worker-profile"}}
	ids := hubWorkerTestIDs()
	completeHubWorkerConfig(&c, ids)
	n := providerconfig.OpenBaoNamesFor(ids.InstallationID)
	if c.Provider.ContextDeletionSigning != (contracts.OwnerPublicTransit{Mount: contracts.SmallOpenBaoAuditMount, Key: n.DeletionSigningKey}) ||
		c.Provider.WorkerConfigurationAudit != (contracts.OwnerPublicTransit{Mount: contracts.SmallOpenBaoAuditMount, Key: n.WorkerConfigurationAuditKey}) || c.KeyService.AuditKey != n.AuditKey {
		t.Fatal("derived names", c.Provider, c.KeyService)
	}
}

// TestHubWorkerConfigRendered loads the config.json that
// scripts/test-helm-hub-worker.py renders (path in ASSERVAT_HUB_WORKER_CONFIG)
// through the loader's own decode, completion and section checks.
func TestHubWorkerConfigRendered(t *testing.T) {
	path := os.Getenv("ASSERVAT_HUB_WORKER_CONFIG")
	if path == "" {
		t.Skip("set by scripts/test-helm-hub-worker.py")
	}
	dir, file := filepath.Split(path)
	if file != contracts.HubWorkerConfigFile {
		t.Fatal("rendered file must be named", contracts.HubWorkerConfigFile)
	}
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	c, err := readHubWorkerConfig(context.Background(), files, hubWorkerTestIDs())
	if err != nil {
		t.Fatal(err)
	}
	ns := cfg.NamespaceRef{Name: c.Namespace, UID: runtimeID}
	if c.Permission == nil || validateHubWorkerPermission(c, ns) != nil {
		t.Fatal("permission section refused", c.Permission)
	}
	if c.Capacity != nil {
		if err := validateHubWorkerCapacity(c.Capacity, hubWorkerTestIDs(), c.Namespace); err != nil {
			t.Fatal("capacity section refused", err)
		}
		w := &hubWorker{config: c, ids: hubWorkerTestIDs()}
		if err := w.validCleanupConfig(); c.Cleanup == nil || err != nil {
			t.Fatal("cleanup section refused", err)
		}
	}
	t.Logf("sections capacity=%t cleanup=%t permission=%t", c.Capacity != nil, c.Cleanup != nil, c.Permission != nil)
}
