package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
)

func ownerInputFixture(t *testing.T) (*ownerInputs, string, contracts.OwnerDeployment) {
	t.Helper()
	f, _, l := newRuntimeFixture(t)
	l.Close()
	dir := t.TempDir()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	roots := [][]byte{f.ca.Raw}
	c := contracts.OwnerDeployment{SchedulingLeases: []contracts.OwnerSchedulingLease{{Lease: "reconcile", ServiceAccount: "reconciler"}}, ConfigurationProbes: []contracts.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "owner-config-probe"}}, Format: contracts.OwnerDeploymentFormat, InstallationID: runtimeID, ClusterID: runtimeID, PermissionRootID: runtimeID, Namespace: contracts.WorkerObjectReference{Name: "hub", UID: runtimeID}, ConfigurationUID: runtimeID, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://api.synthetic.invalid", Roots: roots}, WorkloadGuard: contracts.OwnerDeploymentGuard{Name: "owner-guard", PolicyUID: runtimeID, PolicyGeneration: 1, BindingUID: runtimeID, BindingResourceVersion: "1", Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "installer"}}}, Postgres: contracts.OwnerPostgresEndpoint{Host: "database.synthetic.invalid", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://storage.synthetic.invalid", Roots: roots, Region: "local", Bucket: "audit"}, KeyService: contracts.OwnerKeyService{Endpoint: "https://keys.synthetic.invalid", Roots: roots, AuditMount: "audit", AuditKey: "records", PKIMount: "owner", ServerRole: "server", ClientRole: "client"}, Connections: 2, Concurrency: 1}
	writeOwnerJSON(t, dir, "deployment.json", c)
	in, err := readOwnerInputs(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	return in, dir, c
}
func writeOwnerJSON(t *testing.T, dir, name string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestOwnerMountedInputsAndSQLRotation(t *testing.T) {
	in, dir, c := ownerInputFixture(t)
	ctx := context.Background()
	writeOwnerJSON(t, dir, "sql-registry.json", contracts.OwnerSQLCredential{Username: "registry", Password: "synthetic-first"})
	cfg, err := in.sqlConfig(ctx, "sql-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.Host != c.Postgres.Host || cfg.ConnConfig.Port != 5432 || cfg.ConnConfig.User != "registry" || cfg.ConnConfig.Database != "asservat" || cfg.ConnConfig.TLSConfig.InsecureSkipVerify || cfg.ConnConfig.TLSConfig.ServerName != c.Postgres.Host || len(cfg.ConnConfig.Fallbacks) != 0 || cfg.MaxConns != 2 || strings.Contains(cfg.ConnConfig.ConnString(), "synthetic-first") {
		t.Fatal("unsafe SQL configuration")
	}
	writeOwnerJSON(t, dir, "sql-registry.json", contracts.OwnerSQLCredential{Username: "registry", Password: "synthetic-second"})
	next := cfg.ConnConfig.Copy()
	if err = cfg.BeforeConnect(ctx, next); err != nil || next.Password != "synthetic-second" {
		t.Fatal("rotation", err)
	}
	writeOwnerJSON(t, dir, "sql-registry.json", contracts.OwnerSQLCredential{Username: "activation", Password: "synthetic-second"})
	if err = cfg.BeforeConnect(ctx, next); err == nil {
		t.Fatal("role changed through credential rotation")
	}
	if err = os.Remove(filepath.Join(dir, "sql-registry.json")); err != nil {
		t.Fatal(err)
	}
	if err = cfg.BeforeConnect(ctx, next); err == nil {
		t.Fatal("missing current credentials reused cached password")
	}
	t.Setenv("PGSERVICEFILE", filepath.Join(dir, "not-an-installation-input"))
	if _, err = in.sqlConfig(ctx, "sql-registry.json"); err == nil {
		t.Fatal("ambient PostgreSQL settings accepted")
	}
}
func TestOwnerInputRejections(t *testing.T) {
	for _, mode := range []string{"unknown", "alias", "provider-http", "provider-query", "postgres-socket", "shared-sign-role", "unknown-format", "duplicate-administrator", "nil-roots", "bad-root", "excess-concurrency", "foreign-file", "null-probes", "duplicate-probe", "wildcard-probe", "foreign-probe", "too-many-probes", "null-leases", "duplicate-lease", "wildcard-lease", "foreign-lease-account", "too-many-leases"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := ownerInputFixture(t)
			switch mode {
			case "null-leases":
				c.SchedulingLeases = nil
			case "duplicate-lease":
				c.SchedulingLeases = append(c.SchedulingLeases, c.SchedulingLeases[0])
			case "wildcard-lease":
				c.SchedulingLeases[0].Lease = "*"
			case "foreign-lease-account":
				c.SchedulingLeases[0].ServiceAccount = "../foreign"
			case "too-many-leases":
				c.SchedulingLeases = make([]contracts.OwnerSchedulingLease, 5)
			case "null-probes":
				c.ConfigurationProbes = nil
			case "duplicate-probe":
				c.ConfigurationProbes = append(c.ConfigurationProbes, c.ConfigurationProbes[0])
			case "wildcard-probe":
				c.ConfigurationProbes[0].ConfigMap = "*"
			case "foreign-probe":
				c.ConfigurationProbes[0].ServiceAccount = "../foreign"
			case "too-many-probes":
				c.ConfigurationProbes = make([]contracts.OwnerConfigurationProbe, 9)
			case "provider-http":
				c.KeyService.Endpoint = "http://keys.synthetic.invalid"
			case "provider-query":
				c.Kubernetes.Endpoint += "?token=not-allowed"
			case "postgres-socket":
				c.Postgres.Host = "/tmp/sql"
			case "shared-sign-role":
				c.KeyService.ClientRole = c.KeyService.ServerRole
			case "unknown-format":
				c.Format = "future"
			case "duplicate-administrator":
				c.WorkloadGuard.Administrators = append(c.WorkloadGuard.Administrators, c.WorkloadGuard.Administrators[0])
			case "nil-roots":
				c.Postgres.Roots = nil
			case "bad-root":
				c.Postgres.Roots = [][]byte{[]byte("invalid-root")}
			case "excess-concurrency":
				c.Concurrency = 17
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			if mode == "unknown" || mode == "alias" {
				b, _ := os.ReadFile(filepath.Join(dir, "deployment.json"))
				if mode == "unknown" {
					b = append([]byte(`{"credential":"must-not-leak",`), b[1:]...)
				} else {
					b = []byte(strings.Replace(string(b), `"installationID"`, `"InstallationID"`, 1))
				}
				if err := os.WriteFile(filepath.Join(dir, "deployment.json"), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "foreign-file" {
				other := t.TempDir()
				writeOwnerJSON(t, other, "deployment.json", c)
				if err := os.Remove(filepath.Join(dir, "deployment.json")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(other, "deployment.json"), filepath.Join(dir, "deployment.json")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readOwnerInputs(context.Background(), in.files); err == nil || strings.Contains(err.Error(), "must-not-leak") {
				t.Fatal("invalid deployment accepted or disclosed", err)
			}
		})
	}
}

func TestOwnerStorageProjectionRotationAndLoss(t *testing.T) {
	in, dir, _ := ownerInputFixture(t)
	s := mountedStorage{in.providerInputs}
	ctx := context.Background()
	t.Setenv("AWS_ACCESS_KEY_ID", "ambient-must-not-be-used")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ambient-must-not-be-used")
	for _, secret := range []string{"synthetic-first", "synthetic-rotated"} {
		writeOwnerJSON(t, dir, "audit-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "audit", SecretAccessKey: secret})
		got, err := s.Retrieve(ctx)
		if err != nil || got.AccessKeyID != "audit" || got.SecretAccessKey != secret {
			t.Fatal("current projected storage credential unavailable")
		}
	}
	for _, payload := range []string{
		`{"accessKeyID":"audit","secretAccessKey":"synthetic","sessionToken":"bad\nheader"}`,
		`{"accessKeyID":"audit","secretAccessKey":"synthetic","sessionToken":"","endpoint":"https://foreign.invalid"}`,
		`{"accessKeyID":"audit","secretAccessKey":"synthetic","sessionToken":"","accessKeyID":"other"}`,
		`{"accessKeyID":"audit","secretAccessKey":"synthetic","SessionToken":""}`,
		`{"accessKeyID":"audit","secretAccessKey":"synthetic"}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, "audit-storage.json"), []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := s.Retrieve(ctx)
		if err == nil || got.AccessKeyID != "" || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("malformed credential was accepted, leaked or reused")
		}
	}
	if err := os.Remove(filepath.Join(dir, "audit-storage.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Retrieve(ctx); err == nil {
		t.Fatal("missing storage projection used ambient or previous credentials")
	}
}
func TestOwnerProjectedKubernetesTokenAndCatalog(t *testing.T) {
	in, dir, _ := ownerInputFixture(t)
	var expected atomic.Value
	expected.Store("synthetic.first.token")
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+expected.Load().(string) {
			t.Error("old/ambient Kubernetes token")
		}
		w.WriteHeader(204)
	}))
	defer s.Close()
	in.kubernetesEndpoint = contracts.OwnerProviderEndpoint{Endpoint: s.URL, Roots: [][]byte{s.Certificate().Raw}}
	if err := os.WriteFile(filepath.Join(dir, "kube-observer.token"), []byte(expected.Load().(string)), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := rest.HTTPClientFor(in.kubernetes("kube-observer.token"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.closeHTTP()
	for i := 0; i < 2; i++ {
		resp, err := h.Get(s.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		expected.Store("synthetic.rotated.token")
		if err = os.WriteFile(filepath.Join(dir, "kube-observer.token"), []byte(expected.Load().(string)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Remove(filepath.Join(dir, "kube-observer.token")); err != nil {
		t.Fatal(err)
	}
	if _, err = h.Get(s.URL); err == nil {
		t.Fatal("missing token reused")
	}
	trust, err := mtls.NewWorkerTrustCatalog(runtimeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &OwnerDeployment{inputs: in, trust: trust}
	writeOwnerJSON(t, dir, "worker-controls.json", contracts.OwnerWorkerTrust{Format: contracts.OwnerWorkerTrustFormat, Controls: [][]byte{}})
	first, err := d.refreshWorkerTrust(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.refreshWorkerTrust(context.Background())
	if err != nil || first != second {
		t.Fatal("unchanged catalog", err)
	}
	writeOwnerJSON(t, dir, "worker-controls.json", contracts.OwnerWorkerTrust{Format: contracts.OwnerWorkerTrustFormat, Controls: [][]byte{[]byte("invalid-control")}})
	if _, err = d.refreshWorkerTrust(context.Background()); err == nil || d.catalogDigest != first {
		t.Fatal("failed refresh reported as current")
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err = d.refreshWorkerTrust(ctx); err == nil {
		t.Fatal("expired catalog read succeeded")
	}
}
