package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
)

type continuationBaoFixture struct {
	base   *initialBaoProviderFixture
	issuer string
	opened *initialOpenBaoProvider
	opens  int
}

func newContinuationBaoFixture(t *testing.T, mode string) *continuationBaoFixture {
	t.Helper()
	f := &continuationBaoFixture{base: newInitialBaoProviderFixture(t, mode)}
	material, err := kube.BuildSmallOpenBaoMaterial(f.base.plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, raw := range material {
			clear(raw)
		}
	}()
	f.base.backend = string(material[contracts.SmallOpenBaoBackendKey])
	for path, key := range map[string]string{contracts.InitialBootstrapKeyServicePlanFile: contracts.SmallOpenBaoPlanKey, contracts.InitialBootstrapKeyServiceCAFile: "ca.crt", contracts.InitialBootstrapKeyServiceBackendFile: contracts.SmallOpenBaoBackendKey} {
		if err = os.WriteFile(filepath.Join(f.base.files.Name(), path), material[key], 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, f.issuer = smallServicesHookTLS(t)
	pair, err := tls.X509KeyPair(material["tls.crt"], material["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(initialBaoBuffered(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/mounts/auth/"+contracts.SmallOpenBaoConfigurationAuthMount && r.URL.Path != "/v1/sys/mounts/auth/"+contracts.SmallOpenBaoOwnerAuthMount && r.URL.Path != "/v1/"+contracts.SmallOpenBaoOwnerPKIMount+"/cert/ca" {
			f.base.provider(w, r)
			return
		}
		f.base.mu.Lock()
		defer f.base.mu.Unlock()
		f.base.requests[r.Method+" "+r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != initialBaoToken {
			t.Error("resolver attempted provisioning or lost actual setup identity")
			w.WriteHeader(400)
			return
		}
		if mode == "missing-worker" && strings.HasSuffix(r.URL.Path, contracts.SmallOpenBaoConfigurationAuthMount) || mode == "missing-owner" && strings.HasSuffix(r.URL.Path, contracts.SmallOpenBaoOwnerAuthMount) || mode == "missing-issuer" && strings.HasSuffix(r.URL.Path, "/cert/ca") {
			w.WriteHeader(404)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/cert/ca") {
			cert := f.issuer
			if mode == "invalid-issuer" {
				cert = "not a certificate"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"certificate": cert}})
			return
		}
		accessor := "auth_kubernetes_owner"
		if strings.HasSuffix(r.URL.Path, contracts.SmallOpenBaoConfigurationAuthMount) {
			accessor = "auth_kubernetes_configuration"
		}
		kind := "kubernetes"
		if mode == "mount-type" {
			kind = "oidc"
		}
		if mode == "invalid-accessor" {
			accessor = "foreign/path"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"type": kind, "accessor": accessor, "config": map[string]any{"default_lease_ttl": 0, "max_lease_ttl": 0, "token_type": "default-service"}}})
	}, func(r *http.Request) {
		if f.base.after != nil {
			f.base.after("provider:" + r.URL.Path)
		}
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots, err := providerconfig.TrustRootsPEM(material["ca.crt"], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	f.base.http, err = ownerHTTP(f.base.plan.Endpoint(), roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.base.http.CloseIdleConnections)
	transport := f.base.http.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	target, _ := url.Parse(server.URL)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	return f
}
func (f *continuationBaoFixture) original(t *testing.T) contracts.InitialPreparer {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.base.files.Name(), contracts.InitialBootstrapKeyServiceCAFile))
	if err != nil {
		t.Fatal(err)
	}
	roots, err := providerconfig.TrustRootsPEM(raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var p contracts.InitialPreparer
	p.Plan.RootName = f.base.plan.Name + "-preparation"
	p.Plan.BootstrapNamespace = contracts.WorkerObjectReference{Name: f.base.plan.Namespace, UID: initialBaoNamespace}
	p.Kubernetes = f.base.plan.Kubernetes
	p.Services = &contracts.InitialPreparationServices{Kubernetes: f.base.plan.Kubernetes, KeyService: contracts.ConfigurationKeyService{Endpoint: f.base.plan.Endpoint(), Roots: roots, AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: "audit"}}
	return p
}
func (f *continuationBaoFixture) input() contracts.InstallerContinuation {
	return contracts.InstallerContinuation{Namespace: f.base.plan.Namespace, KeyServiceSource: contracts.InitialBootstrapBundledOpenBaoRoots}
}
func (f *continuationBaoFixture) open(ctx context.Context, _ *os.Root, selected contracts.SmallOpenBaoPlan, config *rest.Config) (*initialOpenBaoProvider, error) {
	f.opens++
	if !reflect.DeepEqual(selected, f.base.plan) || config != f.base.config {
		f.base.t.Fatal("opener received substituted source")
	}
	p, err := f.base.open(ctx)
	f.opened = p
	return p, err
}
func TestContinuationOpenBaoResolvesActualDefaultsWithoutProvisioning(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-defaults", true: "matching-explicit"}[explicit], func(t *testing.T) {
			f := newContinuationBaoFixture(t, "")
			input := f.input()
			if explicit {
				input.WorkerProvider = contracts.InstallerProviderSelection{AuthMount: contracts.SmallOpenBaoConfigurationAuthMount, AuthMountAccessor: "auth_kubernetes_configuration"}
				input.OwnerProvider = contracts.InstallerProviderSelection{AuthMount: contracts.SmallOpenBaoOwnerAuthMount, AuthMountAccessor: "auth_kubernetes_owner"}
				input.OwnerPKIMount = contracts.SmallOpenBaoOwnerPKIMount
				input.OwnerIssuerRootsPEM = f.issuer
			}
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			p, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &input, f.original(t), f.base.config, f.open)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			if input.KeyServiceSource != "" || input.WorkerProvider.AuthMount != contracts.SmallOpenBaoConfigurationAuthMount || input.WorkerProvider.AuthMountAccessor != "auth_kubernetes_configuration" || input.OwnerProvider.AuthMount != contracts.SmallOpenBaoOwnerAuthMount || input.OwnerProvider.AuthMountAccessor != "auth_kubernetes_owner" || input.OwnerPKIMount != contracts.SmallOpenBaoOwnerPKIMount || input.OwnerIssuerRootsPEM != f.issuer || f.opens != 1 {
				t.Fatal("actual provider defaults were not selected exactly")
			}
			f.base.mu.Lock()
			defer f.base.mu.Unlock()
			if len(f.base.requests) != 6 {
				t.Fatal("unexpected provider request paths")
			}
			for key, count := range f.base.requests {
				if count != 1 || strings.HasPrefix(key, "POST ") && key != "POST /v1/auth/asservat-setup/login" {
					t.Fatal("resolver repeated a request or provisioned provider state")
				}
			}
		})
	}
}
func TestContinuationOpenBaoRejectsOriginalMismatchBeforeLogin(t *testing.T) {
	for _, mode := range []string{"unknown-source", "missing-services", "root-name", "namespace", "bootstrap-namespace", "endpoint", "roots", "api", "api-roots", "service-api", "worker-mount", "owner-mount", "pki-mount"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationBaoFixture(t, "")
			input, original := f.input(), f.original(t)
			switch mode {
			case "unknown-source":
				input.KeyServiceSource = "unknown"
			case "missing-services":
				original.Services = nil
			case "root-name":
				original.Plan.RootName = "foreign-preparation"
			case "namespace":
				input.Namespace = "foreign"
			case "bootstrap-namespace":
				original.Plan.BootstrapNamespace.Name = "foreign"
			case "endpoint":
				original.Services.KeyService.Endpoint = "https://foreign.invalid"
			case "roots":
				original.Services.KeyService.Roots = f.base.plan.Kubernetes.Roots
			case "api":
				original.Kubernetes.Endpoint = "https://foreign.invalid"
			case "api-roots":
				original.Kubernetes.Roots = original.Services.KeyService.Roots
			case "service-api":
				original.Services.Kubernetes.Endpoint = "https://foreign.invalid"
			case "worker-mount":
				input.WorkerProvider.AuthMount = "foreign"
			case "owner-mount":
				input.OwnerProvider.AuthMount = "foreign"
			case "pki-mount":
				input.OwnerPKIMount = "foreign"
			}
			before, _ := json.Marshal(input)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			p, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &input, original, f.base.config, f.open)
			if p != nil {
				p.Close()
			}
			if err == nil || f.opens != 0 {
				t.Fatal("original mismatch reached setup login")
			}
			after, _ := json.Marshal(input)
			if !bytes.Equal(before, after) {
				t.Fatal("failed source normalization mutated input")
			}
		})
	}
}
func TestContinuationOpenBaoRequiresExistingPrerequisitesAndExactOverrides(t *testing.T) {
	for _, mode := range []string{"missing-worker", "missing-owner", "missing-issuer", "invalid-issuer", "mount-type", "invalid-accessor", "worker-accessor", "owner-accessor", "issuer-override", "namespace-uid", "cancel-auth"} {
		t.Run(mode, func(t *testing.T) {
			f := newContinuationBaoFixture(t, mode)
			input := f.input()
			switch mode {
			case "worker-accessor":
				input.WorkerProvider.AuthMountAccessor = "auth_wrong"
			case "owner-accessor":
				input.OwnerProvider.AuthMountAccessor = "auth_wrong"
			case "issuer-override":
				raw, _ := os.ReadFile(filepath.Join(f.base.files.Name(), contracts.InitialBootstrapKeyServiceCAFile))
				input.OwnerIssuerRootsPEM = string(raw)
			}
			before, _ := json.Marshal(input)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			if mode == "cancel-auth" {
				f.base.after = func(event string) {
					if event == "provider:/v1/sys/mounts/auth/"+contracts.SmallOpenBaoConfigurationAuthMount {
						end()
					}
				}
			}
			original := f.original(t)
			if mode == "namespace-uid" {
				original.Plan.BootstrapNamespace.UID = initialBaoEntity
			}
			p, err := resolveInstallerContinuationKeyServiceWithOpen(ctx, f.base.files, &input, original, f.base.config, f.open)
			if p != nil {
				p.Close()
			}
			if err == nil {
				t.Fatal("missing/changed prerequisite silently provisioned or adopted")
			}
			after, _ := json.Marshal(input)
			if !bytes.Equal(before, after) {
				t.Fatal("partial failure changed canonical input")
			}
			if f.opened == nil || len(f.opened.Token) != 0 {
				t.Fatal("failed resolver left setup login open")
			}
			f.base.mu.Lock()
			defer f.base.mu.Unlock()
			for key, count := range f.base.requests {
				if count != 1 || strings.HasPrefix(key, "POST ") && key != "POST /v1/auth/asservat-setup/login" {
					t.Fatal("prerequisite failure retried or created provider resources")
				}
			}
		})
	}
}
func TestContinuationOpenBaoExternalSelectionStaysUnchanged(t *testing.T) {
	f := newContinuationBaoFixture(t, "")
	input := f.input()
	input.KeyServiceSource = ""
	input.WorkerProvider.AuthMount = "external"
	before, _ := json.Marshal(input)
	p, err := resolveInstallerContinuationKeyServiceWithOpen(t.Context(), f.base.files, &input, contracts.InitialPreparer{}, nil, f.open)
	if err != nil || p != nil || f.opens != 0 {
		t.Fatal("external provider invoked bundled path")
	}
	after, _ := json.Marshal(input)
	if !bytes.Equal(before, after) {
		t.Fatal("external input changed")
	}
}
