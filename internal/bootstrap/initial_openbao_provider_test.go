package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

const initialBaoNamespace = "10000000-0000-4000-8000-000000000001"
const initialBaoAccount = "10000000-0000-4000-8000-000000000002"
const initialBaoState = "10000000-0000-4000-8000-000000000003"
const initialBaoPVC = "10000000-0000-4000-8000-000000000004"
const initialBaoEntity = "10000000-0000-4000-8000-000000000005"
const initialBaoJWT = "synthetic.projected.jwt"
const initialBaoToken = "synthetic-original-setup-token"

type initialBaoProviderFixture struct {
	mu                               sync.Mutex
	t                                *testing.T
	mode                             string
	plan                             contracts.SmallOpenBaoPlan
	backend                          string
	files                            *os.Root
	config                           *rest.Config
	http                             *http.Client
	requests                         map[string]int
	nativeGets, patches, privateGets int
	ready                            string
	after                            func(string)
	issued                           time.Time
}

func initialBaoBuffered(f func(http.ResponseWriter, *http.Request), after func(*http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := httptest.NewRecorder()
		f(response, r)
		if after != nil {
			after(r)
		}
		for k, values := range response.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(response.Code)
		_, _ = w.Write(response.Body.Bytes())
	})
}
func newInitialBaoProviderFixture(t *testing.T, mode string) *initialBaoProviderFixture {
	t.Helper()
	f := &initialBaoProviderFixture{t: t, mode: mode, requests: map[string]int{}, issued: time.Now().UTC().Truncate(time.Second)}
	apiCert, apiCA := smallServicesHookTLS(t)
	api := httptest.NewUnstartedServer(initialBaoBuffered(f.native, func(r *http.Request) {
		if f.after != nil {
			f.after("native:" + r.Method)
		}
	}))
	api.TLS = &tls.Config{Certificates: []tls.Certificate{apiCert}, MinVersion: tls.VersionTLS13}
	api.StartTLS()
	t.Cleanup(api.Close)
	block, _ := pem.Decode([]byte(apiCA))
	f.plan = contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: "bootstrap", Name: "trial", Image: contracts.SmallOpenBaoImage, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: api.URL, Roots: [][]byte{block.Bytes}}, SetupAccount: "trial-setup"}
	material, err := kube.BuildSmallOpenBaoMaterial(f.plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, b := range material {
			clear(b)
		}
	}()
	f.backend = string(material[contracts.SmallOpenBaoBackendKey])
	dir := t.TempDir()
	f.files, err = os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.files.Close() })
	for path, raw := range map[string][]byte{contracts.InitialBootstrapKeyServicePlanFile: material[contracts.SmallOpenBaoPlanKey], contracts.InitialBootstrapKeyServiceCAFile: material["ca.crt"], contracts.InitialBootstrapKeyServiceBackendFile: material[contracts.SmallOpenBaoBackendKey], contracts.InitialBootstrapKeyServiceTokenFile: []byte(initialBaoJWT)} {
		if err = os.WriteFile(filepath.Join(dir, path), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	pair, err := tls.X509KeyPair(material["tls.crt"], material["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	provider := httptest.NewUnstartedServer(initialBaoBuffered(f.provider, func(r *http.Request) {
		if f.after != nil {
			f.after("provider:" + r.URL.Path)
		}
	}))
	provider.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	provider.Config.ErrorLog = log.New(io.Discard, "", 0)
	provider.StartTLS()
	t.Cleanup(provider.Close)
	roots, err := providerconfig.TrustRootsPEM(material["ca.crt"], time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if mode == "provider-tls" {
		roots = f.plan.Kubernetes.Roots
	}
	f.http, err = ownerHTTP(f.plan.Endpoint(), roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.http.CloseIdleConnections)
	transport := f.http.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	target, _ := url.Parse(provider.URL)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	f.config = &rest.Config{Host: api.URL, TLSClientConfig: rest.TLSClientConfig{CAData: []byte(apiCA)}, BearerToken: "synthetic-native-read"}
	return f
}
func (f *initialBaoProviderFixture) native(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer synthetic-native-read" {
		f.t.Error("native credential lost")
		w.WriteHeader(401)
		return
	}
	metadata := func(name, id string, annotations map[string]string) {
		_ = json.NewEncoder(w).Encode(meta.PartialObjectMetadata{TypeMeta: meta.TypeMeta{APIVersion: "meta.k8s.io/v1", Kind: "PartialObjectMetadata"}, ObjectMeta: meta.ObjectMeta{Name: name, Namespace: f.plan.Namespace, UID: types.UID(id), ResourceVersion: "state1", Labels: map[string]string{"asservat.io/private-role": "small-openbao"}, Annotations: annotations}})
	}
	if r.Method == http.MethodPatch {
		f.patches++
		var p struct {
			Metadata struct {
				UID             types.UID         `json:"uid"`
				ResourceVersion string            `json:"resourceVersion"`
				Annotations     map[string]string `json:"annotations"`
			} `json:"metadata"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || p.Metadata.UID != initialBaoState || p.Metadata.ResourceVersion != "state1" || len(p.Metadata.Annotations) != 1 || p.Metadata.Annotations[contracts.SmallOpenBaoReadyAnnotation] != f.backend+"/"+initialBaoPVC || f.ready != "" {
			f.t.Error("non-original Ready patch")
			w.WriteHeader(400)
			return
		}
		f.ready = p.Metadata.Annotations[contracts.SmallOpenBaoReadyAnnotation]
		metadata(f.plan.StateSecretName(), initialBaoState, map[string]string{contracts.SmallOpenBaoBackendAnnotation: f.backend, contracts.SmallOpenBaoReadyAnnotation: f.ready})
		return
	}
	if r.Method != http.MethodGet {
		f.t.Error("unexpected native effect")
		w.WriteHeader(400)
		return
	}
	f.nativeGets++
	switch {
	case r.URL.Path == "/api/v1/namespaces/"+f.plan.Namespace:
		name := f.plan.Namespace
		if f.mode == "namespace" {
			name = "foreign"
		}
		_ = json.NewEncoder(w).Encode(core.Namespace{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Namespace"}, ObjectMeta: meta.ObjectMeta{Name: name, UID: types.UID(initialBaoNamespace)}})
	case strings.Contains(r.URL.Path, "/serviceaccounts/"):
		id := initialBaoAccount
		if f.mode == "account" {
			id = initialBaoEntity
		}
		_ = json.NewEncoder(w).Encode(core.ServiceAccount{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"}, ObjectMeta: meta.ObjectMeta{Name: f.plan.SetupAccount, Namespace: f.plan.Namespace, UID: types.UID(id)}})
	case strings.Contains(r.URL.Path, "/persistentvolumeclaims/"):
		metadata(f.plan.DataPVCName(), initialBaoPVC, nil)
	case strings.Contains(r.URL.Path, "/secrets/"):
		if r.Header.Get("Accept") != "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1" {
			f.privateGets++
			f.t.Error("private state requested")
			w.WriteHeader(403)
			return
		}
		backend := f.backend
		if f.mode == "state" {
			backend = initialBaoEntity
		}
		annotations := map[string]string{contracts.SmallOpenBaoBackendAnnotation: backend}
		if f.ready != "" {
			annotations[contracts.SmallOpenBaoReadyAnnotation] = f.ready
		}
		metadata(f.plan.StateSecretName(), initialBaoState, annotations)
	default:
		f.t.Error("unexpected native path")
		w.WriteHeader(404)
	}
}
func (f *initialBaoProviderFixture) provider(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	f.requests[r.Method+" "+r.URL.Path]++
	switch r.URL.Path {
	case "/v1/auth/asservat-setup/login":
		var body map[string]string
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if r.Method != http.MethodPost || r.Header.Get("X-Vault-Token") != "" || d.Decode(&body) != nil || len(body) != 2 || body["role"] != contracts.SmallOpenBaoSetupRole || body["jwt"] != initialBaoJWT {
			f.t.Error("login not exact projected credential/role")
			w.WriteHeader(400)
			return
		}
		if f.mode == "login-error" {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(initialBaoToken))
			return
		}
		if f.mode == "login-malformed" {
			_, _ = w.Write([]byte(`{"auth":`))
			return
		}
		if f.mode == "login-redirect" {
			w.Header().Set("Location", "/v1/relogin")
			w.WriteHeader(307)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": initialBaoToken}})
	case "/v1/" + contracts.SmallOpenBaoBackendPolicyPath:
		if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != initialBaoToken {
			f.t.Error("marker not read under actual login")
			w.WriteHeader(403)
			return
		}
		if f.mode == "marker-missing" {
			w.WriteHeader(404)
			return
		}
		backend := f.backend
		if f.mode == "marker-backend" {
			backend = initialBaoEntity
		}
		policy, _ := kube.SmallOpenBaoBackendPolicy(backend)
		if f.mode == "marker-extra" {
			policy = strings.Replace(policy, `["deny"]`, `["deny","read"]`, 1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"name": contracts.SmallOpenBaoBackendPolicyName, "policy": policy, "version": 1, "cas_required": false, "allow_wildcards_in_identity_templates": false, "allow_slashes_in_identity_templates": false}})
	case "/v1/auth/token/lookup-self":
		if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != initialBaoToken {
			f.t.Error("identity not read under original login")
			w.WriteHeader(403)
			return
		}
		entity := initialBaoEntity
		if f.mode == "identity" {
			entity = ""
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"accessor": "actual-setup-accessor", "type": "service", "policies": []string{contracts.SmallOpenBaoSetupPolicy}, "identity_policies": []string{}, "path": "auth/asservat-setup/login", "meta": map[string]string{"role": contracts.SmallOpenBaoSetupRole, "service_account_name": f.plan.SetupAccount, "service_account_namespace": f.plan.Namespace, "service_account_uid": initialBaoAccount}, "num_uses": 0, "orphan": true, "renewable": true, "entity_id": entity, "creation_ttl": 300, "explicit_max_ttl": 900, "issue_time": f.issued, "expire_time": f.issued.Add(300 * time.Second)}})
	default:
		f.t.Error("unexpected provider request (mint/retry/redirect)")
		w.WriteHeader(400)
	}
}
func (f *initialBaoProviderFixture) open(ctx context.Context) (*initialOpenBaoProvider, error) {
	source, err := readInitialOpenBaoProviderSource(ctx, f.files, f.plan, f.config)
	if err != nil {
		return nil, err
	}
	return openInitialOpenBaoProviderSource(ctx, f.files, source, f.config, f.http)
}
func TestInitialOpenBaoProviderPinsNativeSetupIdentityAndReadyOnce(t *testing.T) {
	f := newInitialBaoProviderFixture(t, "")
	ctx, end := context.WithTimeout(t.Context(), time.Minute)
	defer end()
	p, err := f.open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Identity.Valid() || p.Identity.Namespace.UID != initialBaoNamespace || p.Identity.SetupAccount.UID != initialBaoAccount || p.Identity.EntityID != initialBaoEntity || !bytes.Equal(p.Token, []byte(initialBaoToken)) || !p.Identity.SetupParent.IssuedAt.Equal(f.issued) || !p.Identity.SetupParent.ExpiresAt.Equal(f.issued.Add(300*time.Second)) {
		t.Fatal("original setup observation changed")
	}
	f.mu.Lock()
	gets, patches, private, requests, ready := f.nativeGets, f.patches, f.privateGets, len(f.requests), f.ready
	f.mu.Unlock()
	if gets != 3 || patches != 0 || private != 0 || requests != 3 || ready != "" {
		t.Fatalf("unexpected bounded effects: native GET=%d PATCH=%d private GET=%d provider paths=%d", gets, patches, private, requests)
	}
	token := p.Token
	p.Close()
	if len(p.Token) != 0 || !bytes.Equal(token, make([]byte, len(token))) {
		t.Fatal("owned token not cleared on close")
	}
}
func TestInitialOpenBaoProviderRefusesUnprovenSourcesWithoutReplay(t *testing.T) {
	for _, mode := range []string{"plan", "api-source", "namespace", "account", "state", "marker-missing", "marker-backend", "marker-extra", "identity", "login-error", "login-malformed", "login-redirect", "provider-tls", "canceled", "unbounded", "cancel-login", "cancel-marker", "cancel-identity"} {
		t.Run(mode, func(t *testing.T) {
			f := newInitialBaoProviderFixture(t, mode)
			ctx, end := context.WithTimeout(t.Context(), time.Minute)
			defer end()
			switch mode {
			case "plan":
				raw, _ := json.Marshal(f.plan)
				raw = bytes.Replace(raw, []byte(`"name":"trial"`), []byte(`"name":"another"`), 1)
				if err := os.WriteFile(filepath.Join(f.files.Name(), contracts.InitialBootstrapKeyServicePlanFile), raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "api-source":
				f.config.Host = "https://foreign.invalid"
			case "canceled":
				end()
			case "unbounded":
				ctx = t.Context()
			case "cancel-login", "cancel-marker", "cancel-identity":
				f.after = func(event string) {
					if mode == "cancel-login" && event == "provider:/v1/auth/asservat-setup/login" || mode == "cancel-marker" && event == "provider:/v1/"+contracts.SmallOpenBaoBackendPolicyPath || mode == "cancel-identity" && event == "provider:/v1/auth/token/lookup-self" {
						end()
					}
				}
			}
			p, err := f.open(ctx)
			if p != nil {
				p.Close()
			}
			if err == nil {
				t.Fatal("unproven/expired setup accepted")
			}
			if strings.Contains(err.Error(), initialBaoJWT) || strings.Contains(err.Error(), initialBaoToken) {
				t.Fatal("private credential in diagnostics")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.requests["POST /v1/auth/asservat-setup/login"] > 1 || f.requests["GET /v1/auth/token/lookup-self"] > 1 {
				t.Fatal("login/identity observation replayed")
			}
			if f.patches != 0 && mode != "cancel-patch" {
				t.Fatal("unproven source marked Ready")
			}
			if f.privateGets != 0 {
				t.Fatal("ordinary setup read private state")
			}
		})
	}
}
