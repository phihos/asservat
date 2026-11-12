package bootstrap

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	bao "github.com/openbao/openbao/api/v2"
)

type initialBaoMintFixture struct {
	t              *testing.T
	desired        contracts.InitialBootstrap
	claim          kube.InitialBootstrapProviderClaim
	http           *http.Client
	mode           string
	posts, reads   int
	ttl            time.Duration
	issued, expiry time.Time
}

func newInitialBaoMintFixture(t *testing.T, mode string) *initialBaoMintFixture {
	t.Helper()
	now := time.Now().UTC()
	_, apiCA := smallServicesHookTLS(t)
	block, _ := pem.Decode([]byte(apiCA))
	plan := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: "bootstrap", Name: "trial", Image: contracts.SmallOpenBaoImage, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.fixture", Roots: [][]byte{block.Bytes}}, SetupAccount: "trial-bootstrap-runner"}
	data, err := kube.BuildSmallOpenBaoMaterial(plan, now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, raw := range data {
			clear(raw)
		}
	}()
	pair, err := tls.X509KeyPair(data["tls.crt"], data["tls.key"])
	if err != nil {
		t.Fatal(err)
	}
	roots, err := providerconfig.TrustRootsPEM(data["ca.crt"], now)
	if err != nil {
		t.Fatal(err)
	}
	selected := contracts.BundledInitialProviderIdentity{Format: contracts.BundledInitialProviderIdentityFormat, BackendName: plan.Name, Namespace: contracts.WorkerObjectReference{Name: plan.Namespace, UID: initialBaoNamespace}, SetupAccount: contracts.WorkerObjectReference{Name: plan.SetupAccount, UID: initialBaoAccount}, EntityID: initialBaoEntity, SetupParent: contracts.InitialProviderParent{Accessor: "original-setup", IssuedAt: now, ExpiresAt: now.Add(300 * time.Second)}}
	f := &initialBaoMintFixture{t: t, mode: mode, desired: contracts.InitialBootstrap{Name: plan.Name, KeyService: contracts.ConfigurationKeyService{Endpoint: plan.Endpoint(), Roots: roots, AuditMount: contracts.SmallOpenBaoAuditMount, AuditKey: "audit"}, Providers: contracts.SmallOpenBaoInitialProviders()}}
	f.claim = kube.InitialBootstrapProviderClaim{Fresh: true, ValidUntil: now.Add(5 * time.Second), State: contracts.InitialBootstrapState{InstallationID: initialBaoNamespace, RequestID: initialBaoAccount, SeedUID: initialBaoState, Material: &contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat, SetupToken: initialBaoToken, BundledIdentity: &selected}, ProviderMint: &contracts.InitialBootstrapProviderMint{OperationID: initialBaoPVC, StartedAt: now, Until: now.Add(5 * time.Second), ExpiresBefore: selected.SetupParent.ExpiresAt.Add(-contracts.BundledInitialProviderSafetyMargin)}}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.http, err = ownerHTTP(plan.Endpoint(), roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.http.CloseIdleConnections)
	target, _ := url.Parse(server.URL)
	transport := f.http.Transport.(*http.Transport)
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	return f
}
func (f *initialBaoMintFixture) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	if r.Method == http.MethodPost && r.URL.Path == "/v1/auth/token/create/"+contracts.SmallOpenBaoInitialIssuerRole {
		f.posts++
		var body bao.TokenCreateRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		s := f.claim.State
		if decoder.Decode(&body) != nil || r.Header.Get("X-Vault-Token") != initialBaoToken || !reflect.DeepEqual(body.Policies, []string{f.desired.Providers.IssuerPolicy}) || !body.NoDefaultPolicy || body.NoParent || body.Renewable == nil || *body.Renewable || body.Type != "service" || !reflect.DeepEqual(body.Metadata, map[string]string{"asservat-installation": s.InstallationID, "asservat-request": s.RequestID, "asservat-operation": s.ProviderMint.OperationID}) {
			f.t.Error("mint POST did not preserve exact original scope")
			w.WriteHeader(400)
			return
		}
		var err error
		f.ttl, err = time.ParseDuration(body.TTL)
		if err != nil || body.ExplicitMaxTTL != body.TTL || f.ttl <= 0 {
			f.t.Error("invalid explicit TTL")
			w.WriteHeader(400)
			return
		}
		if f.mode == "unknown" {
			w.WriteHeader(503)
			reply(map[string]any{"errors": []string{"private-provider-details"}})
			return
		}
		if f.mode == "redirect" {
			w.Header().Set("Location", "/v1/retry")
			w.WriteHeader(307)
			return
		}
		f.issued = time.Now().UTC()
		f.expiry = f.issued.Add(f.ttl)
		response := map[string]any{"auth": map[string]any{"client_token": "original-issued-token", "accessor": "positive-original-issuer", "token_type": "service", "entity_id": s.Material.BundledIdentity.EntityID, "policies": body.Policies, "token_policies": body.Policies, "metadata": body.Metadata, "lease_duration": int64(f.ttl / time.Second), "renewable": false, "orphan": false, "num_uses": 0}}
		notice := fmt.Sprintf("Explicit max TTL specified both during creation call and in role; using the lesser value of %d seconds", int64(f.ttl/time.Second))
		switch f.mode {
		case "cap-notice", "cap-notice-foreign-entity":
			response["warnings"] = []string{notice}
		case "extra-warning":
			response["warnings"] = []string{notice, "Policy does not exist"}
		case "changed-warning":
			response["warnings"] = []string{notice + " changed"}
		}
		reply(response)
		return
	}
	f.reads++
	if r.Method != http.MethodGet || r.Header.Get("X-Vault-Token") != "original-issued-token" {
		f.t.Error("unexpected mint effect/retry/credential")
		w.WriteHeader(403)
		return
	}
	names := f.desired.Providers
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/auth/token/roles/"):
		name := strings.TrimPrefix(r.URL.Path, "/v1/auth/token/roles/")
		policy := names.WrapPolicy
		if name == names.UnwrapRole {
			policy = names.UnwrapPolicy
		}
		reply(map[string]any{"data": map[string]any{"name": name, "allowed_policies": []string{policy}, "orphan": false, "renewable": false, "token_no_default_policy": true, "token_type": "service", "period": 0, "token_period": 0, "explicit_max_ttl": 0, "token_explicit_max_ttl": 900}})
	case strings.HasPrefix(r.URL.Path, "/v1/sys/policies/acl/"):
		policies, err := kms.InitialBootstrapProviderPolicies(names, f.desired.KeyService.AuditMount, f.desired.KeyService.AuditKey)
		if err != nil {
			f.t.Error(err)
			w.WriteHeader(500)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/sys/policies/acl/")
		reply(map[string]any{"data": map[string]any{"name": name, "policy": policies[name], "version": 1, "cas_required": false, "allow_wildcards_in_identity_templates": false, "allow_slashes_in_identity_templates": false}})
	case r.URL.Path == "/v1/auth/token/lookup-self":
		entity := f.claim.State.Material.BundledIdentity.EntityID
		if f.mode == "foreign-entity" || f.mode == "cap-notice-foreign-entity" {
			entity = initialBaoPVC
		}
		expiry := f.expiry
		if f.mode == "late-expiry" {
			expiry = f.claim.State.Material.BundledIdentity.SetupParent.ExpiresAt.Add(time.Second)
		}
		reply(map[string]any{"data": map[string]any{"accessor": "positive-original-issuer", "type": "service", "policies": []string{names.IssuerPolicy}, "num_uses": 0, "orphan": false, "renewable": false, "entity_id": entity, "identity_policies": []string{}, "creation_ttl": int64(f.ttl / time.Second), "explicit_max_ttl": int64(f.ttl / time.Second), "issue_time": f.issued, "expire_time": expiry}})
	default:
		f.t.Error("unrecognized mint request")
		w.WriteHeader(404)
	}
}
func TestInitialOpenBaoMintOneOriginalPOSTAndActualProfileCheck(t *testing.T) {
	f := newInitialBaoMintFixture(t, "")
	token, parent, err := mintInitialOpenBaoIssuerWithHTTP(t.Context(), f.desired, f.claim, f.http)
	if err != nil || token != "original-issued-token" || f.posts != 1 || f.reads != 6 {
		t.Fatal("bounded original mint/profile failed", err, f.posts, f.reads)
	}
	cutoff := f.claim.State.ProviderMint.ExpiresBefore
	if !parent.ExpiresAt.Before(cutoff) || f.ttl > cutoff.Sub(f.claim.State.ProviderMint.Until)-time.Second {
		t.Fatal("POST moved expiry beyond original cutoff")
	}
}
func TestInitialOpenBaoMintUnknownRefusalNeverRetries(t *testing.T) {
	for _, mode := range []string{"unknown", "redirect", "foreign-entity", "late-expiry", "extra-warning", "changed-warning", "cap-notice-foreign-entity"} {
		t.Run(mode, func(t *testing.T) {
			f := newInitialBaoMintFixture(t, mode)
			token, _, err := mintInitialOpenBaoIssuerWithHTTP(t.Context(), f.desired, f.claim, f.http)
			if err == nil || token != "" || f.posts != 1 {
				t.Fatal("unknown/refused original mint replayed or accepted", err, f.posts)
			}
			if (mode == "foreign-entity" || mode == "late-expiry" || mode == "cap-notice-foreign-entity") && err.Error() != "bundled key provider mint-verification/issuer-profile" {
				t.Fatal("fixed failure phase lost", err)
			}
			if strings.Contains(err.Error(), initialBaoToken) || strings.Contains(err.Error(), "private-provider-details") {
				t.Fatal("private provider response exposed")
			}
		})
	}
}
func TestInitialOpenBaoMintInvalidSeedRefusesBeforePOST(t *testing.T) {
	f := newInitialBaoMintFixture(t, "")
	f.claim.State.SeedUID = ""
	if _, _, err := mintInitialOpenBaoIssuerWithHTTP(t.Context(), f.desired, f.claim, f.http); err == nil || f.posts != 0 {
		t.Fatal("missing actual seed UID spent mint effect", err, f.posts)
	}
}

func TestInitialOpenBaoMintExpectedNoticeStillChecksActualProfile(t *testing.T) {
	f := newInitialBaoMintFixture(t, "cap-notice")
	token, parent, err := mintInitialOpenBaoIssuerWithHTTP(t.Context(), f.desired, f.claim, f.http)
	if err != nil || token != "original-issued-token" || f.posts != 1 || f.reads != 6 || !parent.ExpiresAt.Before(f.claim.State.ProviderMint.ExpiresBefore) {
		t.Fatal("intentional caps notice blocked verified original mint", err, f.posts, f.reads)
	}
}
