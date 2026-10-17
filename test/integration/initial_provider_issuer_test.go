package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/contracts"
)

// This small provider qualification uses fixture-created ACLs, roles and a
// bounded issuer. The synthetic claims below are not the installation journal
// or authority to run the installer. No Kubernetes or activation is involved.
func TestInitialProviderIssuerWithRealOpenBao(t *testing.T) {
	path := os.Getenv("ASSERVAT_FLEET_FIXTURES")
	if path == "" {
		path = os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	}
	if path == "" {
		t.Skip("run owned fleet-integration fixture")
	}
	var f fixture
	raw, e := os.ReadFile(path)
	if e != nil || json.Unmarshal(raw, &f) != nil || f.KMS == "" {
		t.Fatal("provider fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	stem := "initial-issuer-" + strings.ReplaceAll(custodyID(), "-", "")[:12]
	profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "synthetic-material", UID: custodyID()}, IssuerPolicy: stem + "-issuer", WrapRole: stem + "-wrap", WrapPolicy: stem + "-encrypt", UnwrapRole: stem + "-unwrap", UnwrapPolicy: stem + "-decrypt"}
	policies, e := kms.InitialProviderPolicies(profile, stem, "audit")
	if e != nil {
		t.Fatal("fixture policy construction")
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+stem, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", stem+"/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
	for name, policy := range policies {
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": policy}, 204)
	}
	for role, policy := range map[string]string{profile.WrapRole: profile.WrapPolicy, profile.UnwrapRole: profile.UnwrapPolicy} {
		request(t, f.KMS, "synthetic-root", "auth/token/roles/"+role, map[string]any{"allowed_policies": []string{policy}, "orphan": false, "renewable": false, "token_type": "service", "token_no_default_policy": true, "token_explicit_max_ttl": 900}, 204)
	}
	parentReply := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{profile.IssuerPolicy}, "no_default_policy": true, "no_parent": false, "renewable": false, "type": "service", "ttl": "10m", "explicit_max_ttl": "10m"}, 200)
	issuerToken := parentReply["auth"].(map[string]any)["client_token"].(string)
	defer request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": issuerToken}, 204)

	// Observe the actual pinned provider's role-only lookup shape independently
	// of the production decoder. This fixture-only child is revoked before the
	// product's first Issue. Only finite scalar facts are reported, never bodies.
	t.Run("role-only-provider-lookup", func(t *testing.T) {
		r := request(t, f.KMS, issuerToken, "auth/token/create/"+profile.WrapRole, map[string]any{"policies": []string{profile.WrapPolicy}, "no_default_policy": true, "no_parent": false, "renewable": false, "type": "service", "ttl": "60s"}, 200)
		token := r["auth"].(map[string]any)["client_token"].(string)
		defer request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": token}, 204)
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, f.KMS+"/v1/auth/token/lookup-self", nil)
		if e != nil {
			t.Fatal("fixture lookup construction")
		}
		req.Header.Set("X-Vault-Token", token)
		tr := &http.Transport{Proxy: nil}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		response, e := client.Do(req)
		if e != nil {
			t.Fatal("fixture lookup unavailable")
		}
		defer response.Body.Close()
		var lookup struct {
			Data struct {
				MaxTTL      int64     `json:"explicit_max_ttl"`
				CreationTTL int64     `json:"creation_ttl"`
				Renewable   bool      `json:"renewable"`
				Orphan      bool      `json:"orphan"`
				Role        string    `json:"role"`
				Issued      time.Time `json:"issue_time"`
				Expires     time.Time `json:"expire_time"`
			} `json:"data"`
		}
		if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 32768)).Decode(&lookup) != nil {
			t.Fatal("fixture lookup response invalid")
		}
		d := lookup.Data
		if d.MaxTTL != 0 || d.CreationTTL < 1 || d.CreationTTL > 60 || d.Renewable || d.Orphan || d.Role != profile.WrapRole || d.Issued.IsZero() || !d.Issued.Before(d.Expires) || d.Expires.Sub(d.Issued) > 61*time.Second {
			t.Fatal("pinned role-only token shape differs")
		}
		t.Log("role_only_explicit_max_ttl_zero=true; nonrenewable=true; finite_actual_expiry=true")
	})
	if t.Failed() {
		return
	}

	u, e := url.Parse(f.KMS)
	if e != nil {
		t.Fatal("fixture provider URL")
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	proxy.Transport = transport
	var observationsMu sync.Mutex
	observations := []string{}
	proxy.ModifyResponse = func(response *http.Response) error {
		operation := ""
		switch response.Request.URL.Path {
		case "/v1/auth/token/lookup-accessor":
			operation = "accessor-lookup"
		case "/v1/auth/token/revoke-accessor":
			operation = "accessor-revoke"
		case "/v1/auth/token/lookup-self":
			operation = "self-lookup"
		}
		if operation == "" {
			return nil
		}
		exact, single, wrapped := false, false, false
		if operation == "accessor-lookup" && response.StatusCode == 400 {
			body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
			response.Body.Close()
			if err != nil || len(body) > 32768 {
				clear(body)
				return fmt.Errorf("bounded fixture response unavailable")
			}
			var payload struct {
				Errors []string `json:"errors"`
			}
			if json.Unmarshal(body, &payload) == nil {
				single = len(payload.Errors) == 1
				exact = single && payload.Errors[0] == "invalid accessor"
				wrapped = single && payload.Errors[0] == "1 error occurred:\n\t* invalid accessor\n\n"
			}
			response.Body = &initialProviderWireBody{Reader: bytes.NewReader(body), body: body}
		}
		observationsMu.Lock()
		if len(observations) < 64 {
			observations = append(observations, fmt.Sprintf("%s status=%d exact_invalid_accessor=%t single_error=%t exact_wrapped_invalid_accessor=%t", operation, response.StatusCode, exact, single, wrapped))
		}
		observationsMu.Unlock()
		return nil
	}
	resetObservations := func() { observationsMu.Lock(); observations = nil; observationsMu.Unlock() }
	reportObservations := func(t *testing.T) {
		observationsMu.Lock()
		defer observationsMu.Unlock()
		for _, v := range observations {
			t.Log(v)
		}
	}

	var creates atomic.Int64
	bridge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/auth/token/create/") {
			creates.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer bridge.Close()
	issuer, e := kms.NewInitialProviderIssuer(bridge.URL, issuerToken, stem, "audit", custodyID(), custodyID(), profile, bridge.Client(), time.Now)
	if e != nil {
		t.Fatal("product issuer construction")
	}
	defer issuer.Close()
	parent, _, e := issuer.Check(ctx, time.Now().Add(11*time.Minute))
	if e != nil {
		t.Fatal("product issuer preflight", e)
	}
	for _, purpose := range []string{"wrap", "unwrap"} {
		t.Run(purpose, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Microsecond)
			claim := contracts.InitialProviderIssue{ID: custodyID(), StartedAt: now, Until: now.Add(5 * time.Second), ExpiresBefore: parent.ExpiresAt}
			before := creates.Load()
			issued, e := issuer.Issue(ctx, purpose, claim, parent)
			if creates.Load() != before+1 {
				t.Fatal("product Issue did not make exactly one create")
			}
			if e != nil {
				t.Fatal("product rejected actual role-capped child", e)
			}
			if issued.Token == "" || issued.Accessor == "" || issued.IssuedAt.Before(claim.StartedAt) || issued.IssuedAt.After(claim.Until) || !issued.ExpiresAt.Before(claim.ExpiresBefore) {
				t.Fatal("product returned invalid original dates")
			}
			if e = issuer.Verify(ctx, purpose, claim, parent, issued); e != nil || creates.Load() != before+1 {
				t.Fatal("positive response verification failed or repeated create")
			}
			claim.Response = &issued
			resetObservations()
			if _, e = issuer.Revoke(ctx, purpose, claim, parent, issued); e != nil {
				reportObservations(t)
				t.Fatal("positive credential retirement", e)
			}
			reportObservations(t)
			if _, e = issuer.Revoke(ctx, purpose, claim, parent, issued); e != nil || creates.Load() != before+1 {
				t.Fatal("retirement replay failed or created credentials")
			}
			if e = issuer.Verify(ctx, purpose, claim, parent, issued); e == nil {
				t.Fatal("revoked original credential remained usable")
			}
		})
	}
}

// The proxy retains no response body after it forwards the exact original bytes.
// Only fixed labels/status/booleans enter the bounded diagnostic trace.
type initialProviderWireBody struct {
	*bytes.Reader
	body []byte
}

func (r *initialProviderWireBody) Close() error { clear(r.body); r.body = nil; return nil }
