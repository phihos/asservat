package kms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type ownerProviderControlFixture struct {
	mu                                       sync.Mutex
	control                                  *ownerProviderControl
	server                                   *httptest.Server
	issued, expires                          time.Time
	shift                                    time.Duration
	loginCalls, renewCalls, lookups, revokes int
	mode                                     string
	authChange                               func(*ownerProviderAuthReply)
	lookupChange                             func(*initialTokenLookup)
}

func newOwnerProviderControlFixture(t *testing.T, change ...func(*http.Transport)) *ownerProviderControlFixture {
	t.Helper()
	f := &ownerProviderControlFixture{}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(9720), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	f.server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	f.server.StartTLS()
	t.Cleanup(f.server.Close)
	in, account, secret, now := ownerProviderRecipeInput(t)
	in.KeyService.Endpoint, in.KeyService.Roots = f.server.URL, [][]byte{der}
	recipe, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, apply := range change {
		apply(f.server.Client().Transport.(*http.Transport))
	}
	f.control, err = newOwnerProviderControl(in, recipe.Profile, "audit-wrap", f.server.Client(), func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return time.Now().Add(f.shift) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.control.close)
	return f
}

func ownerProviderTestJWT(end time.Time) []byte {
	return []byte("eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":`+strconv.FormatInt(end.Unix(), 10)+`}`)) + ".synthetic-signature")
}

func (f *ownerProviderControlFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now().Add(f.shift)
	meta := map[string]string{"role": f.control.role, "service_account_name": f.control.account, "service_account_uid": f.control.accountUID, "service_account_namespace": f.control.namespace, "service_account_secret_name": ""}
	writeAuth := func() {
		a := ownerProviderAuthReply{ClientToken: "exact-service-token", Accessor: "exact-accessor", Policies: []string{f.control.role}, TokenPolicies: []string{f.control.role}, Metadata: meta, Orphan: true, EntityID: "10000000-0000-4000-8000-000000000009", LeaseDuration: 300, Renewable: true, Type: "service"}
		if f.authChange != nil {
			f.authChange(&a)
		}
		_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Auth: &a})
	}
	switch r.Method + " " + r.URL.Path {
	case "POST /v1/auth/owner-auth/login":
		f.loginCalls++
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["role"] != f.control.role || body["jwt"] == "" || r.Header.Get("X-Vault-Token") != "" {
			w.WriteHeader(403)
			return
		}
		f.issued = now.Truncate(time.Second)
		f.expires = now.Add(300 * time.Second)
		if f.mode == "unknown-login" {
			w.WriteHeader(503)
			return
		}
		writeAuth()
	case "POST /v1/auth/token/renew-self":
		f.renewCalls++
		if r.Header.Get("X-Vault-Token") != "exact-service-token" {
			w.WriteHeader(403)
			return
		}
		f.expires = now.Add(300 * time.Second)
		if f.mode == "unknown-renewal" {
			w.WriteHeader(503)
			return
		}
		writeAuth()
	case "GET /v1/auth/token/lookup-self":
		f.lookups++
		if r.Header.Get("X-Vault-Token") != "exact-service-token" {
			w.WriteHeader(403)
			return
		}
		v := initialTokenLookup{ID: "exact-service-token", Accessor: "exact-accessor", Policies: []string{f.control.role}, Path: "auth/owner-auth/login", Meta: meta, Display: "kubernetes-original-owner", Orphan: true, Creation: f.issued.Unix(), CreationTTL: 300, Expire: f.expires, TTL: int64(f.expires.Sub(now) / time.Second), MaxTTL: 900, Entity: "10000000-0000-4000-8000-000000000009", Type: "service", Renewable: true, Issued: f.issued}
		if f.renewCalls > 0 {
			v.LastRenewal = now.Unix()
			v.LastRenewalDate = now
		}
		if f.lookupChange != nil {
			f.lookupChange(&v)
		}
		raw, _ := json.Marshal(v)
		if f.mode == "extra-lookup-field" {
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			fields["external_namespace_policies"] = json.RawMessage(`{"other":["extra"]}`)
			raw, _ = json.Marshal(fields)
		}
		_ = json.NewEncoder(w).Encode(ownerProviderControlReply{Data: raw})
	case "POST /v1/auth/token/revoke-self":
		f.revokes++
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestOwnerProviderControlUnknownLoginNeverReplaysOrLooksUpAccessor(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	f.mode = "unknown-login"
	credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
	if err == nil || credential != nil {
		t.Fatal("unknown login produced a credential")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.lookups != 0 || f.renewCalls != 0 {
		t.Fatal("unknown login repeated or searched for issued material")
	}
}

func TestOwnerProviderControlLostRenewalNeedsExactReadAndKeepsOriginalObservation(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
	if err != nil {
		t.Fatal("first login", err)
	}
	defer credential.destroy()
	originalEnd, originalIssue, originalJWT := credential.until, credential.issued, credential.jwtUntil
	f.mu.Lock()
	f.shift = 120 * time.Second
	f.mode = "unknown-renewal"
	f.mu.Unlock()
	if next, err := f.control.renew(context.Background(), credential); err == nil || next != nil {
		t.Fatal("unknown renewal expanded known credential")
	}
	if !credential.until.Equal(originalEnd) {
		t.Fatal("renewal mutated earlier usable end")
	}
	next, err := f.control.reconcile(context.Background(), credential)
	if err != nil {
		t.Fatal("same-token positive lookup", err)
	}
	defer next.destroy()
	if !next.until.After(originalEnd) || !next.issued.Equal(originalIssue) || !next.jwtUntil.Equal(originalJWT) || !next.hardUntil.Equal(credential.hardUntil) || !credential.until.Equal(originalEnd) {
		t.Fatal("reconciliation replaced original issuance or existing borrow bounds")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 1 || f.renewCalls != 1 || f.lookups != 2 {
		t.Fatal("reconciliation dispatched another login or renewal")
	}
}

func TestOwnerProviderControlRejectsAdditionalTokenAndIdentityAuthority(t *testing.T) {
	for name, change := range map[string]func(*ownerProviderAuthReply){
		"default":  func(v *ownerProviderAuthReply) { v.Policies = append(v.Policies, "default") },
		"direct":   func(v *ownerProviderAuthReply) { v.TokenPolicies = append(v.TokenPolicies, "other") },
		"identity": func(v *ownerProviderAuthReply) { v.IdentityPolicies = []string{"other"} },
		"account": func(v *ownerProviderAuthReply) {
			v.Metadata["service_account_uid"] = "10000000-0000-4000-8000-000000000099"
		},
		"metadata": func(v *ownerProviderAuthReply) {
			delete(v.Metadata, "service_account_secret_name")
			v.Metadata["new_authority"] = ""
		},
		"batch":  func(v *ownerProviderAuthReply) { v.Type = "batch" },
		"ttl":    func(v *ownerProviderAuthReply) { v.LeaseDuration = 301 },
		"parent": func(v *ownerProviderAuthReply) { v.Orphan = false },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerProviderControlFixture(t)
			f.authChange = change
			if credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second))); err == nil || credential != nil {
				t.Fatal("unexpected authority accepted")
			}
		})
	}
}

func TestOwnerProviderControlSelfLookupCannotReplaceOriginalScopeOrHardEnd(t *testing.T) {
	for name, change := range map[string]func(*initialTokenLookup){
		"identity":     func(v *initialTokenLookup) { v.IdentityPolicies = []string{"extra"} },
		"policy":       func(v *initialTokenLookup) { v.Policies = []string{"other"} },
		"unbounded":    func(v *initialTokenLookup) { v.MaxTTL = 0 },
		"extended-max": func(v *initialTokenLookup) { v.MaxTTL = 901 },
		"wrong-mount":  func(v *initialTokenLookup) { v.Path = "auth/other/login" },
		"expired":      func(v *initialTokenLookup) { v.Expire = time.Now().Add(-time.Second) },
		"other-token":  func(v *initialTokenLookup) { v.ID = "other-token" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newOwnerProviderControlFixture(t)
			f.lookupChange = change
			if credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second))); err == nil || credential != nil {
				t.Fatal("changed self lookup accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.loginCalls != 1 || f.lookups != 1 || f.revokes != 1 {
				t.Fatal("bad positive token was replayed or not finitely retired")
			}
		})
	}
}

func TestOwnerProviderUnverifiedJWTOnlyShortensReauthenticationScheduling(t *testing.T) {
	now := time.Now().UTC()
	c := ownerProviderCredential{observed: now, until: now.Add(300 * time.Second), hardUntil: now.Add(900 * time.Second), jwtUntil: now.Add(200 * time.Second)}
	if !c.reauthenticateAt().Equal(now.Add(170*time.Second)) || !c.renewAt().Equal(now.Add(120*time.Second)) {
		t.Fatal("original short JWT was ignored")
	}
	c.jwtUntil = now.Add(24 * time.Hour)
	if !c.reauthenticateAt().Equal(now.Add(780*time.Second)) || !c.until.Equal(now.Add(300*time.Second)) {
		t.Fatal("unverified JWT widened provider lease or hard maximum")
	}
	for _, raw := range []string{"bad", "a." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":2,"exp":3}`)) + ".b", "a." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":"123"}`)) + ".b", strings.Repeat("x", 16385)} {
		if _, err := ownerProviderJWTEnd([]byte(raw), now); err == nil {
			t.Fatal("unsafe scheduling claims parsed")
		}
	}
}

func TestOwnerProviderControlCannotInheritTLSBypassHooks(t *testing.T) {
	var hooks atomic.Int32
	f := newOwnerProviderControlFixture(t, func(transport *http.Transport) {
		transport.DialTLS = func(string, string) (net.Conn, error) { hooks.Add(1); return nil, errors.New("unexpected custom TLS") }
		transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
			hooks.Add(1)
			return nil, errors.New("unexpected custom TLS")
		}
		transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{"h2": func(string, *tls.Conn) http.RoundTripper { hooks.Add(1); return nil }}
	})
	transport := f.control.http.Transport.(*http.Transport)
	if transport.DialTLS != nil || transport.DialTLSContext != nil || transport.TLSNextProto != nil {
		t.Fatal("credential transport retained a TLS bypass")
	}
	credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
	if err != nil {
		t.Fatal("normal pinned TLS was unavailable", err)
	}
	defer credential.destroy()
	if hooks.Load() != 0 {
		t.Fatal("credential request entered custom TLS")
	}
}

func TestOwnerProviderControlRejectsUnknownLookupAuthorityAndForeignCredential(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	f.mode = "extra-lookup-field"
	if credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second))); err == nil || credential != nil {
		t.Fatal("unknown lookup authority accepted")
	}
	f.mu.Lock()
	f.mode = ""
	f.mu.Unlock()
	credential, err := f.control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	defer credential.destroy()
	other := *f.control
	if _, err = other.renew(context.Background(), credential); err == nil {
		t.Fatal("other control accepted credential")
	}
	if _, err = other.reconcile(context.Background(), credential); err == nil {
		t.Fatal("other control reconciled credential")
	}
	if err = other.revoke(context.Background(), credential); err == nil {
		t.Fatal("other control revoked credential")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 2 || f.renewCalls != 0 || f.lookups != 2 || f.revokes != 1 {
		t.Fatal("foreign control reached provider")
	}
}

func TestOwnerProviderControlPinsProfileRootsBeforeJWTDisclosure(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	in, account, secret, now := ownerProviderRecipeInput(t)
	in.KeyService.Endpoint = f.server.URL // This input's independently generated CA differs.
	recipe, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	control, err := newOwnerProviderControl(in, recipe.Profile, "audit-wrap", f.server.Client(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer control.close()
	if credential, err := control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second))); err == nil || credential != nil {
		t.Fatal("ambient trusted client roots overrode profile")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.loginCalls != 0 {
		t.Fatal("JWT disclosed to a server outside the profile roots")
	}
}

// The hostile injected TLS hook models why replacing TLSClientConfig alone is
// insufficient. Actual TLS connects, but the generated profile trusts another
// CA; the JWT must never reach that server through an inherited custom hook.
func TestOwnerProviderControlRejectsCustomTLSDialBypassBeforeJWTDisclosure(t *testing.T) {
	f := newOwnerProviderControlFixture(t)
	in, account, secret, now := ownerProviderRecipeInput(t)
	in.KeyService.Endpoint = f.server.URL
	recipe, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	client := *f.server.Client()
	transport := client.Transport.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		plain, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// Test-only hostile hook, deliberately outside the profile CA set.
		connection := tls.Client(plain, &tls.Config{InsecureSkipVerify: true})
		if err = connection.HandshakeContext(ctx); err != nil {
			_ = plain.Close()
			return nil, err
		}
		return connection, nil
	}
	client.Transport = transport
	defer transport.CloseIdleConnections()
	control, err := newOwnerProviderControl(in, recipe.Profile, "audit-wrap", &client, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer control.close()
	credential, err := control.login(context.Background(), ownerProviderTestJWT(time.Now().Add(600*time.Second)))
	if credential != nil {
		defer credential.destroy()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err == nil || credential != nil || f.loginCalls != 0 {
		t.Fatalf("custom TLS hook disclosed JWT outside profile: error=%v, login requests=%d", err, f.loginCalls)
	}
}
