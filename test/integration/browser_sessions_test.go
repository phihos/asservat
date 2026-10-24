package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/oidc"
	"asservat.local/asservat/internal/adapters/postgres"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	"github.com/jackc/pgx/v5/pgxpool"
)

type browserFixturePolicy struct{ issuer, client, group string }

type browserRefreshObserver struct {
	app.BrowserProvider
	refreshes atomic.Int64
}

// Pause only this CSRF reader after actual decryption. Refresh keeps its normal
// cipher and provider, so the test races a real committed credential rotation.
type browserCSRFPause struct {
	app.CredentialCipher
	entered, release chan struct{}
}

func (c browserCSRFPause) Decrypt(ctx context.Context, ciphertext, ad []byte) ([]byte, error) {
	plain, err := c.CredentialCipher.Decrypt(ctx, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	close(c.entered)
	select {
	case <-ctx.Done():
		clear(plain)
		return nil, ctx.Err()
	case <-c.release:
		return plain, nil
	}
}

func (p *browserRefreshObserver) Refresh(ctx context.Context, token, subject, session, nonce string) (app.BrowserTokens, error) {
	p.refreshes.Add(1)
	return p.BrowserProvider.Refresh(ctx, token, subject, session, nonce)
}

func (p browserFixturePolicy) IdentityPolicy(_ context.Context, issuer string) (identity.Policy, error) {
	now := time.Now().UTC()
	if issuer != p.issuer {
		return identity.Policy{}, identity.ErrDenied
	}
	return identity.Policy{Revision: identity.Revision{UID: "synthetic-browser-policy", Generation: 1, Digest: [32]byte{1}}, Issuer: issuer, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []identity.Client{{ID: p.client, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{p.group}, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute}, nil
}

// Real HTTPS browser/OIDC, PostgreSQL, and OpenBao. Protected root and identity
// configuration are synthetic acceptance inputs, not production bootstrap.
func (f *kcFixture) browserSessions(t *testing.T, ca []byte, mappers []any, user, group string) {
	t.Helper()
	copyFixture := *f
	copyFixture.t = t
	f = &copyFixture
	ctx := context.Background()
	if f.Postgres == "" || f.KMS == "" {
		t.Fatal("owned browser dependencies absent")
	}
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	u, _ := url.Parse(f.Postgres)
	address, tlsConfig := pgTLSBridge(t, u.Host)
	pc, _ := pgxpool.ParseConfig("postgres://browser_runtime:synthetic-browser@" + address + "/custody_test?sslmode=disable")
	pc.ConnConfig.TLSConfig = tlsConfig
	pc.ConnConfig.Fallbacks = nil
	pc.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	root, epoch := "74000000-0000-4000-8000-000000000001", "74000000-0000-4000-8000-000000000002"
	if _, err = admin.Exec(ctx, "INSERT INTO browser_session_root VALUES($1,$2,true,16,16,16)", root, epoch); err != nil {
		t.Fatal(err)
	}
	settingsConfig := pc.Copy()
	settingsConfig.ConnConfig.User = "browser_settings_runtime"
	settingsConfig.ConnConfig.Password = "synthetic-browser-settings"
	settingsConfig.MaxConns = 2
	settingsPool, err := pgxpool.NewWithConfig(ctx, settingsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer settingsPool.Close()
	projection, err := postgres.NewBrowserSettingsProjection(ctx, settingsPool, root)
	if err != nil {
		t.Fatal(err)
	}
	bridge := tlsBridge(t, f.KMS)
	bao := func(path string, body string) {
		t.Helper()
		req, _ := http.NewRequest("POST", bridge.URL+"/v1/"+path, strings.NewReader(body))
		req.Header.Set("X-Vault-Token", "synthetic-root")
		resp, e := bridge.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			t.Fatalf("synthetic KMS configuration status %d", resp.StatusCode)
		}
	}
	bao("sys/mounts/browser-transit", `{"type":"transit"}`)
	bao("browser-transit/keys/sessions", `{"type":"aes256-gcm96"}`)
	seal, err := kms.NewSealer(bridge.URL, "synthetic-root", "browser-transit", "sessions", bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	open, err := kms.NewOpener(bridge.URL, "synthetic-root", "browser-transit", "sessions", bridge.Client())
	if err != nil {
		t.Fatal(err)
	}
	cipher := kms.BrowserCipher{Sealer: seal, Opener: open}
	var handler browser.SessionHandler
	logoutReceived := make(chan struct{}, 4)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
		if r.URL.Path == "/auth/backchannel-logout" {
			select {
			case logoutReceived <- struct{}{}:
			default:
			}
		}
	}))
	// Bind only loopback. The owned, capability-dropped IdP shares the host
	// network and also binds only loopback, allowing real HTTPS callbacks.
	if net.ParseIP(f.CallbackHost) == nil || !net.ParseIP(f.CallbackHost).IsLoopback() {
		t.Fatal("invalid owned callback interface")
	}
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort(f.CallbackHost, "0"))
	if err != nil {
		t.Fatal(err)
	}
	private, e := os.ReadFile(f.CallbackKey)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := tls.X509KeyPair(ca, private)
	clear(private)
	if e != nil {
		t.Fatal(e)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	clientID, secret := "browser", randomPKCE()
	settings := identity.BrowserSettings{RootID: root, Epoch: epoch, Issuer: f.Issuer, ClientID: clientID, Origin: server.URL, Revision: identity.Revision{UID: "synthetic-browser-settings", Generation: 1, Digest: [32]byte{1}}, MaxLifetimeSeconds: 28800, MaxLogins: 16, MaxSessions: 16, MaxLogoutEvents: 16}
	store, err := postgres.NewBrowserSessions(ctx, pool, settings.Binding())
	if err != nil {
		t.Fatal(err)
	}
	renew := func() error {
		current := settings
		current.ObservedAt = time.Now().UTC()
		current.FreshUntil = current.ObservedAt.Add(5 * time.Second)
		return projection.ObserveBrowserSettings(ctx, current)
	}
	if err = renew(); err != nil {
		t.Fatal(err)
	}
	// This fixture supplies protected settings synthetically. Renewal exercises
	// the separate SQL role; real Kubernetes source/RBAC qualification is tested
	// by permission-integration. Stop before intentional fencing below.
	stopRenewal, renewalDone := make(chan struct{}), make(chan error, 1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopRenewal:
				renewalDone <- nil
				return
			case <-ticker.C:
				if e := renew(); e != nil {
					renewalDone <- e
					return
				}
			}
		}
	}()
	stop := sync.OnceFunc(func() {
		close(stopRenewal)
		if e := <-renewalDone; e != nil {
			t.Error(e)
		}
	})
	defer stop()
	f.json("POST", "/admin/realms/asservat-test/clients", map[string]any{"clientId": clientID, "protocol": "openid-connect", "publicClient": false, "secret": secret, "standardFlowEnabled": true, "directAccessGrantsEnabled": false, "implicitFlowEnabled": false, "serviceAccountsEnabled": false, "fullScopeAllowed": false, "redirectUris": []string{server.URL + "/auth/callback"}, "defaultClientScopes": []string{"basic", "evidence:read", "evidence:download", "evidence:capture"}, "optionalClientScopes": []string{}, "attributes": map[string]string{"pkce.code.challenge.method": "S256", "backchannel.logout.url": server.URL + "/auth/backchannel-logout", "backchannel.logout.session.required": "true"}, "protocolMappers": mappers})
	trust := oidc.Trust{Issuer: f.Issuer, Audience: "asservat-api", JWKSURL: f.Issuer + "/protocol/openid-connect/certs", RootCA: ca, KeyMaxAge: time.Minute, Profile: oidc.Keycloak}
	provider, err := oidc.NewBrowser(oidc.BrowserTrust{Access: trust, ClientID: clientID, ClientSecret: secret, AuthorizationEndpoint: f.Issuer + "/protocol/openid-connect/auth", TokenEndpoint: f.Issuer + "/protocol/openid-connect/token", RedirectURI: server.URL + "/auth/callback", Scopes: []string{"openid", "evidence:read", "evidence:download", "evidence:capture"}}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	verifier, err := oidc.New(trust, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	sessions := app.BrowserSessions{Store: store, Cipher: cipher, Provider: provider, Identities: app.Service{Tokens: verifier, Policies: browserFixturePolicy{f.Issuer, clientID, group}, Now: time.Now}, Logout: provider, Issuer: f.Issuer, ClientID: clientID, Epoch: epoch, Lifetime: 8 * time.Hour, Now: time.Now}
	handler = browser.SessionHandler{Origin: server.URL, Issuer: f.Issuer, Sessions: sessions}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	roots.AddCert(server.Certificate())
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request := func(method, target, body, csrf string) (int, []byte, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(method, target, strings.NewReader(body))
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", server.URL)
			if csrf != "" {
				req.Header.Set("X-CSRF-Token", csrf)
			}
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal("fixture browser HTTP failure")
		}
		defer resp.Body.Close()
		b, e := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		if e != nil {
			t.Fatal(e)
		}
		return resp.StatusCode, b, resp.Header
	}
	login := func() (string, string) {
		t.Helper()
		status, _, headers := request("GET", server.URL+"/auth/login?return_to=%2Finvestigations", "", "")
		if status != 303 {
			t.Fatalf("login start %d", status)
		}
		authURL := headers.Get("Location")
		query, _ := url.Parse(authURL)
		if query.Query().Get("code_challenge_method") != "S256" || query.Query().Get("nonce") == "" || strings.Contains(authURL, "offline_access") {
			t.Fatal("login protocol bounds")
		}
		status, page, headers := request("GET", authURL, "", "")
		if status == 200 {
			match := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
			if len(match) != 2 {
				t.Fatal("login form missing")
			}
			action := html.UnescapeString(string(match[1]))
			if !strings.HasPrefix(action, f.Issuer+"/login-actions/") {
				t.Fatal("wrong login authority")
			}
			status, _, headers = request("POST", action, url.Values{"username": {"developer"}, "password": {f.UserPassword}}.Encode(), "")
		}
		if status != 302 {
			t.Fatalf("provider login %d", status)
		}
		callback := headers.Get("Location")
		status, b, headers := request("GET", callback, "", "")
		if status != 303 {
			t.Fatalf("product callback %d: %s", status, b)
		}
		if headers.Get("Location") != "/investigations" {
			t.Fatal("return path changed")
		}
		for _, c := range headers.Values("Set-Cookie") {
			if strings.HasPrefix(c, browser.SessionCookie+"=") && (!strings.Contains(c, "Secure") || !strings.Contains(c, "HttpOnly") || !strings.Contains(c, "SameSite=Strict") || strings.Contains(c, "Domain=")) {
				t.Fatal("insecure session cookie")
			}
		}
		status, b, _ = request("GET", server.URL+"/api/v1/session", "", "")
		if status != 200 {
			t.Fatalf("session projection %d: %s", status, b)
		}
		var view struct {
			CSRF      string `json:"csrf_token"`
			Principal struct {
				Subject string `json:"subject_id"`
				Kind    string `json:"kind"`
			} `json:"principal"`
			Step string `json:"step_up"`
		}
		if json.Unmarshal(b, &view) != nil || view.Principal.Subject != user || view.Principal.Kind != "user" || view.Step != "unavailable" || len(view.CSRF) != 43 {
			t.Fatal("session projection mismatch")
		}
		return view.CSRF, callback
	}
	csrf, callback := login()
	currentOrigin, _ := url.Parse(server.URL)
	var submissionCookie string
	for _, c := range jar.Cookies(currentOrigin) {
		if c.Name == browser.SessionCookie {
			submissionCookie = c.Value
		}
	}
	verifiedHuman, err := sessions.Resolve(ctx, submissionCookie, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("fleet-bootstrap-issuance", func(t *testing.T) {
		f.qualifyFleetBootstrapIssuance(t, ctx, admin, handler, server.URL, submissionCookie, csrf, clientID, group, seal, open)
	})
	t.Run("signed-policy-submission", func(t *testing.T) {
		testProviderPolicySubmission(t, bridge.URL, bridge.Client(), verifiedHuman.Identity)
	})
	if status, _, _ := request("GET", callback, "", ""); status != 401 {
		t.Fatalf("callback replay %d", status)
	}
	if status, _, _ := request("POST", server.URL+"/auth/refresh", "", randomPKCE()); status != 403 {
		t.Fatal("bad CSRF accepted")
	}
	if status, _, _ := request("GET", server.URL+"/auth/csrf", "", ""); status != 200 {
		t.Fatal("read-only refresh bootstrap failed")
	}
	var encrypted []byte
	var version int64
	if err = admin.QueryRow(ctx, "SELECT ciphertext,version FROM browser_session WHERE root_id=$1", root).Scan(&encrypted, &version); err != nil || version != 1 || bytes.Contains(encrypted, []byte("access_token")) || bytes.Contains(encrypted, []byte(csrf)) {
		t.Fatal("plaintext session state or GET mutation")
	}
	if _, err = pool.Exec(ctx, "UPDATE browser_session_root SET enabled=false WHERE id=$1", root); err == nil {
		t.Fatal("runtime changed protected session root")
	}
	if _, err = pool.Exec(ctx, "SELECT * FROM custody_attempt LIMIT 1"); err == nil {
		t.Fatal("browser has evidence credentials")
	}
	// Corruption cannot produce an identity; restore only through fixture admin.
	if _, err = admin.Exec(ctx, "UPDATE browser_session SET ciphertext=$2 WHERE root_id=$1", root, []byte("corrupt")); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := request("GET", server.URL+"/api/v1/session", "", ""); status != 503 {
		t.Fatalf("corrupt encrypted session %d", status)
	}
	if _, err = admin.Exec(ctx, "UPDATE browser_session SET ciphertext=$2,refresh_at=created_at+interval '1 microsecond' WHERE root_id=$1", root, encrypted); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			status, _, _ := request("POST", server.URL+"/auth/refresh", "", csrf)
			statuses <- status
		}()
	}
	wg.Wait()
	close(statuses)
	ok := false
	for status := range statuses {
		if status == 200 {
			ok = true
		} else if status != http.StatusConflict {
			t.Errorf("concurrent refresh returned %d", status)
		}
	}
	if !ok {
		t.Fatal("no concurrent refresh completed")
	}
	if err = admin.QueryRow(ctx, "SELECT version FROM browser_session WHERE root_id=$1", root).Scan(&version); err != nil || version != 2 {
		t.Fatalf("refresh did not rotate exactly once: %d %v", version, err)
	}
	t.Log("actual confidential OIDC/S256/nonce, opaque cookies, encrypted SQL credentials, current identity and single refresh across eight callers passed")
	if !t.Run("CSRF-read-overlapping-committed-provider-refresh", func(t *testing.T) {
		if _, e := admin.Exec(ctx, "UPDATE browser_session SET refresh_at=created_at+interval '1 microsecond' WHERE root_id=$1", root); e != nil {
			t.Fatal(e)
		}
		paused := sessions
		entered, release := make(chan struct{}), make(chan struct{})
		resume := sync.OnceFunc(func() { close(release) })
		defer resume()
		paused.Cipher = browserCSRFPause{CredentialCipher: cipher, entered: entered, release: release}
		raceCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		type result struct {
			token string
			err   error
		}
		done := make(chan struct{})
		var got result
		go func() {
			token, e := paused.CSRF(raceCtx, submissionCookie)
			got = result{token, e}
			close(done)
		}()
		defer func() { cancel(); resume(); <-done }()
		select {
		case <-entered:
		case <-raceCtx.Done():
			t.Fatal("CSRF reader did not reach actual decrypted credentials")
		}
		if status, _, _ := request("POST", server.URL+"/auth/refresh", "", csrf); status != http.StatusOK {
			t.Fatalf("provider refresh while CSRF read was held: %d", status)
		}
		resume()
		<-done
		if got.token != "" || !errors.Is(got.err, identity.ErrSessionBusy) {
			t.Fatalf("concurrent rotation did not give metadata-free Busy: token returned=%v err=%v", got.token != "", got.err)
		}
		if fresh, e := sessions.CSRF(ctx, submissionCookie); e != nil || fresh != csrf {
			t.Fatal("fresh CSRF lookup did not recover without another rotation", e)
		}
		if e := admin.QueryRow(ctx, "SELECT version FROM browser_session WHERE root_id=$1", root).Scan(&version); e != nil || version != 3 {
			t.Fatalf("CSRF lookup rotated or lost provider result: version=%d err=%v", version, e)
		}
	}) {
		t.FailNow()
	}
	// Complete replacement of membership, including removal, at refresh.
	f.json("DELETE", "/admin/realms/asservat-test/users/"+user+"/groups/"+group, nil)
	if _, err = admin.Exec(ctx, "UPDATE browser_session SET refresh_at=created_at+interval '1 microsecond' WHERE root_id=$1", root); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := request("POST", server.URL+"/auth/refresh", "", csrf); status != 401 {
		t.Fatalf("removed membership refresh %d", status)
	}
	f.json("PUT", "/admin/realms/asservat-test/users/"+user+"/groups/"+group, nil)
	if _, err = admin.Exec(ctx, "DELETE FROM browser_session WHERE root_id=$1", root); err != nil {
		t.Fatal(err)
	}
	csrf, _ = login()
	// Use the actual encrypted SQL session and provider verification for the
	// new shared handoff. This observer changes no provider authority or policy;
	// it makes an unexpected refresh visible even if no SQL rotation completes.
	observedProvider := &browserRefreshObserver{BrowserProvider: provider}
	requestSessions := sessions
	requestSessions.Provider = observedProvider
	var currentIdentity app.CurrentIdentity
	var initialIdentity app.SessionView
	var requestSessionID [32]byte
	var requestSessionVersion int64
	requestContext, cancelRequest := context.WithCancel(ctx)
	defer cancelRequest()
	var liveReader *app.LiveReader
	var liveBatch app.IdentityBatch
	var liveInitial identity.Identity
	if !t.Run("live-reader-across-short-interval-and-explicit-refresh", func(t *testing.T) {
		var cookie string
		for _, c := range jar.Cookies(currentOrigin) {
			if c.Name == browser.SessionCookie {
				cookie = c.Value
			}
		}
		if cookie == "" {
			t.Fatal("actual browser session cookie absent")
		}
		original, e := requestSessions.Resolve(requestContext, cookie, false)
		if e != nil {
			t.Fatal("original live-reader session unavailable", e)
		}
		started := time.Now()
		liveReader, e = app.NewBrowserLiveReader(requestContext, requestSessions, cookie, original.Identity.Principal, original.ExpiresAt, time.Now)
		if e != nil {
			t.Fatal("real live-reader construction failed", e)
		}
		first, e := liveReader.BeginBatch(requestContext)
		if e != nil {
			t.Fatal(e)
		}
		initial, e := first.ResolveIdentity(requestContext)
		if e != nil {
			first.Close()
			t.Fatal(e)
		}
		// Wait through the original real five-second observation. The fixture's
		// existing settings observer continues independently; no source is retimed.
		waitUntil := started.Add(5100 * time.Millisecond)
		if expired := initial.ValidUntil.Add(50 * time.Millisecond); expired.After(waitUntil) {
			waitUntil = expired
		}
		timer := time.NewTimer(time.Until(waitUntil))
		select {
		case <-timer.C:
		case <-requestContext.Done():
			timer.Stop()
			first.Close()
			t.Fatal(requestContext.Err())
		}
		if _, e = first.ResolveIdentity(context.Background()); !errors.Is(e, identity.ErrDenied) {
			first.Close()
			t.Fatal("original real metadata interval was renewed", e)
		}
		first.Close()
		second, e := liveReader.BeginBatch(requestContext)
		if e != nil {
			t.Fatal("real live reader could not authorize a later batch", e)
		}
		current, e := second.ResolveIdentity(requestContext)
		second.Close()
		if e != nil || current.Principal != original.Identity.Principal || !current.ValidUntil.After(initial.ValidUntil) || current.ValidUntil.After(original.ExpiresAt) {
			t.Fatal("later batch changed actor, kept stale interval or extended session", e)
		}
		id := sha256.Sum256([]byte(cookie))
		var before, after int64
		if e = admin.QueryRow(ctx, "SELECT version FROM browser_session WHERE root_id=$1 AND id=$2", root, id[:]).Scan(&before); e != nil {
			t.Fatal(e)
		}
		// Existing fixture mechanism makes the normal CSRF-protected POST due.
		// The native GET/factory never performs the provider exchange itself.
		if _, e = admin.Exec(ctx, "UPDATE browser_session SET refresh_at=created_at+interval '1 microsecond' WHERE root_id=$1 AND id=$2", root, id[:]); e != nil {
			t.Fatal(e)
		}
		if status, _, _ := request("POST", server.URL+"/auth/refresh", "", csrf); status != 200 {
			t.Fatalf("explicit live-session refresh status %d", status)
		}
		if e = admin.QueryRow(ctx, "SELECT version FROM browser_session WHERE root_id=$1 AND id=$2", root, id[:]).Scan(&after); e != nil || after != before+1 {
			t.Fatal("explicit POST did not replace the real credential version", e)
		}
		third, e := liveReader.BeginBatch(requestContext)
		if e != nil {
			t.Fatal("same-session reader rejected explicit credential replacement", e)
		}
		current, e = third.ResolveIdentity(requestContext)
		third.Close()
		if e != nil || current.Principal != original.Identity.Principal || current.ValidUntil.After(original.ExpiresAt) || observedProvider.refreshes.Load() != 0 {
			t.Fatal("reader changed principal/session lifetime or implicitly refreshed", e)
		}
	}) {
		if liveReader != nil {
			liveReader.Close()
		}
		return
	}
	defer liveReader.Close()
	if !t.Run("current-request-before-local-logout", func(t *testing.T) {
		var cookie string
		for _, c := range jar.Cookies(currentOrigin) {
			if c.Name == browser.SessionCookie {
				cookie = c.Value
			}
		}
		if cookie == "" {
			t.Fatal("actual browser session cookie absent")
		}
		requestSessionID = sha256.Sum256([]byte(cookie))
		if e := admin.QueryRow(ctx, "SELECT version FROM browser_session WHERE root_id=$1 AND id=$2", root, requestSessionID[:]).Scan(&requestSessionVersion); e != nil {
			t.Fatal(e)
		}
		var e error
		currentIdentity, initialIdentity, e = app.NewBrowserRequest(requestContext, requestSessions, cookie, false, time.Now)
		if e != nil || initialIdentity.Identity.Principal.Subject != user {
			t.Fatal("actual browser session did not bind a current request", e)
		}
		current, e := currentIdentity.ResolveIdentity(context.Background())
		if e != nil || current.Principal != initialIdentity.Identity.Principal || current.ValidUntil.After(initialIdentity.Identity.ValidUntil) {
			t.Fatal("actual current-session check changed identity or extended its original interval", e)
		}
		public, e := json.Marshal(initialIdentity)
		if e != nil || bytes.Contains(public, []byte("access_token")) || bytes.Contains(public, []byte("refresh_token")) || bytes.Contains(public, []byte(`"Access"`)) || bytes.Contains(public, []byte(`"Refresh"`)) {
			t.Fatal("provider token field crossed the current-identity handoff")
		}
		var after int64
		if e = admin.QueryRow(ctx, "SELECT version FROM browser_session WHERE root_id=$1 AND id=$2", root, requestSessionID[:]).Scan(&after); e != nil || after != requestSessionVersion || observedProvider.refreshes.Load() != 0 {
			t.Fatal("read-only current request rotated real provider or SQL credentials", e)
		}
		liveBatch, e = liveReader.BeginBatch(requestContext)
		if e != nil {
			t.Fatal(e)
		}
		liveInitial, e = liveBatch.ResolveIdentity(requestContext)
		if e != nil {
			t.Fatal(e)
		}
	}) {
		return
	}
	if status, _, _ := request("POST", server.URL+"/auth/logout", "", csrf); status != 204 {
		t.Fatalf("logout %d", status)
	}
	if !t.Run("live-reader-revoked-by-local-logout", func(t *testing.T) {
		if !time.Now().Before(liveInitial.ValidUntil) {
			t.Fatal("live batch expired before logout check; no revocation evidence")
		}
		if _, e := liveBatch.ResolveIdentity(context.Background()); !errors.Is(e, identity.ErrDenied) {
			t.Fatal("revoked real session still supplied live identity", e)
		}
		if !time.Now().Before(liveInitial.ValidUntil) || observedProvider.refreshes.Load() != 0 {
			t.Fatal("live revocation relied on expiry or refreshed provider credentials")
		}
		liveBatch.Close()
		if _, e := liveReader.BeginBatch(context.Background()); !errors.Is(e, identity.ErrDenied) {
			t.Fatal("new live batch recreated a revoked session", e)
		}
	}) {
		return
	}
	if !t.Run("current-request-revoked-by-local-logout", func(t *testing.T) {
		if !time.Now().Before(initialIdentity.Identity.ValidUntil) {
			t.Fatal("initial interval elapsed before revocation check; no revocation evidence")
		}
		if _, e := currentIdentity.ResolveIdentity(context.Background()); !errors.Is(e, identity.ErrDenied) {
			t.Fatal("actual SQL-revoked session remained valid in the shared request", e)
		}
		if !time.Now().Before(initialIdentity.Identity.ValidUntil) || observedProvider.refreshes.Load() != 0 {
			t.Fatal("request denial relied on expiry or invoked credential refresh")
		}
		var remaining int
		if e := admin.QueryRow(ctx, "SELECT count(*) FROM browser_session WHERE root_id=$1 AND id=$2", root, requestSessionID[:]).Scan(&remaining); e != nil || remaining != 0 {
			t.Fatal("revoked request recreated its deleted SQL session", e)
		}
	}) {
		return
	}
	if status, _, _ := request("GET", server.URL+"/api/v1/session", "", ""); status != 401 {
		t.Fatal("logged out cookie remained accepted")
	}

	_, _ = login()
	consoleURL, _ := url.Parse(server.URL)
	var activeCookie string
	for _, cookie := range jar.Cookies(consoleURL) {
		if cookie.Name == browser.SessionCookie {
			activeCookie = cookie.Value
		}
	}
	activeID := sha256.Sum256([]byte(activeCookie))
	activeClaim := [32]byte{73}
	if activeCookie == "" {
		t.Fatal("active browser cookie absent")
	}
	if err = store.ClaimRefresh(ctx, activeID, 1, activeClaim); err != nil {
		t.Fatal(err)
	}
	f.json("POST", "/admin/realms/asservat-test/users/"+user+"/logout", nil)
	select {
	case <-logoutReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("actual provider backchannel not delivered")
	}
	if status, _, _ := request("GET", server.URL+"/api/v1/session", "", ""); status != 401 {
		t.Fatalf("provider logout did not revoke session: %d", status)
	}
	if err = store.FinishRefresh(ctx, activeID, 1, activeClaim, []byte("synthetic-result-arriving-after-logout"), time.Now().Add(time.Minute)); !errors.Is(err, identity.ErrDenied) {
		t.Fatal("actual provider logout lost to claimed refresh")
	}

	stop()
	t.Run("protected-settings", func(t *testing.T) { browserSettingsFences(t, ctx, admin, pool, settingsPool) })
	if err = renew(); err != nil {
		t.Fatal(err)
	}
	t.Run("already-due-refresh-schedule", func(t *testing.T) { browserRefreshScheduleSQL(t, admin, store, root, f.Issuer, clientID) })
	t.Run("SQL-fences", func(t *testing.T) { browserSQLFences(t, admin, store, root, epoch, f.Issuer, clientID, user) })
	t.Run("bounded-cleanup-role", func(t *testing.T) {
		gcConfig := pc.Copy()
		gcConfig.ConnConfig.User = "browser_cleanup_runtime"
		gcConfig.ConnConfig.Password = "synthetic-browser-cleanup"
		gcConfig.MaxConns = 2
		gcPool, e := pgxpool.NewWithConfig(ctx, gcConfig)
		if e != nil {
			t.Fatal(e)
		}
		defer gcPool.Close()
		gc, e := postgres.NewBrowserSessions(ctx, gcPool, settings.Binding())
		if e != nil {
			t.Fatal(e)
		}
		if _, e = gcPool.Exec(ctx, "UPDATE browser_session_root SET enabled=false WHERE id=$1", root); e == nil {
			t.Fatal("cleanup changed protected root")
		}
		if _, e = gcPool.Exec(ctx, "INSERT INTO browser_login SELECT * FROM browser_login WHERE false"); e == nil {
			t.Fatal("cleanup could create a login")
		}
		if _, e = admin.Exec(ctx, `INSERT INTO browser_login(root_id,epoch,id,browser,ciphertext,created_at,expires_at) SELECT $1,$2,decode(md5(n::text)||md5(n::text),'hex'),decode(repeat('01',32),'hex'),'synthetic-ciphertext',clock_timestamp()-interval '10 minutes',clock_timestamp()-interval '6 minutes' FROM generate_series(1,300) n`, root, epoch); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.Exec(ctx, "UPDATE browser_session_root SET enabled=false WHERE id=$1", root); e != nil {
			t.Fatal(e)
		}
		if e = gc.Cleanup(ctx); e != nil {
			t.Fatal(e)
		}
		var remaining int
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM browser_login WHERE root_id=$1", root).Scan(&remaining); e != nil || remaining != 44 {
			t.Fatalf("unbounded cleanup: %d %v", remaining, e)
		}
		if e = gc.Cleanup(ctx); e != nil {
			t.Fatal(e)
		}
		if e = admin.QueryRow(ctx, "SELECT count(*) FROM browser_login WHERE root_id=$1", root).Scan(&remaining); e != nil || remaining != 0 {
			t.Fatal("cleanup did not progress")
		}
	})
	t.Log("browser group removal, local and actual provider back-channel logout, SQL replay/expiry/epoch/role fences and OpenBao credential encryption passed; protected bootstrap remains unqualified")
}

func browserSQLFences(t *testing.T, admin *pgxpool.Pool, store *postgres.BrowserSessions, root, epoch, issuer, client, user string) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	l := identity.BrowserLogin{ID: [32]byte{1}, Browser: [32]byte{2}, Ciphertext: []byte("synthetic-encrypted-login"), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if _, e := admin.Exec(ctx, "UPDATE browser_session_root SET max_logins=1 WHERE id=$1", root); e != nil {
		t.Fatal(e)
	}
	if e := store.PutLogin(ctx, l); e != nil {
		t.Fatal(e)
	}
	second := l
	second.ID = [32]byte{3}
	if e := store.PutLogin(ctx, second); !errors.Is(e, identity.ErrSessionCapacity) {
		t.Fatal("login ceiling ignored")
	}
	if _, e := store.TakeLogin(ctx, l.ID, [32]byte{9}); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("cross-browser login accepted")
	}
	var wg sync.WaitGroup
	success := make(chan bool, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := store.TakeLogin(ctx, l.ID, l.Browser); success <- e == nil }()
	}
	wg.Wait()
	close(success)
	winners := 0
	for ok := range success {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("login callback consumed %d times", winners)
	}
	r := identity.BrowserSession{ID: sha256.Sum256([]byte("synthetic-session")), Principal: identity.Principal{Issuer: issuer, ClientID: client, Subject: user, Kind: identity.Human}, ProviderSession: "synthetic-provider-session", Ciphertext: []byte("synthetic-opaque-fixture"), CreatedAt: now, AuthenticatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), RefreshAt: now.Add(time.Minute), Version: 1}
	if _, e := store.CreateSession(ctx, r); e != nil {
		t.Fatal(e)
	}
	claim := [32]byte{7}
	if e := store.ClaimRefresh(ctx, r.ID, 1, claim); e != nil {
		t.Fatal(e)
	}
	if e := store.ClaimRefresh(ctx, r.ID, 1, [32]byte{8}); !errors.Is(e, identity.ErrSessionBusy) {
		t.Fatalf("second refresh %v", e)
	}
	if _, e := admin.Exec(ctx, "UPDATE browser_session SET claim_until=clock_timestamp()-interval '1 second' WHERE root_id=$1", root); e != nil {
		t.Fatal(e)
	}
	if e := store.FinishRefresh(ctx, r.ID, 1, claim, []byte("replacement"), now.Add(time.Minute)); !errors.Is(e, identity.ErrDenied) {
		t.Fatalf("expired refresh claim %v", e)
	}
	if e := store.ClaimRefresh(ctx, r.ID, 1, [32]byte{9}); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("abandoned refresh taken over")
	}
	if e := store.RevokeSession(ctx, r.ID); e != nil {
		t.Fatal(e)
	}
	event := app.LogoutEvent{Issuer: issuer, ClientID: client, Subject: user, SessionID: r.ProviderSession, ID: "synthetic-logout-jti", IssuedAt: now}
	if e := store.LogoutSessions(ctx, event); e != nil {
		t.Fatal(e)
	}
	if e := store.LogoutSessions(ctx, event); e != nil {
		t.Fatal("exact logout retry rejected")
	}
	if _, e := store.CreateSession(ctx, r); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("logout before callback did not fence later creation")
	}
	r.ProviderSession = "another-provider-session"
	if _, e := store.CreateSession(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e := store.ClaimRefresh(ctx, r.ID, 1, claim); e != nil {
		t.Fatal(e)
	}
	event.ID = "synthetic-subject-logout"
	event.SessionID = ""
	if e := store.LogoutSessions(ctx, event); e != nil {
		t.Fatal(e)
	}
	if e := store.FinishRefresh(ctx, r.ID, 1, claim, []byte("replacement"), now.Add(time.Minute)); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("logout lost to refresh completion")
	}
	// No unexpired check from before a blocking database lock may survive it.
	r.ID = [32]byte{44}
	r.Principal.Subject = "lock-expiry-subject"
	r.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
	r.AuthenticatedAt = r.CreatedAt
	r.ExpiresAt = r.CreatedAt.Add(150 * time.Millisecond)
	r.RefreshAt = r.ExpiresAt
	if _, e := store.CreateSession(ctx, r); e != nil {
		t.Fatal(e)
	}
	tx, e := admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT id FROM browser_session WHERE root_id=$1 AND id=$2 FOR UPDATE", root, r.ID[:]); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- store.ClaimRefresh(ctx, r.ID, 1, [32]byte{45}) }()
	time.Sleep(200 * time.Millisecond)
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, identity.ErrDenied) {
		t.Fatalf("expired session passed blocking lock: %v", e)
	}
	if _, e := admin.Exec(ctx, "UPDATE browser_session_root SET epoch='74000000-0000-4000-8000-000000000003' WHERE id=$1", root); e != nil {
		t.Fatal(e)
	}
	if _, e := store.ReadSession(ctx, r.ID); !errors.Is(e, identity.ErrDenied) {
		t.Fatal("old epoch accepted")
	}
	if _, e := admin.Exec(ctx, "UPDATE browser_session_root SET epoch=$2 WHERE id=$1", root, epoch); e != nil {
		t.Fatal(e)
	}
}
