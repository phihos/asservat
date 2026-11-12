package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/oidc"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xdg-go/scram"
)

// This component focus uses an owned TLS PostgreSQL and the pinned Keycloak
// image. Its realm administrators/users are synthetic fixture setup, never
// Asservat permission or installation authority.
func TestSmallKeycloakBundleWithRealPostgres(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_SMALL_KEYCLOAK_EXPORT"); dir != "" {
		exportSmallKeycloakComponent(t, dir)
		return
	}
	dir := os.Getenv("ASSERVAT_SMALL_KEYCLOAK_FIXTURE")
	if dir == "" {
		t.Skip("requires the owned small Keycloak component fixture")
	}
	read := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, path))
		if err != nil {
			t.Fatal("private fixture input missing")
		}
		return b
	}
	var settings contracts.SmallKeycloakSettings
	if json.Unmarshal(read("kc/settings.json"), &settings) != nil {
		t.Fatal("private fixture settings")
	}
	pgPEM := read("pg/ca.crt")
	root, rest := pem.Decode(pgPEM)
	if root == nil || len(rest) != 0 {
		t.Fatal("fixture PostgreSQL CA")
	}
	endpoint := contracts.OwnerPostgresEndpoint{Host: "trial-postgres.smoke.svc", Port: 5432, Database: "keycloak", Roots: [][]byte{root.Bytes}, MaxConnections: 1}
	credential := contracts.OwnerSQLCredential{Username: "keycloak", Password: string(read("pg/keycloak-password"))}
	operatorPassword, operatorErr := os.ReadFile(filepath.Join(dir, "operator-keycloak-password"))
	if operatorErr != nil && !os.IsNotExist(operatorErr) {
		t.Fatal("operator fixture credential unavailable")
	}
	if os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") != "database" && operatorErr == nil {
		credential.Password = string(operatorPassword)
	}
	proof, err := postgres.NewSmallKeycloakDatabasePresence(endpoint, credential)
	if err != nil {
		t.Fatal("external database proof construction", err)
	}
	if os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") == "database" {
		qualifySmallKeycloakEmptyDatabase(t, endpoint, credential, proof, string(operatorPassword))
		return
	}
	if os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") == "retained" {
		if exists, err := proof.Exists(t.Context()); err != nil || !exists {
			t.Fatal("imported Keycloak database was not recognized as retained state", err)
		}
		t.Log("actual imported Keycloak database refuses new empty-state initialization")
		return
	}
	kcPEM := read("kc-ca.crt")
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(kcPEM) {
		t.Fatal("fixture Keycloak CA")
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	f := &kcFixture{t: t, base: settings.Hostname, Issuer: settings.Hostname + "/realms/" + settings.Realm, http: client, AdminUser: string(read("kc/" + contracts.SmallKeycloakAdminUsername)), AdminPassword: string(read("kc/" + contracts.SmallKeycloakAdminPassword)), UserPassword: "synthetic-component-password-not-a-default"}
	if os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") == "readiness" {
		ctx, end := context.WithTimeout(t.Context(), 60*time.Second)
		defer end()
		for {
			request, err := http.NewRequestWithContext(ctx, "GET", strings.Replace(settings.Hostname, ":8443", ":9000", 1)+"/health/ready", nil)
			if err != nil {
				t.Fatal("readiness request construction")
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("verified readiness transport failed")
			}
			status := response.StatusCode
			response.Body.Close()
			if status == 200 {
				t.Log("actual management HTTPS readiness passed after asynchronous bootstrap")
				return
			}
			if status != 503 {
				t.Fatalf("unexpected startup readiness HTTP status %d", status)
			}
			select {
			case <-ctx.Done():
				t.Fatal("Keycloak readiness deadline")
			case <-time.After(time.Second):
			}
		}
	}
	status, _, _ := f.request("GET", settings.Hostname+"/realms/"+settings.Realm+"/.well-known/openid-configuration", "", "", nil)
	if status != 200 {
		t.Fatalf("imported realm metadata HTTP status %d", status)
	}
	status, _, _ = f.request("GET", strings.Replace(settings.Hostname, ":8443", ":9000", 1)+"/health/ready", "", "", nil)
	if status != 200 {
		t.Fatalf("actual management HTTPS readiness status %d", status)
	}
	f.admin = f.tokens(f.base+"/realms/master/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {f.AdminUser}, "password": {f.AdminPassword}}, 200).Access
	prefix := "/admin/realms/" + settings.Realm
	group := string(read("kc/" + contracts.SmallKeycloakUsersGroup))
	var actualGroup struct {
		ID         string
		Attributes map[string][]string
	}
	if json.Unmarshal(f.json("GET", prefix+"/groups/"+group, nil), &actualGroup) != nil || actualGroup.ID != group || !slices.Equal(actualGroup.Attributes["asservat_group_id"], []string{group}) {
		t.Fatal("import changed native stable group identity")
	}
	processingGroup := ""
	if settings.ProcessingOperators {
		usersID, err := uuid.Parse(group)
		if err != nil || usersID.Version() != 4 || usersID.String() != group {
			t.Fatal("original users group is not the generated immutable UUID")
		}
		processingGroup = uuid.NewSHA1(usersID, []byte("asservat-processing-operators")).String()
		var actual struct {
			ID, Name   string
			Attributes map[string][]string
		}
		if json.Unmarshal(f.json("GET", prefix+"/groups/"+processingGroup, nil), &actual) != nil || actual.ID != processingGroup || !slices.Equal(actual.Attributes["asservat_group_id"], []string{processingGroup}) || actual.ID == group {
			t.Fatal("import changed dedicated processing group identity")
		}
		if os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") != "restart" {
			var members []json.RawMessage
			if actual.Name != "asservat-processing-operators" || json.Unmarshal(f.json("GET", prefix+"/groups/"+processingGroup+"/members", nil), &members) != nil || len(members) != 0 {
				t.Fatal("imported processing group was not empty before deliberate fixture assignment")
			}
		}
	}
	var profile struct {
		Attributes []struct {
			Name        string
			Permissions struct{ Edit, View []string }
		}
	}
	if json.Unmarshal(f.json("GET", prefix+"/users/profile", nil), &profile) != nil {
		t.Fatal("actual protected profile")
	}
	protected := false
	for _, attribute := range profile.Attributes {
		if attribute.Name == "asservat_group_id" {
			protected = slices.Equal(attribute.Permissions.Edit, []string{"admin"}) && slices.Equal(attribute.Permissions.View, []string{"admin"})
		}
	}
	if !protected {
		t.Fatal("import did not protect the authority-bearing attribute")
	}
	var scopes []struct{ Name string }
	if json.Unmarshal(f.json("GET", prefix+"/client-scopes", nil), &scopes) != nil {
		t.Fatal("actual client scopes")
	}
	for _, required := range []string{"basic", "acr", "asservat:mcp", "asservat:downloads"} {
		if !slices.ContainsFunc(scopes, func(s struct{ Name string }) bool { return s.Name == required }) {
			t.Fatalf("import omitted required client scope %s", required)
		}
	}
	consoleSecret := string(read("kc/" + contracts.SmallKeycloakConsoleSecret))
	var clients []struct {
		ID       string
		ClientID string `json:"clientId"`
		Secret   string
	}
	if json.Unmarshal(f.json("GET", prefix+"/clients?clientId="+url.QueryEscape(settings.ConsoleClientID), nil), &clients) != nil || len(clients) != 1 || clients[0].Secret != consoleSecret {
		t.Fatal("console secret environment interpolation or client import failed")
	}
	clientID := clients[0].ID
	receiptPath := os.Getenv("ASSERVAT_SMALL_KEYCLOAK_RECEIPT")
	var original struct {
		Subject, Group, Client string
		ProcessingGroup        string `json:",omitempty"`
	}
	if os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") == "restart" {
		raw, err := os.ReadFile(receiptPath)
		if err != nil || json.Unmarshal(raw, &original) != nil {
			t.Fatal("original component receipt missing")
		}
	} else {
		f.json("POST", prefix+"/users", map[string]any{"username": "developer", "enabled": true, "credentials": []any{map[string]any{"type": "password", "value": f.UserPassword, "temporary": false}}})
	}
	var users []struct{ ID string }
	if json.Unmarshal(f.json("GET", prefix+"/users?username=developer&exact=true", nil), &users) != nil || len(users) != 1 {
		t.Fatal("actual synthetic user identity")
	}
	userID := users[0].ID
	if original.Subject != "" && (original.Subject != userID || original.Group != group || original.Client != clientID || original.ProcessingGroup != processingGroup) {
		t.Fatal("restart replaced persisted identity/client/group")
	}
	if processingGroup != "" && os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") == "restart" {
		// Check retained membership before any PUT could repair it.
		var groups []struct{ ID string }
		if json.Unmarshal(f.json("GET", prefix+"/users/"+userID+"/groups", nil), &groups) != nil || len(groups) != 2 || !slices.ContainsFunc(groups, func(g struct{ ID string }) bool { return g.ID == group }) || !slices.ContainsFunc(groups, func(g struct{ ID string }) bool { return g.ID == processingGroup }) {
			t.Fatal("restart lost original deliberate dual membership")
		}
	}
	f.json("PUT", prefix+"/users/"+userID+"/groups/"+group, nil)
	verifier, err := oidc.New(oidc.Trust{Issuer: f.Issuer, Audience: settings.BrowserAudience, JWKSURL: f.Issuer + "/protocol/openid-connect/certs", Profile: oidc.Keycloak, RootCA: kcPEM, KeyMaxAge: time.Minute}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Close()
	check := func(raw string, wantGroups []string) identity.Claims {
		t.Helper()
		claims, err := verifier.Verify(t.Context(), raw)
		if err != nil || claims.Subject != userID || claims.ClientID != settings.ConsoleClientID || !smallKeycloakSameGroups(claims.Groups, wantGroups) || claims.ACR == "" || claims.AuthTime.IsZero() {
			t.Fatal("actual console token did not satisfy the product identity profile", err)
		}
		return claims
	}
	tokens := smallKeycloakConsoleCode(t, f, settings, consoleSecret, false)
	activeGroups := []string{group}
	if processingGroup != "" && os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") == "restart" {
		activeGroups = append(activeGroups, processingGroup)
	}
	consoleClaims := check(tokens.Access, activeGroups)
	if processingGroup != "" {
		smallKeycloakAssertProcessingClaims(t, settings, consoleClaims, group, processingGroup, true, len(activeGroups) == 2)
	}
	refresh := func(token string) kcTokens {
		return f.tokens(f.Issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {settings.ConsoleClientID}, "client_secret": {consoleSecret}, "refresh_token": {token}}, 200)
	}
	if processingGroup != "" && os.Getenv("ASSERVAT_SMALL_KEYCLOAK_STAGE") != "restart" {
		// This is explicit synthetic administrator action after proving empty import.
		f.json("PUT", prefix+"/users/"+userID+"/groups/"+processingGroup, nil)
		activeGroups = append(activeGroups, processingGroup)
		tokens = refresh(tokens.Refresh)
		claims := check(tokens.Access, activeGroups)
		smallKeycloakAssertProcessingClaims(t, settings, claims, group, processingGroup, true, true)
		f.json("PUT", prefix+"/groups/"+processingGroup, map[string]any{"name": "renamed-component-processing-group", "attributes": map[string]any{"asservat_group_id": []string{processingGroup}}})
	}
	f.json("PUT", prefix+"/groups/"+group, map[string]any{"name": "renamed-component-group", "attributes": map[string]any{"asservat_group_id": []string{group}}})
	tokens = refresh(tokens.Refresh)
	claimsAfterRename := check(tokens.Access, activeGroups)
	if processingGroup != "" {
		smallKeycloakAssertProcessingClaims(t, settings, claimsAfterRename, group, processingGroup, true, true)
	}
	f.json("DELETE", prefix+"/users/"+userID+"/groups/"+group, nil)
	tokens = refresh(tokens.Refresh)
	var remainingGroups []string
	if processingGroup != "" {
		remainingGroups = []string{processingGroup}
	}
	claimsWithoutOrdinary := check(tokens.Access, remainingGroups)
	if processingGroup != "" {
		smallKeycloakAssertProcessingClaims(t, settings, claimsWithoutOrdinary, group, processingGroup, false, false)
	}
	f.json("PUT", prefix+"/users/"+userID+"/groups/"+group, nil)
	if processingGroup != "" {
		tokens = refresh(tokens.Refresh)
		smallKeycloakAssertProcessingClaims(t, settings, check(tokens.Access, activeGroups), group, processingGroup, true, true)
	}
	f.tokens(f.Issuer+"/protocol/openid-connect/token", url.Values{"grant_type": {"password"}, "client_id": {settings.ConsoleClientID}, "client_secret": {consoleSecret}, "username": {"developer"}, "password": {f.UserPassword}}, 400)
	// Authorization-code replay can invalidate that client session, so negative
	// replay checks own separate logins instead of supplying refresh fixtures.
	smallKeycloakConsoleCode(t, f, settings, consoleSecret, true)
	mcp := f.loginScopes(settings.MCPClientID, "openid evidence:read asservat:mcp")
	mcpVerifier, err := oidc.New(oidc.Trust{Issuer: f.Issuer, Audience: settings.Origin + "/mcp", JWKSURL: f.Issuer + "/protocol/openid-connect/certs", Profile: oidc.Keycloak, RootCA: kcPEM, KeyMaxAge: time.Minute}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer mcpVerifier.Close()
	claims, err := mcpVerifier.Verify(t.Context(), mcp.Access)
	if err != nil || claims.Subject != userID || claims.ClientID != settings.MCPClientID || !smallKeycloakSameGroups(claims.Groups, activeGroups) {
		t.Fatal("actual MCP resource token binding", err)
	}
	f.loginScopes(settings.MCPClientID, "openid evidence:read asservat:mcp", "replay")
	f.loginScopes(settings.MCPClientID, "openid evidence:read asservat:mcp", "wrong-verifier")
	if receiptPath != "" {
		body, _ := json.Marshal(struct {
			Subject, Group, Client string
			ProcessingGroup        string `json:",omitempty"`
		}{userID, group, clientID, processingGroup})
		if err = os.WriteFile(receiptPath, body, 0600); err != nil {
			t.Fatal("write public synthetic identity receipt")
		}
	}
	t.Log("actual pinned Keycloak import, protected stable identity, console/MCP code+PKCE, membership refresh and disabled password flow passed; fixture administration grants no Asservat authority")
}

func exportSmallKeycloakComponent(t *testing.T, dir string) {
	t.Helper()
	plan := contracts.SmallPostgresPlan{Format: contracts.SmallPostgresFormat, Namespace: "smoke", Name: "trial", Keycloak: true}
	pg, err := kube.BuildSmallPostgresMaterial(plan, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	settings := contracts.SmallKeycloakSettings{Namespace: "smoke", SecretName: "trial-keycloak-state", Hostname: "https://identity.smoke:8443", Realm: "asservat", Origin: "https://console.smoke", Database: contracts.SmallKeycloakDatabase{Host: "trial-postgres.smoke.svc", Port: 5432, Database: "keycloak", Username: "keycloak"}, ConsoleClientID: "console", BrowserAudience: "asservat-api", MCPClientID: "mcp", MCPRedirectURIs: []string{"http://127.0.0.1:1/callback"}}
	selection := os.Getenv("ASSERVAT_SMALL_KEYCLOAK_PROCESSING_OPERATORS")
	if selection != "" && selection != "false" && selection != "true" {
		t.Fatal("invalid explicit component processing-operator selection")
	}
	settings.ProcessingOperators = selection == "true"
	kc, err := bootstrap.BuildSmallKeycloakMaterial(settings, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]map[string][]byte{"pg": pg, "kc": kc.Data} {
		path := filepath.Join(dir, name)
		if err = os.MkdirAll(path, 0700); err != nil {
			t.Fatal("create private export directory")
		}
		for key, value := range data {
			if err = os.WriteFile(filepath.Join(path, key), value, 0600); err != nil {
				t.Fatal("write private component material")
			}
			clear(value)
		}
	}
}

func qualifySmallKeycloakEmptyDatabase(t *testing.T, p contracts.OwnerPostgresEndpoint, credential contracts.OwnerSQLCredential, proof *postgres.SmallKeycloakDatabasePresence, operatorPassword string) {
	t.Helper()
	if exists, err := proof.Exists(t.Context()); err != nil || exists {
		t.Fatal("actual empty database refused", err)
	}
	roots := x509.NewCertPool()
	for _, der := range p.Roots {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(certificate)
	}
	c, err := pgx.ParseConfig("host=localhost port=1 user=unused dbname=unused sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	c.Host, c.Port, c.Database, c.User, c.Password = p.Host, uint16(p.Port), p.Database, credential.Username, credential.Password
	c.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ServerName: p.Host, RootCAs: roots}
	c.Fallbacks = nil
	ctx, end := context.WithTimeout(t.Context(), 30*time.Second)
	defer end()
	conn, err := pgx.ConnectConfig(ctx, c)
	if err != nil {
		t.Fatal("synthetic SQL producer connection")
	}
	defer conn.Close(ctx)
	for _, sql := range []struct{ create, drop string }{{"CREATE SCHEMA component_empty_schema", "DROP SCHEMA component_empty_schema"}, {"CREATE TABLE public.component_table(id integer)", "DROP TABLE public.component_table"}, {"CREATE SEQUENCE public.component_sequence", "DROP SEQUENCE public.component_sequence"}, {"CREATE FUNCTION public.component_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'", "DROP FUNCTION public.component_function()"}, {"CREATE TYPE public.component_enum AS ENUM ('synthetic')", "DROP TYPE public.component_enum"}} {
		if _, err = conn.Exec(ctx, sql.create); err != nil {
			t.Fatal("synthetic foreign object creation")
		}
		if exists, err := proof.Exists(ctx); err != nil || !exists {
			t.Fatal("retained foreign object was mistaken for an empty database", err)
		}
		if _, err = conn.Exec(ctx, sql.drop); err != nil {
			t.Fatal("synthetic object removal")
		}
	}
	if exists, err := proof.Exists(ctx); err != nil || exists {
		t.Fatal("cleared database did not return to empty", err)
	}
	wrong := p
	wrong.Host = "wrong-host"
	bad, err := postgres.NewSmallKeycloakDatabasePresence(wrong, credential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bad.Exists(ctx); err == nil {
		t.Fatal("hostname mismatch supplied an empty-state proof")
	}
	if operatorPassword != "" {
		// This simulates an independently selected external database credential;
		// it does not change the bundled material generator's random format.
		client, err := scram.SHA256.NewClient("keycloak", operatorPassword, "")
		if err != nil {
			t.Fatal("synthetic operator password preparation")
		}
		var salt [16]byte
		if _, err = rand.Read(salt[:]); err != nil {
			t.Fatal(err)
		}
		stored, err := client.GetStoredCredentialsWithError(scram.KeyFactors{Salt: string(salt[:]), Iters: 4096})
		if err != nil {
			t.Fatal("synthetic operator verifier")
		}
		b64 := base64.StdEncoding.EncodeToString
		verifier := "SCRAM-SHA-256$4096:" + b64(salt[:]) + "$" + b64(stored.StoredKey) + ":" + b64(stored.ServerKey)
		clear(salt[:])
		clear(stored.StoredKey)
		clear(stored.ServerKey)
		// Only the derived SCRAM verifier enters DDL; never the literal password.
		if _, err = conn.Exec(ctx, "ALTER ROLE keycloak PASSWORD '"+verifier+"'"); err != nil {
			t.Fatal("synthetic external credential installation")
		}
		credential.Password = operatorPassword
		literal, err := postgres.NewSmallKeycloakDatabasePresence(p, credential)
		if err != nil {
			t.Fatal(err)
		}
		if exists, err := literal.Exists(ctx); err != nil || exists {
			t.Fatal("literal operator credential failed exact TLS database proof", err)
		}
		t.Log("explicit operator password containing dollar/interpolation syntax authenticated literally through pgx")
	}
	t.Log("actual TLS PostgreSQL empty/nonempty catalog, foreign schema/table/sequence/function/type and wrong-host refusal passed")
}

func smallKeycloakConsoleCode(t *testing.T, f *kcFixture, s contracts.SmallKeycloakSettings, secret string, replay bool) kcTokens {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	previous := f.http.Jar
	f.http.Jar = jar
	defer func() { f.http.Jar = previous }()
	verifier, state, nonce := randomPKCE(), randomPKCE(), randomPKCE()
	challenge := sha256.Sum256([]byte(verifier))
	redirect := s.Origin + "/auth/callback"
	query := url.Values{"client_id": {s.ConsoleClientID}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid evidence:read evidence:download evidence:capture"}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	status, page, _ := f.request("GET", f.Issuer+"/protocol/openid-connect/auth?"+query.Encode(), "", "", nil)
	if status != 200 {
		t.Fatalf("console code page status %d", status)
	}
	match := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`).FindSubmatch(page)
	if len(match) != 2 {
		t.Fatal("actual console login form absent")
	}
	action := html.UnescapeString(string(match[1]))
	if !strings.HasPrefix(action, f.Issuer+"/login-actions/authenticate?") {
		t.Fatal("console form escaped issuer")
	}
	status, _, headers := f.request("POST", action, "", "application/x-www-form-urlencoded", []byte(url.Values{"username": {"developer"}, "password": {f.UserPassword}, "credentialId": {""}}.Encode()))
	if status != 302 {
		t.Fatalf("console login status %d", status)
	}
	callback, err := url.Parse(headers.Get("Location"))
	if err != nil || callback.Scheme+"://"+callback.Host+callback.Path != redirect || callback.Query().Get("state") != state || callback.Query().Get("code") == "" {
		t.Fatal("console callback binding")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {s.ConsoleClientID}, "client_secret": {secret}, "redirect_uri": {redirect}, "code": {callback.Query().Get("code")}, "code_verifier": {verifier}}
	tokens := f.tokens(f.Issuer+"/protocol/openid-connect/token", form, 200)
	if replay {
		f.tokens(f.Issuer+"/protocol/openid-connect/token", form, 400)
	}
	return tokens
}

// Group ordering is not authority. Compare the complete signed UUID set while
// preserving verifier rejection of duplicate/malformed groups.
func smallKeycloakSameGroups(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// Actual signed provider claims enter the product eligibility and privacy
// evaluators. The current policy below is explicit synthetic component input,
// not a fixture grant used by any installed Asservat process.
func smallKeycloakAssertProcessingClaims(t *testing.T, s contracts.SmallKeycloakSettings, claims identity.Claims, users, operators string, wantEligible, wantOperator bool) {
	t.Helper()
	now := time.Now().UTC()
	revision := identity.Revision{UID: "component-protected-settings", Generation: 1, Digest: [32]byte{1}}
	eligible := identity.Policy{Revision: revision, Issuer: s.Hostname + "/realms/" + s.Realm, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Clients: []identity.Client{{ID: s.ConsoleClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{users}, GroupsAtIssueQualified: true, GroupMaxAge: 5 * time.Minute}
	admitted, err := identity.Admit(claims, eligible, now)
	if !wantEligible {
		if err == nil {
			t.Fatal("operator-only membership bypassed ordinary eligibility")
		}
		return
	}
	if err != nil || !smallKeycloakSameGroups(admitted.Groups, claims.Groups) {
		t.Fatal("actual eligibility discarded signed groups", err)
	}
	id := "41414141-4141-4141-8141-414141414141"
	policy := privacy.DownloadPolicy{RootID: id, InstallationID: id, RecoveryEpoch: id, Revision: revision, ProtectionDigest: [32]byte{1}, PermittedRegions: []string{}, Paths: []privacy.DownloadPath{}, Clients: []privacy.DownloadClient{}, Operators: []privacy.ProcessingOperator{{ClientID: s.ConsoleClientID, Issuer: eligible.Issuer, Kind: "Group", ID: operators}}, ObservedAt: now, FreshUntil: now.Add(3 * time.Second)}
	if !policy.Valid(now) || policy.Operator(admitted, now) != wantOperator {
		t.Fatal("actual processing operator evaluator did not honor dedicated membership")
	}
	t.Log("actual signed group claims passed product eligibility/privacy evaluator; synthetic current-policy input is not installed authority")
}
