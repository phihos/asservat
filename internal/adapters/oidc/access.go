// Package oidc implements explicit bounded RS256 access-token profiles.
// It is not browser login, provider discovery, introspection or authorization.
package oidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

const MaxTokenBytes = 32 << 10
const maxKeysBytes = 128 << 10

type TokenProfile string

const (
	RFC9068  TokenProfile = "rfc9068-rs256"
	Keycloak TokenProfile = "keycloak-rs256/v1"
)

// Trust is selected by role bootstrap from protected configuration. No endpoint
// or algorithm may be selected by token headers, claims or public callers.
type Trust struct {
	Issuer, Audience, JWKSURL string
	Profile                   TokenProfile
	RootCA                    []byte
	KeyMaxAge                 time.Duration
}
type keySnapshot struct {
	keys            map[string]crypto.PublicKey
	observed, until time.Time
}
type Verifier struct {
	trust       Trust
	http        *http.Client
	now         func() time.Time
	gate        chan struct{}
	cache       keySnapshot
	nextRefresh time.Time
}

var _ app.TokenVerifier = (*Verifier)(nil)

func endpoint(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.Opaque == "" && len(s) <= 2048
}
func New(t Trust, now func() time.Time) (*Verifier, error) {
	if t.Profile == "" {
		t.Profile = RFC9068
	}
	if t.Profile != RFC9068 && t.Profile != Keycloak {
		return nil, identity.ErrInvalid
	}
	if !endpoint(t.Issuer) || !endpoint(t.JWKSURL) || !identity.Text(t.Audience, 256) || t.KeyMaxAge < time.Second || t.KeyMaxAge > 5*time.Minute || now == nil {
		return nil, identity.ErrInvalid
	}
	var roots *x509.CertPool
	if len(t.RootCA) > 0 {
		if len(t.RootCA) > 128<<10 {
			return nil, identity.ErrInvalid
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(t.RootCA) {
			return nil, identity.ErrInvalid
		}
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxConnsPerHost: 2, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return identity.ErrUnavailable }}
	t.RootCA = nil
	return &Verifier{trust: t, http: client, now: now, gate: make(chan struct{}, 1)}, nil
}
func (v *Verifier) Close() { v.http.CloseIdleConnections() }

// strictJSON runs before ordinary decoder calls, including untrusted JWK data.
func strictJSON(b []byte, limit, tokens, depth int) error {
	if len(b) == 0 || len(b) > limit {
		return identity.ErrInvalid
	}
	d := jsontext.NewDecoder(bytes.NewReader(b))
	count := 0
	for {
		_, err := d.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return identity.ErrInvalid
		}
		count++
		if count > tokens || d.StackDepth() > depth {
			return identity.ErrInvalid
		}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	var raw json.RawMessage
	if dec.Decode(&raw) != nil || dec.Decode(&raw) != io.EOF || len(raw) == 0 || raw[0] != '{' {
		return identity.ErrInvalid
	}
	return nil
}

type header struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}
type claimsDTO struct {
	Issuer          string          `json:"iss"`
	Subject         string          `json:"sub"`
	Client          string          `json:"client_id"`
	AuthorizedParty *string         `json:"azp"`
	Audience        json.RawMessage `json:"aud"`
	Issued          *int64          `json:"iat"`
	Expires         *int64          `json:"exp"`
	NotBefore       *int64          `json:"nbf"`
	ID              string          `json:"jti"`
	Scope           string          `json:"scope"`
	Groups          []string        `json:"groups"`
	Type            string          `json:"typ"`
	StableGroups    []string        `json:"asservat_groups"`
}

func parse(raw string) (header, claimsDTO, error) {
	return parseProfile(raw, RFC9068)
}

func parseProfile(raw string, profile TokenProfile) (header, claimsDTO, error) {
	var h header
	var c claimsDTO
	if len(raw) == 0 || len(raw) > MaxTokenBytes {
		return h, c, identity.ErrInvalid
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(parts[2]) == 0 {
		return h, c, identity.ErrInvalid
	}
	hb, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil || strictJSON(hb, 2048, 64, 4) != nil {
		return h, c, identity.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(hb))
	d.DisallowUnknownFields()
	var hf map[string]json.RawMessage
	if json.Unmarshal(hb, &hf) != nil || len(hf) != 3 || hf["alg"] == nil || hf["typ"] == nil || hf["kid"] == nil || d.Decode(&h) != nil || h.Algorithm != "RS256" || !identity.Text(h.KeyID, 256) {
		return h, c, identity.ErrInvalid
	}
	if profile == RFC9068 && !(strings.EqualFold(h.Type, "at+jwt") || strings.EqualFold(h.Type, "application/at+jwt")) || profile == Keycloak && h.Type != "JWT" || profile != RFC9068 && profile != Keycloak {
		return h, c, identity.ErrInvalid
	}
	cb, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || strictJSON(cb, 24<<10, 2048, 8) != nil {
		return h, c, identity.ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(cb, &fields) != nil || json.Unmarshal(cb, &c) != nil {
		return h, c, identity.ErrInvalid
	}
	// encoding/json struct matching is case-insensitive; JWT claim names are
	// not. Reject aliases rather than permitting two interpretations.
	for name := range fields {
		for _, known := range []string{"iss", "sub", "client_id", "azp", "aud", "iat", "exp", "nbf", "jti", "scope", "groups", "act", "may_act", "cnf", "nonce", "typ", "asservat_groups"} {
			if name != known && strings.EqualFold(name, known) {
				return h, c, identity.ErrInvalid
			}
		}
	}
	required := []string{"iss", "sub", "aud", "iat", "exp", "jti"}
	if profile == RFC9068 {
		required = append(required, "client_id", "groups")
	} else {
		required = append(required, "azp", "typ")
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return h, c, identity.ErrInvalid
		}
	}
	// Delegation/PoP profiles and an ID-token nonce are deliberately unsupported.
	for _, name := range []string{"act", "may_act", "cnf", "nonce"} {
		if _, ok := fields[name]; ok {
			return h, c, identity.ErrInvalid
		}
	}
	for _, name := range []string{"iss", "sub", "client_id", "aud", "iat", "exp", "jti", "scope", "groups", "typ", "asservat_groups"} {
		if b, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return h, c, identity.ErrInvalid
		}
	}
	for _, name := range []string{"nbf", "azp"} {
		if b, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return h, c, identity.ErrInvalid
		}
	}
	if profile == Keycloak {
		// Keycloak ID and refresh tokens also use a JWT header. Only the
		// signed Bearer type plus the pinned API audience is an access token.
		if c.Type != "Bearer" || c.AuthorizedParty == nil || !identity.Text(*c.AuthorizedParty, 256) {
			return h, c, identity.ErrInvalid
		}
		if _, present := fields["client_id"]; present && c.Client != *c.AuthorizedParty {
			return h, c, identity.ErrInvalid
		}
		c.Client = *c.AuthorizedParty
		// Only the protected stable-ID mapper is used, never Keycloak's
		// mutable group-name/path claim. No attributes means no membership.
		c.Groups = c.StableGroups
	}
	return h, c, nil
}

func (v *Verifier) Verify(ctx context.Context, raw string) (identity.Claims, error) {
	var out identity.Claims
	if err := ctx.Err(); err != nil {
		return out, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	h, c, err := parseProfile(raw, v.trust.Profile)
	if err != nil {
		return out, err
	}
	now := v.now()
	checkedAt := now
	if c.Issuer != v.trust.Issuer || !identity.Text(c.Subject, 256) || !identity.Text(c.Client, 256) || !identity.Text(c.ID, 256) || c.Issued == nil || c.Expires == nil || *c.Issued <= 0 || *c.Expires <= *c.Issued || *c.Expires > 253402300799 || *c.Issued > now.Unix() || now.Unix() >= *c.Expires || c.AuthorizedParty != nil && *c.AuthorizedParty != c.Client {
		return out, identity.ErrDenied
	}
	if c.NotBefore != nil && (*c.NotBefore < 0 || *c.NotBefore > now.Unix() || *c.NotBefore >= *c.Expires) {
		return out, identity.ErrDenied
	}
	var audiences []string
	var audience string
	if json.Unmarshal(c.Audience, &audience) == nil {
		audiences = []string{audience}
	} else if json.Unmarshal(c.Audience, &audiences) != nil {
		return out, identity.ErrDenied
	}
	// The initial adapter profile uses one unambiguous resource audience.
	if len(audiences) != 1 || audiences[0] != v.trust.Audience {
		return out, identity.ErrDenied
	}
	var scopes []string
	if c.Scope != "" {
		scopes = strings.Split(c.Scope, " ")
	}
	if !identity.Strings(scopes, 64, 128) || !identity.Strings(c.Groups, 256, 256) {
		return out, identity.ErrDenied
	}
	for _, s := range scopes {
		for _, r := range s {
			if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
				return out, identity.ErrDenied
			}
		}
	}
	key, until, err := v.key(ctx, h.KeyID)
	if err != nil {
		return out, err
	}
	verifier := coreoidc.NewVerifier(v.trust.Issuer, &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key}}, &coreoidc.Config{ClientID: v.trust.Audience, SupportedSigningAlgs: []string{"RS256"}, Now: v.now})
	if _, err = verifier.Verify(ctx, raw); err != nil {
		return out, identity.ErrDenied
	}
	now = v.now()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if now.Before(checkedAt) || !now.Before(until) || now.Unix() >= *c.Expires || *c.Issued > now.Unix() || c.NotBefore != nil && *c.NotBefore > now.Unix() {
		return out, identity.ErrDenied
	}
	return identity.Claims{Issuer: c.Issuer, Subject: c.Subject, ClientID: c.Client, Scopes: scopes, Groups: c.Groups, IssuedAt: time.Unix(*c.Issued, 0).UTC(), ExpiresAt: time.Unix(*c.Expires, 0).UTC(), KeyUntil: until}, nil
}

func (v *Verifier) key(ctx context.Context, kid string) (crypto.PublicKey, time.Time, error) {
	select {
	case v.gate <- struct{}{}:
		defer func() { <-v.gate }()
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
	}
	now := v.now()
	var cached crypto.PublicKey
	if !now.Before(v.cache.observed) && now.Before(v.cache.until) {
		if key, ok := v.cache.keys[kid]; ok {
			// A snapshot is used to its end only while it still covers an
			// evidence-read request; nearer its end it is refreshed on demand
			// (installed native84: a request authenticated 1.4 s before the
			// snapshot expired was cut there, mid-read).
			if v.cache.until.Sub(now) >= keyRefreshMargin || now.Before(v.nextRefresh) {
				return key, v.cache.until, nil
			}
			cached = key
		}
	}
	// Global per-issuer cooldown: attacker-selected kids never grow a cache or
	// cause one outgoing JWKS request per token. Expired keys have no fallback.
	if now.Before(v.nextRefresh) {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	key, until, err := v.refresh(ctx, kid, now)
	// A failed early refresh keeps the still-current snapshot and its own
	// original end; a fetched set without this key is a revocation.
	if err != nil && cached != nil && !errors.Is(err, identity.ErrDenied) && v.now().Before(v.cache.until) {
		return cached, v.cache.until, nil
	}
	return key, until, err
}

// keyRefreshMargin is how much of a key snapshot must remain for it to be
// used without an on-demand refresh: one evidence-read request window.
const keyRefreshMargin = identity.EvidenceReadRequestWindow

func (v *Verifier) refresh(ctx context.Context, kid string, now time.Time) (crypto.PublicKey, time.Time, error) {
	v.nextRefresh = now.Add(time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.trust.JWKSURL, nil)
	if err != nil {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.http.Do(req)
	if err != nil {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxKeysBytes || resp.Header.Get("Content-Encoding") != "" {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxKeysBytes+1))
	if err != nil || strictJSON(b, maxKeysBytes, 8192, 8) != nil {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	var document struct {
		Keys []json.RawMessage `json:"keys"`
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(b, &top) != nil || len(top) != 1 || top["keys"] == nil {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&document) != nil || len(document.Keys) == 0 || len(document.Keys) > 32 {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	keys := map[string]crypto.PublicKey{}
	for _, raw := range document.Keys {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || fields == nil {
			return nil, time.Time{}, identity.ErrUnavailable
		}
		for _, name := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, ok := fields[name]; ok {
				return nil, time.Time{}, identity.ErrUnavailable
			}
		}
		for name := range fields {
			switch name {
			case "kty", "kid", "use", "key_ops", "alg", "n", "e", "crv", "x", "y", "x5c", "x5t", "x5t#S256":
			default:
				return nil, time.Time{}, identity.ErrUnavailable
			}
		}
		var key jose.JSONWebKey
		if json.Unmarshal(raw, &key) != nil || !key.Valid() || !key.IsPublic() {
			return nil, time.Time{}, identity.ErrUnavailable
		}
		if key.Use != "" && key.Use != "sig" || key.Algorithm != "RS256" {
			continue
		}
		if rawOps, ok := fields["key_ops"]; ok {
			var ops []string
			if json.Unmarshal(rawOps, &ops) != nil || len(ops) != 1 || ops[0] != "verify" {
				return nil, time.Time{}, identity.ErrUnavailable
			}
		}
		rsaKey, ok := key.Key.(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 2048 || rsaKey.N.BitLen() > 8192 || rsaKey.E < 65537 || !identity.Text(key.KeyID, 256) || keys[key.KeyID] != nil {
			return nil, time.Time{}, identity.ErrUnavailable
		}
		keys[key.KeyID] = rsaKey
	}
	if len(keys) == 0 {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	until := now.Add(v.trust.KeyMaxAge)
	completed := v.now()
	if completed.Before(now) || !completed.Before(until) {
		return nil, time.Time{}, identity.ErrUnavailable
	}
	v.cache = keySnapshot{keys, now, until}
	if key, ok := keys[kid]; ok {
		return key, until, nil
	}
	return nil, time.Time{}, identity.ErrDenied
}
