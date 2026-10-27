package oidc

import (
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/identity"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
)

// BrowserTrust is private bootstrap configuration. Endpoints are pinned from
// reviewed issuer metadata, never selected by a callback or token. This is an
// ordinary confidential OIDC client, not a provider directory service account.
type BrowserTrust struct {
	Access                                                                    Trust
	ClientID, ClientSecret, AuthorizationEndpoint, TokenEndpoint, RedirectURI string
	Scopes                                                                    []string
}

type BrowserProvider struct {
	trust  BrowserTrust
	access *Verifier
}

var _ app.BrowserProvider = (*BrowserProvider)(nil)
var _ app.LogoutVerifier = (*BrowserProvider)(nil)

func NewBrowser(t BrowserTrust, now func() time.Time) (*BrowserProvider, error) {
	if !identity.Text(t.ClientID, 256) || !identity.Text(t.ClientSecret, 4096) || !endpoint(t.AuthorizationEndpoint) || !endpoint(t.TokenEndpoint) || !endpoint(t.RedirectURI) || !identity.Strings(t.Scopes, 32, 128) {
		return nil, identity.ErrInvalid
	}
	issuer, _ := url.Parse(t.Access.Issuer)
	for _, s := range []string{t.AuthorizationEndpoint, t.TokenEndpoint} {
		u, _ := url.Parse(s)
		if issuer == nil || issuer.Host != u.Host {
			return nil, identity.ErrInvalid
		}
	}
	hasOpenID := false
	for _, s := range t.Scopes {
		if s == "offline_access" || strings.ContainsAny(s, " \t\r\n") {
			return nil, identity.ErrInvalid
		}
		hasOpenID = hasOpenID || s == "openid"
	}
	if !hasOpenID {
		return nil, identity.ErrInvalid
	}
	v, err := New(t.Access, now)
	if err != nil {
		return nil, err
	}
	t.Access.RootCA = nil
	return &BrowserProvider{t, v}, nil
}
func (p *BrowserProvider) Close() { p.access.Close() }
func secret(s string) bool {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return e == nil && len(b) == 32
}
func (p *BrowserProvider) AuthorizationURL(state, nonce, verifier string) (string, error) {
	if !secret(state) || !secret(nonce) || !secret(verifier) {
		return "", identity.ErrInvalid
	}
	u, _ := url.Parse(p.trust.AuthorizationEndpoint)
	hash := sha256.Sum256([]byte(verifier))
	u.RawQuery = url.Values{"client_id": {p.trust.ClientID}, "redirect_uri": {p.trust.RedirectURI}, "response_type": {"code"}, "response_mode": {"query"}, "scope": {strings.Join(p.trust.Scopes, " ")}, "state": {state}, "nonce": {nonce}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}}.Encode()
	return u.String(), nil
}

// StepUpAuthorizationURL takes only administrator-selected ACR values. max_age=0
// requests fresh authentication, while the resulting signed claims still decide
// whether an operation has current step-up assurance (OIDC Core 3.1.2.1).
func (p *BrowserProvider) StepUpAuthorizationURL(state, nonce, verifier string, acrValues []string) (string, error) {
	if len(acrValues) == 0 || !identity.Strings(acrValues, 8, 128) {
		return "", identity.ErrInvalid
	}
	for _, acr := range acrValues {
		if strings.ContainsAny(acr, " \t\r\n") {
			return "", identity.ErrInvalid
		}
	}
	raw, err := p.AuthorizationURL(state, nonce, verifier)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	q.Set("acr_values", strings.Join(acrValues, " "))
	q.Set("max_age", "0")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (p *BrowserProvider) Exchange(ctx context.Context, code, verifier, nonce string) (app.BrowserTokens, error) {
	if !identity.Text(code, 4096) || !secret(verifier) || !secret(nonce) {
		return app.BrowserTokens{}, identity.ErrInvalid
	}
	return p.tokens(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.trust.RedirectURI}, "code_verifier": {verifier}}, nonce, "", "")
}
func (p *BrowserProvider) Refresh(ctx context.Context, refresh, subject, sid, nonce string) (app.BrowserTokens, error) {
	if !identity.Text(refresh, MaxTokenBytes) || !identity.Text(subject, 256) || !identity.Text(sid, 256) || !secret(nonce) {
		return app.BrowserTokens{}, identity.ErrInvalid
	}
	return p.tokens(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}}, nonce, subject, sid)
}
func (p *BrowserProvider) tokens(ctx context.Context, form url.Values, nonce, subject, sid string) (app.BrowserTokens, error) {
	var zero app.BrowserTokens
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := p.access.now()
	form.Set("client_id", p.trust.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.trust.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return zero, identity.ErrUnavailable
	}
	// The reviewed initial provider profile uses client_secret_basic. There is no
	// automatic auth-method probing or retry of a one-use code/refresh token.
	req.SetBasicAuth(url.QueryEscape(p.trust.ClientID), url.QueryEscape(p.trust.ClientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := p.access.http.Do(req)
	if err != nil {
		return zero, identity.ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.ContentLength > 128<<10 || resp.Header.Get("Content-Encoding") != "" {
		return zero, identity.ErrDenied
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (128<<10)+1))
	defer clear(b)
	if err != nil || strictJSON(b, 128<<10, 8192, 8) != nil {
		return zero, identity.ErrDenied
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(b, &fields)
	for _, key := range []string{"access_token", "refresh_token", "id_token", "token_type"} {
		for k := range fields {
			if strings.EqualFold(k, key) && k != key {
				return zero, identity.ErrDenied
			}
		}
	}
	var wire struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
		Type    string `json:"token_type"`
	}
	if json.Unmarshal(b, &wire) != nil || !strings.EqualFold(wire.Type, "Bearer") || !identity.Text(wire.Refresh, MaxTokenBytes) {
		return zero, identity.ErrDenied
	}
	access, err := p.access.Verify(ctx, wire.Access)
	if err != nil || access.ClientID != p.trust.ClientID {
		return zero, identity.ErrDenied
	}
	id, err := p.idToken(ctx, wire.ID, nonce, subject != "")
	if err != nil || id.Subject != access.Subject {
		return zero, identity.ErrDenied
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(wire.Access) != nil {
		return zero, identity.ErrDenied
	}
	var c struct {
		SID      string `json:"sid"`
		AuthTime int64  `json:"auth_time"`
	}
	if id.Claims(&c) != nil || !identity.Text(c.SID, 256) || c.AuthTime <= 0 || c.AuthTime > p.access.now().Unix() {
		return zero, identity.ErrDenied
	}
	if subject != "" && (subject != access.Subject || sid != c.SID) {
		return zero, identity.ErrDenied
	}
	if ctx.Err() != nil || p.access.now().Before(started) {
		return zero, identity.ErrUnavailable
	}
	return app.BrowserTokens{Access: wire.Access, Refresh: wire.Refresh, Subject: access.Subject, SessionID: c.SID, IssuedAt: access.IssuedAt, ExpiresAt: access.ExpiresAt, AuthenticatedAt: time.Unix(c.AuthTime, 0).UTC()}, nil
}

// Strict common signature parsing for ID/logout tokens, separate from access
// token admission. Unknown JOSE key/algorithm selectors are never honored.
func (p *BrowserProvider) signed(ctx context.Context, raw string, logout bool) (*coreoidc.IDToken, map[string]json.RawMessage, error) {
	started := p.access.now()
	if len(raw) == 0 || len(raw) > MaxTokenBytes {
		return nil, nil, identity.ErrDenied
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, identity.ErrDenied
	}
	hb, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil || strictJSON(hb, 2048, 64, 2) != nil {
		return nil, nil, identity.ErrDenied
	}
	var h header
	var hm map[string]json.RawMessage
	if json.Unmarshal(hb, &h) != nil || json.Unmarshal(hb, &hm) != nil || len(hm) != 3 || hm["alg"] == nil || hm["kid"] == nil || hm["typ"] == nil || h.Algorithm != "RS256" || !identity.Text(h.KeyID, 256) {
		return nil, nil, identity.ErrDenied
	}
	if (!logout && h.Type != "JWT") || (logout && h.Type != "JWT" && h.Type != "logout+jwt") {
		return nil, nil, identity.ErrDenied
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil || strictJSON(b, MaxTokenBytes, 4096, 8) != nil {
		return nil, nil, identity.ErrDenied
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(b, &fields) != nil {
		return nil, nil, identity.ErrDenied
	}
	for _, key := range []string{"iss", "sub", "aud", "azp", "iat", "exp", "nbf", "nonce", "sid", "auth_time", "events", "jti", "typ", "at_hash"} {
		for k, v := range fields {
			if strings.EqualFold(k, key) && (k != key || string(v) == "null") {
				return nil, nil, identity.ErrDenied
			}
		}
	}
	var c struct {
		Issuer   string          `json:"iss"`
		Audience json.RawMessage `json:"aud"`
		AZP      string          `json:"azp"`
		IAT      int64           `json:"iat"`
		EXP      int64           `json:"exp"`
		NBF      *int64          `json:"nbf"`
		Type     string          `json:"typ"`
	}
	if json.Unmarshal(b, &c) != nil || c.Issuer != p.trust.Access.Issuer || c.IAT <= 0 || c.IAT > p.access.now().Unix() || c.AZP != "" && c.AZP != p.trust.ClientID {
		return nil, nil, identity.ErrDenied
	}
	if c.NBF != nil && (*c.NBF < 0 || *c.NBF > p.access.now().Unix()) {
		return nil, nil, identity.ErrDenied
	}
	var aud string
	var audiences []string
	if json.Unmarshal(c.Audience, &aud) == nil {
		audiences = []string{aud}
	} else if json.Unmarshal(c.Audience, &audiences) != nil {
		return nil, nil, identity.ErrDenied
	}
	if len(audiences) != 1 || audiences[0] != p.trust.ClientID {
		return nil, nil, identity.ErrDenied
	}
	if logout {
		if c.IAT <= p.access.now().Add(-5*time.Minute).Unix() || c.Type != "" && c.Type != "Logout" {
			return nil, nil, identity.ErrDenied
		}
	} else if c.EXP <= c.IAT || c.EXP > 253402300799 || p.access.now().Unix() >= c.EXP || fields["events"] != nil || c.Type != "" && c.Type != "ID" {
		return nil, nil, identity.ErrDenied
	}
	key, until, err := p.access.key(ctx, h.KeyID)
	if err != nil {
		return nil, nil, err
	}
	v := coreoidc.NewVerifier(p.trust.Access.Issuer, &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key}}, &coreoidc.Config{ClientID: p.trust.ClientID, SupportedSigningAlgs: []string{"RS256"}, Now: p.access.now, SkipExpiryCheck: false})
	id, err := v.Verify(ctx, raw)
	if err != nil || !p.access.now().Before(until) || p.access.now().Before(started) || ctx.Err() != nil || logout && c.IAT <= p.access.now().Add(-5*time.Minute).Unix() {
		return nil, nil, identity.ErrDenied
	}
	if c.EXP <= c.IAT || c.EXP > 253402300799 || p.access.now().Unix() >= c.EXP {
		return nil, nil, identity.ErrDenied
	}
	return id, fields, nil
}
func (p *BrowserProvider) idToken(ctx context.Context, raw, nonce string, refresh bool) (*coreoidc.IDToken, error) {
	id, _, err := p.signed(ctx, raw, false)
	if err != nil {
		return nil, err
	}
	if (!refresh || id.Nonce != "") && id.Nonce != nonce {
		return nil, identity.ErrDenied
	}
	return id, nil
}
func (p *BrowserProvider) VerifyLogout(ctx context.Context, raw string) (app.LogoutEvent, error) {
	var out app.LogoutEvent
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	started := p.access.now()
	id, fields, err := p.signed(ctx, raw, true)
	if err != nil {
		return out, err
	}
	var c struct {
		SID    string                     `json:"sid"`
		JTI    string                     `json:"jti"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if id.Claims(&c) != nil || fields["nonce"] != nil || !identity.Text(c.JTI, 256) || len(c.Events) != 1 || c.SID == "" && id.Subject == "" || c.SID != "" && !identity.Text(c.SID, 256) || id.Subject != "" && !identity.Text(id.Subject, 256) || p.access.now().Before(started) {
		return out, identity.ErrDenied
	}
	var event map[string]json.RawMessage
	if json.Unmarshal(c.Events["http://schemas.openid.net/event/backchannel-logout"], &event) != nil || event == nil || len(event) != 0 {
		return out, identity.ErrDenied
	}
	return app.LogoutEvent{Issuer: p.trust.Access.Issuer, ClientID: p.trust.ClientID, Subject: id.Subject, SessionID: c.SID, ID: c.JTI, IssuedAt: id.IssuedAt}, nil
}
