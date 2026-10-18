package kms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"net/http"
	"net/url"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
)

// This concrete control client is private until the installed profile selects
// it together with current native/source/recovery checks and the fixed token
// owner. No constructor, receipt or provider token grants those authorities.
type ownerProviderControl struct {
	http            *http.Client
	endpoint, mount string
	role, namespace string
	// purpose is the closed provider purpose, for diagnostics only.
	purpose             string
	account, accountUID string
	now                 func() time.Time
}

// The token is deliberately opaque and never serialized into a public receipt.
// A positive renewal returns a new observation; it does not mutate an existing
// credential or any borrow's original usable end.
type ownerProviderCredential struct {
	owner                    *ownerProviderControl
	token                    []byte
	accessor, entity         string
	issued, hardUntil, until time.Time
	observed, jwtUntil       time.Time
	creationTTL              int64
}

func (c *ownerProviderCredential) destroy() {
	if c != nil {
		clear(c.token)
		c.token = nil
	}
}

func newOwnerProviderControl(in contracts.OwnerDeployment, profile contracts.OwnerProviderAuthentication, purpose string, client *http.Client, now func() time.Time) (*ownerProviderControl, error) {
	if now == nil || client == nil || client.Jar != nil || ValidateOwnerProviderAuthentication(in, profile, now()) != nil {
		return nil, ErrKeyService
	}
	recipe, err := OwnerProviderRecipeFor(in, profile.AuthMount, profile.AuthMountAccessor, profile.ServiceAccount, profile.AuditCredentials, now())
	if err != nil {
		return nil, ErrKeyService
	}
	var name string
	for _, role := range recipe.Roles {
		if role.Purpose == purpose {
			name = role.Name
		}
	}
	// ADR-182: the public purposes come from their own pinned recipe.
	if name == "" && in.Public != nil {
		if providerconfig.ValidateOwnerPublicProviderRecipe(in, profile, now()) != nil {
			return nil, ErrKeyService
		}
		roles, _, err := providerconfig.OwnerPublicProviderRecipeFor(in, profile, now())
		if err != nil {
			return nil, ErrKeyService
		}
		for _, role := range roles {
			if role.Purpose == purpose {
				name = role.Name
			}
		}
	}
	// ADR-193: the bootstrap channel comes from its own pinned fleet recipe.
	if name == "" && purpose == providerconfig.OwnerFleetProviderPurpose && in.Public != nil && in.Public.Fleet != nil {
		if providerconfig.ValidateOwnerFleetProviderRecipe(in, profile, now()) != nil {
			return nil, ErrKeyService
		}
		role, _, err := providerconfig.OwnerFleetProviderRecipeFor(in, profile, now())
		if err != nil {
			return nil, ErrKeyService
		}
		name = role.Name
	}
	u, err := url.Parse(in.KeyService.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || name == "" {
		return nil, ErrKeyService
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok || transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrKeyService
	}
	transport = transport.Clone()
	// Custom TLS dialers bypass TLSClientConfig entirely. Custom negotiated
	// protocol handlers also sit outside this fixed HTTPS request boundary.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSNextProto = nil
	roots := x509.NewCertPool()
	for _, der := range in.KeyService.Roots {
		certificate, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, ErrKeyService
		}
		roots.AddCert(certificate)
	}
	// The accepted public profile, not an ambient/custom client's roots or
	// verification callback, determines server authentication.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	transport.Proxy = nil
	u.Path = ""
	h := *client
	h.Transport, h.Timeout = transport, 5*time.Second
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &ownerProviderControl{http: &h, endpoint: u.String(), mount: profile.AuthMount, role: name, purpose: purpose, namespace: in.Namespace.Name, account: profile.ServiceAccount.Name, accountUID: profile.ServiceAccount.UID, now: now}, nil
}

func (c *ownerProviderControl) close() {
	if c != nil && c.http != nil {
		c.http.CloseIdleConnections()
	}
}

type ownerProviderAuthReply struct {
	ClientToken      string            `json:"client_token"`
	Accessor         string            `json:"accessor"`
	Policies         []string          `json:"policies"`
	TokenPolicies    []string          `json:"token_policies"`
	IdentityPolicies []string          `json:"identity_policies"`
	Metadata         map[string]string `json:"metadata"`
	Orphan           bool              `json:"orphan"`
	EntityID         string            `json:"entity_id"`
	LeaseDuration    int64             `json:"lease_duration"`
	Renewable        bool              `json:"renewable"`
	Type             string            `json:"token_type"`
	Uses             int64             `json:"num_uses"`
	MFA              json.RawMessage   `json:"mfa_requirement"`
}

type ownerProviderControlReply struct {
	RequestID     string                  `json:"request_id"`
	LeaseID       string                  `json:"lease_id"`
	LeaseDuration int64                   `json:"lease_duration"`
	Renewable     bool                    `json:"renewable"`
	Data          json.RawMessage         `json:"data"`
	Auth          *ownerProviderAuthReply `json:"auth"`
	Warnings      []string                `json:"warnings"`
	Wrap          json.RawMessage         `json:"wrap_info"`
	MountType     string                  `json:"mount_type"`
}

// The only callers supply one fixed login or self-operation path. There is no
// arbitrary provider request port, transparent POST replay, redirect or token
// accessor lookup. The caller's control context spans the whole login+lookup.
func (c *ownerProviderControl) call(ctx context.Context, method, path string, token []byte, body any) (ownerProviderControlReply, error) {
	var result ownerProviderControlReply
	if ctx == nil || ctx.Err() != nil || c == nil || c.http == nil {
		return result, ErrKeyService
	}
	var raw []byte
	var err error
	if body != nil {
		raw, err = json.Marshal(body)
		if err != nil {
			return result, ErrKeyService
		}
		defer clear(raw)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.endpoint+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		return result, ErrKeyService
	}
	r.GetBody = nil
	r.Header.Set("Content-Type", "application/json")
	if len(token) != 0 {
		if !ValidProviderToken(token) {
			return result, ErrKeyService
		}
		r.Header.Set("X-Vault-Token", string(token))
	}
	response, err := c.http.Do(r)
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil || response == nil || response.Body == nil || response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return result, ErrKeyService
	}
	if response.StatusCode == http.StatusNoContent {
		if method != http.MethodPost || path != "auth/token/revoke-self" || ctx.Err() != nil {
			return result, ErrKeyService
		}
		return result, nil
	}
	if path == "auth/token/revoke-self" {
		return result, ErrKeyService
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	defer clear(encoded)
	if err != nil || len(encoded) > 32768 || !jsontext.Value(encoded).IsValid() || !initialProviderDecode(encoded, &result) || result.LeaseID != "" || result.LeaseDuration != 0 || result.Renewable || len(result.Warnings) != 0 || !ownerProviderNull(result.Wrap) || ctx.Err() != nil {
		return ownerProviderControlReply{}, ErrKeyService
	}
	if result.Auth != nil {
		var outer map[string]json.RawMessage
		if json.Unmarshal(encoded, &outer) != nil || !initialProviderFields(outer["auth"], "client_token", "accessor", "policies", "token_policies", "metadata", "orphan", "entity_id", "lease_duration", "renewable", "token_type", "num_uses") {
			return ownerProviderControlReply{}, ErrKeyService
		}
	}
	return result, nil
}

func ownerProviderNull(b []byte) bool { return len(b) == 0 || string(b) == "null" }

func (c *ownerProviderControl) login(ctx context.Context, jwt []byte) (*ownerProviderCredential, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || !ValidProviderToken(jwt) {
		return nil, ErrKeyService
	}
	start := c.now()
	jwtUntil, err := ownerProviderJWTEnd(jwt, start)
	if err != nil {
		return nil, err
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := c.call(call, http.MethodPost, "auth/"+c.mount+"/login", nil, map[string]string{"role": c.role, "jwt": string(jwt)})
	if err != nil || !c.validAuth(reply, nil) {
		if err == nil && reply.Auth != nil && ValidProviderToken([]byte(reply.Auth.ClientToken)) {
			token := []byte(reply.Auth.ClientToken)
			_, _ = c.call(call, http.MethodPost, "auth/token/revoke-self", token, nil)
			clear(token)
		}
		return nil, ErrKeyService
	}
	token := []byte(reply.Auth.ClientToken)
	defer clear(token)
	credential, err := c.lookup(call, token, nil, start, reply.Auth, jwtUntil)
	if err != nil {
		// The token was received positively; self-revocation is best effort
		// within this same original control call. Failure proves no revocation.
		_, _ = c.call(call, http.MethodPost, "auth/token/revoke-self", token, nil)
		return nil, ErrKeyService
	}
	return credential, nil
}

func (c *ownerProviderControl) renew(ctx context.Context, old *ownerProviderCredential) (*ownerProviderCredential, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || old == nil || old.owner != c || !c.now().Before(old.until) || !c.now().Before(old.jwtUntil) || !ValidProviderToken(old.token) {
		return nil, ErrKeyService
	}
	start := c.now()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := c.call(call, http.MethodPost, "auth/token/renew-self", old.token, map[string]int{"increment": contracts.OwnerProviderTokenTTLSeconds})
	if err != nil || !c.validAuth(reply, old) {
		return nil, ErrKeyService // old remains unchanged even after unknown POST.
	}
	return c.lookup(call, old.token, old, start, reply.Auth, old.jwtUntil)
}

func (c *ownerProviderControl) reconcile(ctx context.Context, old *ownerProviderCredential) (*ownerProviderCredential, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || old == nil || old.owner != c || !ValidProviderToken(old.token) || !c.now().Before(old.hardUntil) {
		return nil, ErrKeyService
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.lookup(call, old.token, old, c.now(), nil, old.jwtUntil)
}

func (c *ownerProviderControl) revoke(ctx context.Context, old *ownerProviderCredential) error {
	if c == nil || ctx == nil || ctx.Err() != nil || old == nil || old.owner != c || !ValidProviderToken(old.token) {
		return ErrKeyService
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := c.call(call, http.MethodPost, "auth/token/revoke-self", old.token, nil)
	return err
}
