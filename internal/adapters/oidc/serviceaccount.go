package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

// ErrServiceAccountDenied refuses a connector token (ADR-334).
var ErrServiceAccountDenied = errors.New("connector service account token denied")

// ServiceAccountCluster is one registered workload cluster: its connector
// ServiceAccount and either a static JWKS or discovery of its issuer.
// Discovery is the issuer's /.well-known/openid-configuration, or, with
// Discovery set, that base URL (the hub's own API server in combined mode,
// whose issuer name may not resolve outside it).
type ServiceAccountCluster struct {
	ClusterID, PeerID  string
	Issuer             string
	JWKS               []byte
	Discovery          string
	Namespace, Account string
	Client             *http.Client
}

// ServiceAccountVerifier attributes a projected ServiceAccount token to the
// one registered cluster whose issuer, audience, signature, expiry and
// connector subject it matches.
type ServiceAccountVerifier struct {
	audiences []string
	clusters  []*saCluster
}

type saCluster struct {
	ServiceAccountCluster
	mu       sync.Mutex
	verifier *gooidc.IDTokenVerifier
}

// NewServiceAccountVerifier accepts tokens for any of audiences: the hub
// URLs connectors dial.
func NewServiceAccountVerifier(audiences []string, clusters []ServiceAccountCluster) (*ServiceAccountVerifier, error) {
	if len(audiences) == 0 || slices.Contains(audiences, "") {
		return nil, ErrServiceAccountDenied
	}
	v := &ServiceAccountVerifier{audiences: slices.Clone(audiences)}
	for _, c := range clusters {
		if c.ClusterID == "" || c.PeerID == "" || c.Namespace == "" || c.Account == "" || c.Issuer == "" && c.Discovery == "" {
			return nil, ErrServiceAccountDenied
		}
		if c.Client == nil {
			c.Client = http.DefaultClient
		}
		s := &saCluster{ServiceAccountCluster: c}
		if len(c.JWKS) != 0 {
			var set jose.JSONWebKeySet
			if json.Unmarshal(c.JWKS, &set) != nil || len(set.Keys) == 0 || c.Issuer == "" {
				return nil, ErrServiceAccountDenied
			}
			keys := &gooidc.StaticKeySet{}
			for _, k := range set.Keys {
				keys.PublicKeys = append(keys.PublicKeys, k.Key)
			}
			s.verifier = gooidc.NewVerifier(c.Issuer, keys, saConfig)
		}
		v.clusters = append(v.clusters, s)
	}
	return v, nil
}

// Verify returns the cluster the token belongs to.
func (v *ServiceAccountVerifier) VerifyConnector(ctx context.Context, raw string) (ServiceAccountCluster, error) {
	var zero ServiceAccountCluster
	issuer, subject, ok := unverifiedClaims(raw)
	if v == nil || !ok {
		return zero, ErrServiceAccountDenied
	}
	for _, c := range v.clusters {
		if subject != "system:serviceaccount:"+c.Namespace+":"+c.Account {
			continue
		}
		verifier, err := c.current(ctx, issuer)
		if err != nil {
			continue
		}
		if t, err := verifier.Verify(gooidc.ClientContext(ctx, c.Client), raw); err == nil && t.Subject == subject && slices.ContainsFunc(t.Audience, func(a string) bool { return slices.Contains(v.audiences, a) }) {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.ServiceAccountCluster, nil
		}
	}
	return zero, ErrServiceAccountDenied
}

// current discovers the issuer once; the remote key set refreshes itself on
// an unknown key ID.
func (c *saCluster) current(ctx context.Context, issuer string) (*gooidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Issuer != "" && c.Issuer != issuer {
		return nil, ErrServiceAccountDenied
	}
	if c.verifier != nil {
		return c.verifier, nil
	}
	base := c.Discovery
	if base == "" {
		base = c.Issuer
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&doc) != nil || doc.Issuer == "" || c.Issuer != "" && doc.Issuer != c.Issuer {
		return nil, ErrServiceAccountDenied
	}
	jwks := doc.JWKSURI
	if c.Discovery != "" {
		// The API server serves its keys at a fixed path; its advertised
		// jwks_uri may name an address only reachable outside the cluster.
		jwks = strings.TrimSuffix(c.Discovery, "/") + "/openid/v1/jwks"
	}
	c.Issuer = doc.Issuer
	keys := gooidc.NewRemoteKeySet(gooidc.ClientContext(context.WithoutCancel(ctx), c.Client), jwks)
	c.verifier = gooidc.NewVerifier(doc.Issuer, keys, saConfig)
	return c.verifier, nil
}

// saConfig checks the audience itself (any of the hub's URLs) and accepts
// the asymmetric algorithms Kubernetes can sign ServiceAccount tokens with.
var saConfig = &gooidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: []string{gooidc.RS256, gooidc.RS384, gooidc.RS512, gooidc.ES256, gooidc.ES384, gooidc.ES512, gooidc.PS256, gooidc.PS384, gooidc.PS512, gooidc.EdDSA}}

// unverifiedClaims selects the candidate clusters; Verify checks everything.
func unverifiedClaims(raw string) (issuer, subject string, ok bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 16<<10 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
	}
	if err != nil || json.Unmarshal(payload, &c) != nil || c.Iss == "" || c.Sub == "" {
		return "", "", false
	}
	return c.Iss, c.Sub, true
}
