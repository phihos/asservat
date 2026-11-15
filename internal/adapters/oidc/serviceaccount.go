package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"
)

// ErrServiceAccountDenied refuses a connector token (ADR-334).
var ErrServiceAccountDenied = errors.New("connector service account token denied")

// discoveryTimeout bounds one issuer discovery (ADR-330 D5 I/O timeout).
const discoveryTimeout = 5 * time.Second

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

// saCluster keeps its registration immutable; the discovered issuer and
// verifier are published once through state.
type saCluster struct {
	cluster ServiceAccountCluster
	state   atomic.Pointer[saState]
	flight  singleflight.Group
	now     func() time.Time
	// attempted is the UnixNano of the last discovery attempt; a failed
	// discovery is retried no sooner than jwksRefetchInterval later.
	attempted atomic.Int64
}

type saState struct {
	issuer   string
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
		s := &saCluster{cluster: c, now: time.Now}
		if len(c.JWKS) != 0 {
			var set jose.JSONWebKeySet
			if json.Unmarshal(c.JWKS, &set) != nil || len(set.Keys) == 0 || c.Issuer == "" {
				return nil, ErrServiceAccountDenied
			}
			keys := &gooidc.StaticKeySet{}
			for _, k := range set.Keys {
				keys.PublicKeys = append(keys.PublicKeys, k.Key)
			}
			s.state.Store(&saState{issuer: c.Issuer, verifier: gooidc.NewVerifier(c.Issuer, keys, saConfig)})
		}
		v.clusters = append(v.clusters, s)
	}
	return v, nil
}

// VerifyConnector returns the cluster the token belongs to. Candidates are
// selected by the token's unverified issuer and subject before any key
// lookup; the verifier then checks signature, issuer, audience and expiry.
func (v *ServiceAccountVerifier) VerifyConnector(ctx context.Context, raw string) (ServiceAccountCluster, error) {
	c, _, err := v.VerifyConnectorToken(ctx, raw)
	return c, err
}

// VerifyConnectorToken also returns the token's expiry, which bounds any use
// of the authentication.
func (v *ServiceAccountVerifier) VerifyConnectorToken(ctx context.Context, raw string) (ServiceAccountCluster, time.Time, error) {
	var zero ServiceAccountCluster
	issuer, subject, ok := unverifiedClaims(raw)
	if v == nil || !ok {
		return zero, time.Time{}, ErrServiceAccountDenied
	}
	for _, c := range v.clusters {
		if !c.candidate(issuer, subject) {
			continue
		}
		state, err := c.current(ctx)
		if err != nil || state.issuer != issuer {
			continue
		}
		if t, err := state.verifier.Verify(gooidc.ClientContext(ctx, c.cluster.Client), raw); err == nil && t.Subject == subject && slices.ContainsFunc(t.Audience, func(a string) bool { return slices.Contains(v.audiences, a) }) {
			return c.cluster, t.Expiry, nil
		}
	}
	return zero, time.Time{}, ErrServiceAccountDenied
}

// candidate matches the connector subject and the registered issuer, or,
// for the hub's own API server, the issuer it published once discovered.
func (c *saCluster) candidate(issuer, subject string) bool {
	if subject != "system:serviceaccount:"+c.cluster.Namespace+":"+c.cluster.Account {
		return false
	}
	if c.cluster.Issuer != "" {
		return c.cluster.Issuer == issuer
	}
	s := c.state.Load()
	return s == nil || s.issuer == issuer
}

// current returns the discovered verifier, discovering the issuer on demand
// (once at a time, outside any lock, within its own I/O timeout). A failed
// discovery is not cached; a later request tries again, no sooner than
// jwksRefetchInterval after the failed attempt.
func (c *saCluster) current(ctx context.Context) (*saState, error) {
	if s := c.state.Load(); s != nil {
		return s, nil
	}
	if a := c.attempted.Load(); a != 0 && c.now().Sub(time.Unix(0, a)) < jwksRefetchInterval {
		return nil, ErrServiceAccountDenied
	}
	out, err, _ := c.flight.Do("discover", func() (any, error) {
		if s := c.state.Load(); s != nil {
			return s, nil
		}
		c.attempted.Store(c.now().UnixNano())
		call, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
		defer cancel()
		s, err := c.discover(call)
		if err != nil {
			return nil, err
		}
		c.state.Store(s)
		return s, nil
	})
	if err != nil {
		return nil, err
	}
	return out.(*saState), nil
}

func (c *saCluster) discover(ctx context.Context) (*saState, error) {
	base := c.cluster.Discovery
	if base == "" {
		base = c.cluster.Issuer
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(base, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.cluster.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<10)).Decode(&doc) != nil || doc.Issuer == "" || c.cluster.Issuer != "" && doc.Issuer != c.cluster.Issuer {
		return nil, ErrServiceAccountDenied
	}
	jwks := doc.JWKSURI
	if c.cluster.Discovery != "" {
		// The API server serves its keys at a fixed path; its advertised
		// jwks_uri may name an address only reachable outside the cluster.
		jwks = strings.TrimSuffix(c.cluster.Discovery, "/") + "/openid/v1/jwks"
	}
	keys := &remoteKeys{url: jwks, client: c.cluster.Client, now: c.now}
	return &saState{issuer: doc.Issuer, verifier: gooidc.NewVerifier(doc.Issuer, keys, saConfig)}, nil
}

// jwksRefetchInterval spaces unknown-key refetches of one issuer's JWKS. It
// bounds the load an unauthenticated caller with made-up key IDs can put on
// the issuer to one fetch per 10 s per issuer, and a legitimately rotated key
// is accepted within 10 s of its first use.
const jwksRefetchInterval = 10 * time.Second

// remoteKeys is a discovered JWKS: cached, and fetched again (once at a
// time, within the I/O timeout, at most every jwksRefetchInterval) when a
// token names an unknown key ID, such as after the cluster rotated its
// ServiceAccount signing key.
type remoteKeys struct {
	url     string
	client  *http.Client
	keys    atomic.Pointer[jose.JSONWebKeySet]
	fetched atomic.Int64 // UnixNano of the last fetch attempt
	flight  singleflight.Group
	now     func() time.Time
	// attempted is the UnixNano of the last discovery attempt; a failed
	// discovery is retried no sooner than jwksRefetchInterval later.
	attempted atomic.Int64
}

func (r *remoteKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, saAlgorithms)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, ErrServiceAccountDenied
	}
	kid := jws.Signatures[0].Header.KeyID
	set := r.keys.Load()
	if set == nil || len(set.Key(kid)) == 0 {
		if f := r.fetched.Load(); f != 0 && r.now().Sub(time.Unix(0, f)) < jwksRefetchInterval {
			return nil, ErrServiceAccountDenied
		}
		if set, err = r.fetch(ctx); err != nil {
			return nil, err
		}
	}
	for _, k := range set.Key(kid) {
		if payload, err := jws.Verify(k); err == nil {
			return payload, nil
		}
	}
	return nil, ErrServiceAccountDenied
}

func (r *remoteKeys) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	out, err, _ := r.flight.Do("jwks", func() (any, error) {
		r.fetched.Store(r.now().UnixNano())
		call, cancel := context.WithTimeout(context.WithoutCancel(ctx), discoveryTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(call, http.MethodGet, r.url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := r.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		var set jose.JSONWebKeySet
		if resp.StatusCode != http.StatusOK || json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 256<<10)).Decode(&set) != nil {
			return nil, ErrServiceAccountDenied
		}
		r.keys.Store(&set)
		return &set, nil
	})
	if err != nil {
		return nil, err
	}
	return out.(*jose.JSONWebKeySet), nil
}

var saAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA}

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
