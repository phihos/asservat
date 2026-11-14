package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type saKey struct {
	private *ecdsa.PrivateKey
	id      string
}

func newSAKey(t *testing.T, id string) saKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return saKey{k, id}
}

func (k saKey) public() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.private.PublicKey, KeyID: k.id, Algorithm: "ES256", Use: "sig"}
}

func (k saKey) token(t *testing.T, issuer, subject, audience string, expiry time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: k.private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.id))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{Issuer: issuer, Subject: subject, Audience: jwt.Audience{audience}, Expiry: jwt.NewNumericDate(expiry), IssuedAt: jwt.NewNumericDate(time.Now())}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

const (
	saAudience = "https://hub.example.test"
	saSubject  = "system:serviceaccount:asservat-system:asservat-connector"
)

// ADR-334: a static JWKS registers a cluster whose issuer the hub cannot
// reach; only a token of that issuer, audience and connector subject that has
// not expired is attributed to it.
func TestServiceAccountVerifierStaticJWKS(t *testing.T) {
	key := newSAKey(t, "eu-1")
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.public()}})
	v, err := NewServiceAccountVerifier([]string{saAudience}, []ServiceAccountCluster{{ClusterID: "eu", PeerID: "eu-peer", Issuer: "https://eu.example.test", JWKS: jwks, Namespace: "asservat-system", Account: "asservat-connector"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := v.VerifyConnector(ctx, key.token(t, "https://eu.example.test", saSubject, saAudience, time.Now().Add(time.Minute)))
	if err != nil || got.ClusterID != "eu" || got.PeerID != "eu-peer" {
		t.Fatal("valid token", got, err)
	}
	other := newSAKey(t, "eu-1")
	for name, token := range map[string]string{
		"audience": key.token(t, "https://eu.example.test", saSubject, "https://other.example.test", time.Now().Add(time.Minute)),
		"subject":  key.token(t, "https://eu.example.test", "system:serviceaccount:default:default", saAudience, time.Now().Add(time.Minute)),
		"issuer":   key.token(t, "https://us.example.test", saSubject, saAudience, time.Now().Add(time.Minute)),
		"expired":  key.token(t, "https://eu.example.test", saSubject, saAudience, time.Now().Add(-time.Minute)),
		"key":      other.token(t, "https://eu.example.test", saSubject, saAudience, time.Now().Add(time.Minute)),
		"garbage":  "not.a.token",
	} {
		if _, err := v.VerifyConnector(ctx, token); err == nil {
			t.Fatal("accepted token with wrong", name)
		}
	}
}

// Discovery: the issuer's keys are fetched once and refreshed on an unknown
// key ID (a rotated ServiceAccount signing key) without a restart.
func TestServiceAccountVerifierDiscoveryRefreshesOnUnknownKey(t *testing.T) {
	first, second := newSAKey(t, "k1"), newSAKey(t, "k2")
	var current atomic.Pointer[saKey]
	current.Store(&first)
	var fetches atomic.Int32
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{current.Load().public()}})
	})
	v, err := NewServiceAccountVerifier([]string{saAudience}, []ServiceAccountCluster{{ClusterID: "eu", PeerID: "eu-peer", Issuer: server.URL, Namespace: "asservat-system", Account: "asservat-connector", Client: server.Client()}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = v.VerifyConnector(ctx, first.token(t, server.URL, saSubject, saAudience, time.Now().Add(time.Minute))); err != nil {
		t.Fatal("first key", err)
	}
	current.Store(&second)
	if _, err = v.VerifyConnector(ctx, second.token(t, server.URL, saSubject, saAudience, time.Now().Add(time.Minute))); err != nil || fetches.Load() != 2 {
		t.Fatal("rotated key", err, fetches.Load())
	}
}

// The hub's own cluster in combined mode: discovery through its API server
// address, whose advertised issuer name need not resolve.
func TestServiceAccountVerifierLocalDiscovery(t *testing.T) {
	key := newSAKey(t, "local")
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	const issuer = "https://kubernetes.default.svc.cluster.local"
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "jwks_uri": "https://172.18.0.2:6443/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.public()}})
	})
	v, err := NewServiceAccountVerifier([]string{saAudience}, []ServiceAccountCluster{{ClusterID: "hub", PeerID: "hub-peer", Discovery: server.URL, Namespace: "asservat-system", Account: "asservat-connector", Client: server.Client()}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.VerifyConnector(context.Background(), key.token(t, issuer, saSubject, saAudience, time.Now().Add(time.Minute)))
	if err != nil || got.ClusterID != "hub" {
		t.Fatal("local token", got, err)
	}
}

// Candidates are chosen by the token's issuer before any network call: a
// token of another issuer never triggers this cluster's discovery. A failed
// discovery is not cached; the next request discovers again.
func TestServiceAccountVerifierSelectsByIssuerAndRetriesFailedDiscovery(t *testing.T) {
	key := newSAKey(t, "k1")
	var discoveries, failures atomic.Int32
	failures.Store(1)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		discoveries.Add(1)
		if failures.Add(-1) >= 0 {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": server.URL, "jwks_uri": server.URL + "/openid/v1/jwks"})
	})
	mux.HandleFunc("/openid/v1/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.public()}})
	})
	v, err := NewServiceAccountVerifier([]string{saAudience}, []ServiceAccountCluster{{ClusterID: "eu", PeerID: "eu-peer", Issuer: server.URL, Namespace: "asservat-system", Account: "asservat-connector", Client: server.Client()}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err = v.VerifyConnector(ctx, key.token(t, "https://other.example.test", saSubject, saAudience, time.Now().Add(time.Minute))); err == nil || discoveries.Load() != 0 {
		t.Fatal("foreign issuer reached discovery", err, discoveries.Load())
	}
	token := key.token(t, server.URL, saSubject, saAudience, time.Now().Add(time.Minute))
	if _, err = v.VerifyConnector(ctx, token); err == nil || discoveries.Load() != 1 {
		t.Fatal("failed discovery accepted", err, discoveries.Load())
	}
	if _, err = v.VerifyConnector(ctx, token); err != nil || discoveries.Load() != 2 {
		t.Fatal("discovery not retried", err, discoveries.Load())
	}
	if _, err = v.VerifyConnector(ctx, token); err != nil || discoveries.Load() != 2 {
		t.Fatal("discovery repeated after success", err, discoveries.Load())
	}
}
