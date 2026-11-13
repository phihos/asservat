package kms

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseTransitSigningKeyReturnsLatestAndEveryVersion(t *testing.T) {
	k1, k2 := base64.StdEncoding.EncodeToString(make([]byte, 32)), base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1))
	body := func(name, kind, latest, keys string) []byte {
		return []byte(`{"data":{"name":"` + name + `","type":"` + kind + `","exportable":false,"latest_version":` + latest + `,"keys":{` + keys + `}}}`)
	}
	both := `"1":{"public_key":"` + k1 + `"},"2":{"public_key":"` + k2 + `"}`
	latest, keys, err := parseTransitSigningKey(body("deletion", "ed25519", "2", both), "deletion")
	if err != nil || latest != 2 || len(keys) != 2 || len(keys[2]) != ed25519.PublicKeySize || keys[2][31] != 1 {
		t.Fatal("transit key versions not read", err, latest, len(keys))
	}
	for name, b := range map[string][]byte{
		"name":    body("other", "ed25519", "2", both),
		"type":    body("deletion", "aes256-gcm96", "2", both),
		"latest":  body("deletion", "ed25519", "3", both),
		"version": body("deletion", "ed25519", "2", `"01":{"public_key":"`+k1+`"},"2":{"public_key":"`+k2+`"}`),
		"key":     body("deletion", "ed25519", "1", `"1":{"public_key":"`+strings.Repeat("A", 8)+`"}`),
		"export":  []byte(strings.Replace(string(body("deletion", "ed25519", "2", both)), `"exportable":false`, `"exportable":true`, 1)),
	} {
		if _, _, err := parseTransitSigningKey(b, "deletion"); err == nil {
			t.Fatal("invalid transit key accepted", name)
		}
	}
}

func TestOwnerProviderReadTransportAdmitsOnlyExactGET(t *testing.T) {
	reached := 0
	lease := &ownerProviderLeaseTransport{base: http.DefaultTransport, now: time.Now, source: func(context.Context) (ownerProviderLease, error) {
		reached++
		return ownerProviderLease{}, ErrKeyService
	}}
	endpoint, _ := url.Parse("https://keys.invalid")
	transport := &ownerProviderEffectTransport{next: lease, endpoint: *endpoint, path: "/v1/audit/keys/deletion", mode: providerPathGET}
	try := func(method, path string) {
		r, _ := http.NewRequest(method, "https://keys.invalid"+path, nil)
		_, _ = transport.RoundTrip(r)
	}
	try(http.MethodPost, "/v1/audit/keys/deletion")
	try(http.MethodGet, "/v1/audit/keys/other")
	try(http.MethodGet, "/v1/audit/keys/deletion/rotate")
	if reached != 0 {
		t.Fatal("token borrowed for a refused request")
	}
	try(http.MethodGet, "/v1/audit/keys/deletion")
	if reached != 1 {
		t.Fatal("exact key read did not reach the lease")
	}
}
