package kms

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// ADR-193 step 4: the bootstrap channel lifetime discloses its token only for
// GET or POST of one record directly below the installation prefix.
func TestOwnerProviderChannelTransportAdmitsOnlySingleRecords(t *testing.T) {
	reached := 0
	lease := &ownerProviderLeaseTransport{base: http.DefaultTransport, now: time.Now, source: func(context.Context) (ownerProviderLease, error) {
		reached++
		return ownerProviderLease{}, ErrKeyService
	}}
	endpoint, _ := url.Parse("https://keys.invalid")
	transport := &ownerProviderEffectTransport{next: lease, endpoint: *endpoint, path: "/v1/fleet-kv/data/connector/10000000-0000-4000-8000-000000000001/", records: true}
	try := func(method, path string) {
		r, _ := http.NewRequest(method, "https://keys.invalid"+path, nil)
		_, _ = transport.RoundTrip(r)
	}
	base := "/v1/fleet-kv/data/connector/10000000-0000-4000-8000-000000000001/"
	for _, refused := range []struct{ method, path string }{
		{http.MethodGet, base},
		{http.MethodGet, base + "10000000-0000-4000-8000-000000000002/extra"},
		{http.MethodDelete, base + "10000000-0000-4000-8000-000000000002"},
		{"LIST", base},
		{http.MethodGet, "/v1/fleet-kv/metadata/connector/10000000-0000-4000-8000-000000000001/10000000-0000-4000-8000-000000000002"},
		{http.MethodGet, "/v1/fleet-kv/data/connector/10000000-0000-4000-8000-000000000009/10000000-0000-4000-8000-000000000002"},
	} {
		try(refused.method, refused.path)
	}
	if reached != 0 {
		t.Fatal("token borrowed for a refused request")
	}
	try(http.MethodGet, base+"10000000-0000-4000-8000-000000000002")
	try(http.MethodPost, base+"10000000-0000-4000-8000-000000000002")
	if reached != 2 {
		t.Fatal("single-record GET and POST did not reach the lease", reached)
	}
}
