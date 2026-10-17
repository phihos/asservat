package kubernetes

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/contracts"
	"k8s.io/client-go/rest"
)

// Static inputs must be rejected before the first native prelude/seed effect,
// rather than only when the later preparation profile is constructed.
func TestInitialBootstrapRejectsInvalidProviderNamesBeforeEffects(t *testing.T) {
	desired := bootstrapAdmissionFixture(t)
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unexpected API effect", http.StatusInternalServerError)
	}))
	defer server.Close()
	desired.Kubernetes = contracts.OwnerProviderEndpoint{Endpoint: server.URL, Roots: [][]byte{server.Certificate().Raw}}
	config := &rest.Config{Host: server.URL, Transport: server.Client().Transport}
	if err := validateBootstrap(desired); err != nil {
		t.Fatal("valid static provider names rejected", err)
	}
	fields := func(p *contracts.InitialBootstrapProviders) []*string {
		return []*string{&p.IssuerPolicy, &p.WrapRole, &p.WrapPolicy, &p.UnwrapRole, &p.UnwrapPolicy}
	}
	check := func(t *testing.T, p contracts.InitialBootstrapProviders) {
		t.Helper()
		invalid := desired
		invalid.Providers = p
		instance, err := NewInitialBootstrap(context.Background(), config, invalid)
		if instance != nil {
			instance.Close()
		}
		if err == nil {
			t.Fatal("invalid provider names accepted before bootstrap effects")
		}
		if calls.Load() != 0 {
			t.Fatal("invalid provider names reached the API")
		}
	}
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			t.Run(fmt.Sprintf("duplicate-%d-%d", i, j), func(t *testing.T) {
				p := desired.Providers
				names := fields(&p)
				*names[j] = *names[i]
				check(t, p)
			})
		}
		for _, name := range []string{"", "root", "default", "role/name", "role name", strings.Repeat("x", 65)} {
			t.Run(fmt.Sprintf("invalid-%d-%s", i, name), func(t *testing.T) {
				p := desired.Providers
				*fields(&p)[i] = name
				check(t, p)
			})
		}
	}
}
