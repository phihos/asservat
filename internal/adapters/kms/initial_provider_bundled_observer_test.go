package kms

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestObserveBundledInitialIdentityChecksActualSetupMetadata(t *testing.T) {
	in, _, _, now := ownerProviderRecipeInput(t)
	plan := contracts.SmallOpenBaoPlan{Format: contracts.SmallOpenBaoFormat, Namespace: "bootstrap", Name: "trial", Image: contracts.SmallOpenBaoImage, Kubernetes: in.Kubernetes, SetupAccount: "trial-setup"}
	namespace := contracts.WorkerObjectReference{Name: plan.Namespace, UID: "20000000-0000-4000-8000-000000000010"}
	account := contracts.WorkerObjectReference{Name: plan.SetupAccount, UID: "20000000-0000-4000-8000-000000000011"}
	original := initialTokenLookup{Accessor: "original-setup", Type: "service", Policies: []string{contracts.SmallOpenBaoSetupPolicy}, Path: "auth/asservat-setup/login", Meta: map[string]string{"role": contracts.SmallOpenBaoSetupRole, "service_account_name": account.Name, "service_account_namespace": namespace.Name, "service_account_uid": account.UID}, Orphan: true, Renewable: true, CreationTTL: 300, MaxTTL: 900, Issued: now, Expire: now.Add(300 * time.Second), Entity: "20000000-0000-4000-8000-000000000012"}
	var change func(*initialTokenLookup)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != "actual-setup-token" {
			t.Error("unexpected effect or credential")
			w.WriteHeader(403)
			return
		}
		copy := original
		copy.Meta = map[string]string{}
		for k, v := range original.Meta {
			copy.Meta[k] = v
		}
		if change != nil {
			change(&copy)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": copy})
	}))
	defer server.Close()
	h := server.Client()
	transport := h.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = server.Certificate().DNSNames[0]
	target, _ := url.Parse(server.URL)
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}
	h.Transport = transport
	observe := func() (contracts.BundledInitialProviderIdentity, error) {
		return ObserveBundledInitialProviderIdentity(context.Background(), plan.Endpoint(), "actual-setup-token", plan, namespace, account, h, func() time.Time { return now.Add(time.Second) })
	}
	got, err := observe()
	if err != nil || !got.Valid() || got.EntityID != original.Entity || !got.SetupParent.ExpiresAt.Equal(original.Expire) || got.Namespace != namespace || got.SetupAccount != account || requests != 1 {
		t.Fatal("actual setup identity not pinned once", err, requests)
	}
	for name, mutation := range map[string]func(*initialTokenLookup){
		"foreign-account":       func(v *initialTokenLookup) { v.Meta["service_account_uid"] = "20000000-0000-4000-8000-000000000099" },
		"foreign-name":          func(v *initialTokenLookup) { v.Meta["service_account_name"] = "foreign" },
		"foreign-namespace":     func(v *initialTokenLookup) { v.Meta["service_account_namespace"] = "foreign" },
		"foreign-role":          func(v *initialTokenLookup) { v.Meta["role"] = "foreign" },
		"foreign-auth-path":     func(v *initialTokenLookup) { v.Path = "auth/foreign/login" },
		"identity-policy":       func(v *initialTokenLookup) { v.IdentityPolicies = []string{"extra"} },
		"extra-policy":          func(v *initialTokenLookup) { v.Policies = append(v.Policies, "default") },
		"no-entity":             func(v *initialTokenLookup) { v.Entity = "" },
		"renewed-parent":        func(v *initialTokenLookup) { v.LastRenewal = 1 },
		"longer-parent":         func(v *initialTokenLookup) { v.Expire = v.Issued.Add(900 * time.Second) },
		"expired-parent":        func(v *initialTokenLookup) { v.Issued = now.Add(-300 * time.Second); v.Expire = now },
		"unrecognized-metadata": func(v *initialTokenLookup) { v.Meta["foreign"] = "field" },
	} {
		t.Run(name, func(t *testing.T) {
			change = mutation
			if _, err := observe(); err == nil {
				t.Fatal("mismatched setup identity accepted")
			}
		})
	}
}
