package kms

import (
	"asservat.local/asservat/internal/contracts"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestInitialProviderPinnedRetirementEncoding(t *testing.T) {
	f := newInitialProviderFixture(t)
	f.accessorErrors = []string{"1 error occurred:\n\t* invalid accessor\n\n"}
	parent, claim := f.claim(t)
	issued, e := f.issuer.Issue(context.Background(), "wrap", claim, parent)
	if e != nil {
		t.Fatal(e)
	}
	claim.Response = &issued
	until, e := f.issuer.Revoke(context.Background(), "wrap", claim, parent, issued)
	if e != nil || !time.Now().Before(until) {
		t.Fatal("pinned single-error retirement rejected", e)
	}
	if _, e = f.issuer.Revoke(context.Background(), "wrap", claim, parent, issued); e != nil {
		t.Fatal("exact retirement replay rejected", e)
	}
	if e = f.issuer.Verify(context.Background(), "wrap", claim, parent, issued); e == nil {
		t.Fatal("revoked credential accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.posts != 1 {
		t.Fatal("retirement created another credential")
	}
}
func TestInitialProviderRetirementEncodingRejectsAmbiguousErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"plain", 400, `{"errors":["invalid accessor"]}`, true},
		{"pinned-wrapper", 400, `{"errors":["1 error occurred:\n\t* invalid accessor\n\n"]}`, true},
		{"raw-plain", 400, "invalid accessor", false},
		{"raw-wrapper", 400, "1 error occurred:\n\t* invalid accessor\n\n", false},
		{"multiple-errors", 400, `{"errors":["invalid accessor","provider failure"]}`, false},
		{"two-wrapped", 400, `{"errors":["2 errors occurred:\n\t* invalid accessor\n\t* provider failure\n\n"]}`, false},
		{"prefix", 400, `{"errors":["failure: invalid accessor"]}`, false},
		{"suffix", 400, `{"errors":["1 error occurred:\n\t* invalid accessor\n\nextra"]}`, false},
		{"whitespace", 400, `{"errors":[" invalid accessor"]}`, false},
		{"other-bad-request", 400, `{"errors":["missing accessor"]}`, false},
		{"wrong-status", 403, `{"errors":["invalid accessor"]}`, false},
		{"success", 200, `{"errors":["invalid accessor"]}`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			c, e := client(server.URL, "synthetic-token", server.Client())
			if e != nil {
				t.Fatal(e)
			}
			got := initialProviderRejection(context.Background(), c, http.MethodPost, "auth/token/lookup-accessor", map[string]string{"accessor": "original"}, 400, "invalid accessor")
			if got != test.want {
				t.Fatalf("rejection proof=%t, want=%t", got, test.want)
			}
		})
	}
}
func TestInitialProviderRetirementStillRequiresOriginalTokenDenial(t *testing.T) {
	for _, status := range []int{200, 400, 401, 403, 404, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			childChecks := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/auth/token/lookup-accessor" {
					w.WriteHeader(400)
					_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"1 error occurred:\n\t* invalid accessor\n\n"}})
					return
				}
				if r.URL.Path != "/v1/auth/token/lookup-self" || r.Header.Get("X-Vault-Token") != "original-child-token" {
					t.Error("wrong proof request")
				}
				childChecks++
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
			}))
			defer server.Close()
			c, e := client(server.URL, "synthetic-issuer", server.Client())
			if e != nil {
				t.Fatal(e)
			}
			s := &InitialProviderIssuer{client: c}
			e = s.verifyRevoked(context.Background(), contracts.InitialProviderResponse{Token: "original-child-token", Accessor: "original"})
			if (e == nil) != (status == 403) || childChecks != 1 {
				t.Fatal("original child denial not independently required")
			}
		})
	}
}
