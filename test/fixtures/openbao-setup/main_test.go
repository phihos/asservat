//go:build asservat_testfixture

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"time"

	"asservat.local/asservat/internal/contracts"
	"encoding/json"
	bao "github.com/openbao/openbao/api/v2"
	"strings"
	"testing"
)

func TestTokenFactsExcludeCredentialsAndIdentifiers(t *testing.T) {
	data := map[string]any{"id": "private-token", "accessor": "private-accessor", "entity_id": "private-entity", "meta": map[string]string{"service_account_uid": "private-uid"}, "orphan": false, "renewable": false, "creation_ttl": json.Number("900"), "explicit_max_ttl": json.Number("900"), "ttl": json.Number("880"), "identity_policies": []any{}}
	facts := safeTokenFacts(data)
	raw, err := json.Marshal(facts)
	if err != nil || strings.Contains(string(raw), "private-") || facts["entityPresent"] != true || facts["creationTTL"] != int64(900) || facts["explicitMaxTTL"] != int64(900) {
		t.Fatal("unsafe or incomplete diagnostic projection")
	}
}

func TestProbeInputIsClosed(t *testing.T) {
	for _, raw := range []string{`{"unrecognized":"field"}`, `{} {}`} {
		var in input
		if readClosed(strings.NewReader(raw), &in) == nil {
			t.Fatal("unrecognized input accepted")
		}
	}
}

func TestProductionMintWireAndSafeClassification(t *testing.T) {
	until := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var got map[string]any
		if json.NewDecoder(r.Body).Decode(&got) != nil || r.Method != http.MethodPost || r.URL.Path != "/v1/auth/token/create/"+contracts.SmallOpenBaoInitialIssuerRole || r.Header.Get("X-Vault-Token") != "private-setup" {
			t.Error("wrong actual production request boundary")
			w.WriteHeader(400)
			return
		}
		want := map[string]any{"policies": []any{contracts.SmallOpenBaoInitialProviders().IssuerPolicy}, "no_default_policy": true, "renewable": false, "type": "service", "ttl": "270s", "explicit_max_ttl": "270s", "meta": map[string]any{"asservat-installation": "10000000-0000-4000-8000-000000000001", "asservat-request": "10000000-0000-4000-8000-000000000009", "asservat-operation": "10000000-0000-4000-8000-000000000010"}, "display_name": "", "num_uses": float64(0), "entity_alias": ""}
		if !reflect.DeepEqual(got, want) {
			t.Error("SDK production wire fields differ")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"auth":{"client_token":"private-issued-token"},"warnings":["TTL of private-duration exceeded the effective max_ttl of private-bound; TTL value is capped accordingly"]}`))
	}))
	defer server.Close()
	c, err := client(server.URL, server.Client(), "private-setup")
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.Auth().Token().CreateWithRoleWithContext(ctx, productionInitialMintRequest(270), contracts.SmallOpenBaoInitialIssuerRole)
	facts := classifyProductionMintResponse(ctx, until, response, err, time.Now(), 270)
	if calls != 1 || err != nil || !facts.AuthPresent || facts.WarningCount != 1 || facts.TTLCappedWarningCount != 1 || facts.UnknownWarningCount != 0 || facts.ContextCanceled || facts.RequestRemainingMS <= 0 || facts.TokenLength != len("private-issued-token") || facts.ProductionGuardAccepted {
		t.Fatal("production warning refusal classification differs")
	}
	raw, _ := json.Marshal(facts)
	if strings.Contains(string(raw), "private-") {
		t.Fatal("credential/provider warning content escaped diagnostic projection")
	}
	cancel()
	if !classifyProductionMintResponse(ctx, until, response, err, time.Now(), 270).ContextCanceled {
		t.Fatal("original cancellation lost")
	}
}

func TestProductionMintClassificationDoesNotLeakUnknownWarningOrErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	now := time.Now()
	until := now.Add(time.Second)
	response := &bao.Secret{Auth: &bao.SecretAuth{ClientToken: "private-token"}, Warnings: []string{"Endpoint ignored these unrecognized parameters: [meta private-token]", "private-provider-warning"}}
	facts := classifyProductionMintResponse(ctx, until, response, &bao.ResponseError{StatusCode: 400, Errors: []string{"private-provider-error"}}, now, 270)
	raw, _ := json.Marshal(facts)
	if strings.Contains(string(raw), "private-") || facts.ErrorHTTPStatus != 400 || !facts.ErrorPresent || facts.UnknownWarningCount != 2 || !reflect.DeepEqual(facts.WarningProtocolFields, []string{"meta"}) || facts.ProductionGuardAccepted || facts.RequestRemainingMS != 1000 {
		t.Fatal("unsafe/error classification")
	}
	clean := classifyProductionMintResponse(ctx, until, &bao.Secret{Auth: &bao.SecretAuth{ClientToken: "valid-issued-token"}}, nil, now, 270)
	if !clean.ProductionGuardAccepted || clean.ErrorHTTPStatus != 0 || clean.WarningCount != 0 || clean.ContextCanceled {
		t.Fatal("unchanged valid production response refused")
	}
}

func TestProductionMintClassifiesOnlyExactRoleCapNotice(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	now := time.Now()
	until := now.Add(time.Second)
	known := "Explicit max TTL specified both during creation call and in role; using the lesser value of 270 seconds"
	for _, warnings := range [][]string{{known}, {known + " private-provider-content"}, {known, "private-provider-content"}, {strings.Replace(known, "270", "269", 1)}} {
		facts := classifyProductionMintResponse(ctx, until, &bao.Secret{Auth: &bao.SecretAuth{ClientToken: "private-issued-token"}, Warnings: warnings}, nil, now, 270)
		allowed := len(warnings) == 1 && warnings[0] == known
		if facts.ProductionGuardAccepted != allowed || (facts.ExplicitMaxTTLRoleNoticeCount == 1) != allowed {
			t.Fatal("exact role-cap notice profile changed")
		}
		raw, _ := json.Marshal(facts)
		if strings.Contains(string(raw), "private-") {
			t.Fatal("private warning/token escaped classification")
		}
	}
}
