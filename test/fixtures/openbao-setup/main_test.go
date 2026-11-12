//go:build asservat_testfixture

package main

import (
	"encoding/json"
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
