package bootstrap

import (
	"encoding/json"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInstallerServingTLSRecipeOnlyAddsExpectedHostnames(t *testing.T) {
	original := []byte(`{"format":"asservat-owner-provider-setup/v1","apply":[{"method":"POST","path":"auth/owner/role/runtime","body":{}}],"inspect":["auth/owner/role/runtime"]}`)
	plan := contracts.InstallerServingTLSPlan{FederationServerName: "federation.example.test", KeyServiceServerName: "keys.example.test"}
	got, err := withInstallerServingTLSRecipe(original, plan)
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(original, &before)
	_ = json.Unmarshal(got, &after)
	var selected contracts.InstallerServingTLSPlan
	if json.Unmarshal(after["servingTLS"], &selected) != nil || selected != plan || len(after) != len(before)+1 {
		t.Fatal("serving recipe shape", string(got))
	}
	delete(after, "servingTLS")
	for key, value := range before {
		if string(after[key]) != string(value) {
			t.Fatal("provider recipe changed", key)
		}
	}
	if _, err := withInstallerServingTLSRecipe(got, plan); err == nil {
		t.Fatal("overwrote existing TLS selection")
	}
	got, err = withInstallerServingTLSRecipe(original, contracts.InstallerServingTLSPlan{})
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(got, &after)
	if _, present := after["servingTLS"]; present {
		t.Fatal("unselected TLS material requested")
	}
}
