package kms

import (
	"reflect"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestInitialBootstrapProviderPolicyRecipePreservesAcceptedProfileBytes(t *testing.T) {
	names := contracts.InitialBootstrapProviders{IssuerPolicy: "initial-issuer", WrapRole: "initial-wrap", WrapPolicy: "initial-encrypt", UnwrapRole: "initial-unwrap", UnwrapPolicy: "initial-decrypt"}
	public, err := InitialBootstrapProviderPolicies(names, "audit", "key")
	if err != nil {
		t.Fatal(err)
	}
	profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "original", UID: "10000000-0000-4000-8000-000000000001"}, IssuerPolicy: names.IssuerPolicy, WrapRole: names.WrapRole, WrapPolicy: names.WrapPolicy, UnwrapRole: names.UnwrapRole, UnwrapPolicy: names.UnwrapPolicy}
	existing, err := InitialProviderPolicies(profile, "audit", "key")
	if err != nil || !reflect.DeepEqual(public, existing) {
		t.Fatal("public recipe changed runtime policy bytes", err)
	}
	want := map[string]string{
		"initial-issuer":  `{"path":{"auth/token/create/initial-unwrap":{"capabilities":["update"]},"auth/token/create/initial-wrap":{"capabilities":["update"]},"auth/token/lookup-accessor":{"capabilities":["update"]},"auth/token/lookup-self":{"capabilities":["read"]},"auth/token/revoke-accessor":{"capabilities":["update"]},"auth/token/roles/initial-unwrap":{"capabilities":["read"]},"auth/token/roles/initial-wrap":{"capabilities":["read"]},"sys/policies/acl/initial-decrypt":{"capabilities":["read"]},"sys/policies/acl/initial-encrypt":{"capabilities":["read"]},"sys/policies/acl/initial-issuer":{"capabilities":["read"]}}}`,
		"initial-encrypt": `{"path":{"audit/encrypt/key":{"capabilities":["update"]},"auth/token/lookup-self":{"capabilities":["read"]}}}`,
		"initial-decrypt": `{"path":{"audit/decrypt/key":{"capabilities":["update"]},"auth/token/lookup-self":{"capabilities":["read"]}}}`,
	}
	if !reflect.DeepEqual(existing, want) {
		t.Fatal("original exact policy changed")
	}
	profile.Material.UID = ""
	if _, err = InitialProviderPolicies(profile, "audit", "key"); err == nil {
		t.Fatal("public static recipe relaxed runtime material identity")
	}
}
