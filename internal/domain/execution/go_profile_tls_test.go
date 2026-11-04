package execution

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestGoProfileTLSMaterialZeroAndBoundedImmutableValue(t *testing.T) {
	var zero GoProfileTLSMaterial
	if !zero.IsZero() || zero.Valid() {
		t.Fatal("HTTP zero became TLS")
	}
	material := GoProfileTLSMaterial{RootsPEM: "public certificate material", ServerName: "profile.example.test"}
	material.RootsDigest = artifact.Digest(sha256.Sum256([]byte(material.RootsPEM)))
	if material.IsZero() || !material.Valid() {
		t.Fatal("bounded public material refused")
	}
	for _, change := range []func(*GoProfileTLSMaterial){
		func(m *GoProfileTLSMaterial) { m.RootsPEM = "" },
		func(m *GoProfileTLSMaterial) {
			m.RootsPEM = strings.Repeat("x", GoProfileTLSRootsLimit+1)
			m.RootsDigest = artifact.Digest(sha256.Sum256([]byte(m.RootsPEM)))
		},
		func(m *GoProfileTLSMaterial) { m.RootsDigest[0]++ },
		func(m *GoProfileTLSMaterial) { m.ServerName = "https://profile.example.test" },
	} {
		copy := material
		change(&copy)
		if copy.Valid() {
			t.Fatal("invalid TLS material accepted")
		}
		if !material.Valid() {
			t.Fatal("copied value mutated original")
		}
	}
	encoded, err := json.Marshal(struct {
		TLS GoProfileTLSMaterial `json:"tls,omitzero"`
	}{})
	if err != nil || string(encoded) != "{}" {
		t.Fatal("HTTP encoding gained TLS fields", string(encoded), err)
	}
}

func TestGoProfileServerNameKeepsExistingGrammar(t *testing.T) {
	for _, name := range []string{"localhost", "profile.example.test", "127.0.0.1", "::1", "2001:db8::5"} {
		if !ValidGoProfileServerName(name) {
			t.Fatal("existing name refused", name)
		}
	}
	for _, name := range []string{"", "EXAMPLE.test", "https://profile.example.test", "profile.example.test:443", "profile.example.test.", "-profile.test", "profile-.test", "*.example.test", "::", "224.0.0.1", "fe80::1%eth0", "::ffff:127.0.0.1", "profile\r\nheader"} {
		if ValidGoProfileServerName(name) {
			t.Fatal("server name grammar expanded", name)
		}
	}
}
