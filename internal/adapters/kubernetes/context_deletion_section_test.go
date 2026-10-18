package kubernetes

import (
	"crypto/ed25519"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestContextDeletionSectionValid(t *testing.T) {
	now := time.Now()
	key, _, _ := ed25519.GenerateKey(nil)
	valid := func() *contracts.ContextDeletionDeployment {
		return &contracts.ContextDeletionDeployment{EvidenceStore: contracts.OwnerAuditStore{Endpoint: "https://evidence.example.test", Region: "test", Bucket: "evidence", Roots: [][]byte{ownerConfigurationTestRoot(t, now)}},
			Signing: contracts.ContextDeletionSigning{Mount: "transit", Key: "asservat-x-context-deletion", Version: 2, KeyID: "v2", PublicKeys: map[string][]byte{"v1": key, "v2": key}}}
	}
	if !ContextDeletionSectionValid(nil, now) || !ContextDeletionSectionValid(valid(), now) {
		t.Fatal("absent or valid section refused")
	}
	for name, change := range map[string]func(*contracts.ContextDeletionDeployment){
		"http endpoint": func(v *contracts.ContextDeletionDeployment) {
			v.EvidenceStore.Endpoint = "http://evidence.example.test"
		},
		"no roots":       func(v *contracts.ContextDeletionDeployment) { v.EvidenceStore.Roots = nil },
		"no bucket":      func(v *contracts.ContextDeletionDeployment) { v.EvidenceStore.Bucket = "" },
		"mount path":     func(v *contracts.ContextDeletionDeployment) { v.Signing.Mount = "transit/x" },
		"zero version":   func(v *contracts.ContextDeletionDeployment) { v.Signing.Version = 0 },
		"unknown key ID": func(v *contracts.ContextDeletionDeployment) { v.Signing.KeyID = "v3" },
		"short key":      func(v *contracts.ContextDeletionDeployment) { v.Signing.PublicKeys["v1"] = key[:16] },
		"no public keys": func(v *contracts.ContextDeletionDeployment) { v.Signing.PublicKeys = nil },
	} {
		v := valid()
		change(v)
		if ContextDeletionSectionValid(v, now) {
			t.Fatal("invalid section accepted:", name)
		}
	}
}
