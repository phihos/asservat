package providerconfig

import (
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestOwnerProviderProjectionRejectsInvalidAndOverlappingPKIRoles(t *testing.T) {
	now := time.Now().UTC()
	block, _ := pem.Decode(bootstrapInputCA(t, now, 67001))
	roots := [][]byte{block.Bytes}
	kubernetes := contracts.OwnerProviderEndpoint{Endpoint: "https://api.example", Roots: roots}
	postgres := contracts.OwnerPostgresEndpoint{Host: "database.example", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 1}
	store := contracts.OwnerAuditStore{Endpoint: "https://store.example", Roots: roots, Region: "test", Bucket: "audit"}
	key := contracts.OwnerKeyService{Endpoint: "https://keys.example", Roots: roots, AuditMount: "transit", AuditKey: "audit", PKIMount: "pki", ServerRole: "owner-server", ClientRole: "owner-client"}
	if err := ValidateOwner(kubernetes, postgres, store, key, now); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*contracts.OwnerKeyService){
		"missing-pki":       func(v *contracts.OwnerKeyService) { v.PKIMount = "" },
		"pki-path":          func(v *contracts.OwnerKeyService) { v.PKIMount = "pki/other" },
		"missing-server":    func(v *contracts.OwnerKeyService) { v.ServerRole = "" },
		"invalid-server":    func(v *contracts.OwnerKeyService) { v.ServerRole = "server role" },
		"missing-client":    func(v *contracts.OwnerKeyService) { v.ClientRole = "" },
		"oversized-client":  func(v *contracts.OwnerKeyService) { v.ClientRole = strings.Repeat("c", 129) },
		"same-role":         func(v *contracts.OwnerKeyService) { v.ClientRole = v.ServerRole },
		"same-mount":        func(v *contracts.OwnerKeyService) { v.PKIMount = v.AuditMount },
		"invalid-audit":     func(v *contracts.OwnerKeyService) { v.AuditKey = "a/b" },
		"insecure-provider": func(v *contracts.OwnerKeyService) { v.Endpoint = "http://keys.example" },
		"missing-roots":     func(v *contracts.OwnerKeyService) { v.Roots = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := key
			change(&bad)
			if ValidateOwner(kubernetes, postgres, store, bad, now) == nil {
				t.Fatal("invalid provider input could be persisted")
			}
		})
	}
}
