package mcp

import (
	"context"
	"testing"

	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/presentation"
)

func TestMCPRejectsTypedNilOperationsWithoutPanic(t *testing.T) {
	cfg := Config{PublicOrigin: "https://console.invalid", Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}
	resolver := resolverFunc(func(context.Context, string) (identity.Identity, error) { return testIdentity(), nil })
	var captures *presentation.ContextOperations
	var cases *presentation.ContextCaseOperations
	var composed *presentation.InvestigationOperations
	for name, ops := range map[string]presentation.Operations{"capture": captures, "case": cases, "composed": composed} {
		t.Run(name, func(t *testing.T) {
			if h, err := NewContextHandler(cfg, resolver, ops); err == nil || h != nil {
				t.Fatal("typed nil operations accepted")
			}
		})
	}
}
