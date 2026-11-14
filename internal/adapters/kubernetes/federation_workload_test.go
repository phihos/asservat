package kubernetes

import (
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

func TestFederationWorkloadRejectsInvalidOwnerAccount(t *testing.T) {
	installation := "10000000-0000-4000-8000-000000000001"
	ns := contracts.WorkerObjectReference{Name: "asservat-hub"}
	d := contracts.FederationDeployment{InstallationID: installation, Port: contracts.FederationPort, Owner: &contracts.OwnerGuardInputs{Namespace: ns}, ProviderAuthentication: &contracts.FederationProviderAuthentication{Namespace: ns, ServiceAccount: contracts.WorkerObjectReference{Name: contracts.FederationServiceAccountName(installation)}}}
	for _, account := range []string{"", "*", "other/account", "Owner", strings.Repeat("a", 254)} {
		if _, err := BuildFederationWorkload(ns.Name, "registry.example/asservat@sha256:"+strings.Repeat("a", 64), "hub-owner", account, d, "NodePort", 31446); err == nil {
			t.Fatalf("invalid owner account accepted: %q", account)
		}
	}
}
