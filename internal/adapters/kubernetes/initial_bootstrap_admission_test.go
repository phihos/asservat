package kubernetes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func bootstrapAdmissionFixture(t *testing.T) contracts.InitialBootstrap {
	t.Helper()
	root := ownerConfigurationTestRoot(t, time.Now())
	raw, err := os.ReadFile("../../../examples/fleet-settings.json")
	var fleet contracts.FleetSettings
	if err != nil || json.Unmarshal(raw, &fleet) != nil {
		t.Fatal("synthetic fleet fixture unavailable")
	}
	return contracts.InitialBootstrap{
		Format: contracts.InitialBootstrapFormat, Name: "install", BootstrapNamespace: "trusted-bootstrap", TargetNamespace: "asservat",
		Image: "example.invalid/asservat@sha256:" + strings.Repeat("a", 64), ProbeAudience: "asservat-bootstrap-observation",
		Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: "original-administrator"}},
		Kubernetes:     contracts.OwnerProviderEndpoint{Endpoint: "https://kube.example.test", Roots: [][]byte{root}},
		Postgres:       contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", MaxConnections: 2, Roots: [][]byte{root}},
		AuditStore:     contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Region: "test", Bucket: "audit", Roots: [][]byte{root}},
		KeyService:     contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", AuditMount: "transit", AuditKey: "audit", Roots: [][]byte{root}},
		Fleet:          contracts.InitialBootstrapFleet{Issuer: fleet.Issuer, Clients: fleet.Clients, Subjects: fleet.Subjects, Groups: fleet.Groups, DeliveryProfiles: fleet.DeliveryProfiles, MaxActiveBootstraps: fleet.MaxActiveBootstraps, MaxBootstrapHistory: fleet.MaxBootstrapHistory, MaxClusters: fleet.MaxClusters},
		Providers:      contracts.InitialBootstrapProviders{IssuerPolicy: "issuer", WrapRole: "wrap-role", WrapPolicy: "wrap-policy", UnwrapRole: "unwrap-role", UnwrapPolicy: "unwrap-policy"},
	}
}

// Kubernetes explicitly excludes variables from matchConditions because they
// run before variable composition. This catches the actual unsupported policy
// expression, rather than merely testing the later validation expression.
func TestInitialBootstrapAdmissionMatchesWithoutPolicyVariables(t *testing.T) {
	policy, _, err := InitialBootstrapAdmission(bootstrapAdmissionFixture(t))
	if err != nil {
		t.Fatal("synthetic desired input rejected", err)
	}
	if len(policy.Spec.MatchConditions) != 1 || len(policy.Spec.Validations) != 1 {
		t.Fatal("closed guard shape changed")
	}
	for _, condition := range policy.Spec.MatchConditions {
		if strings.Contains(condition.Expression, "variables.") {
			t.Fatal("Kubernetes matchConditions cannot resolve policy variables")
		}
		for _, name := range []string{"install-bootstrap-state", "install-private-progress", "install-continuity-probe", "install-bootstrap-probe", "install-preparer", "install-probe", "install-probe-lifetime", "install-sql-material", "install-provider-material", "trusted-bootstrap"} {
			if !strings.Contains(condition.Expression, "\""+name+"\"") {
				t.Fatalf("fixed protected key omitted: %s", name)
			}
		}
		if !strings.Contains(condition.Expression, "oldObject.metadata.name") || !strings.Contains(condition.Expression, "request.resource.resource == 'namespaces'") {
			t.Fatal("original deletion identity or namespace occupancy omitted")
		}
	}
	if !strings.Contains(policy.Spec.Validations[0].Expression, "variables.sub") {
		t.Fatal("subresource restrictions were lost while correcting matching")
	}
}
