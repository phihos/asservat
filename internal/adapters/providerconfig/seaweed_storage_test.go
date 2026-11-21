package providerconfig

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"asservat.local/asservat/internal/contracts"
)

const swInstall = "00000000-0000-4000-8000-000000000001"
const swCluster = "00000000-0000-4000-8000-000000000002"
const swRoot = "00000000-0000-4000-8000-000000000003"

func swCredential(t *testing.T, purpose, scope string) contracts.SeaweedCredential {
	t.Helper()
	c, e := GenerateSeaweedCredential(contracts.SeaweedPrincipalKey{Purpose: purpose, ScopeID: scope})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestSeaweedCompileRefusesIgnoredOrForeignAuthority(t *testing.T) {
	admin := swCredential(t, "admin", swInstall)
	base := contracts.SeaweedGrant{Credential: swCredential(t, "initial-audit", swInstall), Bucket: "audit", InstallationID: swInstall}
	cases := map[string]func(*contracts.SeaweedGrant){"ignored-prefix": func(g *contracts.SeaweedGrant) { g.Prefixes = []string{"unreviewed/"} }, "foreign-principal": func(g *contracts.SeaweedGrant) { g.Credential.Principal.ScopeID = swCluster }, "broad-bucket": func(g *contracts.SeaweedGrant) { g.Bucket = "*" }, "admin": func(g *contracts.SeaweedGrant) { g.Credential = admin }}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			g := base
			f(&g)
			if _, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{g}); e == nil {
				t.Fatal("invalid authority accepted")
			}
		})
	}
	if _, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{base, base}); e == nil {
		t.Fatal("duplicate identity")
	}
	audit := base
	audit.Credential = swCredential(t, "owner-audit", swInstall)
	audit.RootID = swRoot
	audit.Prefixes = []string{"operation-audit/v1/" + swCluster + "/"}
	if _, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{audit}); e == nil {
		t.Fatal("foreign root prefix")
	}
	history := base
	history.Credential = swCredential(t, "regional-history", swCluster)
	history.ClusterID = swCluster
	history.RootID = swRoot
	out, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{history})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(out.Config), "history/v1/"+swRoot+"/"+swCluster+"/*") || len(out.Policies["audit"]) != 0 {
		t.Fatal("missing history/inventory boundary")
	}
}

func TestSeaweedBackendAdministratorDoesNotMintInstallationIdentity(t *testing.T) {
	admin := swCredential(t, "admin", swCluster) // independent retained backend UUID
	first := contracts.SeaweedGrant{Credential: swCredential(t, "initial-audit", swInstall), Bucket: "audit", InstallationID: swInstall}
	if _, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{first}); e != nil {
		t.Fatal("actual installation refused under independent backend", e)
	}
	foreign := contracts.SeaweedGrant{Credential: swCredential(t, "download-read", swRoot), Bucket: "evidence", InstallationID: swRoot}
	if _, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{first, foreign}); e == nil {
		t.Fatal("multiple installation scopes accepted")
	}
}

// Seaweed4.53's policy_engine.StringOrStringSlice marshaler emits one value
// as a string for Action/Resource/Condition. Emit that reviewed canonical shape
// directly; readback equality must remain exact rather than ignoring fields.
func TestSeaweedPolicyUsesProviderCanonicalSingletonShape(t *testing.T) {
	admin := swCredential(t, "admin", swCluster)
	g := contracts.SeaweedGrant{Credential: swCredential(t, "evidence-delete", swInstall), Bucket: "evidence", InstallationID: swInstall}
	out, e := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{g})
	if e != nil {
		t.Fatal(e)
	}
	var policy struct {
		Statement []map[string]any `json:"Statement"`
	}
	if json.Unmarshal(out.Policies["evidence"], &policy) != nil {
		t.Fatal("policy")
	}
	check := func(value any) {
		t.Helper()
		if values, ok := value.([]any); ok && len(values) == 1 {
			t.Fatal("provider would re-encode singleton policy array")
		}
	}
	for _, statement := range policy.Statement {
		check(statement["Action"])
		check(statement["Resource"])
		if conditions, ok := statement["Condition"].(map[string]any); ok {
			for _, keys := range conditions {
				for _, value := range keys.(map[string]any) {
					check(value)
				}
			}
		}
	}
}

func TestSeaweedRegionalPoliciesDoNotGrowTheBucketPolicy(t *testing.T) {
	admin := swCredential(t, "admin", swInstall)
	ordinary := contracts.SeaweedGrant{Credential: swCredential(t, "download-read", swInstall), Bucket: "evidence", InstallationID: swInstall}
	one, err := CompileSeaweedStorage(admin, []contracts.SeaweedGrant{ordinary})
	if err != nil {
		t.Fatal(err)
	}
	grants := []contracts.SeaweedGrant{ordinary}
	for n := 1; n <= 65; n++ {
		cluster := fmt.Sprintf("10000000-0000-4000-8000-%012d", n)
		for _, role := range contracts.RemoteObjectStorePrincipals() {
			grants = append(grants, contracts.SeaweedGrant{Credential: swCredential(t, role, cluster), Bucket: "evidence", InstallationID: swInstall, ClusterID: cluster, RootID: swRoot})
		}
	}
	fleet, err := CompileSeaweedStorage(admin, grants)
	if err != nil {
		t.Fatal(err)
	}
	if string(fleet.Policies["evidence"]) != string(one.Policies["evidence"]) {
		t.Fatal("regional principals changed the shared bucket policy")
	}
	var config struct {
		Policies   []struct{ Name, Content string }
		Identities []struct {
			Name                 string
			Actions, PolicyNames []string
		}
	}
	if err := json.Unmarshal(fleet.Config, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Policies) != 130 {
		t.Fatalf("got %d regional policies", len(config.Policies))
	}
	policies := map[string]string{}
	for _, p := range config.Policies {
		policies[p.Name] = p.Content
	}
	for _, id := range config.Identities {
		if strings.HasPrefix(id.Name, "asservat-regional-") && (len(id.Actions) != 0 || len(id.PolicyNames) != 1 || id.PolicyNames[0] != id.Name || !json.Valid([]byte(policies[id.Name]))) {
			t.Fatalf("regional identity %s lacks its own scoped policy", id.Name)
		}
	}
}
