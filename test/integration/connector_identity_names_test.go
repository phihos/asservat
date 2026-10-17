package integration

import (
	"strings"
	"testing"
)

// custodyID uses a stable prefix and a unique counter suffix. Keep the whole
// UUID so independent fixture scenarios cannot alias their private SQL roles.
func connectorSQLRolePrefix(id string) string {
	return "ci_" + strings.ReplaceAll(id, "-", "") + "_"
}

func TestConnectorSQLFixtureRolesKeepCompleteDeterministicIdentity(t *testing.T) {
	first := "10000000-0000-4000-8000-000000000001"
	second := "10000000-0000-4000-8000-000000000002"
	seen := make(map[string]bool)
	for _, id := range []string{first, second} {
		for _, duty := range []string{"source", "journal", "acknowledgement", "cleanup", "verifier", "finalizer", "read"} {
			name := connectorSQLRolePrefix(id) + duty
			if len(name) > 63 || seen[name] || !strings.Contains(name, strings.ReplaceAll(id, "-", "")) {
				t.Fatal("fixture role lost its unique identity or exceeds PostgreSQL's identifier limit", name)
			}
			seen[name] = true
		}
	}
}
