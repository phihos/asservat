package authorization

import (
	value "asservat.local/asservat/internal/domain/authorization"
	"testing"
)

func TestRawQueryCanonicalScopeRejectsChangedSelection(t *testing.T) {
	g := value.Grant{Kind: value.GrantRawQuery, RawQuery: &value.RawQueryScope{CaseID: "case", Artifacts: []value.RawQueryArtifact{{NativeBytes: 800}}, Reason: "inspect"}}
	g.Scope, g.ExecutionDigest = RawQueryScopeBytes(*g.RawQuery)
	if !RawQueryScopeMatches(g) {
		t.Fatal("original scope mismatch")
	}
	g.RawQuery.Artifacts[0].NativeBytes++
	if RawQueryScopeMatches(g) {
		t.Fatal("changed typed selection accepted")
	}
	g.RawQuery.Artifacts[0].NativeBytes--
	g.ExecutionDigest[0]++
	if RawQueryScopeMatches(g) {
		t.Fatal("changed digest accepted")
	}
	g.ExecutionDigest[0]--
	g.Scope = []byte("{}")
	if RawQueryScopeMatches(g) {
		t.Fatal("changed scope bytes accepted")
	}
}
