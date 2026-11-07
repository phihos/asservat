package planning

import (
	value "asservat.local/asservat/internal/domain/planning"
	"slices"
	"testing"
)

func ongoingHTTPComposition(t *testing.T) value.ProfileComposition {
	c := network(text("sample", "packetFilter", "tcp port 8080"))
	c.Resolved = []value.CatalogProfile{rawCatalogProfile(t, httpProfile(16, 4096, 65536, 1048576, "5s"))}
	c.Components[0].Profile = value.ProfileRef{Catalog: "namespace", Name: "raw-capture", Version: "v1"}
	return c
}
func TestExplicitOngoingHTTPSourceKeepsReviewedProjectionAndFilter(t *testing.T) {
	c := ongoingHTTPComposition(t)
	p, err := CompileOngoingPolicyRecorder(c, &fakeCompiler{program: fixtureProgram})
	if err != nil || !p.Valid() || p.Action.ExecutionMode != "ongoing" || p.Action.PacketProfile != "httpHeaders" || !slices.Contains(p.Action.Sensitive, value.ReasonHTTPHeaders) || p.HTTP == nil || !p.HTTP.Valid() || p.HTTP.MaxTotalBytes != 1048576 || p.Filter == nil {
		t.Fatal("explicit reviewed HTTP source unavailable", err)
	}
	if p.Profile.SourceUID != c.Resolved[0].SourceUID || p.Profile.SourceNamespaceUID != c.Resolved[0].SourceNamespaceUID || p.Profile.SourceClusterID != c.Resolved[0].SourceClusterID {
		t.Fatal("HTTP source lost immutable profile provenance")
	}
	if _, err := CompilePolicyRecorder(c, &fakeCompiler{program: fixtureProgram}); err == nil {
		t.Fatal("ongoing HTTP bypassed source-purpose compiler")
	}
}

func TestOngoingHTTPSourceRawPredicateReviewRegression(t *testing.T) {
	c := ongoingHTTPComposition(t)
	c.Components[0].Edits = []value.ProfileEdit{text("sample", "packetFilter", "tcp[20:4] = 1")}
	if !RawBytePredicate("tcp[20:4] = 1") {
		t.Fatal("not an actual raw predicate")
	}
	if p, err := CompileOngoingPolicyRecorder(c, &fakeCompiler{program: fixtureProgram}); err == nil {
		t.Fatalf("ongoing HTTP source compiled unsupported raw predicate: %s", p.Action.Filter)
	}
}
