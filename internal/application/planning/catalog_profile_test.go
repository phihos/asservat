package planning

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/planning"
)

// catalogDocument re-publishes the embedded network builtin's definition as
// a catalog version under name/version.
func catalogDocument(t *testing.T, name, version string) []byte {
	t.Helper()
	raw, err := builtinFiles.ReadFile("profiles/network-connections-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"], _ = json.Marshal(name)
	doc["version"], _ = json.Marshal(version)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func namespaceComposition(t *testing.T, ref value.ProfileRef, resolved ...value.CatalogProfile) value.ProfileComposition {
	c := network()
	c.Components[0].Profile = ref
	c.Resolved = resolved
	return c
}

// REQ-CPR-001: catalog versions resolve only from the caller's read of that
// exact catalog, pin their digest and source, and never shadow a builtin.
func TestCatalogProfilesResolveWithoutShadowing(t *testing.T) {
	ref := value.ProfileRef{Catalog: "namespace", Name: "team-network", Version: "v2"}
	published := value.CatalogProfile{Ref: ref, SourceClusterID: "00000000-0000-4000-8000-000000000001", SourceNamespaceUID: "ns-uid", SourceUID: "profile-uid", Document: catalogDocument(t, "team-network", "v2"), Enabled: true, Deprecated: true}
	c := namespaceComposition(t, ref, published)
	actions, p, err := expand(c, &fakeCompiler{program: fixtureProgram})
	if err != nil || len(actions) == 0 || p.SourceUID != "profile-uid" || p.SourceNamespaceUID != "ns-uid" || !p.Deprecated || p.Ref != ref {
		t.Fatalf("namespace profile %+v %v", p, err)
	}
	wire, _ := json.Marshal(p.wire("net"))
	if !bytes.Contains(wire, []byte(`"sourceUID":"profile-uid"`)) {
		t.Fatalf("provenance lacks source: %s", wire)
	}
	builtin, _ := json.Marshal(mustBuiltin(t).wire("net"))
	if bytes.Contains(builtin, []byte("source")) {
		t.Fatalf("builtin provenance names a source: %s", builtin)
	}

	refused := func(c value.ProfileComposition, why string) {
		t.Helper()
		_, _, err := expand(c, &fakeCompiler{program: fixtureProgram})
		var e value.CompositionError
		if !errors.As(err, &e) || e.Code != value.CompositionProfileMissing {
			t.Fatalf("%s: %v", why, err)
		}
	}
	refused(namespaceComposition(t, ref), "unpublished version resolved")
	disabled := published
	disabled.Enabled = false
	refused(namespaceComposition(t, ref, disabled), "disabled version resolved")
	other := published
	other.Ref = value.ProfileRef{Catalog: "organization", Name: "team-network", Version: "v2"}
	refused(namespaceComposition(t, ref, other), "organization version shadowed a namespace reference")
	mismatch := published
	mismatch.Document = catalogDocument(t, "other-name", "v2")
	if _, _, err := expand(namespaceComposition(t, ref, mismatch), &fakeCompiler{program: fixtureProgram}); err == nil {
		t.Fatal("document under another name accepted")
	}

	// A namespace object claiming the builtin name cannot replace the builtin.
	impostor := value.CatalogProfile{Ref: value.ProfileRef{Catalog: "namespace", Name: "network-connections", Version: "v1"}, SourceClusterID: published.SourceClusterID, SourceNamespaceUID: "ns-uid", SourceUID: "impostor", Document: catalogDocument(t, "network-connections", "v1"), Enabled: true}
	_, p, err = expand(namespaceComposition(t, value.ProfileRef{Catalog: "builtin", Name: "network-connections", Version: "v1"}, impostor), &fakeCompiler{program: fixtureProgram})
	if err != nil || p.SourceUID != "" || p.Digest != mustBuiltin(t).Digest {
		t.Fatalf("builtin reference resolved to a namespace object: %+v %v", p, err)
	}
}

func mustBuiltin(t *testing.T) resolvedProfile {
	t.Helper()
	p, err := loadBuiltin("network-connections")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
