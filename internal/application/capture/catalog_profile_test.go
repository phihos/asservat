package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type catalogFixture struct {
	profiles []planning.CatalogProfile
	reads    int
}

func (c *catalogFixture) ReadCatalogProfiles(_ context.Context, _ targets.PodResolution, refs []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	c.reads++
	return c.profiles, nil
}

// organizationDocument re-publishes the network builtin's definition as an
// organization version.
func organizationDocument(t *testing.T, name, version string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../planning/profiles/network-connections-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"], _ = json.Marshal(name)
	doc["version"], _ = json.Marshal(version)
	out, _ := json.Marshal(doc)
	return out
}

// REQ-CPR-001: a composition referencing an organization version previews
// from the current catalog read, pins its source; a disabled version is a
// field error, and builtin-only compositions read no catalog.
func TestCompositionPreviewResolvesOrganizationProfiles(t *testing.T) {
	f := newInvestigationFixture()
	f.svc.Filters = &stubFilters{}
	ref := planning.ProfileRef{Catalog: "organization", Name: "team-network", Version: "v3"}
	catalog := &catalogFixture{profiles: []planning.CatalogProfile{{Ref: ref, SourceClusterID: fixtureID(4), SourceNamespaceUID: "hub-ns", SourceUID: "org-profile", Document: organizationDocument(t, "team-network", "v3"), Enabled: true}}}
	f.svc.Profiles = catalog
	ctx := context.Background()
	c := networkComposition()
	c.Components[0].Profile = ref
	r, err := f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(c))
	if err != nil {
		var step interface{ FixedStep() string }
		if errors.As(err, &step) {
			t.Log("preview failed at", step.FixedStep(), errors.Unwrap(err))
		}
		t.Fatal(err)
	}
	if catalog.reads != 1 || !bytes.Contains(r.Preview.CanonicalScope, []byte(`"sourceUID":"org-profile"`)) || len(r.Plan.Profiles) != 1 || r.Plan.Profiles[0].SourceUID != "org-profile" {
		t.Fatal("organization profile not resolved with its source", catalog.reads, r.Plan.Profiles)
	}
	b, _ := json.Marshal(r.Preview)
	if bytes.Contains(b, []byte("Resolved")) {
		t.Fatal("catalog documents persisted with the preview")
	}

	catalog.profiles[0].Enabled = false
	_, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(c))
	var e planning.CompositionError
	if !errors.As(err, &e) || e.Code != planning.CompositionProfileMissing {
		t.Fatal("disabled organization version previewed", err)
	}

	reads := catalog.reads
	if _, err = f.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(networkComposition())); err != nil || catalog.reads != reads {
		t.Fatal("builtin composition read the catalog", err)
	}
}
