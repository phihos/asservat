package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
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

func (c *catalogFixture) ListCatalogProfiles(_ context.Context, _ targets.PodResolution, catalog string) ([]planning.CatalogProfile, error) {
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

// REQ-CPR-001: a stored preview carries no catalog documents, so a start
// re-reads the pinned organization version and compiles with it; a changed
// version refuses before admission.
func TestCatalogProfileStartFromStoredPreview(t *testing.T) {
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	base.svc.Previews, base.svc.Admission, base.svc.Recorders = f, f, availableRecording{base}
	base.svc.Filters = &stubFilters{}
	ref := planning.ProfileRef{Catalog: "organization", Name: "team-network", Version: "v3"}
	catalog := &catalogFixture{profiles: []planning.CatalogProfile{{Ref: ref, SourceClusterID: fixtureID(4), SourceNamespaceUID: "hub-ns", SourceUID: "org-profile", Document: organizationDocument(t, "team-network", "v3"), Enabled: true}}}
	base.svc.Profiles = catalog
	ctx := context.Background()
	c := networkComposition()
	c.Components[0].Profile = ref
	preview, err := base.svc.PreviewComposition(ctx, f.source(t, ctx), f.compositionIntent(c))
	if err != nil || !preview.Recordable {
		t.Fatal("preview", err, preview.Recordable)
	}
	p := preview.Preview
	stored := f.previews[p.ID]
	stored.Intent.Composition.Resolved = nil // as persisted (json:"-")
	f.previews[p.ID] = stored
	if _, err = f.request(t, p, "start"); !errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 || catalog.reads != 2 {
		t.Fatal("start from stored preview", err, catalog.reads)
	}
	catalog.profiles[0].SourceUID = "republished"
	if _, err = f.request(t, p, "changed"); errors.Is(err, reachedRecordingAdmission) || len(f.seen) != 1 {
		t.Fatal("changed version reached admission", err)
	}
}

// REQ-CPR-001: an eligible caller lists builtins and published versions with
// availability and modes, and reads one exact version with its digest; a
// missing version is not found and an ineligible caller is denied.
func TestCaptureProfileListAndGet(t *testing.T) {
	f := newInvestigationFixture()
	ref := planning.ProfileRef{Catalog: "organization", Name: "team-network", Version: "v3"}
	f.svc.Profiles = &catalogFixture{profiles: []planning.CatalogProfile{{Ref: ref, SourceUID: "org-profile", Document: organizationDocument(t, "team-network", "v3"), Deprecated: true}}}
	ctx := context.Background()
	source := f.source(t, ctx)
	target := f.compositionIntent(networkComposition()).Target
	all, _, err := f.svc.CaptureProfiles(ctx, source, target, "")
	if err != nil || len(all) != 6 || all[0].Ref.Catalog != "builtin" || !all[0].Available || all[3].Ref.Name != "finite-logs" || !all[3].Available || all[4].Ref.Name != "inspect-processes" || !all[4].Available || all[5].Ref != ref || all[5].Available || !all[5].Deprecated || len(all[5].ExecutionModes) != 2 {
		t.Fatalf("list = %+v, %v", all, err)
	}
	if builtins, _, err := f.svc.CaptureProfiles(ctx, source, target, "builtin"); err != nil || len(builtins) != 5 {
		t.Fatal("builtin filter", builtins, err)
	}
	got, _, err := f.svc.CaptureProfile(ctx, source, target, ref)
	if err != nil || got.Ref != ref || got.Digest != all[5].Digest || !bytes.Contains(got.Definition, []byte(`"editableFields"`)) {
		t.Fatal("get", got, err)
	}
	if _, _, err = f.svc.CaptureProfile(ctx, source, target, planning.ProfileRef{Catalog: "organization", Name: "absent", Version: "v1"}); !errors.Is(err, value.ErrProfileNotFound) {
		t.Fatal("absent version", err)
	}
	f.denied = true
	if _, _, err = f.svc.CaptureProfiles(ctx, source, target, ""); err == nil {
		t.Fatal("ineligible caller listed profiles")
	}
}
