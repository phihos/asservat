package capture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type storedProfileCatalog struct {
	catalogFixture
	onRead func(context.Context, targets.PodResolution, []planning.ProfileRef)
}

func (c *storedProfileCatalog) ReadCatalogProfiles(ctx context.Context, target targets.PodResolution, refs []planning.ProfileRef) ([]planning.CatalogProfile, error) {
	if c.onRead != nil {
		c.onRead(ctx, target, refs)
	}
	return c.catalogFixture.ReadCatalogProfiles(ctx, target, refs)
}

type storedProfileReview struct {
	f        *retainedRecording
	preview  RecorderPreviewResult
	grants   *fakeGrants
	catalog  *storedProfileCatalog
	endpoint *changingProfileEndpoint
	access   *authorization.ResultAccess
}

func newStoredProfileReview(t *testing.T, namespace bool) storedProfileReview {
	t.Helper()
	base := newInvestigationFixture()
	f := &retainedRecording{investigationFixture: base}
	base.target.NodeUID, base.target.NodeBootID, base.target.Pin.NodeName = "", "", ""
	base.target.ExecutionClass, base.cap.ExecutionClass = artifact.ContextAPIExecution, artifact.ContextAPIExecution
	endpoint, grants, catalog := &changingProfileEndpoint{}, &fakeGrants{}, &storedProfileCatalog{}
	base.svc.Previews, base.svc.Admission, base.svc.Recorders = f, f, availableProfile{availableRecording{base}}
	base.svc.ProfileEndpoints, base.svc.Grants, base.svc.Profiles = endpoint, grants, catalog
	ref := planning.ProfileRef{Catalog: "builtin", Name: "go-cpu", Version: "v1"}
	if namespace {
		ref = planning.ProfileRef{Catalog: "namespace", Name: "go-heap-snapshot", Version: "v1"}
		raw, err := os.ReadFile("../planning/profiles/go-cpu-v1.json")
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if json.Unmarshal(raw, &doc) != nil {
			t.Fatal("profile document")
		}
		doc["name"] = ref.Name
		definition := doc["definition"].(map[string]any)
		recipe := definition["recipe"].(map[string]any)
		action := recipe["actions"].([]any)[0].(map[string]any)
		parameters := action["parameters"].(map[string]any)
		parameters["type"], parameters["mode"], parameters["forceGC"] = "heap", "snapshot", false
		delete(parameters, "duration")
		action["limits"].(map[string]any)["timeout"] = "5s"
		definition["editableFields"] = []any{map[string]any{"actionID": "cpu", "field": "actionMaxBytes", "label": "Output limit"}}
		raw, err = json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		catalog.profiles = []planning.CatalogProfile{{Ref: ref, SourceClusterID: base.target.Request.ClusterID, SourceNamespaceUID: base.target.Request.Namespace.UID, SourceUID: "heap-version", Document: raw, Enabled: true}}
	}
	c := planning.ProfileComposition{Components: []planning.ProfileComponent{{ID: "profile", Profile: ref}}, MaxTotalBytes: 16 << 20, MaxDuration: "30s"}
	preview, err := base.svc.PreviewComposition(t.Context(), f.source(t, t.Context()), f.compositionIntent(&c))
	if err != nil || !preview.Recordable {
		t.Fatal("profile preview", err)
	}
	// Exercise the persisted wire boundary: Resolved is deliberately json:"-".
	raw, err := json.Marshal(preview.Preview)
	var stored value.ContextPreview
	if err != nil || json.Unmarshal(raw, &stored) != nil || stored.Intent.Composition.Resolved != nil {
		t.Fatal("preview persistence")
	}
	f.previews[stored.ID] = stored
	access := &authorization.ResultAccess{ActionIDs: []string{preview.Plan.Actions[0].ID}, Operations: []string{authorization.GrantDownloadOperation}, ClientIDs: []string{"console"}, MaxArtifacts: 1, MaxBytes: 16 << 20, MaxOperations: 1, NotAfter: f.now.Add(time.Hour)}
	return storedProfileReview{f, preview, grants, catalog, endpoint, access}
}

func TestProfileStoredNamespaceReviewRehydratesCatalog(t *testing.T) {
	x := newStoredProfileReview(t, true)
	p := x.preview.Preview
	targetReads, endpointReads := x.f.targetReads.Load(), x.endpoint.calls
	for attempt := 0; attempt < 2; attempt++ {
		_, err := x.f.svc.RequestWithResultAccess(t.Context(), x.f.source(t, t.Context()), p.ID, "review", x.access)
		if !errors.Is(err, authorization.ErrApprovalRequired) || len(x.grants.requests) != 1 {
			t.Fatal("stored namespace profile did not open exactly one review", err, len(x.grants.requests))
		}
	}
	in := x.grants.requests[0]
	profile := in.Review.Actions[0].Profile
	e := x.preview.Plan.Input.Endpoints[0]
	if in.DataClass != "raw" || !bytes.Equal(in.Scope, p.CanonicalScope) || in.ExecutionDigest != p.ScopeDigest || x.grants.grant.ResultAccessDigest != authapp.ResultAccessDigest(p.CaptureID, p.ScopeDigest, authapp.NormalizeResultAccess(*x.access)) || in.Review.Actions[0].MaxBytes != 16<<20 || profile == nil || profile.Runtime != "go" || profile.Source != "httpEndpoint" || profile.Type != "heap" || profile.Mode != "snapshot" || profile.ForceGC || profile.Duration != "" || profile.Timeout != "5s" || profile.Port != e.Port || profile.SourceRef != e.Request.SourceRef || profile.SourceName != e.SourceName || profile.PathPolicy != e.PathPolicy || profile.AddressMode != e.AddressMode || profile.EndpointDigest != x.preview.Plan.Actions[0].EndpointDigest || !in.Review.Deadline.Equal(p.Deadline) {
		t.Fatal("stored profile review replaced approved facts", profile)
	}
	if x.catalog.reads != 2 || x.f.targetReads.Load() != targetReads || x.endpoint.calls != endpointReads || len(x.f.seen) != 0 || x.f.previews[p.ID].Intent.Composition.Resolved != nil {
		t.Fatal("review reselected, persisted documents, acquired, or re-read pending grant", x.catalog.reads)
	}
	x.grants.covering = nil
	x.grants.grant.ExpiresAt = x.f.now.Add(time.Minute)
	_, err := x.f.svc.RequestWithResultAccess(t.Context(), x.f.source(t, t.Context()), p.ID, "approved", x.access)
	if !errors.Is(err, reachedRecordingAdmission) || len(x.f.seen) != 1 || x.catalog.reads != 3 || len(x.grants.requests) != 1 {
		t.Fatal("approved stored profile did not use the ordinary single catalog read before admission", err, x.catalog.reads)
	}
}

func TestProfileStoredReviewRejectsChangedCatalog(t *testing.T) {
	for _, change := range []string{"replaced", "definition", "disabled", "missing", "reader-missing"} {
		t.Run(change, func(t *testing.T) {
			x := newStoredProfileReview(t, true)
			switch change {
			case "replaced":
				x.catalog.profiles[0].SourceUID = "replacement"
			case "definition":
				x.catalog.profiles[0].Document = bytes.Replace(x.catalog.profiles[0].Document, []byte(`"timeout":"5s"`), []byte(`"timeout":"6s"`), 1)
			case "disabled":
				x.catalog.profiles[0].Enabled = false
			case "missing":
				x.catalog.profiles = nil
			case "reader-missing":
				x.f.svc.Profiles = nil
			}
			_, err := x.f.svc.RequestWithResultAccess(t.Context(), x.f.source(t, t.Context()), x.preview.Preview.ID, "review", x.access)
			if err == nil || errors.Is(err, authorization.ErrApprovalRequired) || len(x.grants.requests) != 0 || len(x.f.seen) != 0 {
				t.Fatal("changed catalog opened a review or acquired", change, err)
			}
		})
	}
}

func TestProfileStoredReviewKeepsOriginalBounds(t *testing.T) {
	for _, change := range []string{"caller-bound", "preview-bound", "cancel", "preview-expired"} {
		t.Run(change, func(t *testing.T) {
			x := newStoredProfileReview(t, true)
			p := x.preview.Preview
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			until, _ := ctx.Deadline()
			if change == "preview-bound" {
				ctx = t.Context()
				until = p.Deadline
			}
			x.catalog.onRead = func(call context.Context, target targets.PodResolution, refs []planning.ProfileRef) {
				got, ok := call.Deadline()
				if !ok || !got.Equal(until) || target.Request != p.Target || len(refs) != 1 || refs[0] != p.Intent.Composition.Components[0].Profile {
					t.Fatal("catalog read lost original target, version or deadline")
				}
				if change == "cancel" {
					cancel()
				}
				if change == "preview-expired" {
					x.f.now = p.Deadline
				}
			}
			var err error
			if change == "preview-bound" {
				_, err = x.f.svc.recorderRequest(ctx, x.f.source(t, ctx), x.f.previews[p.ID], "review", x.access)
			} else {
				_, err = x.f.svc.RequestWithResultAccess(ctx, x.f.source(t, ctx), p.ID, "review", x.access)
			}
			if change == "caller-bound" || change == "preview-bound" {
				if !errors.Is(err, authorization.ErrApprovalRequired) || len(x.grants.requests) != 1 {
					t.Fatal("bounded review failed", err)
				}
			} else if err == nil || errors.Is(err, authorization.ErrApprovalRequired) || len(x.grants.requests) != 0 {
				t.Fatal("late/cancelled catalog read opened review", err)
			}
		})
	}
}

func TestProfileStoredBuiltinAndCoveringGrantNeedNoCatalogRead(t *testing.T) {
	x := newStoredProfileReview(t, false)
	_, err := x.f.svc.RequestWithResultAccess(t.Context(), x.f.source(t, t.Context()), x.preview.Preview.ID, "review", x.access)
	if !errors.Is(err, authorization.ErrApprovalRequired) || len(x.grants.requests) != 1 || x.catalog.reads != 0 {
		t.Fatal("builtin review read catalog or failed", err, x.catalog.reads)
	}
	x = newStoredProfileReview(t, true)
	p := x.preview.Preview
	_, err = x.f.svc.RequestWithResultAccess(t.Context(), x.f.source(t, t.Context()), p.ID, "review", x.access)
	if !errors.Is(err, authorization.ErrApprovalRequired) {
		t.Fatal(err)
	}
	x.grants.covering = nil
	x.catalog.onRead = func(context.Context, targets.PodResolution, []planning.ProfileRef) {
		t.Fatal("covering grant added a catalog read")
	}
	if err := x.f.svc.reviewResultAccess(t.Context(), x.f.source(t, t.Context()), p.ID, "approved", x.access); err != nil || x.catalog.reads != 2 || len(x.grants.requests) != 1 {
		t.Fatal("covering grant changed its review path", err)
	}
}
