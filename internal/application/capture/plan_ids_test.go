package capture

import (
	"context"
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
)

// ADR-330 D9: the plan digest ignores the random IDs of a preview, so two
// previews of one intent and the request's recomputation name the same plan;
// another plan is ReviewChanged and admits nothing.
func TestPlanDigestStableAcrossPreviewsAndRequest(t *testing.T) {
	f := newInvestigationFixture()
	ctx := t.Context()
	source := f.source(t, ctx)
	plan := func() (value.ContextPreview, artifact.Digest) {
		scoped, digest := WithPlanScope(ctx)
		r, err := f.svc.Preview(scoped, source, f.intent())
		if err != nil {
			t.Fatal(err)
		}
		return r.Preview, digest(r.Preview)
	}
	first, digest := plan()
	second, again := plan()
	if digest == (artifact.Digest{}) || digest != again || first.CaptureID == second.CaptureID {
		t.Fatal("plan digest depends on preview IDs or previews share IDs")
	}
	recompute := func(ctx context.Context) (value.ContextPreview, error) {
		r, err := f.svc.Preview(ctx, source, f.intent())
		return r.Preview, err
	}
	if _, err := f.svc.Request(ctx, source, CaptureRequest{Key: "changed", Plan: artifact.Digest{1}, Preview: recompute}); !errors.Is(err, value.ErrChanged) || f.admissions.Load() != 0 {
		t.Fatal("another plan was admitted", err)
	}
	a, err := f.svc.Request(ctx, source, CaptureRequest{Key: "reviewed", Plan: digest, Preview: recompute})
	if err != nil || f.admissions.Load() != 1 || a.CaptureID == first.CaptureID || a.CaptureID == second.CaptureID {
		t.Fatal("request scope recomputed another plan or reused preview IDs", err)
	}
}
