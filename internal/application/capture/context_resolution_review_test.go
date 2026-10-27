package capture

import (
	"context"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// reviewRevocation is a decision-time review port whose repeated review of
// the preview's Pod finds the exec right revoked: the recorded decision ends,
// so the resolution's own eligibility check refuses (ADR-245).
type reviewRevocation struct {
	f       *investigationFixture
	preview string
}

func (r *reviewRevocation) ReviewResolved(context.Context, identity.Identity, targets.Request) error {
	return nil
}
func (r *reviewRevocation) ReviewPreview(_ context.Context, _ identity.Identity, preview string) error {
	r.preview = preview
	r.f.mu.Lock()
	r.f.denied = true
	r.f.mu.Unlock()
	return nil
}

func TestResolveContextRequestRepeatsDecisionTimeReviewFirst(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	reviews := &reviewRevocation{f: f}
	f.svc.Reviews = reviews
	if _, err := f.svc.ResolveContextRequest(context.Background(), f.source(t, context.Background()), p.ID, "original"); !errors.Is(err, value.ErrDenied) || reviews.preview != p.ID {
		t.Fatal("a revoked exec right resolved the request", err, reviews.preview)
	}
}
