package capture

import (
	"context"
	"errors"
	"testing"

	value "asservat.local/asservat/internal/domain/capture"
)

// The public deterministic key is correlation, never a secret or authority.
// These checks exercise the real investigation service, not a browser hint.
func TestPublicApprovalIntentKeyCannotCrossActorClientOrPreview(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	key := "approved-preview-" + p.ID
	accepted, err := f.request(t, p, key)
	if err != nil {
		t.Fatal(err)
	}
	original := f.actor
	for _, change := range []string{"subject", "client"} {
		f.actor = original
		if change == "subject" {
			f.actor.Subject = "another-person"
		} else {
			f.actor.ClientID = "another-client"
		}
		if _, err := f.request(t, p, key); !errors.Is(err, value.ErrDenied) || f.admissions.Load() != 1 {
			t.Fatal("known key granted another actor/client authority", change, err)
		}
	}
	f.actor = original
	replay, err := f.request(t, p, key)
	if err != nil || !replay.Replay || replay.CaptureID != accepted.CaptureID {
		t.Fatal("original intent was not recoverable", err)
	}
	other := f.preview(t)
	if _, err := f.request(t, other, key); !errors.Is(err, value.ErrConflict) || f.admissions.Load() != 1 {
		t.Fatal("known key changed its bound preview", err)
	}
}

func TestClosedPublicApprovalIntentNeedsNewPreviewEvenWithNewKey(t *testing.T) {
	f := newInvestigationFixture()
	p := f.preview(t)
	key := "approved-preview-" + p.ID
	ctx := context.Background()
	closed, err := f.svc.ResolveContextRequest(ctx, f.source(t, ctx), p.ID, key)
	if err != nil || closed.State != value.RequestClosed {
		t.Fatal("original intent did not close", err)
	}
	for _, attempt := range []string{key, "different-attempt-key"} {
		if _, err := f.request(t, p, attempt); !errors.Is(err, value.ErrDenied) || f.admissions.Load() != 0 {
			t.Fatal("closed preview became a fresh start", err)
		}
	}
	fresh := f.preview(t)
	if _, err := f.request(t, fresh, "approved-preview-"+fresh.ID); err != nil || f.admissions.Load() != 1 {
		t.Fatal("fresh review could not create a new intent", err)
	}
}
