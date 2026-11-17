package capture

import (
	"context"
	"errors"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
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
	other := reviewed(f.preview(t), key)
	other.Plan = artifact.Digest{9}
	if _, err := f.svc.Request(context.Background(), f.source(t, context.Background()), other); !errors.Is(err, value.ErrConflict) || f.admissions.Load() != 1 {
		t.Fatal("known key changed its bound preview", err)
	}
}
